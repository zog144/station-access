"""Independent operator endorsement of the canonical Credential Authority signer."""
import base64
import binascii
import hashlib
import hmac
import json
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from django.conf import settings
from zog.host_identify import credential_delivery as cd
from . import credential_https_authority as protected

SCHEMA = "zog-credential-v1-authority-signing-approval-v1"
FIELDS = frozenset(("schema", "grant_sha256",
    "authorization_envelope_sha256", "authority_signer_sha256",
    "authorization_id", "revision", "expires_at", "signature_ed25519"))


def deny():
    raise ValueError("credential-authority-approval-unavailable") from None


def _unique(pairs):
    result = {}
    for key, val in pairs:
        if key in result:
            deny()
        result[key] = val
    return result


def verify(grant, envelope_bytes, signer_public, authorization):
    """Only the previously pinned operator can approve a new signer and envelope."""
    if (type(grant) is not dict or type(envelope_bytes) is not bytes
            or type(signer_public) is not bytes or len(signer_public) != 32):
        deny()
    raw = protected._protected(getattr(
        settings, "HOST_CREDENTIAL_V1_AUTHORITY_APPROVAL_FILE", ""), 0o600)
    try:
        approval = json.loads(raw, object_pairs_hook=_unique,
                              parse_constant=lambda _: deny())
        if (type(approval) is not dict or set(approval) != FIELDS
                or approval["schema"] != SCHEMA
                or approval["authorization_id"] != authorization["authorization_id"]
                or type(approval["revision"]) is not int
                or approval["revision"] != authorization["revision"]
                or type(approval["expires_at"]) is not int
                or approval["expires_at"] <= int(time.time())
                or authorization["expires_at"] > approval["expires_at"]
                or approval["expires_at"] > grant["expires_at"]):
            deny()
        expected = {
            "grant_sha256": hashlib.sha256(cd.canonical(grant)).hexdigest(),
            "authorization_envelope_sha256": hashlib.sha256(envelope_bytes).hexdigest(),
            "authority_signer_sha256": hashlib.sha256(signer_public).hexdigest(),
        }
        for key, digest in expected.items():
            if type(approval[key]) is not str or not hmac.compare_digest(
                    approval[key], digest):
                deny()
        proof = base64.b64decode(approval["signature_ed25519"], validate=True)
        if len(proof) != 64 or base64.b64encode(proof).decode("ascii") != approval["signature_ed25519"]:
            deny()
        unsigned = dict(approval)
        unsigned.pop("signature_ed25519")
        pin = protected._protected(getattr(
            settings, "HOST_CREDENTIAL_HTTPS_OPERATOR_PIN_FILE", ""), 0o444)
        station_pin = protected._protected(getattr(
            settings, "HOST_CREDENTIAL_HTTPS_SIGNER_PIN_FILE", ""), 0o444)
        if len(pin) != 32 or len(station_pin) != 32 or hmac.compare_digest(
                station_pin, signer_public):
            deny()
        Ed25519PublicKey.from_public_bytes(pin).verify(
            proof, SCHEMA.encode("ascii") + bytes([0]) + cd.canonical(unsigned))
    except (ValueError, TypeError, KeyError, UnicodeError, OSError,
            binascii.Error, InvalidSignature):
        deny()
    return True
