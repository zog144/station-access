"""Independent operator signature tests; deliberately synthetic keys only."""
import base64
import hashlib
import json
import time
from pathlib import Path
from unittest.mock import patch

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from django.test import override_settings
from zog.host_identify import credential_delivery as cd
from zog.station_access.host_registry import credential_v1_signer_approval as approval


V = json.loads((Path(__file__).resolve().parents[2] /
    "tests/host_registry/fixtures/credential-delivery-v1-vector.json").read_text())


def values():
    now = int(time.time())
    operator = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(V["host_seed_hex"]))
    authority = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(V["authority_seed_hex"]))
    other = Ed25519PrivateKey.generate()
    from cryptography.hazmat.primitives import serialization
    raw = lambda k: k.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    auth = dict(V["authorization"], approved_at=now - 10, expires_at=now + 3600)
    envelope = cd.canonical(cd.sign_authorization(auth, authority))
    grant = {"operator_approval_sha256": "a"*64, "expires_at": now + 7200,
             "host_id": auth["host_id"], "credential_revision": auth["credential_revision"],
             "revision": auth["revision"]}
    unsigned = {
        "schema": approval.SCHEMA,
        "grant_sha256": hashlib.sha256(cd.canonical(grant)).hexdigest(),
        "authorization_envelope_sha256": hashlib.sha256(envelope).hexdigest(),
        "authority_signer_sha256": hashlib.sha256(raw(authority)).hexdigest(),
        "authorization_id": auth["authorization_id"],
        "revision": auth["revision"],
        "expires_at": now + 5400,
    }
    signed = dict(unsigned)
    signed["signature_ed25519"] = base64.b64encode(operator.sign(
        approval.SCHEMA.encode() + bytes([0]) + cd.canonical(unsigned))).decode()
    return operator, authority, raw, auth, grant, envelope, signed, raw(other)


def test_independent_operator_approval_exact_envelope_and_separate_key():
    operator, authority, raw, auth, grant, envelope, signed, station_pin = values()
    contents = {
        "/root/authority-approval": cd.canonical(signed),
        "/root/operator-pin": raw(operator),
        "/root/station-pin": station_pin,
    }
    with override_settings(
            HOST_CREDENTIAL_V1_AUTHORITY_APPROVAL_FILE="/root/authority-approval",
            HOST_CREDENTIAL_HTTPS_OPERATOR_PIN_FILE="/root/operator-pin",
            HOST_CREDENTIAL_HTTPS_SIGNER_PIN_FILE="/root/station-pin"), \
         patch.object(approval.protected, "_protected",
                      side_effect=lambda path, mode: contents[path]):
        assert approval.verify(grant, envelope, raw(authority), auth)
        with pytest.raises(ValueError):
            approval.verify(grant, envelope+b" ", raw(authority), auth)
        with pytest.raises(ValueError):
            approval.verify(dict(grant, revision=10), envelope, raw(authority), auth)
        with pytest.raises(ValueError):
            approval.verify(grant, envelope, raw(operator), auth)
        with pytest.raises(ValueError):
            approval.verify(grant, envelope, station_pin, auth)
        with pytest.raises(ValueError):
            approval.verify(grant, envelope, raw(authority),
                            dict(auth, revision=999))
        contents["/root/operator-pin"] = station_pin
        with pytest.raises(ValueError):
            approval.verify(grant, envelope, raw(authority), auth)


def test_canonical_authority_loader_verifies_distinct_key_and_operator_signature():
    """Exercise signer PEM, v1 signed envelope and operator approval together."""
    from unittest.mock import patch
    from cryptography.hazmat.primitives import serialization
    from zog.station_access.host_registry import credential_v1_authority as authority
    operator, signing_key, raw, auth, _, _, _, station_pin = values()
    # Real canonical Cloudflare credential identities have the selected UUID
    # embedded in the nonsecret public credential_id field.
    selected_id = "00000000-0000-4000-8000-000000000014"
    auth = dict(auth, credential_id="cloudflare-" + selected_id.replace("-", ""))
    envelope = cd.canonical(cd.sign_authorization(auth, signing_key))
    grant = {
        "host_id": auth["host_id"], "fingerprint": auth["host_fingerprint"],
        "installation_id": auth["installation_id"],
        "state_volume_id": auth["state_volume_id"],
        "registry_id": auth["registry_id"],
        "revision": auth["revision"],
        "credential_revision": auth["credential_revision"],
        "expires_at": auth["expires_at"] + 1800,
    }
    endorsement = {
        "schema": approval.SCHEMA,
        "grant_sha256": hashlib.sha256(cd.canonical(grant)).hexdigest(),
        "authorization_envelope_sha256": hashlib.sha256(envelope).hexdigest(),
        "authority_signer_sha256": hashlib.sha256(raw(signing_key)).hexdigest(),
        "authorization_id": auth["authorization_id"],
        "revision": auth["revision"],
        "expires_at": auth["expires_at"] + 900,
    }
    endorsement["signature_ed25519"] = base64.b64encode(operator.sign(
        approval.SCHEMA.encode() + bytes([0])
        + cd.canonical(endorsement))).decode("ascii")
    signer_pem = signing_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption())
    protected = {
        "/root/v1-key": signer_pem,
        "/root/v1-pin": raw(signing_key),
        "/root/v1-envelope": envelope,
        "/root/v1-endorsement": cd.canonical(endorsement),
        "/root/operator-pin": raw(operator),
        "/root/station-pin": station_pin,
    }
    def read_protected(path, mode, maximum=8192):
        return protected[path]
    with override_settings(
            HOST_IDENTITY_ORIGIN=V["origin"],
            HOST_CREDENTIAL_V1_SIGNING_KEY_FILE="/root/v1-key",
            HOST_CREDENTIAL_V1_SIGNER_PIN_FILE="/root/v1-pin",
            HOST_CREDENTIAL_V1_AUTHORIZATION_FILE="/root/v1-envelope",
            HOST_CREDENTIAL_V1_AUTHORITY_APPROVAL_FILE="/root/v1-endorsement",
            HOST_CREDENTIAL_HTTPS_OPERATOR_PIN_FILE="/root/operator-pin",
            HOST_CREDENTIAL_HTTPS_SIGNER_PIN_FILE="/root/station-pin"), \\
         patch.object(authority.legacy, "_authority", return_value=grant), \\
         patch.object(authority.legacy, "_projection",
                      return_value={"authorization":{"credential_id":selected_id}}), \\
         patch.object(authority.legacy, "_protected", side_effect=read_protected):
        confirmed_grant, confirmed_auth, confirmed_signer = (
            authority._identity_and_authorization())
        assert confirmed_grant == grant
        assert confirmed_auth == auth
        assert raw(confirmed_signer) == raw(signing_key)
        # Switching the installed private signer must fail its pinned public
        # key check even when the authorization envelope has not changed.
        other = Ed25519PrivateKey.generate()
        protected["/root/v1-key"] = other.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption())
        with pytest.raises(ValueError):
            authority._identity_and_authorization()
        protected["/root/v1-key"] = signer_pem
        # Replacing the envelope, without independent operator endorsement,
        # fails even when a new valid Credential Authority signature exists.
        changed = dict(auth, expires_at=auth["expires_at"] - 60)
        protected["/root/v1-envelope"] = cd.canonical(
            cd.sign_authorization(changed, signing_key))
        with pytest.raises(ValueError):
            authority._identity_and_authorization()
        protected["/root/v1-envelope"] = envelope
        # A reused station certificate signer key fails role separation.
        protected["/root/station-pin"] = raw(signing_key)
        with pytest.raises(ValueError):
            authority._identity_and_authorization()
