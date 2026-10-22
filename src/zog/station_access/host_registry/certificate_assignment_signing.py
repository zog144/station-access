"""Distinct protected Ed25519 signer for certificate assignment receipts.

A receipt attests approved station intent, not root's authorization to issue.
Consumers MUST pin this key independently and validate owner grants locally.
"""
import base64
import json
import os
import re
import stat
import time
import uuid
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from django.conf import settings
from datetime import datetime, timezone
from zog.host_identify import signatures


class SigningUnavailable(RuntimeError):
    pass


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")


def managed_enabled():
    """Only advertise when a protected, separately approved managed issuer exists."""
    if not (getattr(settings,"HOST_CERTIFICATE_ASSIGNMENT_ENABLED",False)
            and getattr(settings,"HOST_MANAGED_ADMISSION_ENABLED",False)):
        return False
    try:
        from .managed_views import signer
        signer()
    except (OSError, ValueError, TypeError, RuntimeError, AttributeError):
        return False
    return True



def managed_authority_pin(*, host_id, installation_id, registry_id,
                          host_fingerprint, expected_key_id):
    """Export only a reviewable *candidate* public-key pin for the native owner.

    This cannot authenticate or install the host's root pin. The trusted
    installation/enrollment path must independently verify this candidate
    against the reviewed station signer before installing it. No HTTP route.
    """
    from .models import HostIdentity, ManagedAdmission
    if not getattr(settings, "HOST_MANAGED_ADMISSION_ENABLED", False):
        raise SigningUnavailable("managed admission unavailable")

    try:
        if (type(host_id) is not str or type(installation_id) is not str
                or str(uuid.UUID(host_id)) != host_id
                or str(uuid.UUID(installation_id)) != installation_id):
            raise ValueError()
    except (ValueError, TypeError, AttributeError):
        raise SigningUnavailable("managed pin identity mismatch") from None
    if (type(registry_id) is not str
            or not re.fullmatch(r"[a-z][a-z0-9-]{0,63}", registry_id)
            or type(host_fingerprint) is not str
            or not re.fullmatch(r"[a-f0-9]{64}", host_fingerprint)
            or type(expected_key_id) is not str
            or not re.fullmatch(r"[a-f0-9]{64}", expected_key_id)):
        raise SigningUnavailable("managed pin binding invalid")

    admission = ManagedAdmission.objects.select_related("host").filter(
        host_id=host_id).first()
    if (admission is None or admission.host.archived_at is not None
            or admission.fingerprint != host_fingerprint
            or str(admission.installation_id) != installation_id
            or admission.registry_id != registry_id
            or not HostIdentity.objects.filter(
                host_id=host_id, fingerprint=host_fingerprint,
                status="approved").exists()):
        raise SigningUnavailable("managed pin admission mismatch")
    claims = admission.claims
    if (type(claims) is not dict
            or claims.get("fingerprint") != host_fingerprint
            or claims.get("installation_id") != installation_id
            or claims.get("registry_id") != registry_id
            or type(claims.get("jti")) is not str
            or not claims["jti"]
            or type(claims.get("exp")) not in (int, float)
            or claims["exp"] <= time.time()):
        raise SigningUnavailable("managed pin session unavailable")
    try:
        from .managed_views import signer
        public_key = signer().public_key()
        key_id = signatures.fingerprint(public_key)
        public_text = signatures.public_text(public_key)
    except (OSError, ValueError, TypeError, RuntimeError, AttributeError):
        raise SigningUnavailable("managed pin signer unavailable") from None
    if key_id != expected_key_id:
        raise SigningUnavailable("managed pin key mismatch")
    return {
        "schema": 1,
        "kind": "zog-certificate-assignment-authority-pin",
        "registry_id": registry_id,
        "authority_public_key": public_text,
        "authority_key_id": key_id,
    }


def _unix(value):
    return int(datetime.fromisoformat(value.replace("Z","+00:00")).timestamp())


def managed_envelope(statement):
    """Exact managed host-discover v1 envelope, signed by pinned control key."""
    if not managed_enabled():
        raise SigningUnavailable("managed certificate assignment producer disabled")
    from .managed_views import signer
    key = signer()
    policy = statement["policy"]
    dns01 = policy["challenge"] == "dns-01"
    assignment = {
        "schema": "zog-certificate-assignment-v1",
        "authority_origin": "command-center",
        "host_id": statement["host_id"],
        "installation_id": statement["installation_id"],
        "operation_id": statement["operation_id"],
        "revision": statement["revision"],
        "status": statement["state"],
        "approved_at": _unix(statement["approved_at"]),
        "revoked_at": _unix(statement["revoked_at"]) if statement.get("revoked_at") else None,
        "expires_at": _unix(statement["expires_at"]),
        "certificate_id": policy["certificate_id"],
        "hostnames": policy["hostnames"],
        "contact_email": policy["email"],
        "acme_directory": policy["acme_directory"],
        "challenge": policy["challenge"],
        "dns_mode": "local-cloudflare" if dns01 else None,
        "dns_zone": statement["zone_name"] if dns01 else None,
        "credential_id": ("cloudflare-" + statement["credential_id"].replace("-", "")) if dns01 else None,
        "credential_revision": statement["credential_revision"] if dns01 else None,
        "consumer": statement["consumer"],
    }
    data = b"zog-certificate-assignment-v1\0" + canonical(assignment)
    signature = base64.b64encode(key.sign(data)).decode("ascii")
    return {
        "schema":"zog-certificate-assignment-envelope-v1",
        "key_id":signatures.fingerprint(key.public_key()),
        "assignment":assignment,
        "signature":signature,
    }


def sign(statement):
    if statement.get('origin') == 'managed':
        return managed_envelope(statement)
    path_string = getattr(settings, "HOST_CERTIFICATE_ASSIGNMENT_SIGNING_KEY_FILE", "")
    key_id = getattr(settings, "HOST_CERTIFICATE_ASSIGNMENT_SIGNER_ID", "")
    if (not path_string or not key_id or not isinstance(key_id, str)
            or not 1 <= len(key_id) <= 80 or any(c not in
            "abcdefghijklmnopqrstuvwxyz0123456789-_" for c in key_id)):
        raise SigningUnavailable("certificate assignment signer unavailable")
    path = Path(path_string)
    # The file must be owner-controlled and not writable by other users.
    for candidate in (path, *path.parents):
        if candidate.is_symlink():
            raise SigningUnavailable("certificate assignment signing path unsafe")
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise SigningUnavailable("certificate assignment signing key is not private")
    from zog.host_identify.storage import read_owned
    try:
        private = serialization.load_pem_private_key(read_owned(path, 0o600), password=None)
    except (ValueError, TypeError, OSError):
        raise SigningUnavailable("certificate assignment signing key unavailable") from None
    if not isinstance(private, Ed25519PrivateKey):
        raise SigningUnavailable("certificate assignment signing key type mismatch")
    # Key ID is included IN the signed statement and separately pinned by host.
    signed = dict(statement, signer_id=key_id)
    signature = base64.b64encode(private.sign(canonical(signed))).decode("ascii")
    return {"schema": "zog-certificate-assignment-receipt-v1",
            "statement": signed, "signature_ed25519": signature}
