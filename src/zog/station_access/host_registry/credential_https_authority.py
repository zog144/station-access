"""Privileged local issuer-only HTTPS credential broker.

Not a Django view. Network ingress uses a distinct unprivileged process and
may request *only* this narrow operation over a protected AF_UNIX socket.
Never create root grant, assign a hostname, enroll a Host or reveal arbitrary
vault material here. Runtime delivery is disabled unless separately installed.
"""
import base64
import binascii
import hashlib
import json
import os
import re
import secrets
import socket
import stat
import struct
import time
from datetime import timedelta
from pathlib import Path

from django.conf import settings
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from django.utils import timezone
from zog.host_identify import signatures
from zog.host_identify.storage import read_owned

from . import identity
from .identity import locked
from .models import (
    HostIdentity, Host, ManagedAdmission, HttpsCredentialDeliveryNonce,
    HttpsCredentialDeliveryRevision,
)
from .issuer_cloudflare_reader import (
    _assignment, authorization_id, ROOT_FIELDS, PROJECT_FIELDS,
)
from zog.station_access.credential_delivery_protocol import (
    PATH, PURPOSE, CONSUMER, DESTINATION, MAX_ENVELOPE,
    MAX_SECRET, DeliveryDenied, HEX, deny, unpack,
)

GRANT_SCHEMA = "zog-command-center-credential-authority-grant-v1"
GRANT_FIELDS = frozenset(("schema", "state", "purpose", "consumer",
    "destination", "host_id", "fingerprint", "installation_id",
    "state_volume_id", "authority_id", "registry_id", "assignment_id",
    "assignment_revision", "credential_revision", "authorization_id",
    "grant_id", "storage_id", "operator_approval_sha256",
    "independent_signer_pin_sha256", "revision", "expires_at"))
_PROJECTION_PATH = "HOST_ISSUER_CREDENTIAL_AUTHORIZATION_FILE"
_GRANT_PATH = "HOST_CREDENTIAL_HTTPS_AUTHORITY_FILE"
_READER_PATH = "HOST_ISSUER_CREDENTIAL_SOCKET_PATH"


def _protected(path, mode, maximum=8192):
    """Read root-owned one-link exact-mode files; don't follow symlinks."""
    if type(path) is not str or not path.startswith("/") or len(path) > 512:
        deny()
    obj = Path(path)
    try:
        for p in reversed(obj.parents):
            st = p.lstat()
            if not stat.S_ISDIR(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o022:
                deny()
        data = read_owned(obj, mode)
        if not 0 < len(data) <= maximum:
            deny()
        return data
    except (OSError, ValueError, PermissionError):
        deny()


def _json_root(name, mode=0o600):
    try:
        value = json.loads(_protected(getattr(settings, name, ""), mode))
        if type(value) is not dict:
            deny()
        return value
    except (ValueError, TypeError, UnicodeError):
        deny()


def _independent_approval(grant):
    """An independently installed Ed25519 operator key signs the exact grant.

    The station's candidate signer/exporter is NOT an approval key. Only a
    pre-approved native installer may place or rotate this separate root pin.
    """
    from .certificate_assignment_signing import canonical
    import hmac
    try:
        approval_raw = _protected(getattr(
            settings, "HOST_CREDENTIAL_HTTPS_OPERATOR_APPROVAL_FILE", ""), 0o600)
        approval = json.loads(approval_raw)
        if (type(approval) is not dict
                or set(approval) != {"schema", "grant_sha256", "signature_ed25519"}
                or approval["schema"] != "zog-credential-delivery-operator-approval-v1"
                or not isinstance(approval["grant_sha256"], str)
                or not HEX.fullmatch(approval["grant_sha256"])):
            deny()
        packet = dict(grant)
        packet.pop("operator_approval_sha256")
        candidate = hashlib.sha256(canonical(packet)).hexdigest()
        if not hmac.compare_digest(approval["grant_sha256"], candidate):
            deny()
        sig = base64.b64decode(approval["signature_ed25519"], validate=True)
        if len(sig) != 64 or base64.b64encode(sig).decode() != approval["signature_ed25519"]:
            deny()
        pin = _protected(getattr(
            settings, "HOST_CREDENTIAL_HTTPS_OPERATOR_PIN_FILE", ""), 0o444)
        if len(pin) != 32:
            deny()
        Ed25519PublicKey.from_public_bytes(pin).verify(
            sig, b"zog-credential-delivery-operator-approval-v1\0"
                 + canonical(packet))
        if hashlib.sha256(canonical(approval)).hexdigest() != grant["operator_approval_sha256"]:
            deny()
        station_pin = _protected(getattr(
            settings, "HOST_CREDENTIAL_HTTPS_SIGNER_PIN_FILE", ""), 0o444)
        if hashlib.sha256(station_pin).hexdigest() != grant["independent_signer_pin_sha256"]:
            deny()
    except (OSError, UnicodeError, ValueError, TypeError, InvalidSignature,
            binascii.Error, KeyError):
        deny()


def _authority(*, allow_revoked=False):
    grant = _json_root(_GRANT_PATH)
    if set(grant) != GRANT_FIELDS or grant.get("schema") != GRANT_SCHEMA:
        deny()
    if (grant.get("state") not in (("approved", "revoked") if allow_revoked else ("approved",))
            or grant.get("purpose") != PURPOSE):
        deny()
    if grant.get("consumer") != CONSUMER or grant.get("destination") != DESTINATION:
        deny()
    if any(type(grant[k]) is not str or not HEX.fullmatch(grant[k])
           for k in ("fingerprint", "authorization_id",
                     "operator_approval_sha256", "independent_signer_pin_sha256")):
        deny()
    if any(type(grant[k]) is not int or grant[k] < 1
           for k in ("revision", "assignment_revision", "credential_revision")):
        deny()
    if type(grant["expires_at"]) is not int or grant["expires_at"] <= int(time.time()):
        deny()
    for k in ("host_id", "installation_id", "state_volume_id", "assignment_id"):
        from zog.station_access.credential_delivery_protocol import canonical_uuid
        canonical_uuid(grant[k])
    if (type(grant["registry_id"]) is not str
            or not re.fullmatch("[a-z][a-z0-9-]{0,63}", grant["registry_id"])
            or type(grant["authority_id"]) is not str
            or type(grant["grant_id"]) is not str
            or type(grant["storage_id"]) is not str
            or not re.fullmatch(r"[0-9a-f]{32}", grant["grant_id"])
            or not re.fullmatch(r"[0-9a-f]{32}", grant["storage_id"])):
        deny()
    _independent_approval(grant)
    return grant


def _projection():
    # Root can read the vault identity's 0440 projection, but cannot replace
    # that owner's separate protected approval or derive signer trust from it.
    projection = _json_root(_PROJECTION_PATH, 0o440)
    if (set(projection) != PROJECT_FIELDS
            or projection.get("schema") != "zog-station-issuer-reader-authorization-v1"
            or set(projection.get("authorization", {})) != ROOT_FIELDS):
        deny()
    return projection


def _current(grant, data, fingerprint, projection):
    if (any(data[k] != grant[k] for k in (
            "purpose", "consumer", "destination", "host_id",
            "installation_id", "state_volume_id", "registry_id",
            "assignment_id", "assignment_revision",
            "credential_revision", "authorization_id"))
            or fingerprint != grant["fingerprint"]):
        deny()
    if (projection.get("origin") != "managed"
            or projection.get("host_id") != grant["host_id"]
            or projection.get("installation_id") != grant["installation_id"]
            or authorization_id(projection) != grant["authorization_id"]):
        deny()
    a = projection["authorization"]
    if (a.get("state") != "approved"
            or a.get("assignment_id") != grant["assignment_id"]
            or a.get("assignment_revision") != grant["assignment_revision"]
            or a.get("credential_revision") != grant["credential_revision"]
            or a.get("grant_id") != grant["grant_id"]
            or a.get("storage_id") != grant["storage_id"]):
        deny()
    host = Host.objects.filter(pk=grant["host_id"], archived_at__isnull=True,
                               provider="generic").first()
    if host is None:
        deny()
    key = HostIdentity.objects.filter(
        host=host, fingerprint=fingerprint, status="approved").first()
    if key is None:
        deny()
    session = ManagedAdmission.objects.filter(host=host).first()
    if (session is None or session.fingerprint != fingerprint
            or str(session.installation_id) != grant["installation_id"]
            or str(session.state_volume_id) != grant["state_volume_id"]
            or str(session.authority_id) != grant["authority_id"]
            or session.registry_id != grant["registry_id"]
            or type(session.claims) is not dict
            or session.claims.get("exp", 0) <= time.time()
            or not session.claims.get("jti")):
        deny()
    # Reuse precisely the signed certificate assignment + managed DNS-01
    # hostname and Cloudflare zone checks of the protected vault reader.
    row, credential = _assignment(projection)
    if (row.binding_id != "managed-dns01" or str(row.host_id) != grant["host_id"]
            or str(row.pk) != grant["assignment_id"]
            or row.credential_revision != grant["credential_revision"]):
        deny()
    return key


def _consume(grant, data, fingerprint, signature_nonce, signature_expiry):
    """Durable audit and request/authorization fences under the shared writer."""
    from .certificate_assignment_signing import canonical
    digest = hashlib.sha256(canonical(grant)).hexdigest()
    with locked():
        _current(grant, data, fingerprint, _projection())
        now = timezone.now()
        HttpsCredentialDeliveryNonce.objects.filter(
            created_at__lt=now-timedelta(hours=48)).delete()
        if (HttpsCredentialDeliveryNonce.objects.count() >= 10000
                or HttpsCredentialDeliveryNonce.objects.filter(nonce=data["nonce"]).exists()):
            deny()
        history = HttpsCredentialDeliveryRevision.objects.filter(host_id=grant["host_id"]).first()
        if history and (
            grant["revision"] < history.grant_revision or
            grant["credential_revision"] < history.credential_revision or
            (grant["revision"] == history.grant_revision
             and (digest != history.grant_sha256 or history.revoked))):
            deny()
        identity.consume(fingerprint, signature_nonce, signature_expiry)
        HttpsCredentialDeliveryNonce.objects.create(
            nonce=data["nonce"], host_id=grant["host_id"],
            authorization_id=grant["authorization_id"],
            credential_revision=grant["credential_revision"])
        HttpsCredentialDeliveryRevision.objects.update_or_create(
            host_id=grant["host_id"],
            defaults={"grant_revision":grant["revision"],
                      "grant_sha256":digest,
                      "revoked":False,
                      "credential_revision":grant["credential_revision"]})
        identity.audit("credential-broker", "https-credential-request-consumed",
                       fingerprint=fingerprint,
                       host=Host.objects.get(pk=grant["host_id"]),
                       purpose=PURPOSE, grant_revision=grant["revision"],
                       credential_revision=grant["credential_revision"],
                       assignment_id=grant["assignment_id"])
    return digest


def reconcile_signed_revocation():
    """Root-only, no-secret adoption of an operator-signed revoked grant.

    Requires the exact independently installed approval and signer pin. A
    durable tombstone survives reboot and blocks restoring older approvals.
    Root owner must perform this *before* withdrawing the installed grant.
    """
    if os.geteuid() != 0:
        deny()
    grant = _authority(allow_revoked=True)
    if grant["state"] != "revoked":
        deny()
    from .certificate_assignment_signing import canonical
    fingerprint = hashlib.sha256(canonical(grant)).hexdigest()
    with locked():
        history = HttpsCredentialDeliveryRevision.objects.filter(
            host_id=grant["host_id"]).first()
        if history and (
            grant["revision"] < history.grant_revision
            or grant["credential_revision"] < history.credential_revision
            or (grant["revision"] == history.grant_revision
                and (fingerprint != history.grant_sha256 or not history.revoked))):
            deny()
        HttpsCredentialDeliveryRevision.objects.update_or_create(
            host_id=grant["host_id"], defaults={
                "grant_revision": grant["revision"],
                "grant_sha256": fingerprint, "revoked": True,
                "credential_revision": grant["credential_revision"]})
        identity.audit("credential-operator", "https-credential-grant-revoked",
            fingerprint=grant["fingerprint"],
            host=Host.objects.get(pk=grant["host_id"]),
            purpose=grant["purpose"], grant_revision=grant["revision"],
            credential_revision=grant["credential_revision"])
    return {"status":"revoked", "host_id":grant["host_id"],
            "grant_revision":grant["revision"], "credential_transferred":False}


def _read_local_token(authorization):
    path = getattr(settings, _READER_PATH, "")
    if type(path) is not str or not path.startswith("/") or len(path) > 256:
        deny()
    from .issuer_cloudflare_reader import TOKEN, REQUEST_SCHEMA
    request = {"schema": REQUEST_SCHEMA,
               "operation": "read-approved-cloudflare-issuer-token",
               "authorization_id": authorization,
               "nonce": secrets.token_hex(16)}
    link = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        link.settimeout(4)
        link.connect(path)
        link.sendall(json.dumps(request, sort_keys=True,
                                separators=(",", ":")).encode()+b"\n")
        link.shutdown(socket.SHUT_WR)
        token = bytearray()
        while len(token) <= MAX_SECRET:
            chunk = link.recv(MAX_SECRET+1-len(token))
            if not chunk:
                break
            token.extend(chunk)
        if not TOKEN.fullmatch(bytes(token)):
            deny()
        return bytes(token)
    finally:
        link.close()


def authorize_and_read(raw):
    """Fail closed: no live release until an independent native owner enables."""
    if os.geteuid() != 0 or not getattr(settings, "HOST_HTTPS_CREDENTIAL_LIVE_ENABLED", False):
        deny()
    body, headers, data = unpack(raw)
    grant = _authority()
    if (headers["X-Host-Id"] != data["host_id"]
            or headers["X-Host-Key"] != grant["fingerprint"]):
        deny()
    # Verify the signed *exact* HTTPS URL, not a forwarded address. The
    # expected origin is independently configured from the station deployment.
    current_key = HostIdentity.objects.filter(
        host_id=data["host_id"], fingerprint=grant["fingerprint"],
        status="approved").first()
    if current_key is None:
        deny()
    nonce, expiry = signatures.verify(
        signatures.origin(settings.HOST_IDENTITY_ORIGIN)+PATH,
        "POST", headers, body,
        signatures.public_key(current_key.public_key), data["host_id"])
    _consume(grant, data, grant["fingerprint"], nonce, expiry)
    secret = _read_local_token(grant["authorization_id"])
    # No secret output if policy, enrolment, grant or projection changed while
    # the local vault service completed its independently replay-checked read.
    with locked():
        if _authority() != grant:
            deny()
        _current(grant, data, grant["fingerprint"], _projection())
    return secret


def serve_once(listener):
    connection, _ = listener.accept()
    with connection:
        try:
            uid = struct.unpack("3i", connection.getsockopt(
                socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")))[1]
            expected = getattr(settings, "HOST_CREDENTIAL_HTTPS_INGRESS_UID", None)
            if type(expected) is not int or expected <= 0 or uid != expected:
                deny()
            connection.settimeout(4)
            data = bytearray()
            while len(data) <= MAX_ENVELOPE:
                chunk = connection.recv(MAX_ENVELOPE + 1 - len(data))
                if not chunk:
                    break
                data.extend(chunk)
            if not data or len(data) > MAX_ENVELOPE or not data.endswith(b"\n"):
                deny()
            token = authorize_and_read(bytes(data[:-1]))
            connection.sendall(token)
        except Exception:
            # The broker never emits failure diagnostics or secret metadata.
            pass
