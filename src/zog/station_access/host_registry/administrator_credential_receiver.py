"""Disabled-by-default, source-only canonical HTTPS administrator receiver.

A protected *local* receiver is given a root-broker-verified signed HTTPS
exchange and an already sealed anonymous secret FD. This is NOT a Django view,
a beacon handler, a password export API or a root/SSH socket. The native owner
must attest the receiver's UID, FD provenance and independently installed pins.
Only Django's existing SecurityGate and account APIs may mutate the password.
"""
import base64
import fcntl
import hashlib
import hmac
import json
import os
import re
import stat
import time
import uuid

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.db.models import Max
from django.utils import timezone
from zog.host_identify import credential_delivery as cd, signatures
from .identity import audit, consume, locked
from .models import AdministratorPasswordReception
from .user_views import revision, revoke
from zog.station_access.credential_https_interop import PATH

CONSUMER = "station-access"
PURPOSE = "station-access-administrator-password"
CREDENTIAL_ID = "station-admin"
POLICY_SCHEMA = "zog-station-admin-password-approval-v1"
RESULT_SCHEMA = "zog-station-admin-password-protected-commit-v1"
POLICY_FIELDS = frozenset({
    "schema", "issuer", "destination_host_id", "destination_fingerprint",
    "destination_installation_id", "destination_state_volume_id",
    "registry_id", "consumer", "purpose", "credential_id", "user_id",
    "username", "expected_account_revision", "authorization_id",
    "authorization_revision", "authorization_envelope_sha256",
    "credential_revision", "authority_signer_sha256", "issued_at",
    "expires_at", "operator_signature",
})
_HEX = re.compile(r"[0-9a-f]{64}\Z")
_ACCOUNT_REVISION = re.compile(r"[0-9a-f]{40}\Z")


class ProtectedAdminCredentialDenied(ValueError):
    pass


def deny():
    # Never include the password, signed envelope, user, account or raw JSON
    # in exceptions, logs or network/browser-visible errors.
    raise ProtectedAdminCredentialDenied("administrator-credential-unavailable") from None


def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            deny()
        result[key] = value
    return result


def strict(raw):
    if type(raw) is not bytes or not 0 < len(raw) <= cd.MAX_BODY:
        deny()
    try:
        data = json.loads(raw, object_pairs_hook=unique,
                          parse_constant=lambda _: deny())
        if type(data) is not dict or cd.canonical(data) != raw:
            deny()
        return data
    except (ValueError, TypeError, UnicodeError):
        deny()


def _pin(value, expected):
    if (type(value) is not bytes or len(value) != 32
            or type(expected) is not str or not _HEX.fullmatch(expected)
            or not hmac.compare_digest(hashlib.sha256(value).hexdigest(), expected)):
        deny()


def _enabled():
    allowed_uid = getattr(settings, "HOST_ADMIN_PASSWORD_V1_RECEIVER_UID", None)
    if (getattr(settings, "HOST_ADMIN_PASSWORD_V1_RECEIVER_ENABLED", False) is not True
            or type(allowed_uid) is not int or allowed_uid <= 0
            or os.geteuid() != allowed_uid):
        deny()


def _approval(raw, operator_pin, authorization_raw, authority_pin, now):
    value = strict(raw)
    if set(value) != POLICY_FIELDS or value["schema"] != POLICY_SCHEMA:
        deny()
    if (type(value["issued_at"]) is not int
            or type(value["expires_at"]) is not int
            or value["issued_at"] > now or value["expires_at"] <= now
            or value["expires_at"] - value["issued_at"] > 7 * 86400):
        deny()
    expected_operator = getattr(settings, "HOST_ADMIN_PASSWORD_V1_OPERATOR_PIN_SHA256", "")
    expected_authority = getattr(settings, "HOST_ADMIN_PASSWORD_V1_AUTHORITY_PIN_SHA256", "")
    _pin(operator_pin, expected_operator)
    _pin(authority_pin, expected_authority)
    if hmac.compare_digest(operator_pin, authority_pin):
        deny()
    if (value["authority_signer_sha256"] != hashlib.sha256(authority_pin).hexdigest()
            or value["authorization_envelope_sha256"] != hashlib.sha256(authorization_raw).hexdigest()
            or value["consumer"] != CONSUMER or value["purpose"] != PURPOSE
            or value["credential_id"] != CREDENTIAL_ID
            or type(value["user_id"]) is not int or value["user_id"] <= 0
            or type(value["username"]) is not str or not value["username"]
            or len(value["username"]) > 150
            or type(value["expected_account_revision"]) is not str
            or not _ACCOUNT_REVISION.fullmatch(value["expected_account_revision"])
            or type(value["credential_revision"]) is not int
            or value["credential_revision"] <= 0
            or type(value["authorization_revision"]) is not int
            or value["authorization_revision"] <= 0):
        deny()
    try:
        signature = base64.b64decode(value["operator_signature"], validate=True)
        if len(signature) != 64 or base64.b64encode(signature).decode("ascii") != value["operator_signature"]:
            deny()
        unsigned = dict(value)
        unsigned.pop("operator_signature")
        Ed25519PublicKey.from_public_bytes(operator_pin).verify(
            signature, POLICY_SCHEMA.encode() + b"\0" + cd.canonical(unsigned))
    except (TypeError, ValueError, InvalidSignature):
        deny()
    return value


def _envelopes(*, signed_authorization, signed_delivery, request_body,
               request_headers, request_url, authority_pin, host_pin,
               operator_pin, signed_approval, expected_origin, now):
    auth_raw = signed_authorization
    approval = _approval(signed_approval, operator_pin, auth_raw, authority_pin, now)
    auth_envelope = strict(auth_raw)
    binding = {
        "host_id": approval["destination_host_id"],
        "host_fingerprint": approval["destination_fingerprint"],
        "installation_id": approval["destination_installation_id"],
        "state_volume_id": approval["destination_state_volume_id"],
        "registry_id": approval["registry_id"],
        "consumer": CONSUMER,
        "purpose": PURPOSE,
        "credential_id": CREDENTIAL_ID,
    }
    try:
        actual_origin = signatures.origin(expected_origin)
        if (request_url != actual_origin + PATH
                or signatures.origin(approval["issuer"]) != actual_origin):
            deny()
        auth = cd.verify_authorization(
            auth_envelope, Ed25519PublicKey.from_public_bytes(authority_pin),
            expected_issuer=actual_origin, expected_binding=binding, now=now)
        if (auth["status"] != "approved"
                or auth["authorization_id"] != approval["authorization_id"]
                or auth["revision"] != approval["authorization_revision"]
                or auth["credential_revision"] != approval["credential_revision"]
                or auth["expires_at"] > approval["expires_at"]
                or signatures.fingerprint(Ed25519PublicKey.from_public_bytes(host_pin)) !=
                   binding["host_fingerprint"]):
            deny()
        strict(request_body)  # Exact canonical frame, no duplicate keys or alternate encodings.
        request, nonce, expiry = cd.verify_request_http(
            request_url, "POST", request_headers, request_body,
            Ed25519PublicKey.from_public_bytes(host_pin), auth, now=now)
        delivery_envelope = strict(signed_delivery)
        delivery = cd.verify_delivery(
            delivery_envelope, Ed25519PublicKey.from_public_bytes(authority_pin),
            request, auth, now=now)
        if request["action"] != "deliver":
            deny()  # Rotation requires separately approved higher credential revision.
        return approval, auth, request, delivery, nonce, expiry
    except (ValueError, TypeError, KeyError, InvalidSignature):
        deny()


def _secret_from_fd(fd, delivery):
    """Read a *sealed, anonymous, readonly* Linux memfd; never store its bytes."""
    if type(fd) is not int or fd < 3:
        deny()
    try:
        info = os.fstat(fd)
        flags = fcntl.fcntl(fd, fcntl.F_GETFL)
        seals = fcntl.fcntl(fd, fcntl.F_GET_SEALS)
        needed = (fcntl.F_SEAL_SEAL | fcntl.F_SEAL_WRITE |
                  fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 0
                or flags & os.O_ACCMODE != os.O_RDONLY
                or seals & needed != needed
                or not 0 < info.st_size <= 1024):
            deny()
        raw = os.pread(fd, 1025, 0)
        if len(raw) != info.st_size or not hmac.compare_digest(raw, cd.secret_bytes(delivery)):
            deny()
        password = raw.decode("utf-8", "strict")
        if not password or "\x00" in password or len(password) > 1024:
            deny()
        return password
    except (OSError, UnicodeError, ValueError):
        deny()


def install(*, signed_authorization, signed_delivery, request_body,
            request_headers, request_url, signed_approval, authority_pin,
            operator_pin, host_pin, expected_origin, secret_fd, now=None):
    """One-shot protected local installation; returns only nonsecret commit metadata.

    The caller must verify native FD/UID/owner provenance and independent pin
    installation separately. A valid signature alone does not authorize service
    activation. No production path invokes this function by default.
    """
    _enabled()
    timestamp = int(time.time()) if now is None else now
    if type(timestamp) is not int or timestamp <= 0:
        deny()
    approval, auth, request, delivery, nonce, expiry = _envelopes(
        signed_authorization=signed_authorization,
        signed_delivery=signed_delivery, request_body=request_body,
        request_headers=request_headers, request_url=request_url,
        authority_pin=authority_pin, operator_pin=operator_pin,
        host_pin=host_pin, signed_approval=signed_approval,
        expected_origin=expected_origin, now=timestamp)
    password = _secret_from_fd(secret_fd, delivery)
    try:
        with locked():
            # Both the user and SecurityGate must be current inside the same
            # durable database transaction. No password writes occur on error.
            user = get_user_model().objects.get(pk=approval["user_id"])
            if (user.username != approval["username"] or not user.is_active
                    or not user.is_superuser or not user.is_staff
                    or not hmac.compare_digest(revision(user),
                                               approval["expected_account_revision"])):
                deny()
            if AdministratorPasswordReception.objects.filter(
                    request_id=request["request_id"]).exists():
                deny()
            if AdministratorPasswordReception.objects.filter(
                    delivery_id=delivery["delivery_id"]).exists():
                deny()
            last = (AdministratorPasswordReception.objects.filter(user=user)
                    .aggregate(max_revision=Max("credential_revision"))["max_revision"])
            if last is not None and auth["credential_revision"] <= last:
                deny()
            # Validated signature nonce is consumed atomically with password,
            # session revocations, provenance record and nonsecret audit.
            consume(request["host_fingerprint"], nonce, expiry)
            user.full_clean(exclude=["password", "last_login", "date_joined"])
            validate_password(password, user)
            before = revision(user)
            user.set_password(password)
            user.save(update_fields=["password"])
            revoke(user)  # All DB sessions and unused VNC grants; no exemptions.
            after = revision(user)
            installed = timezone.now()
            operation = AdministratorPasswordReception.objects.create(
                user=user, request_id=uuid.UUID(request["request_id"]),
                delivery_id=uuid.UUID(delivery["delivery_id"]),
                authorization_id=uuid.UUID(auth["authorization_id"]),
                authorization_revision=auth["revision"],
                credential_revision=auth["credential_revision"],
                approved_policy_sha256=hashlib.sha256(signed_approval).hexdigest(),
                account_revision_before=before,
                account_revision_after=after, installed_at=installed,
            )
            audit("protected-credential-v1", "admin-password-installed",
                  user_id=user.pk, username=user.username,
                  request_id=str(operation.request_id),
                  delivery_id=str(operation.delivery_id),
                  credential_revision=operation.credential_revision)
            return {
                "schema": RESULT_SCHEMA,
                "state": "committed-awaiting-host-signed-receipt",
                "request_id": request["request_id"],
                "delivery_id": delivery["delivery_id"],
                "authorization_id": auth["authorization_id"],
                "credential_revision": auth["credential_revision"],
                "account_id": user.pk,
                "installed_at": int(installed.timestamp()),
            }
    except (ValidationError, get_user_model().DoesNotExist,
            ProtectedAdminCredentialDenied):
        deny()
    finally:
        password = None


def inspect_committed(*, request_id):
    """Recovery-only trusted local query; the caller MUST enforce the same UID gate."""
    _enabled()
    try:
        operation = AdministratorPasswordReception.objects.get(request_id=uuid.UUID(request_id))
    except (ValueError, AdministratorPasswordReception.DoesNotExist):
        deny()
    return {
        "schema": RESULT_SCHEMA, "state": "committed-awaiting-host-signed-receipt",
        "request_id": str(operation.request_id),
        "delivery_id": str(operation.delivery_id),
        "authorization_id": str(operation.authorization_id),
        "credential_revision": operation.credential_revision,
        "account_id": operation.user_id,
        "installed_at": int(operation.installed_at.timestamp()),
    }
