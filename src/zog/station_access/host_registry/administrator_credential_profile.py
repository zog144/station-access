"""Source-only administrator credential provisioning profile.

This module never reads/reverses Django password hashes, stores plaintext,
opens a delivery endpoint, or authorizes remote provisioning.  It reconciles
the selected administrator account and maps its exact destination onto the
shared host-identify HTTPS credential-delivery binding.
"""
from __future__ import annotations

import re
import uuid

from django.utils.crypto import constant_time_compare
from django.views.decorators.debug import sensitive_variables

SCHEMA = "zog-admin-credential-provisioning-proposal-v1"
PURPOSE = "station-administrator-password"
CONSUMER = "station-access"
CREDENTIAL_ID = "station-admin"
DESTINATION = "protected-station-admin-state"

_HEX = re.compile(r"[0-9a-f]{64}\Z")
_ACCOUNT_REVISION = re.compile(r"[0-9a-f]{40,128}\Z")

FIELDS = frozenset((
    "schema", "purpose", "consumer", "credential_id", "operation",
    "host_id", "host_fingerprint", "installation_id", "state_volume_id",
    "registry_id", "account_id", "account", "credential_revision",
    "operator_approval_sha256", "destination", "source_kind",
    "source_password_verified", "receiver_grant_id", "account_revision",
    "session_revocation_required",
))


class AdministratorCredentialProfileError(ValueError):
    pass


def _deny(code="administrator-credential-profile-denied"):
    raise AdministratorCredentialProfileError(code) from None


def _uuid(value, code):
    try:
        parsed = str(uuid.UUID(value))
    except (TypeError, ValueError, AttributeError):
        _deny(code)
    if parsed != value:
        _deny(code)
    return parsed


def _token(value, code):
    if (
        type(value) is not str
        or not re.fullmatch(r"[a-z][a-z0-9-]{0,62}", value)
    ):
        _deny(code)
    return value


def validate_proposal(proposal):
    """Validate only non-secret operator intent; remote delivery stays disabled."""
    if type(proposal) is not dict or set(proposal) != FIELDS:
        _deny()
    if (
        proposal["schema"] != SCHEMA
        or proposal["purpose"] != PURPOSE
        or proposal["consumer"] != CONSUMER
        or proposal["credential_id"] != CREDENTIAL_ID
        or proposal["operation"] not in ("first-provision", "rotate")
        or proposal["account"] != "station-admin"
        or type(proposal["account_id"]) is not int
        or proposal["account_id"] < 1
        or proposal["destination"] != DESTINATION
        or proposal["source_kind"] not in (
            "first-login-verified-export",
            "operator-provisioned-new-secret",
        )
        or proposal["source_password_verified"] is not True
        or type(proposal["credential_revision"]) is not int
        or proposal["credential_revision"] < 1
        or type(proposal["operator_approval_sha256"]) is not str
        or not _HEX.fullmatch(proposal["operator_approval_sha256"])
        or type(proposal["account_revision"]) is not str
        or not _ACCOUNT_REVISION.fullmatch(proposal["account_revision"])
        or proposal["session_revocation_required"] is not True
    ):
        _deny()
    _uuid(proposal["host_id"], "invalid-host-id")
    _uuid(proposal["installation_id"], "invalid-installation-id")
    _uuid(proposal["state_volume_id"], "invalid-state-volume-id")
    _uuid(proposal["receiver_grant_id"], "invalid-receiver-grant-id")
    if (
        type(proposal["host_fingerprint"]) is not str
        or not _HEX.fullmatch(proposal["host_fingerprint"])
    ):
        _deny("invalid-host-fingerprint")
    _token(proposal["registry_id"], "invalid-registry-id")

    return {
        "schema": SCHEMA,
        "status": "proposal-only-not-enabled",
        "purpose": PURPOSE,
        "consumer": CONSUMER,
        "credential_id": CREDENTIAL_ID,
        "credential_revision": proposal["credential_revision"],
        "account_id": proposal["account_id"],
        "account": proposal["account"],
        "account_revision": proposal["account_revision"],
        "remote_delivery_authorized": False,
    }


def common_binding(proposal):
    """Return the exact shared v1 non-secret binding.

    host-identify 0.3.5 is intentionally a source-integration prerequisite for
    this disabled profile; the accepted station companion pin is updated only
    by its separate review workflow.
    """
    validate_proposal(proposal)
    try:
        from zog.host_identify import credential_delivery
    except ImportError as exc:
        raise AdministratorCredentialProfileError(
            "host-identify-credential-delivery-unavailable"
        ) from exc
    try:
        return credential_delivery.binding({
            "host_id": proposal["host_id"],
            "host_fingerprint": proposal["host_fingerprint"],
            "installation_id": proposal["installation_id"],
            "state_volume_id": proposal["state_volume_id"],
            "registry_id": proposal["registry_id"],
            "consumer": CONSUMER,
            "purpose": PURPOSE,
            "credential_id": CREDENTIAL_ID,
        })
    except credential_delivery.CredentialProtocolError as exc:
        raise AdministratorCredentialProfileError(
            "shared-credential-binding-invalid"
        ) from exc


def validate_for_account(proposal, user):
    """Bind proposal to the exact current Django account revision.

    This does not inspect plaintext.  A protected source ceremony must already
    have verified the proposed secret separately.
    """
    result = validate_proposal(proposal)
    from .user_views import revision

    if (
        user.pk != proposal["account_id"]
        or user.username != "station-admin"
        or not user.is_active
        or not user.is_superuser
        or not constant_time_compare(
            proposal["account_revision"], revision(user)
        )
    ):
        _deny("administrator-account-changed")
    return result


@sensitive_variables("password")
def source_password_is_current(user, password):
    """In-memory check for a deliberately recoverable source password.

    Django hashes are used only for one-way verification.  The function returns
    no secret and cannot recover one from the database.
    """
    if (
        type(password) is not str
        or not 1 <= len(password) <= 4096
        or "\x00" in password
        or user.username != "station-admin"
        or not user.is_active
        or not user.is_superuser
    ):
        return False
    return bool(user.check_password(password))
