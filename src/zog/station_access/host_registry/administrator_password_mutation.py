"""Protected station-admin password mutation; no HTTP/CLI entry point.

Caller MUST be an installed root-authenticated HTTPS-v1 receiver which has
already durably recorded delivery (including HTTP replay nonce), independently
verified issuer signer and HostIdentity, and retained an original root ledger.
The separately supplied root verifier is mandatory and runs while SecurityGate
is locked. This module cannot establish that provenance on its own.

Never log, persist, return, hash in an audit, or put plaintext in a URL,
environment, argv, file or a queue. Only the Django password hasher sees it.
"""
from __future__ import annotations

import re
import uuid

from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from django.contrib.sessions.models import Session
from django.utils import timezone
from django.utils.crypto import constant_time_compare
from django.views.decorators.debug import sensitive_variables

from .administrator_credential_profile import (
    validate_for_account, source_password_is_current,
)
from .identity import locked, audit
from .models import SecurityAudit
from .user_views import revision, revoke
from zog.station_access.models import VncAccessGrant

PROOF_SCHEMA = "zog-admin-credential-protected-handoff-v1"
RESULT_SCHEMA = "zog-admin-credential-django-mutation-v1"
ACTION = "administrator-credential-installed"
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
REVISION = re.compile(r"[0-9a-f]{40,128}\Z")

FIELDS = frozenset((
    "schema", "status", "host_id", "host_fingerprint", "installation_id",
    "state_volume_id", "registry_id", "consumer", "purpose",
    "credential_id", "credential_revision", "authorization_id",
    "authorization_revision", "request_id", "delivery_id", "account_id",
    "account_revision", "receiver_grant_id", "operator_approval_sha256",
    "approved_proposal_sha256", "ledger_checkpoint_sha256",
))


class AdministratorPasswordMutationDenied(ValueError):
    """Never include received plaintext or its hash in error messages."""


def deny(code="administrator-password-mutation-denied"):
    raise AdministratorPasswordMutationDenied(code) from None


def _uuid(value):
    if type(value) is not str:
        deny("invalid-delivery-identity")
    try:
        parsed = uuid.UUID(value)
    except (ValueError, TypeError, AttributeError):
        deny("invalid-delivery-identity")
    if str(parsed) != value:
        deny("invalid-delivery-identity")


def validate_handoff(proposal, proof):
    """Exact, secret-free binding. Never treat this as provenance verification."""
    from .administrator_credential_profile import validate_proposal
    validate_proposal(proposal)
    if type(proof) is not dict or set(proof) != FIELDS:
        deny("invalid-protected-handoff")
    if (
        proof["schema"] != PROOF_SCHEMA
        or proof["status"] != "root-verified-delivered-not-installed"
        or proof["consumer"] != "station-access"
        or proof["purpose"] != "station-administrator-password"
        or proof["credential_id"] != "station-admin"
        or type(proof["account_id"]) is not int
        or proof["account_id"] != proposal["account_id"]
        or type(proof["credential_revision"]) is not int
        or proof["credential_revision"] != proposal["credential_revision"]
        or type(proof["authorization_revision"]) is not int
        or proof["authorization_revision"] < 1
        or proof["account_revision"] != proposal["account_revision"]
        or proof["receiver_grant_id"] != proposal["receiver_grant_id"]
        or proof["operator_approval_sha256"]
            != proposal["operator_approval_sha256"]
    ):
        deny("protected-handoff-binding-mismatch")
    for key in (
        "host_id", "host_fingerprint", "installation_id",
        "state_volume_id", "registry_id",
    ):
        if proof[key] != proposal[key]:
            deny("protected-handoff-destination-mismatch")
    for key in ("authorization_id", "request_id", "delivery_id",
                "receiver_grant_id"):
        _uuid(proof[key])
    for key in ("approved_proposal_sha256", "ledger_checkpoint_sha256",
                "operator_approval_sha256"):
        if type(proof[key]) is not str or not HEX64.fullmatch(proof[key]):
            deny("protected-handoff-digest-invalid")
    if type(proof["account_revision"]) is not str or not REVISION.fullmatch(
        proof["account_revision"]
    ):
        deny("protected-handoff-revision-invalid")
    return proof


def _stored_installations():
    return SecurityAudit.objects.filter(action=ACTION).order_by("-pk")


def _verify_revocation(user):
    """Recheck existing Users-API semantics before declaring installation."""
    if VncAccessGrant.objects.filter(user=user, revoked_at__isnull=True).exists():
        deny("vnc-grant-revocation-incomplete")
    for session in Session.objects.filter(expire_date__gt=timezone.now()).iterator():
        if str(session.get_decoded().get("_auth_user_id")) == str(user.pk):
            deny("session-revocation-incomplete")


@sensitive_variables("plaintext", "proposal", "proof", "verify_root_admission")
def install_authorized(proposal, plaintext, proof, *, verify_root_admission):
    """Commit one new password under the existing station SecurityGate lock.

    verify_root_admission is an installed, privileged verifier supplied by the
    protected receiver owner, never from HTTP/JSON. It MUST recheck the
    durable original root-ledger state and current signed authorization while
    this lock is held, and return exactly True on success. With no trusted
    native verifier configured this ceremony is unavailable.
    """
    if not callable(verify_root_admission):
        deny("protected-receiver-unavailable")
    validate_handoff(proposal, proof)
    if (
        type(plaintext) is not str or not 1 <= len(plaintext) <= 1024
        or "\x00" in plaintext
    ):
        deny("invalid-password-input")
    with locked():
        # The callback must fail closed on replay, stale/withdrawn approval,
        # uncommitted delivery or higher-revision revocation.
        if verify_root_admission(proposal, proof) is not True:
            deny("root-admission-rejected")
        user = get_user_model().objects.get(pk=proposal["account_id"])
        try:
            validate_for_account(proposal, user)
        except ValueError:
            deny("administrator-account-changed")
        if not user.is_staff:
            deny("administrator-role-changed")

        # SecurityAudit itself is durable, database-local receipt evidence.
        # Never write the same received plaintext twice after a lost response.
        for row in _stored_installations():
            detail = row.details
            if (
                detail.get("request_id") == proof["request_id"]
                or detail.get("delivery_id") == proof["delivery_id"]
            ):
                deny("delivery-already-installed")
            if (
                type(detail.get("credential_revision")) is int
                and detail["credential_revision"] >= proof["credential_revision"]
            ):
                deny("credential-revision-not-monotonic")

        if proposal["source_kind"] == "first-login-verified-export":
            if proposal["operation"] != "first-provision" or not (
                source_password_is_current(user, plaintext)
            ):
                deny("bootstrap-password-no-longer-current")
        elif user.check_password(plaintext):
            deny("new-password-must-change-existing-password")

        # Match the Users API: full_clean + validate_password + set_password.
        user.full_clean(exclude=["password", "last_login", "date_joined"])
        validate_password(plaintext, user)
        before = revision(user)
        user.set_password(plaintext)
        user.save(update_fields=["password"])
        revoke(user, current_session=None)  # Never keep a machine-owned web session.
        after = revision(user)
        if (
            constant_time_compare(before, after)
            or not user.check_password(plaintext)
            or not user.is_active or not user.is_superuser or not user.is_staff
        ):
            deny("password-commit-verification-failed")
        _verify_revocation(user)
        audit(
            "protected-credential-receiver", ACTION,
            account_id=user.pk, account="station-admin",
            account_revision_before=before,
            account_revision_after=after,
            host_id=proof["host_id"],
            installation_id=proof["installation_id"],
            state_volume_id=proof["state_volume_id"],
            registry_id=proof["registry_id"],
            authorization_id=proof["authorization_id"],
            authorization_revision=proof["authorization_revision"],
            credential_revision=proof["credential_revision"],
            request_id=proof["request_id"],
            delivery_id=proof["delivery_id"],
            receiver_grant_id=proof["receiver_grant_id"],
            operator_approval_sha256=proof["operator_approval_sha256"],
            approved_proposal_sha256=proof["approved_proposal_sha256"],
            ledger_checkpoint_sha256=proof["ledger_checkpoint_sha256"],
            session_revocation_verified=True,
            vnc_grants_revoked=True,
        )
        evidence = _stored_installations().filter(
            details__request_id=proof["request_id"],
        ).first()
        if evidence is None:
            deny("audit-not-durable")
        return {
            "schema": RESULT_SCHEMA,
            "status": "django-password-committed",
            "audit_id": evidence.pk,
            "account_id": user.pk,
            "account_revision_before": before,
            "account_revision_after": after,
            "request_id": proof["request_id"],
            "delivery_id": proof["delivery_id"],
            "credential_revision": proof["credential_revision"],
            "session_revocation_verified": True,
            "vnc_grants_revoked": True,
            "shared_v1_receipt_signed": False,
        }


def inspect_installed(*, request_id, delivery_id, expected_after_revision):
    """Nonsecret readback for lost-response reconciliation; never reapply."""
    _uuid(request_id)
    _uuid(delivery_id)
    if type(expected_after_revision) is not str or not REVISION.fullmatch(
        expected_after_revision
    ):
        deny("invalid-account-revision")
    with locked():
        row = _stored_installations().filter(
            details__request_id=request_id,
        ).first()
        if row is None or row.details.get("delivery_id") != delivery_id:
            return {"schema": RESULT_SCHEMA, "status": "not-proven-installed"}
        user = get_user_model().objects.filter(
            pk=row.details.get("account_id"),
            username="station-admin", is_active=True,
            is_superuser=True, is_staff=True,
        ).first()
        if user is None or not constant_time_compare(
            expected_after_revision, revision(user)
        ) or not constant_time_compare(
            expected_after_revision,
            row.details.get("account_revision_after", ""),
        ):
            return {"schema": RESULT_SCHEMA, "status": "stale-or-changed"}
        _verify_revocation(user)
        return {
            "schema": RESULT_SCHEMA,
            "status": "django-password-committed",
            "audit_id": row.pk,
            "account_id": user.pk,
            "account_revision_before":
                row.details["account_revision_before"],
            "account_revision_after": expected_after_revision,
            "request_id": request_id,
            "delivery_id": delivery_id,
            "credential_revision": row.details["credential_revision"],
            "session_revocation_verified": True,
            "vnc_grants_revoked": True,
            "shared_v1_receipt_signed": False,
        }
