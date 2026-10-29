"""Nonsecret proposal admission for future administrator credential provisioning.

No token/password read, Django password-hash reversal, or network delivery.
This is *not* in the enabled HTTPS purpose allowlist.
"""
import re
from zog.station_access.credential_delivery_protocol import (
    canonical_uuid, HEX, deny,
)

SCHEMA = "zog-admin-credential-provisioning-proposal-v1"
PURPOSE = "station-administrator-bootstrap"
FIELDS = frozenset(("schema", "purpose", "operation", "host_id",
    "installation_id", "state_volume_id", "account", "credential_revision",
    "operator_approval_sha256", "destination", "source_kind",
    "source_password_verified", "receiver_grant_id", "account_revision",
    "session_revocation_required"))


def validate_proposal(proposal):
    """Source proposal only; return secret-free decision for future reviewer."""
    if type(proposal) is not dict or set(proposal) != FIELDS:
        deny()
    if (proposal["schema"] != SCHEMA or proposal["purpose"] != PURPOSE
            or proposal["operation"] not in ("first-provision", "rotate")
            or proposal["account"] != "station-admin"
            or proposal["destination"] != "protected-station-admin-state"
            or proposal["source_kind"] not in (
                "first-login-verified-export", "operator-provisioned-new-secret")
            or proposal["source_password_verified"] is not True
            or type(proposal["operator_approval_sha256"]) is not str
            or not HEX.fullmatch(proposal["operator_approval_sha256"])
            or type(proposal["receiver_grant_id"]) is not str
            or not re.fullmatch(r"[0-9a-f]{32}", proposal["receiver_grant_id"])
            or type(proposal["credential_revision"]) is not int
            or proposal["credential_revision"] < 1
            or type(proposal["account_revision"]) is not int
            or proposal["account_revision"] < 1
            or proposal["session_revocation_required"] is not True):
        deny()
    for key in ("host_id", "installation_id", "state_volume_id"):
        canonical_uuid(proposal[key])
    return {"schema": SCHEMA, "status": "proposal-only-not-enabled",
            "purpose": PURPOSE, "credential_revision": proposal["credential_revision"],
            "account": proposal["account"], "remote_delivery_authorized": False}
