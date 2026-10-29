import uuid

import pytest

try:
    from zog.host_identify import credential_delivery as cd
except ImportError:
    cd = None

pytestmark = pytest.mark.skipif(
    cd is None,
    reason="shared credential-delivery v1 requires host-identify 0.3.5",
)

from zog.station_access.host_registry import administrator_credential_profile as admin


def proposal(**changes):
    value = {
        "schema": admin.SCHEMA,
        "purpose": admin.PURPOSE,
        "consumer": admin.CONSUMER,
        "credential_id": admin.CREDENTIAL_ID,
        "operation": "first-provision",
        "host_id": str(uuid.uuid4()),
        "host_fingerprint": "a" * 64,
        "installation_id": str(uuid.uuid4()),
        "state_volume_id": str(uuid.uuid4()),
        "registry_id": "primary",
        "account_id": 1,
        "account": "station-admin",
        "credential_revision": 1,
        "operator_approval_sha256": "b" * 64,
        "destination": admin.DESTINATION,
        "source_kind": "first-login-verified-export",
        "source_password_verified": True,
        "receiver_grant_id": str(uuid.uuid4()),
        "account_revision": "c" * 40,
        "session_revocation_required": True,
    }
    value.update(changes)
    return value


def test_profile_maps_exactly_to_shared_nonsecret_binding():
    value = proposal()
    binding = admin.common_binding(value)
    assert binding == cd.binding(binding)
    assert binding == {
        "host_id": value["host_id"],
        "host_fingerprint": value["host_fingerprint"],
        "installation_id": value["installation_id"],
        "state_volume_id": value["state_volume_id"],
        "registry_id": value["registry_id"],
        "consumer": "station-access",
        "purpose": "station-administrator-password",
        "credential_id": "station-admin",
    }
    encoded = repr(binding).lower()
    assert "password" in encoded  # purpose name only
    assert "source_password" not in encoded
    assert "operator_approval" not in encoded
    assert "receiver_grant" not in encoded


@pytest.mark.parametrize(
    "field,value",
    [
        ("host_id", "not-a-uuid"),
        ("host_fingerprint", "x" * 64),
        ("installation_id", "not-a-uuid"),
        ("state_volume_id", "not-a-uuid"),
        ("registry_id", "../primary"),
        ("consumer", "browser"),
        ("purpose", "station-administrator-bootstrap"),
        ("credential_id", "generic-password"),
    ],
)
def test_shared_profile_rejects_wrong_destination_binding(field, value):
    with pytest.raises(admin.AdministratorCredentialProfileError):
        admin.common_binding(proposal(**{field: value}))


def test_profile_is_intent_only_not_a_delivery_authorization():
    decision = admin.validate_proposal(proposal())
    assert decision["remote_delivery_authorized"] is False
    assert set(decision) == {
        "schema",
        "status",
        "purpose",
        "consumer",
        "credential_id",
        "credential_revision",
        "account_id",
        "account",
        "account_revision",
        "remote_delivery_authorized",
    }
