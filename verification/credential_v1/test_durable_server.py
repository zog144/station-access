"""Durable canonical protocol state; all payloads are synthetic."""
import json
import time
from pathlib import Path
import pytest
from zog.host_identify import credential_delivery as cd, signatures
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

pytestmark = pytest.mark.django_db(transaction=True)
ROOT = Path(__file__).resolve().parents[2]
V = json.loads((ROOT / "tests/host_registry/fixtures/credential-delivery-v1-vector.json").read_text())


def setup():
    from zog.station_access.host_registry.models import SecurityGate
    from zog.station_access.host_registry import credential_v1_state as service
    SecurityGate.objects.get_or_create(pk=1)
    key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(V["host_seed_hex"]))
    signing_key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(V["authority_seed_hex"]))
    now = int(time.time())
    auth = dict(V["authorization"], approved_at=now-10, expires_at=now+3600)
    req = dict(V["request"], created_at=now, expires_at=now+60)
    delivery = dict(V["delivery"], issued_at=now, expires_at=now+60)
    return service, key, signing_key, now, auth, req, delivery


def send(key, value, path, nonce):
    return signatures.sign(
        V["origin"] + path, cd.canonical(value), key, value["host_id"], nonce=nonce)


def test_pending_then_delivered_reboot_and_receipt():
    from zog.station_access.host_registry.models import HttpsCredentialV1Ledger, HttpsCredentialV1Operation
    service, key, signing_key, now, auth, request, delivery = setup()
    signed = send(key, request, V["request_path"], "A"*24)
    request_id = service.request_admit(
        auth=auth, url=signed.url, headers=dict(signed.headers), body=signed.body,
        host_key=key.public_key(), origin=V["origin"], now=now)
    with pytest.raises(ValueError):
        service.request_admit(
            auth=auth, url=signed.url, headers=dict(signed.headers), body=signed.body,
            host_key=key.public_key(), origin=V["origin"], now=now)
    response = service.delivery_commit(
        auth=auth, request_id=request_id, value=delivery, signing_key=signing_key, now=now)
    cd.verify_delivery(json.loads(response), signing_key.public_key(), request, auth, now=now)
    assert HttpsCredentialV1Ledger.objects.get().state["requests"][-1]["status"] == "delivered"
    operation = HttpsCredentialV1Operation.objects.get()
    assert "secret" not in operation.delivery_metadata
    assert delivery["secret"] not in json.dumps(operation.delivery_metadata)
    receipt = {"schema":cd.RECEIPT_SCHEMA,
        **{k:request[k] for k in ("host_id","host_fingerprint","installation_id",
            "state_volume_id","registry_id","consumer","purpose","credential_id",
            "credential_revision","authorization_id","authorization_revision","request_id")},
        "delivery_id":delivery["delivery_id"],"receipt_id":"00000000-0000-4000-8000-000000000007",
        "outcome":"installed","installed_at":now}
    signed_receipt = send(key, receipt, V["receipt_path"], "B"*24)
    assert service.receipt_commit(
        auth=auth, url=signed_receipt.url, headers=dict(signed_receipt.headers),
        body=signed_receipt.body, host_key=key.public_key(),
        origin=V["origin"], now=now) == receipt["receipt_id"]
    assert HttpsCredentialV1Ledger.objects.get().state["requests"][-1]["status"] == "installed"


def test_signed_revocation_highwater():
    from zog.station_access.host_registry.models import HttpsCredentialV1Ledger
    service, _, _, now, auth, _, _ = setup()
    assert service.reconcile_authorization(auth) == ("approved", 2)
    newer = dict(auth, revision=3, status="revoked", revoked_at=now)
    assert service.reconcile_authorization(newer) == ("revoked", 3)
    assert HttpsCredentialV1Ledger.objects.get().state["authorization_status"] == "revoked"
    with pytest.raises(cd.CredentialProtocolError):
        service.reconcile_authorization(auth)
