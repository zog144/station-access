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


def test_delivered_unreceipted_blocks_second_request_and_requires_rotation():
    from zog.station_access.host_registry.models import HttpsCredentialV1Ledger
    service, key, signing_key, now, auth, request, delivery = setup()
    first = send(key, request, V["request_path"], "C"*24)
    service.request_admit(
        auth=auth, url=first.url, headers=dict(first.headers), body=first.body,
        host_key=key.public_key(), origin=V["origin"], now=now)
    service.delivery_commit(
        auth=auth, request_id=request["request_id"], value=delivery,
        signing_key=signing_key, now=now)
    second = dict(request, request_id="00000000-0000-4000-8000-000000000099")
    second_http = send(key, second, V["request_path"], "D"*24)
    with pytest.raises(cd.CredentialProtocolError):
        service.request_admit(
            auth=auth, url=second_http.url, headers=dict(second_http.headers),
            body=second_http.body, host_key=key.public_key(), origin=V["origin"],
            now=now)
    cancel = {
        "schema": cd.CANCEL_SCHEMA,
        **{k: request[k] for k in (
            "host_id", "host_fingerprint", "installation_id", "state_volume_id",
            "registry_id", "consumer", "purpose", "credential_id",
            "credential_revision", "authorization_id",
            "authorization_revision", "request_id")},
        "cancel_id": "00000000-0000-4000-8000-000000000008",
        "reason": "interruption-recovery", "created_at": now,
        "expires_at": now + 60}
    cancelled = send(key, cancel, V["cancel_path"], "E"*24)
    assert service.cancel_commit(
        auth=auth, url=cancelled.url, headers=dict(cancelled.headers),
        body=cancelled.body, host_key=key.public_key(),
        origin=V["origin"], now=now) is True
    current = HttpsCredentialV1Ledger.objects.get().state
    assert current["requests"][-1]["status"] == "cancelled-after-delivery"
    assert current["rotation_required"] is True
    with pytest.raises(cd.CredentialProtocolError):
        service.request_admit(
            auth=auth, url=second_http.url, headers=dict(second_http.headers),
            body=second_http.body, host_key=key.public_key(), origin=V["origin"],
            now=now)


def test_canonical_wsgi_remains_disabled_and_browser_routes_are_denied():
    from io import BytesIO
    from unittest.mock import patch
    from zog.station_access import credential_v1_https_ingress as ingress
    headers = []
    environ = {
        "REQUEST_METHOD": "POST", "PATH_INFO": V["request_path"],
        "QUERY_STRING": "", "wsgi.url_scheme": "https",
        "CONTENT_TYPE": "application/json", "CONTENT_LENGTH": "2",
        "wsgi.input": BytesIO(b"{}")}
    with patch.object(ingress, "relay", side_effect=AssertionError("unexpected relay")):
        assert b"".join(ingress.application(
            environ, lambda status, hdrs: headers.append(status))) == b""
        assert headers[-1] == "403 Forbidden"
        environ["PATH_INFO"] = "/api/hosts/"
        assert b"".join(ingress.application(
            environ, lambda status, hdrs: headers.append(status))) == b""
        assert headers[-1] == "403 Forbidden"


def test_expired_pending_request_cannot_be_signed_later():
    service, key, signing_key, now, auth, request, delivery = setup()
    original = send(key, request, V["request_path"], "F"*24)
    service.request_admit(
        auth=auth, url=original.url, headers=dict(original.headers),
        body=original.body, host_key=key.public_key(), origin=V["origin"],
        now=now)
    with pytest.raises(ValueError, match="request-expired"):
        service.delivery_commit(
            auth=auth, request_id=request["request_id"], value=delivery,
            signing_key=signing_key, now=now+61)


def test_same_revision_authority_envelope_change_is_rejected():
    service, key, signing_key, now, auth, request, delivery = setup()
    assert service.reconcile_authorization(auth) == ("approved", 2)
    changed = dict(auth, expires_at=auth["expires_at"] + 60)
    with pytest.raises(ValueError, match="same-revision-authorization-substituted"):
        service.reconcile_authorization(changed)
    # A newer signed revision is accepted by the shared state machine.
    advanced = dict(changed, revision=3)
    assert service.reconcile_authorization(advanced) == ("approved", 3)


def test_root_broker_emits_signed_delivery_only_after_durable_commit():
    from unittest.mock import patch
    from django.test import override_settings
    from zog.station_access.host_registry import credential_v1_authority as server
    from zog.station_access.host_registry.models import HttpsCredentialV1Ledger
    service, key, signing_key, now, auth, request, delivery = setup()
    grant = {"authorization_id": "a"*64}
    signed_req = send(key, request, V["request_path"], "G"*24)
    synthetic = b"SYNTHETIC_TEST_ONLY_TOKEN"
    with override_settings(
            HOST_CREDENTIAL_V1_BROKER_ENABLED=True,
            HOST_CREDENTIAL_V1_LIVE_ENABLED=True,
            HOST_IDENTITY_ORIGIN=V["origin"]), \
         patch.object(server.os, "geteuid", return_value=0), \
         patch.object(server, "_context",
                      return_value=(grant, auth, signing_key, key.public_key())), \
         patch.object(server.legacy, "_read_local_token",
                      return_value=synthetic):
        status, data = server.handle(
            V["request_path"],
            dict(signed_req.headers), signed_req.body)
        assert status == 200
        proof = json.loads(data)
        assert cd.verify_delivery(
            proof, signing_key.public_key(), request, auth)["request_id"] == request["request_id"]
        assert proof["delivery"]["secret"] == __import__("base64").b64encode(synthetic).decode()
        assert HttpsCredentialV1Ledger.objects.get().state["requests"][-1]["status"] == "delivered"
        assert synthetic.decode() not in json.dumps(HttpsCredentialV1Ledger.objects.get().state)
