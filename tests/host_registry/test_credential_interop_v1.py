"""Cross-repository public test vectors for EXACT host-identify v1 (0.3.5).

All private seeds are TEST keys and all secret fields carry synthetic bytes.
No network listener, root owner, Django database or real credential is used.
"""
import base64
import hashlib
import json
import time
from datetime import datetime, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from zog.host_identify import credential_delivery as cd
from zog.host_identify import signatures
from zog.station_access import credential_https_interop as interop


VECTOR = Path(__file__).parent / "fixtures" / "credential-delivery-v1-vector.json"


def load():
    fixture = json.loads(VECTOR.read_text())
    host = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(fixture["host_seed_hex"]))
    authority = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(fixture["authority_seed_hex"]))
    return fixture, host, authority


def test_exact_canonical_fixture_and_independent_ed25519_signatures():
    v, host, authority = load()
    auth, req, delivery = v["authorization"], v["request"], v["delivery"]
    assert signatures.fingerprint(host.public_key()) == auth["host_fingerprint"]
    assert hashlib.sha256(cd.canonical(auth)).hexdigest() == v["authorization_sha256"]
    assert hashlib.sha256(cd.canonical(req)).hexdigest() == v["request_sha256"]
    assert hashlib.sha256(cd.canonical(delivery)).hexdigest() == v["delivery_sha256"]
    signed = cd.sign_authorization(auth, authority)
    assert signed["signature"] == v["authorization_signature_base64"]
    assert cd.verify_authorization(
        signed, authority.public_key(), expected_issuer=v["origin"],
        expected_binding=cd.binding(auth), now=v["time"]) == auth
    assert interop.authorization_signed(
        signed, authority.public_key(), expected_issuer=v["origin"],
        expected_binding=cd.binding(auth), now=v["time"]) == auth
    assert cd.validate_request(req, auth, now=v["time"]) == req
    envelope = cd.sign_delivery(delivery, authority)
    assert envelope["signature"] == v["delivery_signature_base64"]
    assert cd.verify_delivery(
        envelope, authority.public_key(), req, auth, now=v["time"]) == delivery
    with pytest.raises(cd.CredentialProtocolError):
        cd.verify_delivery(envelope, host.public_key(), req, auth, now=v["time"])


def test_exact_ledger_delivered_is_not_installed_and_requires_receipt():
    v, host, authority = load()
    a, r, d = v["authorization"], v["request"], v["delivery"]
    state = cd.admit_request(cd.new_ledger(a), r)
    signed, delivered = interop.delivery_record(state, d, r, a, authority, now=v["time"])
    assert cd.verify_delivery(signed, authority.public_key(), r, a, now=v["time"]) == d
    assert delivered["requests"][-1]["status"] == "delivered"
    assert delivered["requests"][-1]["receipt_id"] is None
    assert d["secret"] not in cd.canonical(delivered).decode()
    with pytest.raises(cd.CredentialProtocolError):
        cd.admit_request(delivered, dict(r, request_id="00000000-0000-4000-8000-000000000099"))
    receipt = {
        "schema": cd.RECEIPT_SCHEMA,
        **{k:r[k] for k in (
            "host_id", "host_fingerprint", "installation_id", "state_volume_id",
            "registry_id", "consumer", "purpose", "credential_id",
            "credential_revision", "authorization_id", "authorization_revision",
            "request_id")},
        "delivery_id": d["delivery_id"], "receipt_id": "00000000-0000-4000-8000-000000000007",
        "outcome": "installed", "installed_at": v["time"],
    }
    assert cd.validate_receipt(receipt, r, d, now=v["time"]) == receipt
    installed = cd.record_installation(delivered, receipt)
    assert installed["requests"][-1]["status"] == "installed"
    assert "secret" not in cd.canonical(installed).decode()
    assert cd.record_installation(installed, receipt) == installed


def test_actual_host_signed_http_request_and_receipt_interoperate():
    v, host, authority = load()
    now = int(time.time())
    a = dict(v["authorization"], approved_at=now-10, expires_at=now+3600)
    r = dict(v["request"], created_at=now, expires_at=now+60)
    posted = cd.prepare_request(
        v["origin"] + v["request_path"], r, a, host,
        now=datetime.now(timezone.utc), nonce="A"*24)
    request, nonce, expiry, admitted = interop.request_admit(
        posted.url, "POST", dict(posted.headers), posted.body,
        host.public_key(), a, cd.new_ledger(a), now=now)
    assert request == r and nonce == "A"*24
    assert admitted["requests"][-1]["status"] == "pending"
    with pytest.raises((ValueError, cd.CredentialProtocolError)):
        interop.request_admit(
            posted.url, "POST", dict(posted.headers), posted.body,
            authority.public_key(), a, cd.new_ledger(a), now=now)
    with pytest.raises(interop.InteropDenied):
        interop.request_admit(
            v["origin"] + "/api/hosts/credential-delivery/v1/receive/",
            "POST", dict(posted.headers), posted.body,
            host.public_key(), a, cd.new_ledger(a), now=now)

    d = dict(v["delivery"], issued_at=now, expires_at=now+60)
    delivered = cd.record_delivery(admitted, d)
    receipt = {
        "schema": cd.RECEIPT_SCHEMA,
        **{k:r[k] for k in (
            "host_id", "host_fingerprint", "installation_id", "state_volume_id",
            "registry_id", "consumer", "purpose", "credential_id",
            "credential_revision", "authorization_id", "authorization_revision",
            "request_id")},
        "delivery_id": d["delivery_id"], "receipt_id": "00000000-0000-4000-8000-000000000007",
        "outcome": "installed", "installed_at": now,
    }
    wire = cd.prepare_receipt(
        v["origin"] + v["receipt_path"], receipt, r, d, host,
        now=datetime.now(timezone.utc), nonce="B"*24)
    observed, nonce2, expiry2, installed = interop.receipt_record(
        wire.url, "POST", dict(wire.headers), wire.body,
        host.public_key(), r, d, delivered, now=now)
    assert observed == receipt and nonce2 == "B"*24
    assert installed["requests"][-1]["status"] == "installed"


def test_shared_negative_contract_revocation_wrong_purpose_and_cancel():
    v, host, authority = load()
    a, req, delivery = v["authorization"], v["request"], v["delivery"]
    with pytest.raises(interop.InteropDenied):
        interop.authorization_signed(
            cd.sign_authorization(dict(a, purpose="archive-mirror"), authority),
            authority.public_key(), expected_issuer=v["origin"],
            expected_binding=cd.binding(dict(a, purpose="archive-mirror")),
            now=v["time"])
    with pytest.raises(cd.CredentialProtocolError):
        cd.validate_request(dict(req, consumer="archive-mirror"), a, now=v["time"])
    state = cd.record_delivery(cd.admit_request(cd.new_ledger(a), req), delivery)
    cancelled = {
        "schema": cd.CANCEL_SCHEMA,
        **{k:req[k] for k in (
            "host_id", "host_fingerprint", "installation_id", "state_volume_id",
            "registry_id", "consumer", "purpose", "credential_id",
            "credential_revision", "authorization_id", "authorization_revision",
            "request_id")},
        "cancel_id": "00000000-0000-4000-8000-000000000008",
        "reason": "interruption-recovery",
        "created_at": v["time"], "expires_at": v["time"]+60,
    }
    state = cd.record_cancel(state, cancelled)
    assert state["rotation_required"] is True
    assert state["requests"][-1]["status"] == "cancelled-after-delivery"
    with pytest.raises(cd.CredentialProtocolError):
        cd.admit_request(state, dict(req, request_id="00000000-0000-4000-8000-000000000099"))
    revoked = dict(a, revision=3, status="revoked", revoked_at=v["time"])
    blocked = cd.advance_authorization(state, revoked)
    assert blocked["authorization_status"] == "revoked"
    with pytest.raises(cd.CredentialProtocolError):
        cd.record_installation(blocked, {
            "request_id": req["request_id"], "delivery_id": delivery["delivery_id"],
            "receipt_id": "00000000-0000-4000-8000-000000000010"})
