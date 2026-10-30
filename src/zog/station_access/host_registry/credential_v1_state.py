"""Durable Credential Authority state transitions using host-identify v1.

Only nonsecret authorization/operation/ledger metadata enters Django. Every
transition and HTTP signature nonce is committed under the station's existing
SecurityGate. The native root broker must independently recheck operator
approval, enrollment, selected issuer and signed authorization before calling.
This module does not inspect a vault, authenticate an operator or open HTTP.
"""
import hashlib
import uuid

from . import identity
from .identity import locked
from .models import HttpsCredentialV1Ledger, HttpsCredentialV1Operation


def _common():
    from zog.host_identify import credential_delivery as cd
    return cd


def _subject(auth):
    cd = _common()
    return hashlib.sha256(
        (auth["host_id"] + ":" + auth["consumer"] + ":" +
         auth["purpose"] + ":" + auth["credential_id"]).encode("ascii")
    ).hexdigest()


def _ledger(auth):
    cd = _common()
    key = _subject(auth)
    row = HttpsCredentialV1Ledger.objects.filter(pk=key).first()
    if row is None:
        return None, cd.new_ledger(auth)
    if (str(row.host_id) != auth["host_id"]
            or row.credential_id != auth["credential_id"]
            or str(row.authorization_id) != auth["authorization_id"]):
        raise ValueError("credential-authorization-changed")
    cd.validate_ledger(row.state)
    return row, cd.advance_authorization(row.state, auth)


def _save(row, auth, state):
    cd = _common()
    cd.validate_ledger(state)
    if row is None:
        row = HttpsCredentialV1Ledger(
            subject_sha256=_subject(auth),
            host_id=uuid.UUID(auth["host_id"]),
            credential_id=auth["credential_id"],
            authorization_id=uuid.UUID(auth["authorization_id"]),
            state=state)
    else:
        row.state = state
    row.save()
    return row


def reconcile_authorization(auth):
    """Persist a reviewed higher authorization/revocation revision.

    The root broker must have verified the independently signed authorization
    and current operator approval before this transition.
    """
    cd = _common()
    cd.binding(auth)
    with locked():
        row, state = _ledger(auth)
        _save(row, auth, state)
        return state["authorization_status"], state["authorization_revision"]


def request_admit(*, auth, url, headers, body, host_key, origin, now=None):
    """Consume the signed HTTP nonce and reserve a pending request atomically.

    The caller must recheck signed operator authorization while holding the
    same security writer; this method by itself never releases credentials.
    """
    cd = _common()
    from zog.station_access import credential_https_interop as wire
    if type(body) is not bytes or len(body) > cd.MAX_BODY:
        raise ValueError("invalid-request")
    # Require one canonical wire byte sequence; disallow duplicate JSON keys.
    _operation_id(body, cd.REQUEST_SCHEMA)
    with locked():
        row, state = _ledger(auth)
        request, nonce, expiry, pending = wire.request_admit(
            url, "POST", headers, body, host_key, auth, state,
            expected_origin=origin, now=now)
        # Refuse same request identity even when the common pure state machine
        # regards an identical repeated request as idempotent.
        if HttpsCredentialV1Operation.objects.filter(
                request_id=request["request_id"]).exists():
            raise ValueError("request-already-recorded")
        identity.consume(request["host_fingerprint"], nonce, expiry)
        row = _save(row, auth, pending)
        HttpsCredentialV1Operation.objects.create(
            request_id=uuid.UUID(request["request_id"]), ledger=row,
            request=request)
        return request["request_id"]


def delivery_commit(*, auth, request_id, value, signing_key, now):
    """Sign and mark delivered BEFORE caller emits the signed response bytes.

    A failed send is permanently ambiguous until explicit signed cancellation;
    no recipient is ever allowed to reuse the same request or credential
    revision through this method.
    """
    cd = _common()
    from zog.station_access import credential_https_interop as wire
    with locked():
        row, current = _ledger(auth)
        if row is None or current["authorization_status"] != "approved":
            raise ValueError("authorization-unavailable")
        operation = HttpsCredentialV1Operation.objects.select_related(
            "ledger").get(pk=uuid.UUID(request_id), ledger=row)
        if operation.delivery_metadata:
            raise ValueError("delivery-already-committed")
        request = operation.request
        if request["expires_at"] <= now or request["created_at"] > now + cd.CLOCK_SKEW:
            raise ValueError("request-expired-before-delivery")
        signed, delivered = wire.delivery_record(
            current, value, request, auth, signing_key, now=now)
        # Only necessary receipt-correlation metadata, NEVER value['secret'].
        metadata = {key: value[key] for key in (
            "request_id", "delivery_id", "issued_at", "expires_at")}
        _save(row, auth, delivered)
        operation.delivery_metadata = metadata
        operation.save(update_fields=["delivery_metadata"])
        return cd.canonical(signed)


def receipt_commit(*, auth, url, headers, body, host_key, origin, now=None):
    cd = _common()
    from zog.station_access import credential_https_interop as wire
    if type(body) is not bytes or len(body) > cd.MAX_BODY:
        raise ValueError("invalid-receipt")
    # Lookup is only a locator; signature/authorization are validated inside
    # the writer before any status is changed or 204 is returned.
    request_id = _operation_id(body, cd.RECEIPT_SCHEMA)
    with locked():
        row, current = _ledger(auth)
        operation = HttpsCredentialV1Operation.objects.get(
            pk=uuid.UUID(request_id), ledger=row)
        if not operation.delivery_metadata:
            raise ValueError("delivery-unresolved")
        receipt, nonce, expiry, installed = wire.receipt_record(
            url, "POST", headers, body, host_key, operation.request,
            operation.delivery_metadata, current,
            expected_origin=origin, now=now)
        identity.consume(receipt["host_fingerprint"], nonce, expiry)
        _save(row, auth, installed)
        return receipt["receipt_id"]


def cancel_commit(*, auth, url, headers, body, host_key, origin, now=None):
    cd = _common()
    from zog.station_access import credential_https_interop as wire
    if type(body) is not bytes or len(body) > cd.MAX_BODY:
        raise ValueError("invalid-cancellation")
    request_id = _operation_id(body, cd.CANCEL_SCHEMA)
    with locked():
        row, current = _ledger(auth)
        operation = HttpsCredentialV1Operation.objects.get(
            pk=uuid.UUID(request_id), ledger=row)
        cancel, nonce, expiry, cancelled = wire.cancel_record(
            url, "POST", headers, body, host_key, operation.request,
            current, expected_origin=origin, now=now)
        identity.consume(cancel["host_fingerprint"], nonce, expiry)
        _save(row, auth, cancelled)
        return cancelled["rotation_required"]


def _operation_id(raw, schema):
    import json
    cd = _common()
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("duplicate-json-key")
            value[key] = item
        return value
    value = json.loads(raw, object_pairs_hook=unique,
                       parse_constant=lambda _: (_ for _ in ()).throw(
                           ValueError("nonfinite-number")))
    if (type(value) is not dict or value.get("schema") != schema
            or cd.canonical(value) != raw):
        raise ValueError("invalid-canonical-operation")
    return str(uuid.UUID(value["request_id"]))
