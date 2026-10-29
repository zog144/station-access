"""Pure source compatibility for host-identify unified HTTPS v1.

This adapter never opens a socket, reads a vault or installs a secret. It is
the single station-access authority-side schema/transition boundary; legacy
PR #9 draft messages are *not* mapped or coerced into shared v1 messages.
All returned ledgers must be committed durably under the original root-owned
Station SecurityGate before the corresponding external action.
"""
from zog.host_identify import credential_delivery as cd
from zog.host_identify import signatures

PURPOSE = "issuer-cloudflare-dns01"
CONSUMER = "certify-manage"
PATH = "/.well-known/zog/credential-delivery/v1"
RECEIPT_PATH = PATH + "/receipt"
CANCEL_PATH = PATH + "/cancel"
SCHEMAS = (cd.AUTHORIZATION_SCHEMA, cd.REQUEST_SCHEMA,
           cd.DELIVERY_ENVELOPE_SCHEMA, cd.RECEIPT_SCHEMA, cd.CANCEL_SCHEMA)


class InteropDenied(ValueError):
    pass


def _restrict(value):
    if (type(value) is not dict or value.get("purpose") != PURPOSE
            or value.get("consumer") != CONSUMER
            or type(value.get("credential_id")) is not str
            or not value["credential_id"].startswith("cloudflare-")):
        raise InteropDenied("unapproved-credential-purpose")
    return value


def authorization_signed(value, key, *, expected_issuer, expected_binding, now):
    auth = cd.verify_authorization(
        value, key, expected_issuer=expected_issuer,
        expected_binding=expected_binding, now=now)
    return _restrict(auth)


def request_admit(url, method, headers, body, host_key, authorization, ledger, *,
                  expected_origin, now=None):
    """Caller must separately atomically persist signature nonce and ledger."""
    if method != "POST" or url != signatures.origin(expected_origin) + PATH:
        raise InteropDenied("wrong-request-route")
    _restrict(authorization)
    request, nonce, expiry = cd.verify_request_http(
        url, method, headers, body, host_key, authorization, now=now)
    state = cd.admit_request(ledger, request)
    return request, nonce, expiry, state


def delivery_record(ledger, value, request, authorization, authority_key, *,
                    now):
    """Sign then durably record nonsecret delivered status before HTTP output.

    'value' is a protected broker's selected delivery object. This function
    must NOT be called by the nonprivileged web ingress.
    """
    _restrict(authorization)
    cd.validate_delivery(value, request, authorization, now=now)
    next_state = cd.record_delivery(ledger, value)
    signed = cd.sign_delivery(value, authority_key)
    return signed, next_state


def receipt_record(url, method, headers, body, host_key,
                   request, delivery_metadata, ledger, *, expected_origin, now=None):
    if method != "POST" or url != signatures.origin(expected_origin) + RECEIPT_PATH:
        raise InteropDenied("wrong-receipt-route")
    receipt, nonce, expiry = cd.verify_receipt_http(
        url, method, headers, body, host_key, request, delivery_metadata, now=now)
    state = cd.record_installation(ledger, receipt)
    return receipt, nonce, expiry, state


def cancel_record(url, method, headers, body, host_key, request, ledger, *,
                  expected_origin, now=None):
    if method != "POST" or url != signatures.origin(expected_origin) + CANCEL_PATH:
        raise InteropDenied("wrong-cancel-route")
    cancelled, nonce, expiry = cd.verify_cancel_http(
        url, method, headers, body, host_key, request, now=now)
    state = cd.record_cancel(ledger, cancelled)
    return cancelled, nonce, expiry, state
