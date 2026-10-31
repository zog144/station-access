"""Disabled local broker entry: no Django URL, CLI, socket listener or activation.

The accepted installation must supply a protected SOCK_SEQPACKET channel and an
independently attested root broker ExpectedPeer. The wire frame never selects
the account or redefines the peer. The common SCM_RIGHTS primitive currently
lives in draft root-control PR #19, not an accepted installed pin.
"""
from __future__ import annotations

import os
import time
from django.conf import settings

from . import administrator_credential_receiver as receiver


def _broker_gate(peer):
    receiver._enabled()
    if getattr(settings, "HOST_ADMIN_PASSWORD_V1_FD_BROKER_ENABLED", False) is not True:
        receiver.deny()
    # The root-only broker's peer must be independently supplied by the
    # installed launcher, not reconstructed from a message sent on the socket.
    allowed = getattr(settings, "HOST_ADMIN_PASSWORD_V1_FD_BROKER_UID", None)
    if (type(allowed) is not int or allowed != 0 or getattr(peer, "uid", None) != 0):
        receiver.deny()


def _frame(verified, approval):
    from zog.root_control.administrator_fd import operation_frame
    auth, request, delivery = verified
    return operation_frame(request_id=request["request_id"],
                           delivery_id=delivery["delivery_id"],
                           authorization_id=auth["authorization_id"],
                           credential_revision=auth["credential_revision"],
                           account_id=approval["user_id"])


def install_from_broker(*, channel, broker_peer, install_args):
    """Verify canonical signatures first; only then receive/close a protected FD."""
    _broker_gate(broker_peer)
    if type(install_args) is not dict or "secret_fd" in install_args:
        receiver.deny()
    now = install_args.get("now")
    now = int(time.time()) if now is None else now
    # Keep native source requirements identical to the Django mutation:
    # this is not permission to bypass signer or account approval.
    approval, auth, request, delivery, _, _ = receiver._envelopes(
        signed_authorization=install_args["signed_authorization"],
        signed_delivery=install_args["signed_delivery"],
        request_body=install_args["request_body"],
        request_headers=install_args["request_headers"],
        request_url=install_args["request_url"],
        authority_pin=install_args["authority_pin"],
        host_pin=install_args["host_pin"],
        operator_pin=install_args["operator_pin"],
        signed_approval=install_args["signed_approval"],
        expected_origin=install_args["expected_origin"], now=now)
    from zog.root_control.administrator_fd import receive_secret_fd
    secret = receive_secret_fd(channel, broker=broker_peer,
                               frame=_frame((auth, request, delivery), approval))
    try:
        return receiver.install(**install_args, secret_fd=secret)
    finally:
        os.close(secret)


def inspect_from_broker(*, channel, broker_peer, request_id, delivery_id,
                        authorization_id, credential_revision, account_id):
    """After ambiguous commit: authenticated read-only DB inspection, no FD.

    Recovery selectors MUST come from the protected installer's durable
    original request/delivery record; never from a browser or wire message.
    """
    _broker_gate(broker_peer)
    from zog.root_control.administrator_fd import operation_frame, receive_recovery
    frame = operation_frame(request_id=request_id, delivery_id=delivery_id,
                            authorization_id=authorization_id,
                            credential_revision=credential_revision,
                            account_id=account_id)
    receive_recovery(channel, broker=broker_peer, frame=frame)
    result = receiver.inspect_committed(request_id=request_id)
    if (result["delivery_id"] != delivery_id
        or result["authorization_id"] != authorization_id
        or result["credential_revision"] != credential_revision
        or result["account_id"] != account_id):
        receiver.deny()
    return result
