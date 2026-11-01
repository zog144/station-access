"""Candidate-only, exact-head source composition of three administrator FD owners.

Not part of the previously accepted default station-access dependency matrix.
Explicitly exercised by administrator-fd-source-exact-head.yml against pinned
root-control and host-install PRs. Single-process synthetic native UID boundary;
actual SOCK_SEQPACKET/SCM_RIGHTS, signer policy and Django commit are real.
"""
import json
import os
import uuid
from unittest.mock import patch
from django.test import TestCase, override_settings

from zog.host_identify import credential_delivery as cd
from zog.station_access.host_registry import administrator_credential_receiver as receiver
from zog.station_access.host_registry.models import AdministratorPasswordReception
from .test_administrator_credential_receiver import (
    AdministratorCredentialReceiverTests, secret_fd, ORIGIN, PASS,
)


class AdministratorFdCandidateTests(TestCase):
    setUp = AdministratorCredentialReceiverTests.setUp
    frames = AdministratorCredentialReceiverTests.frames

    def test_exact_three_owner_socket_fd_commit_and_lost_reply_recovery(self):
        """Synthetic source composition with real SCM_RIGHTS and Django transaction.

        The *native installer* root UID and separate receiver process identity
        cannot be installed in source CI. Simulate those two admission checks
        only; leave root-control's real SO_PEERCRED, SCM_CREDENTIALS, sealed
        read-only memfd and exact request-frame verification active.
        """
        import socket
        from contextlib import closing
        from types import SimpleNamespace
        from zog.root_control import administrator_fd as wire
        from zog.host_install import station_admin_password_handoff as handoff
        from zog.station_access.host_registry import administrator_fd_broker as bridge

        if os.getuid() == 0:
            self.skipTest("single-process nonroot source fixture, never native root acceptance")
        options = dict(self.options, HOST_ADMIN_PASSWORD_V1_FD_BROKER_ENABLED=True,
                       HOST_ADMIN_PASSWORD_V1_FD_BROKER_UID=0)
        args, _ = self.frames()
        # Actual signed HTTPS evidence and operator approval are verified by
        # the *real* receiver; they are not constructed from transport input.
        with override_settings(**options), patch.object(receiver.os, "geteuid", return_value=1201):
            approval, auth, request, delivery, _, _ = receiver._envelopes(**args)
            start, cgroup = wire.process_identity(os.getpid())
            peer = wire.ExpectedPeer(os.getpid(), os.getuid(), os.getgid(), start, cgroup)
            def synthetic_installed_peer(selected):
                assert selected == peer
                receiver._enabled()
            root_uid = SimpleNamespace(geteuid=lambda: 0)
            selectors = dict(authorization=auth, request=request, delivery=delivery,
                             account_id=approval["user_id"],
                             expected_binding=cd.binding(auth),
                             expected_origin=ORIGIN)
            with patch.object(handoff, "os", root_uid), patch.object(
                    bridge, "_broker_gate", side_effect=synthetic_installed_peer):
                with secret_fd() as fd:
                    host, station = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
                    with closing(host), closing(station):
                        wire.prepare_receiver_socket(host)
                        wire.prepare_receiver_socket(station)
                        submitted = handoff.handoff(
                            channel=host, readonly_fd=fd, receiver_peer=peer,
                            now=self.now, **selectors)
                        assert submitted["host_signed_receipt_authorized"] is False
                        committed = bridge.install_from_broker(
                            channel=station, broker_peer=peer, install_args=args)
                        assert committed["request_id"] == request["request_id"]
                        verified = handoff.read_committed_reply(
                            channel=host, receiver_peer=peer, now=self.now + 30,
                            **selectors)
                        assert verified["source_contract_matched"] is True
                        assert verified["host_signed_receipt_authorized"] is False
                        assert PASS not in json.dumps(verified)
                self.target.refresh_from_db()
                assert self.target.check_password(PASS)
                assert AdministratorPasswordReception.objects.count() == 1
                # A lost post-commit acknowledgement must NOT trigger a new
                # password transfer; recover the exact saved selector only.
                host, station = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
                with closing(host), closing(station):
                    wire.prepare_receiver_socket(host)
                    wire.prepare_receiver_socket(station)
                    recovered = handoff.recover(
                        channel=host, receiver_peer=peer, now=self.now + 6000,
                        **selectors)
                    assert recovered["host_signed_receipt_authorized"] is False
                    observed = bridge.inspect_from_broker(
                        channel=station, broker_peer=peer,
                        request_id=request["request_id"],
                        delivery_id=delivery["delivery_id"],
                        authorization_id=auth["authorization_id"],
                        credential_revision=auth["credential_revision"],
                        account_id=approval["user_id"])
                    assert observed == committed
                    accepted = handoff.read_committed_reply(
                        channel=host, receiver_peer=peer, now=self.now + 6000,
                        **selectors)
                    assert accepted["source_contract_matched"]
                    assert accepted["host_signed_receipt_authorized"] is False
                assert AdministratorPasswordReception.objects.count() == 1

    def test_three_owner_fd_rejects_foreign_operation_before_password_mutation(self):
        import socket
        from contextlib import closing
        from types import SimpleNamespace
        from zog.root_control import administrator_fd as wire
        from zog.host_install import station_admin_password_handoff as handoff
        from zog.station_access.host_registry import administrator_fd_broker as bridge

        args, _ = self.frames()
        options = dict(self.options, HOST_ADMIN_PASSWORD_V1_FD_BROKER_ENABLED=True,
                       HOST_ADMIN_PASSWORD_V1_FD_BROKER_UID=0)
        with override_settings(**options), patch.object(receiver.os, "geteuid", return_value=1201):
            approval, auth, request, delivery, _, _ = receiver._envelopes(**args)
            start, cgroup = wire.process_identity(os.getpid())
            peer = wire.ExpectedPeer(os.getpid(), os.getuid(), os.getgid(), start, cgroup)
            expected = wire.operation_frame(
                request_id=request["request_id"], delivery_id=delivery["delivery_id"],
                authorization_id=auth["authorization_id"],
                credential_revision=auth["credential_revision"],
                account_id=approval["user_id"])
            foreign = wire.operation_frame(
                request_id=str(uuid.uuid4()), delivery_id=delivery["delivery_id"],
                authorization_id=auth["authorization_id"],
                credential_revision=auth["credential_revision"],
                account_id=approval["user_id"])
            with secret_fd() as fd:
                host, station = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
                with closing(host), closing(station):
                    wire.prepare_receiver_socket(station)
                    wire.send_secret_fd(host, fd, receiver=peer, frame=foreign)
                    with self.assertRaises(wire.ProtectedFdDenied):
                        wire.receive_secret_fd(station, broker=peer, frame=expected)
                assert not AdministratorPasswordReception.objects.exists()
            with patch.object(handoff, "os", SimpleNamespace(geteuid=lambda: 0)):
                selectors = dict(authorization=auth, request=request, delivery=delivery,
                                 account_id=approval["user_id"],
                                 expected_binding=cd.binding(auth),
                                 expected_origin=ORIGIN, now=self.now)
                bad = dict(selectors, expected_binding=dict(cd.binding(auth), purpose="issuer-cloudflare-dns01"))
                with self.assertRaises(handoff.AdministratorReceiptContractError):
                    handoff.handoff(channel=object(), readonly_fd=77, receiver_peer=peer,
                                    **bad)
            # No caller-supplied ExpectedPeer can authorize the disabled
            # receiver, even if the signed envelopes are otherwise valid.
            with self.assertRaises(receiver.ProtectedAdminCredentialDenied):
                bridge.install_from_broker(channel=object(), broker_peer=peer,
                                           install_args=args)
            assert not AdministratorPasswordReception.objects.exists()

