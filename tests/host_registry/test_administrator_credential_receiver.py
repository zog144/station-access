"""Synthetic sealed-FD canonical HTTPS administrator reception (never real secrets)."""
import base64
import fcntl
import hashlib
import json
import os
import time
import uuid
from contextlib import contextmanager
from datetime import timedelta
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from django.contrib.auth import get_user_model
from django.contrib.sessions.models import Session
from django.core.exceptions import ValidationError
from django.test import Client, TestCase, override_settings
from django.utils import timezone

from zog.host_identify import credential_delivery as cd, signatures
from zog.station_access.credential_https_interop import PATH
from zog.station_access.host_registry import administrator_credential_receiver as receiver
from zog.station_access.host_registry.models import (
    AdministratorPasswordReception, SecurityAudit)
from zog.station_access.host_registry.user_views import revision
from zog.station_access.models import VncAccessGrant, VncWorkspace

ORIGIN = "https://station.example.test"
PASS = "Synthetic-replacement-only-Password-9345!"
KEY = lambda key: key.public_key().public_bytes(
    serialization.Encoding.Raw, serialization.PublicFormat.Raw)


@contextmanager
def secret_fd(password=PASS):
    fd = os.memfd_create("synthetic-admin-credential", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    try:
        os.write(fd, password.encode())
        fcntl.fcntl(fd, fcntl.F_ADD_SEALS,
                    fcntl.F_SEAL_SEAL | fcntl.F_SEAL_WRITE |
                    fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK)
        readonly = os.open("/proc/self/fd/" + str(fd), os.O_RDONLY | os.O_CLOEXEC)
        try:
            yield readonly
        finally:
            os.close(readonly)
    finally:
        os.close(fd)


class AdministratorCredentialReceiverTests(TestCase):
    def setUp(self):
        self.target = get_user_model().objects.create_superuser(
            "station-admin", password="Synthetic-original-Password-7348!")
        self.operator_key = Ed25519PrivateKey.generate()
        self.authority_key = Ed25519PrivateKey.generate()
        self.host_key = Ed25519PrivateKey.generate()
        self.now = int(time.time())
        self.subject = {
            "host_id": str(uuid.uuid4()),
            "host_fingerprint": signatures.fingerprint(self.host_key.public_key()),
            "installation_id": str(uuid.uuid4()),
            "state_volume_id": str(uuid.uuid4()),
            "registry_id": "station-registry",
            "consumer": receiver.CONSUMER,
            "purpose": receiver.PURPOSE,
            "credential_id": "station-admin-" + str(self.target.pk),
        }
        self.options = {
            "HOST_ADMIN_PASSWORD_V1_RECEIVER_ENABLED": True,
            "HOST_ADMIN_PASSWORD_V1_RECEIVER_UID": 1201,
            "HOST_ADMIN_PASSWORD_V1_OPERATOR_PIN_SHA256": hashlib.sha256(KEY(self.operator_key)).hexdigest(),
            "HOST_ADMIN_PASSWORD_V1_AUTHORITY_PIN_SHA256": hashlib.sha256(KEY(self.authority_key)).hexdigest(),
        }
        self.auth = {
            "schema": cd.AUTHORIZATION_SCHEMA, "issuer": ORIGIN,
            **self.subject,
            "credential_revision": 1,
            "authorization_id": str(uuid.uuid4()),
            "revision": 1, "status": "approved",
            "approved_at": self.now - 10,
            "revoked_at": None, "expires_at": self.now + 1800,
        }
        self.envelope = cd.canonical(cd.sign_authorization(self.auth, self.authority_key))

    def frames(self, *, password=PASS, credential_revision=1, **updates):
        auth = dict(self.auth, credential_revision=credential_revision)
        auth.update(updates.get("authorization", {}))
        envelope = cd.canonical(cd.sign_authorization(auth, self.authority_key))
        request = {
            "schema": cd.REQUEST_SCHEMA, **self.subject,
            "credential_revision": auth["credential_revision"],
            "authorization_id": auth["authorization_id"],
            "authorization_revision": auth["revision"],
            "request_id": str(uuid.uuid4()), "action": "deliver",
            "previous_delivery_id": None,
            "created_at": self.now, "expires_at": self.now + 120,
        }
        # A request can be signed while authorization is approved, then
        # independently revoked before the local receiver is called.
        signing_view = (auth if auth["status"] == "approved" else
                        dict(auth, status="approved", revoked_at=None))
        signed_request = cd.prepare_request(
            ORIGIN + PATH, request, signing_view, self.host_key,
            nonce="F" + uuid.uuid4().hex[:23])
        delivery = {
            "schema": cd.DELIVERY_SCHEMA, "request_id": request["request_id"],
            "delivery_id": str(uuid.uuid4()), "authorization_id": auth["authorization_id"],
            "authorization_revision": auth["revision"],
            "credential_id": auth["credential_id"],
            "credential_revision": auth["credential_revision"],
            "consumer": receiver.CONSUMER, "purpose": receiver.PURPOSE,
            "issued_at": self.now, "expires_at": self.now + 120,
            "secret_format": "base64",
            "secret": base64.b64encode(password.encode()).decode(),
        }
        proposal = {
            "schema": receiver.POLICY_SCHEMA,
            "issuer": ORIGIN,
            "destination_host_id": auth["host_id"],
            "destination_fingerprint": auth["host_fingerprint"],
            "destination_installation_id": auth["installation_id"],
            "destination_state_volume_id": auth["state_volume_id"],
            "registry_id": auth["registry_id"],
            "consumer": receiver.CONSUMER, "purpose": receiver.PURPOSE,
            "credential_id": auth["credential_id"],
            "user_id": self.target.pk,
            "username": self.target.username,
            "expected_account_revision": revision(self.target),
            "authorization_id": auth["authorization_id"],
            "authorization_revision": auth["revision"],
            "authorization_envelope_sha256": hashlib.sha256(envelope).hexdigest(),
            "credential_revision": auth["credential_revision"],
            "authority_signer_sha256": hashlib.sha256(KEY(self.authority_key)).hexdigest(),
            "issued_at": self.now - 1, "expires_at": self.now + 2400,
        }
        proposal.update(updates.get("policy", {}))
        proposal["operator_signature"] = base64.b64encode(self.operator_key.sign(
            receiver.POLICY_SCHEMA.encode() + b"\0" + cd.canonical(proposal))).decode()
        args = {
            "signed_authorization": envelope,
            "signed_delivery": cd.canonical(cd.sign_delivery(delivery, self.authority_key)),
            "request_body": signed_request.body,
            "request_headers": dict(signed_request.headers),
            "request_url": ORIGIN + PATH,
            "signed_approval": cd.canonical(proposal),
            "operator_pin": KEY(self.operator_key),
            "authority_pin": KEY(self.authority_key),
            "host_pin": KEY(self.host_key),
            "expected_origin": ORIGIN,
            "now": self.now,
        }
        return args, delivery

    def install(self, args, *, password=PASS):
        with override_settings(**self.options), patch.object(receiver.os, "geteuid", return_value=1201), secret_fd(password) as fd:
            return receiver.install(**args, secret_fd=fd)

    def test_password_commit_history_sessions_vnc_and_secret_free_audit(self):
        client = Client(); client.force_login(self.target)
        session_key = client.session.session_key
        workspace = VncWorkspace.objects.create(
            name="Fixture", number=104, owner=self.target, application_name="desktop")
        grant = VncAccessGrant.objects.create(
            user=self.target, workspace=workspace, token_digest="b"*64,
            runtime_id="fixture", endpoint_revision=0,
            target_host="127.0.0.1", target_port=5901,
            expires_at=timezone.now() + timedelta(minutes=2))
        args, delivery = self.frames()
        result = self.install(args)
        self.target.refresh_from_db()
        assert self.target.check_password(PASS)
        assert result["state"] == "committed-awaiting-host-signed-receipt"
        assert not Session.objects.filter(session_key=session_key).exists()
        grant.refresh_from_db()
        assert grant.revoked_at is not None
        assert AdministratorPasswordReception.objects.count() == 1
        assert SecurityAudit.objects.filter(action="admin-password-installed").count() == 1
        stored = json.dumps(list(AdministratorPasswordReception.objects.values()) +
                            list(SecurityAudit.objects.values()), default=str)
        assert PASS not in stored and delivery["secret"] not in stored
        with override_settings(**self.options), patch.object(receiver.os, "geteuid", return_value=1201):
            assert receiver.inspect_committed(request_id=result["request_id"]) == result

    def test_disabled_and_unsupported_identity_or_purpose_cannot_install(self):
        args, _ = self.frames()
        with secret_fd() as fd:
            with self.assertRaises(receiver.ProtectedAdminCredentialDenied):
                receiver.install(**args, secret_fd=fd)
        for field, value in [
            ("consumer", "certify-manage"),
            ("purpose", "issuer-cloudflare-dns01"),
            ("destination_host_id", str(uuid.uuid4())),
            ("destination_installation_id", str(uuid.uuid4())),
            ("destination_state_volume_id", str(uuid.uuid4())),
            ("user_id", self.target.pk + 1000),
            ("username", "different-admin"),
            ("credential_revision", 2),
            ("authorization_revision", 2),
            ("authority_signer_sha256", "0"*64),
        ]:
            with self.subTest(field=field):
                a, _ = self.frames(policy={field: value})
                with self.assertRaises(receiver.ProtectedAdminCredentialDenied):
                    self.install(a)
        assert not AdministratorPasswordReception.objects.exists()

    def test_replay_stale_account_revision_and_credential_highwater(self):
        args, _ = self.frames()
        self.install(args)
        with self.assertRaises(receiver.ProtectedAdminCredentialDenied):
            self.install(args)
        # New request/credential revision alone cannot override the stale
        # user account approval or the prior version high water.
        args, _ = self.frames(credential_revision=2)
        with self.assertRaises(receiver.ProtectedAdminCredentialDenied):
            self.install(args)
        self.target.refresh_from_db()
        fresh, _ = self.frames(credential_revision=2,
                               password="New-synthetic-rotation-Password-0987!")
        self.install(fresh, password="New-synthetic-rotation-Password-0987!")
        assert AdministratorPasswordReception.objects.count() == 2
        assert list(AdministratorPasswordReception.objects.order_by(
            "credential_revision").values_list("credential_revision", flat=True)) == [1, 2]
        self.target.refresh_from_db()
        old, _ = self.frames(credential_revision=1)
        with self.assertRaises(receiver.ProtectedAdminCredentialDenied):
            self.install(old)
        assert AdministratorPasswordReception.objects.count() == 2

    def test_validation_failure_and_transaction_rollback_preserve_password(self):
        old = self.target.password
        args, _ = self.frames(password="weak")
        with self.assertRaises(receiver.ProtectedAdminCredentialDenied):
            self.install(args, password="weak")
        self.target.refresh_from_db()
        assert self.target.password == old
        assert not AdministratorPasswordReception.objects.exists()
        assert not SecurityAudit.objects.filter(action="admin-password-installed").exists()
        args, _ = self.frames()
        with patch.object(receiver, "audit", side_effect=RuntimeError("simulated-rollback")):
            with self.assertRaises(RuntimeError):
                self.install(args)
        self.target.refresh_from_db()
        assert self.target.password == old
        assert not AdministratorPasswordReception.objects.exists()

    def test_wrong_fd_unsealed_and_secret_mismatch_refused(self):
        args, _ = self.frames()
        with override_settings(**self.options), patch.object(receiver.os, "geteuid", return_value=1201):
            with self.assertRaises(receiver.ProtectedAdminCredentialDenied):
                receiver.install(**args, secret_fd=-1)
            fd = os.memfd_create("unsealed-fixture", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
            try:
                os.write(fd, PASS.encode())
                with self.assertRaises(receiver.ProtectedAdminCredentialDenied):
                    receiver.install(**args, secret_fd=fd)
            finally:
                os.close(fd)
        with self.assertRaises(receiver.ProtectedAdminCredentialDenied):
            self.install(args, password="Other-synthetic-Password-7879!")

    def test_signer_substitution_missing_operator_and_revocation_refused(self):
        args, _ = self.frames()
        altered = dict(args, operator_pin=KEY(Ed25519PrivateKey.generate()))
        with self.assertRaises(receiver.ProtectedAdminCredentialDenied):
            self.install(altered)
        altered = dict(args, authority_pin=KEY(Ed25519PrivateKey.generate()))
        with self.assertRaises(receiver.ProtectedAdminCredentialDenied):
            self.install(altered)
        changed, _ = self.frames(authorization={"status": "revoked", "revoked_at": self.now})
        with self.assertRaises(receiver.ProtectedAdminCredentialDenied):
            self.install(changed)
        altered = dict(args, request_url=ORIGIN + "/api/users/")
        with self.assertRaises(receiver.ProtectedAdminCredentialDenied):
            self.install(altered)
        altered = dict(args, request_body=args["request_body"] + b"\\n")
        with self.assertRaises(receiver.ProtectedAdminCredentialDenied):
            self.install(altered)
        self.target.is_superuser = False; self.target.save(update_fields=["is_superuser"])
        with self.assertRaises(receiver.ProtectedAdminCredentialDenied):
            self.install(args)
        assert not AdministratorPasswordReception.objects.exists()
