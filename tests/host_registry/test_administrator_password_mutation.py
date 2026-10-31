"""Synthetic internal-only receiver tests; no live HTTPS or credentials."""
import uuid
from datetime import timedelta

from django.contrib.auth import get_user_model
from django.contrib.sessions.models import Session
from django.test import Client, TestCase
from django.utils import timezone

from zog.station_access.host_registry.administrator_credential_profile import (
    SCHEMA, PURPOSE, CONSUMER, CREDENTIAL_ID, DESTINATION,
)
from zog.station_access.host_registry.administrator_password_mutation import (
    PROOF_SCHEMA, AdministratorPasswordMutationDenied, install_authorized,
    inspect_installed,
)
from zog.station_access.host_registry.models import SecurityAudit
from zog.station_access.host_registry.user_views import revision
from zog.station_access.models import VncAccessGrant, VncWorkspace


class AdministratorPasswordMutationTests(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_superuser(
            "station-admin", password="Existing-fixture-password-712!"
        )
        self.proposal = {
            "schema": SCHEMA,
            "purpose": PURPOSE,
            "consumer": CONSUMER,
            "credential_id": CREDENTIAL_ID,
            "operation": "rotate",
            "host_id": str(uuid.uuid4()),
            "host_fingerprint": "a" * 64,
            "installation_id": str(uuid.uuid4()),
            "state_volume_id": str(uuid.uuid4()),
            "registry_id": "primary",
            "account_id": self.user.pk,
            "account": "station-admin",
            "credential_revision": 2,
            "operator_approval_sha256": "b" * 64,
            "destination": DESTINATION,
            "source_kind": "operator-provisioned-new-secret",
            "source_password_verified": True,
            "receiver_grant_id": str(uuid.uuid4()),
            "account_revision": revision(self.user),
            "session_revocation_required": True,
        }
        self.proof = {
            "schema": PROOF_SCHEMA,
            "status": "root-verified-delivered-not-installed",
            "host_id": self.proposal["host_id"],
            "host_fingerprint": self.proposal["host_fingerprint"],
            "installation_id": self.proposal["installation_id"],
            "state_volume_id": self.proposal["state_volume_id"],
            "registry_id": self.proposal["registry_id"],
            "consumer": CONSUMER,
            "purpose": PURPOSE,
            "credential_id": CREDENTIAL_ID,
            "credential_revision": 2,
            "authorization_id": str(uuid.uuid4()),
            "authorization_revision": 3,
            "request_id": str(uuid.uuid4()),
            "delivery_id": str(uuid.uuid4()),
            "account_id": self.user.pk,
            "account_revision": revision(self.user),
            "receiver_grant_id": self.proposal["receiver_grant_id"],
            "operator_approval_sha256": "b" * 64,
            "approved_proposal_sha256": "c" * 64,
            "ledger_checkpoint_sha256": "d" * 64,
        }
        self.password = "New-fixture-password-944!Strong"

    @staticmethod
    def accepted(proposal, proof):
        return True

    def invoke(self, **changes):
        return install_authorized(
            self.proposal, changes.get("password", self.password),
            changes.get("proof", self.proof),
            verify_root_admission=changes.get("attestor", self.accepted),
        )

    def test_transactional_password_history_sessions_and_vnc_revocation(self):
        client = Client()
        client.force_login(self.user)
        old_session = client.session.session_key
        workspace = VncWorkspace.objects.create(
            name="One", number=730, owner=self.user,
            application_name="desktop",
        )
        grant = VncAccessGrant.objects.create(
            user=self.user, workspace=workspace, token_digest="9" * 64,
            runtime_id="test-runtime", endpoint_revision=1,
            target_host="127.0.0.1", target_port=5901,
            expires_at=timezone.now() + timedelta(hours=1),
        )
        result = self.invoke()
        self.user.refresh_from_db()
        grant.refresh_from_db()
        self.assertTrue(self.user.check_password(self.password))
        self.assertTrue(self.user.is_active and self.user.is_superuser and self.user.is_staff)
        self.assertFalse(Session.objects.filter(session_key=old_session).exists())
        self.assertIsNotNone(grant.revoked_at)
        self.assertNotEqual(result["account_revision_before"], result["account_revision_after"])
        self.assertEqual(result["status"], "django-password-committed")
        self.assertFalse(result["shared_v1_receipt_signed"])
        audit = SecurityAudit.objects.get(pk=result["audit_id"])
        self.assertEqual(audit.action, "administrator-credential-installed")
        self.assertEqual(audit.details["request_id"], self.proof["request_id"])
        self.assertNotIn(self.password, str(audit.details))
        self.assertNotIn(self.user.password, str(audit.details))
        self.assertNotIn(self.password, str(result))
        self.assertEqual(
            inspect_installed(
                request_id=self.proof["request_id"],
                delivery_id=self.proof["delivery_id"],
                expected_after_revision=result["account_revision_after"],
            )["status"], "django-password-committed"
        )
        with self.assertRaises(AdministratorPasswordMutationDenied):
            self.invoke()

    def test_no_root_attestor_or_wrong_admission_is_a_stop(self):
        for attestor in (None, lambda proposal, proof: False):
            with self.assertRaises(AdministratorPasswordMutationDenied):
                self.invoke(attestor=attestor)
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password("Existing-fixture-password-712!"))
        self.assertFalse(SecurityAudit.objects.filter(
            action="administrator-credential-installed",
        ).exists())

    def test_invalid_proof_destination_or_stale_account_revision_fails(self):
        wrong = dict(self.proof, host_id=str(uuid.uuid4()))
        with self.assertRaises(AdministratorPasswordMutationDenied):
            self.invoke(proof=wrong)
        self.user.first_name = "Concurrent"
        self.user.save(update_fields=["first_name"])
        with self.assertRaises(ValueError):
            self.invoke()
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password("Existing-fixture-password-712!"))

    def test_weak_password_rejected_without_audit_or_mutation(self):
        with self.assertRaises(Exception):
            self.invoke(password="short")
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password("Existing-fixture-password-712!"))
        self.assertFalse(SecurityAudit.objects.filter(
            action="administrator-credential-installed",
        ).exists())

    def test_rotation_must_not_reuse_current_password(self):
        with self.assertRaises(AdministratorPasswordMutationDenied):
            self.invoke(password="Existing-fixture-password-712!")

    def test_first_login_source_requires_current_plaintext(self):
        self.proposal.update(
            operation="first-provision",
            source_kind="first-login-verified-export",
            credential_revision=1,
        )
        self.proof["credential_revision"] = 1
        with self.assertRaises(AdministratorPasswordMutationDenied):
            self.invoke(password="Not-the-original-password!")
        result = self.invoke(password="Existing-fixture-password-712!")
        self.assertEqual(result["status"], "django-password-committed")

    def test_revision_replay_and_reconcile_after_lost_reply(self):
        result = self.invoke()
        with self.assertRaises(AdministratorPasswordMutationDenied):
            self.invoke()
        self.assertEqual(SecurityAudit.objects.filter(
            action="administrator-credential-installed",
        ).count(), 1)
        self.assertEqual(
            inspect_installed(
                request_id=self.proof["request_id"],
                delivery_id=self.proof["delivery_id"],
                expected_after_revision="a" * 64,
            )["status"], "stale-or-changed"
        )
        self.assertEqual(
            inspect_installed(
                request_id=self.proof["request_id"],
                delivery_id=str(uuid.uuid4()),
                expected_after_revision=result["account_revision_after"],
            )["status"], "not-proven-installed"
        )

    def test_callback_failure_after_password_change_rolls_back_everything(self):
        session_client = Client()
        session_client.force_login(self.user)
        old_session = session_client.session.session_key
        with self.assertRaises(AdministratorPasswordMutationDenied):
            from unittest.mock import patch
            with patch(
                "zog.station_access.host_registry.administrator_password_mutation._verify_revocation",
                side_effect=AdministratorPasswordMutationDenied("incomplete"),
            ):
                self.invoke()
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password("Existing-fixture-password-712!"))
        self.assertTrue(Session.objects.filter(session_key=old_session).exists())
        self.assertFalse(SecurityAudit.objects.filter(
            action="administrator-credential-installed",
        ).exists())

    def test_account_demotion_and_absent_revision_block(self):
        self.user.is_staff = False
        self.user.save(update_fields=["is_staff"])
        self.proposal["account_revision"] = revision(self.user)
        self.proof["account_revision"] = revision(self.user)
        with self.assertRaises(AdministratorPasswordMutationDenied):
            self.invoke()
        self.user.is_staff = True
        self.user.is_superuser = False
        self.user.save(update_fields=["is_staff", "is_superuser"])
        self.proposal["account_revision"] = revision(self.user)
        self.proof["account_revision"] = revision(self.user)
        with self.assertRaises(ValueError):
            self.invoke()
