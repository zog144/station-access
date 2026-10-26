"""Source-only gate for a fresh protected empty shared DNS owner.

The provider fixtures perform no DNS writes; native owner/permissions and
installed-byte acceptance remain separate.
"""
import json
import os
import tempfile
import time
from pathlib import Path
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import TestCase, override_settings
from zog.network_register.contracts import NetworkError
from zog.network_register.store import SqliteStateStore
from zog.station_access.host_registry import dns_empty_bootstrap as bootstrap
from zog.station_access.host_registry import dns_cutover, dns_shared
from zog.station_access.host_registry.dns_reconcile import controller_lock
from zog.station_access.host_registry.models import (
    ProviderCredential, DnsAssignment, Host, SecurityAudit,
)


class EmptySharedBootstrapTests(TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.state = Path(self.tmp.name)
        self.root = self.state / "dns-controller"
        self.admin = get_user_model().objects.create_superuser(
            username="empty-dns-owner", email="", password="test")
        self.other = get_user_model().objects.create_superuser(
            username="foreign-dns-owner", email="", password="test")
        self.credential = ProviderCredential.objects.create(
            provider="cloudflare", label="Test credential", account_id="a" * 32,
            revision=2, key_id="test-vault-id", ciphertext="not-read")
        self.zone = "example.test"
        self.selected = {
            "schema": 1, "owner_user_id": self.admin.pk,
            "credential_id": str(self.credential.pk), "credential_revision": 2,
            "binding_id": "empty-controller-test", "binding_revision": 1,
            "zone_id": "zone-identifier", "zone_name": self.zone,
            "prefix": "hosts.example.test", "nameservers": ["ns1.example.test"],
            "host_ids": [],
        }
        self.override = override_settings(
            STATE_DIRECTORY=self.state,
            HOST_DNS_CONFIGURATION=str(self.root / "configuration.json"))
        self.override.enable()
        self.addCleanup(self.override.disable)
        self.provider_calls = []
        self.mocks = [
            patch("zog.station_access.host_registry.dns_setup.candidate",
                  side_effect=self.candidate),
            patch("zog.station_access.host_registry.dns_setup.validate",
                  side_effect=self.validate),
        ]
        for m in self.mocks:
            m.start()
            self.addCleanup(m.stop)

    def candidate(self, owner, credential, revision, zone, label,
                  *, binding_id=None, provider_factory=None):
        self.provider_calls.append(("candidate", zone, label))
        if (owner != self.admin.pk or str(credential) != str(self.credential.pk)
                or revision != 2 or zone != "zone-identifier"
                or label != "hosts"):
            raise NetworkError("conflict")
        result = dict(self.selected)
        result["binding_id"] = binding_id or result["binding_id"]
        return result

    def validate(self, data, *, collector=None, provider_factory=None, empty=True):
        self.provider_calls.append(("read-only-inventory", data["zone_id"]))
        if data != self.selected or not empty:
            raise NetworkError("conflict")

    def review(self):
        return bootstrap.review(
            owner=self.admin.pk, credential_id=str(self.credential.pk),
            credential_revision=2, zone_id="zone-identifier", prefix_label="hosts")

    def commit(self, review=None):
        review = review or self.review()
        return bootstrap.commit(owner=self.admin.pk, review_id=review["review_id"])

    def test_review_commits_empty_writer_and_reopens_through_normal_controller(self):
        proposal = self.review()
        self.assertEqual(proposal["provider_writes"], 0)
        self.assertEqual(proposal["writer"], "uninitialized")
        self.assertFalse((self.root / "configuration.json").exists())
        self.assertFalse((self.root / "controller.json").exists())
        result = self.commit(proposal)
        self.assertFalse(result["replayed"])
        self.assertEqual(result["writer"], "shared")
        self.assertEqual(result["provider_writes"], 0)
        config = json.loads((self.root / "configuration.json").read_text())
        self.assertEqual(config["account_id"], self.credential.account_id)
        self.assertEqual(config["suffix"], "hosts.example.test")
        self.assertEqual(dns_cutover.controller_state(config)["writer"], "shared")
        self.assertEqual((self.root / "controller.json").stat().st_mode & 0o077, 0)
        self.assertEqual((self.root / "configuration.json").stat().st_mode & 0o077, 0)
        store = SqliteStateStore(self.root / ("dns-ledger-" + proposal["review_id"] + ".sqlite3"))
        with store.transaction():
            self.assertEqual(store.all("record"), [])
            self.assertEqual(store.all("operation"), [])
            self.assertEqual(store.read("meta", "cutover"), {"review_id": proposal["review_id"]})
        with controller_lock(config, modes=("shared",)) as root:
            self.assertEqual(root, self.root)
            selected, source, engine = dns_shared.open_runtime(
                config, root, collector=None)
            self.assertEqual(selected.host_ids, ())
            self.assertEqual(engine.store.path, store.path)
        self.assertEqual(bootstrap.inspect(owner=self.admin.pk,
                                           review_id=proposal["review_id"])["writer"], "shared")
        again = self.commit(proposal)
        self.assertTrue(again["replayed"])
        self.assertEqual(SecurityAudit.objects.filter(action="dns-empty-bootstrap").count(), 1)
        self.assertFalse(Host.objects.exists())

    def test_review_requires_fixed_config_path_and_valid_owner(self):
        with override_settings(HOST_DNS_CONFIGURATION=""):
            with self.assertRaises(bootstrap.EmptyBootstrapError):
                self.review()
        with override_settings(HOST_DNS_CONFIGURATION=str(self.state / "elsewhere")):
            with self.assertRaises(bootstrap.EmptyBootstrapError):
                self.review()
        with self.assertRaises(NetworkError):
            bootstrap.review(owner=-5, credential_id=str(self.credential.pk),
                             credential_revision=2, zone_id="zone-identifier",
                             prefix_label="hosts")
        self.assertFalse(self.root.exists())

    def test_invalid_scopes_and_existing_assignments_fail_closed(self):
        with self.assertRaises(bootstrap.EmptyBootstrapError):
            bootstrap.review(owner=self.admin.pk,
                             credential_id=str(self.credential.pk),
                             credential_revision=2, zone_id="zone-identifier",
                             prefix_label="../evil")
        h = Host.objects.create(label="existing host")
        DnsAssignment.objects.create(host=h, name="old.example.test",
                                     owner_id="existing-legacy")
        with self.assertRaises(bootstrap.EmptyBootstrapError) as e:
            self.review()
        self.assertEqual(e.exception.code, "existing-dns-ownership")
        self.assertFalse((self.root / "controller.json").exists())
        self.assertFalse((self.root / "network-register").exists())

    def test_credential_revisions_and_zone_checks_repeat_at_commit(self):
        candidate = self.review()
        self.credential.revision = 3
        self.credential.save(update_fields=["revision"])
        with self.assertRaises((bootstrap.EmptyBootstrapError, NetworkError)):
            self.commit(candidate)
        self.assertFalse((self.root / "empty-bootstrap.json").exists())
        self.assertFalse((self.root / "controller.json").exists())

    def test_operator_and_hash_fences(self):
        candidate = self.review()
        with self.assertRaises(bootstrap.EmptyBootstrapError):
            bootstrap.commit(owner=self.other.pk, review_id=candidate["review_id"])
        review_file = self.root / ("dns-review-" + candidate["review_id"] + ".json")
        value = json.loads(review_file.read_text())
        value["zone_id"] = "foreign-zone"
        review_file.write_text(json.dumps(value))
        with self.assertRaises(bootstrap.EmptyBootstrapError):
            self.commit(candidate)
        self.assertFalse((self.root / "controller.json").exists())

    def test_expiry_blocks_unprepared_commit_without_mutation(self):
        candidate = self.review()
        with patch.object(bootstrap.time, "time", return_value=time.time() + 700):
            with self.assertRaises(bootstrap.EmptyBootstrapError) as e:
                self.commit(candidate)
        self.assertEqual(e.exception.code, "review-expired")
        self.assertFalse((self.root / "empty-bootstrap.json").exists())

    def test_foreign_controller_state_blocks_review(self):
        self.root.mkdir(mode=0o700)
        (self.root / "unexpected-ledger").write_text("foreign")
        with self.assertRaises(bootstrap.EmptyBootstrapError):
            self.review()
        self.assertEqual((self.root / "unexpected-ledger").read_text(), "foreign")

    def test_recovery_after_preparation_keeps_same_review(self):
        candidate = self.review()
        original = bootstrap._ledger
        def fail(root, key, data, *, allow_create):
            raise OSError("simulated-crash-before-ledger")
        with patch.object(bootstrap, "_ledger", side_effect=fail):
            with self.assertRaises(OSError):
                self.commit(candidate)
        self.assertTrue((self.root / "empty-bootstrap.json").exists())
        self.assertFalse((self.root / "controller.json").exists())
        result = self.commit(candidate)
        self.assertTrue(result["replayed"])
        self.assertEqual(bootstrap.inspect(owner=self.admin.pk,
                                           review_id=candidate["review_id"])["writer"], "shared")

    def test_missing_ledger_after_commit_never_recreated(self):
        candidate = self.review()
        self.commit(candidate)
        ledger = self.root / ("dns-ledger-" + candidate["review_id"] + ".sqlite3")
        ledger.unlink()
        with self.assertRaises((bootstrap.EmptyBootstrapError, NetworkError)):
            self.commit(candidate)
        with self.assertRaises((bootstrap.EmptyBootstrapError, NetworkError)):
            bootstrap.inspect(owner=self.admin.pk, review_id=candidate["review_id"])
        self.assertFalse(ledger.exists())

    def test_controller_lock_refuses_legacy_writer_after_commit(self):
        candidate = self.review()
        result = self.commit(candidate)
        config = json.loads(Path(result["configuration"]).read_text())
        with self.assertRaises(ValueError):
            with controller_lock(config, modes=("legacy",)):
                pass
        with controller_lock(config, modes=("shared",)):
            with self.assertRaises(BlockingIOError):
                self.commit(candidate)

    def test_cli_never_leaks_provider_body_on_failures(self):
        with self.assertRaises(CommandError) as e:
            call_command("bootstrap_empty_host_dns", "commit",
                         owner=self.admin.pk, review_id="not-a-digest")
        self.assertIn("blocked", str(e.exception))
        self.assertNotIn("test-vault-id", str(e.exception))
