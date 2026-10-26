"""Source-only gate for a fresh protected empty shared DNS owner.

The provider fixtures perform no DNS writes; native owner/permissions and
installed-byte acceptance remain separate.
"""
import json
import os
import subprocess
import sys
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
        from zog.network_register.evidence import (
            AuthorityEvidence, AuthoritativeAnswer,
        )
        class VerifiedCollector:
            def authority(self, connection, binding):
                now = time.time()
                return AuthorityEvidence(
                    connection.owner_id, connection.id, connection.revision,
                    connection.credential_ref, binding.id, binding.revision,
                    binding.zone_id, binding.zone_name, binding.prefix,
                    binding.nameservers, now,
                    tuple(AuthoritativeAnswer(ns, binding.zone_name, True, now, True)
                          for ns in binding.nameservers),
                )
        with controller_lock(config, modes=("shared",)) as root:
            self.assertEqual(root, self.root)
            selected, source, engine = dns_shared.open_runtime(
                config, root, collector=VerifiedCollector())
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

    def test_new_dns_ownership_after_review_blocks_before_publication(self):
        proposal = self.review()
        host = Host.objects.create(label="concurrent host")
        DnsAssignment.objects.create(host=host, name="new.example.test",
                                     owner_id="other-authority")
        with self.assertRaises(bootstrap.EmptyBootstrapError) as result:
            self.commit(proposal)
        self.assertEqual(result.exception.code, "existing-dns-ownership")
        self.assertFalse((self.root / "controller.json").exists())
        self.assertFalse((self.root / "configuration.json").exists())

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

    def test_uncertain_ledger_creation_blocks_without_reinitializing(self):
        candidate = self.review()
        def fail(root, key, data, *, allow_create):
            raise OSError("simulated-crash-before-ledger")
        with patch.object(bootstrap, "_ledger", side_effect=fail):
            with self.assertRaises(OSError):
                self.commit(candidate)
        self.assertTrue((self.root / "empty-bootstrap.json").exists())
        self.assertFalse((self.root / "controller.json").exists())
        with self.assertRaises(bootstrap.EmptyBootstrapError) as error:
            self.commit(candidate)
        self.assertEqual(error.exception.code, "missing-controller-ledger")
        self.assertFalse((self.root / ("dns-ledger-" + candidate["review_id"] + ".sqlite3")).exists())

    def test_resume_after_ledger_commit_before_active_marker(self):
        candidate = self.review()
        original = bootstrap.save
        def fail_after_ledger(path, value):
            original(path, value)
            if path.name == "empty-bootstrap.json" and value.get("stage") == "ledger-ready":
                raise OSError("simulated-crash-after-ledger")
        with patch.object(bootstrap, "save", side_effect=fail_after_ledger):
            with self.assertRaises(OSError):
                self.commit(candidate)
        self.assertFalse((self.root / "controller.json").exists())
        self.assertTrue((self.root / ("dns-ledger-" + candidate["review_id"] + ".sqlite3")).exists())
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

    def _ledger_path(self, candidate):
        return self.root / ("dns-ledger-" + candidate["review_id"] + ".sqlite3")

    def _ready_ledger_pending_activation(self, candidate):
        original = bootstrap._exclusive_json
        def fail_config(path, value):
            if path.name == "configuration.json":
                raise OSError("simulated-crash-before-config")
            return original(path, value)
        with patch.object(bootstrap, "_exclusive_json", side_effect=fail_config):
            with self.assertRaises(OSError):
                self.commit(candidate)
        self.assertTrue(self._ledger_path(candidate).exists())
        self.assertFalse((self.root / "controller.json").exists())

    def test_stable_lock_fails_closed_after_unlink_replacement(self):
        proposal = self.review()
        self.commit(proposal)
        config = json.loads((self.root / "configuration.json").read_text())
        path = self.root / "controller.lock"
        original_inode = path.stat().st_ino
        with self.assertRaises(NetworkError):
            with controller_lock(config, modes=("shared",)):
                path.unlink()
                path.write_text("replacement")
                path.chmod(0o600)
                self.assertNotEqual(original_inode, path.stat().st_ino)
                # A new worker must refuse the replacement pathname,
                # even while the original inode remains locked.
                with self.assertRaises(NetworkError):
                    with controller_lock(config, modes=("shared",)):
                        pass
        with self.assertRaises(NetworkError):
            self.commit(proposal)
        self.assertFalse((self.root / "controller.lock").is_symlink())

    def test_lost_symlinked_and_unsafe_lock_refuse_new_writer(self):
        proposal = self.review()
        self.commit(proposal)
        config = json.loads((self.root / "configuration.json").read_text())
        path = self.root / "controller.lock"
        path.chmod(0o644)
        with self.assertRaises(NetworkError):
            with controller_lock(config, modes=("shared",)):
                pass
        path.chmod(0o600)
        path.unlink()
        with self.assertRaises(NetworkError):
            with controller_lock(config, modes=("shared",)):
                pass
        with self.assertRaises(NetworkError):
            self.commit(proposal)
        other = self.root / "other.lock"
        other.write_text("foreign")
        other.chmod(0o600)
        path.symlink_to(other)
        with self.assertRaises((NetworkError, OSError)):
            with controller_lock(config, modes=("shared",)):
                pass
        self.assertTrue(path.is_symlink())

    def test_second_process_cannot_enter_live_shared_writer(self):
        proposal = self.review()
        self.commit(proposal)
        command = (
            "import sys\n"
            "from zog.station_access.host_registry.dns_controller_lock import writer_lock\n"
            "from pathlib import Path\n"
            "root = Path(sys.argv[1])\n"
            "try:\n"
            "    with writer_lock(root): sys.exit(13)\n"
            "except BlockingIOError: sys.exit(0)\n"
        )
        with bootstrap._guard():
            child = subprocess.run(
                [sys.executable, "-c", command, str(self.root)],
                capture_output=True, text=True, timeout=8)
            self.assertEqual(child.returncode, 0, child.stderr)
        # A restarted fresh process can reopen exactly the same lock.
        child = subprocess.run(
            [sys.executable, "-c", command.replace("sys.exit(13)", "sys.exit(0)"),
             str(self.root)], capture_output=True, text=True, timeout=8)
        self.assertEqual(child.returncode, 0, child.stderr)

    def test_empty_ledger_rejects_every_foreign_kind_and_duplicate_owner(self):
        proposal = self.review()
        self._ready_ledger_pending_activation(proposal)
        path = self._ledger_path(proposal)
        store = SqliteStateStore(path)
        unexpected = [
            ("connection", "extra"), ("binding", "extra"),
            ("meta", "foreign"), ("record", "extra"), ("operation", "extra"),
            ("reservation", "extra"), ("allocation", "extra"),
            ("adoption", "extra"), ("membership-operation", "extra"),
            ("name-receipt", "extra"), ("membership", "extra"),
            ("unreviewed-history", "extra"),
        ]
        for kind, key in unexpected:
            with self.subTest(kind=kind):
                with store.transaction():
                    store.write(kind, key, {"unapproved": True})
                with self.assertRaises((bootstrap.EmptyBootstrapError, NetworkError)):
                    self.commit(proposal)
                self.assertFalse((self.root / "controller.json").exists())
                with store.transaction():
                    store.delete(kind, key)
        self.assertEqual(self.commit(proposal)["writer"], "shared")

    def test_replaced_ledger_inode_and_symlink_block_inspect_and_runtime(self):
        proposal = self.review()
        self.commit(proposal)
        config = json.loads((self.root / "configuration.json").read_text())
        ledger = self._ledger_path(proposal)
        original = self.root / "saved-original-ledger"
        ledger.rename(original)
        ledger.write_bytes(original.read_bytes())
        ledger.chmod(0o600)
        self.assertNotEqual(ledger.stat().st_ino, original.stat().st_ino)
        with self.assertRaises((bootstrap.EmptyBootstrapError, NetworkError)):
            bootstrap.inspect(owner=self.admin.pk, review_id=proposal["review_id"])
        with controller_lock(config, modes=("shared",)) as root:
            with self.assertRaises((bootstrap.EmptyBootstrapError, NetworkError)):
                dns_shared.open_runtime(config, root)
        ledger.unlink()
        ledger.symlink_to(original)
        with self.assertRaises((bootstrap.EmptyBootstrapError, NetworkError)):
            bootstrap.inspect(owner=self.admin.pk, review_id=proposal["review_id"])
        with self.assertRaises((bootstrap.EmptyBootstrapError, NetworkError)):
            self.commit(proposal)

    def test_active_runtime_rejects_foreign_static_ownership_but_keeps_history(self):
        proposal = self.review()
        self.commit(proposal)
        config = json.loads((self.root / "configuration.json").read_text())
        store = SqliteStateStore(self._ledger_path(proposal))
        # Membership history is allowed after activation, never additional
        # foreign connection/binding ownership.
        with store.transaction():
            store.write("meta", "membership-enabled", {"enabled": True})
            store.write("meta", "membership",
                        {"revision": 1, "host_ids": [], "pending": None})
        from zog.network_register.evidence import (
            AuthorityEvidence, AuthoritativeAnswer,
        )
        class Collector:
            def authority(self, connection, binding):
                now = time.time()
                return AuthorityEvidence(
                    connection.owner_id, connection.id, connection.revision,
                    connection.credential_ref, binding.id, binding.revision,
                    binding.zone_id, binding.zone_name, binding.prefix,
                    binding.nameservers, now,
                    tuple(AuthoritativeAnswer(ns, binding.zone_name, True, now, True)
                          for ns in binding.nameservers),
                )
        with controller_lock(config, modes=("shared",)) as root:
            selected, _, _ = dns_shared.open_runtime(config, root, collector=Collector())
            self.assertEqual(selected.host_ids, ())
        for kind in ("connection", "binding"):
            with self.subTest(kind=kind):
                with store.transaction():
                    store.write(kind, "foreign-extra", {"foreign": True})
                with controller_lock(config, modes=("shared",)) as root:
                    with self.assertRaises((bootstrap.EmptyBootstrapError, NetworkError)):
                        dns_shared.open_runtime(config, root, collector=Collector())
                with store.transaction():
                    store.delete(kind, "foreign-extra")

    def test_crash_before_lock_identity_file_prevents_automatic_recreation(self):
        from zog.station_access.host_registry import dns_controller_lock as lock
        original_save = lock.save
        def crash_before_authority(path, payload):
            if path.name == "controller-lock-identity.json":
                raise OSError("crash-after-lock-inode-before-identity")
            return original_save(path, payload)
        with patch.object(lock, "save", side_effect=crash_before_authority):
            with self.assertRaises(OSError):
                self.review()
        lock_path = self.root / "controller.lock"
        self.assertTrue(lock_path.exists())
        inode = lock_path.stat().st_ino
        with self.assertRaises(NetworkError):
            self.review()
        self.assertEqual(lock_path.stat().st_ino, inode)
        self.assertFalse((self.root / "controller.json").exists())

    def test_crash_at_configuration_and_after_active_publication(self):
        proposal = self.review()
        original = bootstrap._exclusive_json
        def fail_after_config(path, value):
            result = original(path, value)
            if path.name == "configuration.json":
                raise OSError("crash-after-config")
            return result
        with patch.object(bootstrap, "_exclusive_json", side_effect=fail_after_config):
            with self.assertRaises(OSError):
                self.commit(proposal)
        saved_inode = self._ledger_path(proposal).stat().st_ino
        self.assertEqual(self.commit(proposal)["writer"], "shared")
        self.assertEqual(self._ledger_path(proposal).stat().st_ino, saved_inode)
        self.assertEqual(bootstrap.inspect(owner=self.admin.pk,
                                           review_id=proposal["review_id"])["writer"], "shared")

    def test_partial_ledger_inode_replacement_and_symlink_block_activation(self):
        proposal = self.review()
        self._ready_ledger_pending_activation(proposal)
        path = self._ledger_path(proposal)
        original = self.root / "original-prepare-ledger"
        path.rename(original)
        path.write_bytes(original.read_bytes())
        path.chmod(0o600)
        with self.assertRaises((bootstrap.EmptyBootstrapError, NetworkError)):
            self.commit(proposal)
        self.assertFalse((self.root / "controller.json").exists())
        path.unlink()
        path.symlink_to(original)
        with self.assertRaises((bootstrap.EmptyBootstrapError, NetworkError)):
            self.commit(proposal)
        self.assertFalse((self.root / "controller.json").exists())

    def test_crash_after_controller_publication_reopens_same_review(self):
        proposal = self.review()
        original = bootstrap._exclusive_json
        def fail_after_controller(path, value):
            result = original(path, value)
            if path.name == "controller.json":
                raise OSError("crash-after-controller-published")
            return result
        with patch.object(bootstrap, "_exclusive_json", side_effect=fail_after_controller):
            with self.assertRaises(OSError):
                self.commit(proposal)
        inode = self._ledger_path(proposal).stat().st_ino
        result = self.commit(proposal)
        self.assertTrue(result["replayed"])
        self.assertEqual(inode, self._ledger_path(proposal).stat().st_ino)
        self.assertEqual(SecurityAudit.objects.filter(action="dns-empty-bootstrap").count(), 1)
        self.assertEqual(bootstrap.inspect(
            owner=self.admin.pk, review_id=proposal["review_id"])["writer"], "shared")

    def test_cli_never_leaks_provider_body_on_failures(self):
        with self.assertRaises(CommandError) as e:
            call_command("bootstrap_empty_host_dns", "commit",
                         owner=self.admin.pk, review_id="not-a-digest")
        self.assertIn("blocked", str(e.exception))
        self.assertNotIn("test-vault-id", str(e.exception))
