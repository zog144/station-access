"""Source-only recovery tests; no provider writes or native authorization."""
import json
import os
import time
from unittest.mock import patch
import tempfile
from pathlib import Path

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from zog.network_register.contracts import NetworkError
from zog.station_access.host_registry import dns_lock_adoption as adoption
from zog.station_access.host_registry.dns_controller_lock import writer_lock


class LockAdoptionTests(TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.state = Path(self.temp.name)
        self.root = self.state / "dns-controller"
        self.root.mkdir(mode=0o700)
        self.lock = self.root / "controller.lock"
        self.lock.touch(mode=0o600)
        self.user = get_user_model().objects.create_superuser(
            username="adoption-reviewer", email="", password="test")
        override = override_settings(
            STATE_DIRECTORY=self.state,
            HOST_DNS_CONFIGURATION=str(self.root / "configuration.json"))
        override.enable()
        self.addCleanup(override.disable)

    def test_existing_lock_is_preserved_and_reopen_is_supported(self):
        before = self.lock.stat()
        candidate = adoption.review(owner=self.user.pk)
        result = adoption.commit(owner=self.user.pk, review_id=candidate["review_id"])
        self.assertTrue(result["adopted"])
        self.assertEqual(before.st_ino, self.lock.stat().st_ino)
        self.assertEqual(before.st_dev, self.lock.stat().st_dev)
        self.assertEqual(adoption.inspect(owner=self.user.pk,
                         review_id=candidate["review_id"])["provider_writes"], 0)
        with writer_lock(self.root):
            pass
        replay = adoption.commit(owner=self.user.pk, review_id=candidate["review_id"])
        self.assertTrue(replay["replayed"])

    def test_concurrent_writer_refuses_review(self):
        with writer_lock_unbound(self.root):
            with self.assertRaises(BlockingIOError):
                adoption.review(owner=self.user.pk)

    def test_replaced_lock_and_changed_evidence_block(self):
        candidate = adoption.review(owner=self.user.pk)
        original_inode = self.lock.stat().st_ino
        replacement = self.root / "new-inode"
        replacement.write_bytes(b"")
        replacement.chmod(0o600)
        self.assertNotEqual(original_inode, replacement.stat().st_ino)
        os.replace(replacement, self.lock)
        with self.assertRaises(adoption.LockAdoptionError):
            adoption.commit(owner=self.user.pk, review_id=candidate["review_id"])
        self.assertFalse((self.root / "controller-lock-identity.json").exists())

    def test_unexpected_state_and_symlink_block(self):
        (self.root / "dns-ledger-foreign.sqlite3").write_bytes(b"historical")
        with self.assertRaises(adoption.LockAdoptionError):
            adoption.review(owner=self.user.pk)
        (self.root / "dns-ledger-foreign.sqlite3").unlink()
        self.lock.unlink()
        self.lock.symlink_to(self.root / "foreign")
        with self.assertRaises(adoption.LockAdoptionError):
            adoption.review(owner=self.user.pk)

    def test_expiry_refuses_first_commit_without_a_marker(self):
        candidate = adoption.review(owner=self.user.pk)
        with patch.object(adoption.time, "time", return_value=time.time() + 800):
            with self.assertRaises(adoption.LockAdoptionError) as caught:
                adoption.commit(owner=self.user.pk, review_id=candidate["review_id"])
        self.assertEqual(caught.exception.code, "adoption-review-expired")
        self.assertFalse((self.root / "controller-lock-identity.json").exists())

    def test_crash_after_durable_marker_preserves_same_lock_and_replays(self):
        candidate = adoption.review(owner=self.user.pk)
        original = self.lock.stat()
        with patch.object(adoption, "_fsync_dir",
                          side_effect=OSError("simulated failure after marker write")):
            with self.assertRaises(OSError):
                adoption.commit(owner=self.user.pk, review_id=candidate["review_id"])
        self.assertEqual(original.st_ino, self.lock.stat().st_ino)
        self.assertTrue((self.root / "controller-lock-identity.json").exists())
        with writer_lock(self.root):
            pass
        result = adoption.commit(owner=self.user.pk, review_id=candidate["review_id"])
        self.assertTrue(result["replayed"])
        self.assertEqual(adoption.inspect(owner=self.user.pk,
                         review_id=candidate["review_id"])["adopted"], True)

    def test_foreign_marker_binding_and_prior_review_evidence_refuse_repair(self):
        prior = adoption.review(owner=self.user.pk)
        candidate = adoption.review(owner=self.user.pk)
        receipt = self.root / ("dns-review-" + prior["review_id"] + ".json")
        receipt.write_text('{"tampered":true}')
        with self.assertRaises(adoption.LockAdoptionError):
            adoption.commit(owner=self.user.pk, review_id=candidate["review_id"])
        self.assertFalse((self.root / "controller-lock-identity.json").exists())

    def test_adopted_marker_must_be_complete_and_single_linked(self):
        candidate = adoption.review(owner=self.user.pk)
        adoption.commit(owner=self.user.pk, review_id=candidate["review_id"])
        marker = self.root / "controller-lock-identity.json"
        alias = self.root / "marker-second-link"
        os.link(marker, alias)
        with self.assertRaises(NetworkError):
            with writer_lock(self.root):
                pass
        alias.unlink()
        marker.write_bytes(marker.read_bytes() + b" " * 4096)
        with self.assertRaises(NetworkError):
            with writer_lock(self.root):
                pass

    def test_adopted_receipt_must_remain_exact_and_protected(self):
        candidate = adoption.review(owner=self.user.pk)
        adoption.commit(owner=self.user.pk, review_id=candidate["review_id"])
        receipt = self.root / ("dns-review-" + candidate["review_id"] + ".json")
        alias = self.root / "receipt-second-link"
        os.link(receipt, alias)
        with self.assertRaises(NetworkError):
            with writer_lock(self.root):
                pass
        alias.unlink()
        receipt.write_bytes(receipt.read_bytes() + b"\x20" * 65536)
        with self.assertRaises(NetworkError):
            with writer_lock(self.root):
                pass

    def test_approval_expiry_and_crash_marker_refuse_overwrite(self):
        candidate = adoption.review(owner=self.user.pk)
        marker = self.root / "controller-lock-identity.json"
        marker.write_text('{"partial":true}')
        marker.chmod(0o600)
        with self.assertRaises(adoption.LockAdoptionError):
            adoption.commit(owner=self.user.pk, review_id=candidate["review_id"])
        self.assertEqual(json.loads(marker.read_text()), {"partial": True})
        with self.assertRaises(NetworkError):
            with writer_lock(self.root):
                pass


def writer_lock_unbound(root):
    return adoption._unbound_lock(root)
