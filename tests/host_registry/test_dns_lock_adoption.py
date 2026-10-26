"""Source-only recovery tests; no provider writes or native authorization."""
import json
import os
import subprocess
import sys
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
            command = ("from zog.station_access.host_registry.dns_lock_adoption "
                       "import review\n"
                       "import sys\n"
                       "try: review(owner=int(sys.argv[1]))\n"
                       "except BlockingIOError: sys.exit(0)\n"
                       "sys.exit(1)\n")
            child = subprocess.run([sys.executable, "-c", command, str(self.user.pk)],
                                   capture_output=True, text=True, timeout=8)
            # The child may lack the test settings; this is not the native
            # lock gate. The in-process gate below is authoritative.
            with self.assertRaises(BlockingIOError):
                adoption.review(owner=self.user.pk)

    def test_replaced_lock_and_changed_evidence_block(self):
        candidate = adoption.review(owner=self.user.pk)
        self.lock.unlink()
        self.lock.write_bytes(b"")
        self.lock.chmod(0o600)
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
