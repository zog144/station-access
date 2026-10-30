"""Offline signer proposal is inert and never a source of operator trust."""
import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

from zog.station_access import credential_v1_offline_signer as signer


class OfflineSignerTests(unittest.TestCase):
    def test_proposed_private_key_and_public_fingerprint_have_no_approval(self):
        pem, pub, encoded = signer._candidate(Ed25519PrivateKey.generate(), "a"*40)
        key = serialization.load_pem_private_key(pem, password=None)
        actual = key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.assertEqual(pub, actual)
        receipt = json.loads(encoded)
        self.assertEqual(encoded, signer.canonical(receipt))
        self.assertEqual(receipt["authority_status"], "unapproved-offline-candidate")
        self.assertEqual(receipt["public_pin_sha256"], hashlib.sha256(pub).hexdigest())
        self.assertFalse(receipt["operator_approval_present"])
        self.assertFalse(receipt["root_grant_present"])
        self.assertFalse(receipt["credential_delivery_authorized"])
        self.assertFalse(receipt["installation_authorized"])
        self.assertNotIn(pem, encoded)
        with self.assertRaises(signer.OfflineCandidateDenied):
            signer._candidate(Ed25519PrivateKey.generate(), "old-version")

    def test_no_overwrite_and_symlink_negative(self):
        with tempfile.TemporaryDirectory() as root:
            fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                signer._create(fd, "new", b"synthetic", 0o600)
                self.assertEqual(stat.S_IMODE(os.stat("new", dir_fd=fd).st_mode), 0o600)
                with self.assertRaises(FileExistsError):
                    signer._create(fd, "new", b"other", 0o600)
                self.assertEqual(Path(root, "new").read_bytes(), b"synthetic")
                os.symlink(Path(root, "new"), Path(root, "alias"))
                with self.assertRaises(FileExistsError):
                    signer._create(fd, "alias", b"other", 0o600)
            finally:
                os.close(fd)

    def test_root_only_and_nonoffline_paths_rejected(self):
        with patch.object(signer.os, "geteuid", return_value=1000):
            with self.assertRaises(signer.OfflineCandidateDenied):
                signer._offline_parent("/opt/station-trust/credential-v1-offline")
        with self.assertRaises(signer.OfflineCandidateDenied):
            signer._offline_parent("/etc/zog/certify-policy")
        with self.assertRaises(signer.OfflineCandidateDenied):
            signer._offline_parent("/opt/station-trust/live")

    def test_unknown_or_interrupted_preparation_never_auto_replaces_key(self):
        # An existing candidate directory is an intentional fail-closed hold,
        # even if it contains no file. No file is deleted or truncated.
        with tempfile.TemporaryDirectory() as root:
            folder = Path(root) / signer.NAME
            folder.mkdir()
            with patch.object(signer, "_offline_parent",
                              side_effect=lambda _: os.open(root, os.O_RDONLY | os.O_DIRECTORY)):
                with self.assertRaises(signer.OfflineCandidateDenied):
                    signer.prepare("/opt/station-trust/example-offline", "a"*40)
            self.assertTrue(folder.is_dir())
            self.assertEqual(list(folder.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
