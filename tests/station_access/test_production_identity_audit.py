"""Read-only DAC checks on a disposable station-data mount approximation."""
import json
import os
from pathlib import Path
import tempfile
import unittest

from zog.station_access.production_identity_audit import audit_station_state


class ProductionIdentityAuditTests(unittest.TestCase):
    def setUp(self):
        if os.geteuid() == 0 or os.getegid() == 0:
            self.skipTest("Use non-root test user to exercise non-root grant DAC")
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "station-data"
        self.root.mkdir(mode=0o700)
        self.uid, self.gid = os.geteuid(), os.getegid()
        self.write("station-access.sqlite3", b"db")
        self.write("station-access.sqlite3-wal", b"wal")
        self.write("station-access.sqlite3-shm", b"shm")
        self.write("deployment-secrets.json", b"secret")
        self.rpc = self.root / "compiler-rpc"
        self.rpc.mkdir(mode=0o700)
        for name in ("configuration.json", "client-key.pem", "client-cert.pem", "server-ca.pem"):
            self.write("compiler-rpc/" + name, b"fixture")

    def write(self, name, contents):
        path = self.root / name
        path.write_bytes(contents)
        path.chmod(0o600)

    def audit(self, uid=None, gid=None, *, strict=False):
        return audit_station_state(self.root,
                                   expected_uid=self.uid if uid is None else uid,
                                   expected_gid=self.gid if gid is None else gid,
                                   require_compiler_rpc=strict)

    def test_clean_prepared_state_and_sqlite_companions(self):
        report = self.audit()
        self.assertEqual(report["state"], "observed")
        self.assertFalse(report["safe_to_cut_over"])
        for key in ("state", "station-access.sqlite3", "station-access.sqlite3-wal",
                    "station-access.sqlite3-shm", "deployment-secrets.json",
                    "compiler-rpc/client-key.pem"):
            self.assertEqual(report["checks"][key], "verified")
        self.assertNotIn(str(self.root), json.dumps(report))

    def test_wrong_grant_blocks_without_chown(self):
        before = (self.root / "deployment-secrets.json").stat()
        report = self.audit(uid=self.uid + 1000)
        self.assertEqual(report["state"], "blocked")
        self.assertEqual(report["checks"]["deployment-secrets.json"], "owner-mismatch")
        after = (self.root / "deployment-secrets.json").stat()
        self.assertEqual((before.st_uid, before.st_gid), (after.st_uid, after.st_gid))

    def test_unprivate_sqlite_wal_shm_and_client_key_block(self):
        for name in ("station-access.sqlite3", "station-access.sqlite3-wal",
                     "station-access.sqlite3-shm", "deployment-secrets.json",
                     "compiler-rpc/client-key.pem"):
            with self.subTest(name=name):
                target = self.root / name
                target.chmod(0o644)
                self.assertEqual(self.audit()["checks"][name], "unsafe-mode")
                target.chmod(0o600)

    def test_missing_secret_and_symlink_are_rejected(self):
        secret = self.root / "deployment-secrets.json"
        secret.unlink()
        self.assertEqual(self.audit()["checks"]["deployment-secrets.json"], "missing")
        secret.symlink_to(self.root / "station-access.sqlite3")
        self.assertEqual(self.audit()["checks"]["deployment-secrets.json"], "invalid-type")

    def test_missing_optional_journals_are_safe_only_as_dac_observation(self):
        (self.root / "station-access.sqlite3-wal").unlink()
        (self.root / "station-access.sqlite3-shm").unlink()
        report = self.audit()
        self.assertEqual(report["checks"]["station-access.sqlite3-wal"], "absent")
        self.assertFalse(report["safe_to_cut_over"])

    def test_root_or_invalid_uid_cannot_be_claimed(self):
        for uid, gid in ((0, self.gid), (self.uid, 0), (True, self.gid)):
            with self.subTest(uid=uid, gid=gid), self.assertRaises(ValueError):
                audit_station_state(self.root, expected_uid=uid, expected_gid=gid)

    def test_candidate_requires_complete_private_observer_bundle(self):
        self.assertEqual(self.audit(strict=True)["state"], "observed")
        (self.rpc / "server-ca.pem").unlink()
        report = self.audit(strict=True)
        self.assertEqual(report["state"], "blocked")
        self.assertEqual(report["checks"]["compiler-rpc/server-ca.pem"], "missing")
        self.assertFalse(report["safe_to_cut_over"])
        self.assertEqual(self.audit()["state"], "blocked")  # No partial bundle is valid.
        (self.rpc / "server-ca.pem").write_bytes(b"fixture")
        (self.rpc / "server-ca.pem").chmod(0o600)
        (self.rpc / "unexpected-key.pem").write_bytes(b"never expose this")
        report = self.audit(strict=True)
        self.assertEqual(report["checks"]["compiler-rpc-contents"], "unexpected-or-missing")
        self.assertNotIn("unexpected-key.pem", json.dumps(report))

    def test_candidate_does_not_accept_missing_observer_state(self):
        for child in self.rpc.iterdir():
            child.unlink()
        self.rpc.rmdir()
        self.assertEqual(self.audit()["state"], "observed")
        candidate = self.audit(strict=True)
        self.assertEqual(candidate["checks"]["compiler-rpc"], "missing")
        self.assertEqual(candidate["profile"], "candidate")
        self.assertEqual(candidate["state"], "blocked")

    def test_candidate_requires_private_certificates_and_consistent_sidecars(self):
        certificate = self.rpc / "client-cert.pem"
        certificate.chmod(0o644)
        self.assertEqual(self.audit()["state"], "observed")
        self.assertEqual(self.audit(strict=True)["checks"]["compiler-rpc/client-cert.pem"],
                         "unsafe-mode")
        certificate.chmod(0o600)
        (self.root / "station-access.sqlite3-shm").unlink()
        report = self.audit(strict=True)
        self.assertEqual(report["checks"]["sqlite-sidecar-pair"],
                         "incomplete-or-mismatched")
        (self.root / "station-access.sqlite3-wal").unlink()
        self.assertEqual(self.audit(strict=True)["state"], "observed")
        self.write("station-access.sqlite3-journal", b"uncheckpointed")
        self.assertEqual(self.audit(strict=True)["checks"]["sqlite-rollback-journal"],
                         "operator-checkpoint-required")

    def test_candidate_rejects_credential_symlink_without_following_it(self):
        target = self.rpc / "client-key.pem"
        target.unlink()
        target.symlink_to(self.root / "deployment-secrets.json")
        report = self.audit(strict=True)
        self.assertEqual(report["state"], "blocked")
        self.assertEqual(report["checks"]["compiler-rpc/client-key.pem"], "invalid-type")
