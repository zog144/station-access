"""Synthetic offline authority ownership; never touches live keys/STATE."""
import base64
import copy
import hashlib
import os
from pathlib import Path
import stat
import tempfile
import time
import unittest
import uuid

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from zog.station_access import credential_v1_offline_identity as check


def example():
    now = int(time.time())
    operator = Ed25519PrivateKey.generate()
    pin = operator.public_key().public_bytes_raw()
    observation = dict(path="/var/lib/station-access/database.sqlite3",
                       device=187, inode=307826, owner_uid=999, mode=0o644,
                       parent_device=187, parent_inode=307800)
    fields = {
        "schema": check.SCHEMA,
        "station_role": "command-center-host",
        "installation_mode": "externally-managed",
        "state_mode": "existing-station-application-database",
        "command_center_host_id": "6a129eff-b8ac-434e-a9bd-e9c085bd5b0b",
        "command_center_installation_id": "7fd2b309-ea8a-4d83-86f5-b1672e96d8ec",
        "external_host_instance_id": "i-0c676721165320da0",
        "external_host_evidence_sha256": "c"*64,
        "station_registry_id": "host-registry",
        "station_source_commit": "4966c5a7419ba62335eadc6b71ec0fe530270a13",
        "database_path": observation["path"],
        "database_device": observation["device"],
        "database_inode": observation["inode"],
        "database_owner_uid": observation["owner_uid"],
        "database_mode": observation["mode"],
        "database_parent_device": observation["parent_device"],
        "database_parent_inode": observation["parent_inode"],
        "enrolled_consumer_host_id": "305a221a-ef73-42a8-af21-a0b28bca5201",
        "enrolled_consumer_installation_id": "fdf20ffe-2353-40a8-a198-508e103f4348",
        "enrolled_consumer_state_volume_id": "8c7affc9-8be7-4959-9040-d144b5b4dc98",
        "certificate_signer_pin_sha256": "1ecf7d17bd8abc00ca50bde297f427b0fa28f2f6894b0a0cb71ae8d1237425cb",
        "review_revision": 1,
        "issued_at": now - 1,
        "expires_at": now + 900,
    }
    return operator, pin, observation, fields, now


def signed(operator, fields):
    doc = dict(fields)
    doc["signature_ed25519"] = base64.b64encode(operator.sign(
        check.DOMAIN + check.canonical(fields))).decode("ascii")
    return check.canonical(doc)


class OfflineCommandCenterTests(unittest.TestCase):
    def verify(self, raw, pin, obs, now):
        return check.verify(
            raw, pin, obs,
            expected_operator_sha256=hashlib.sha256(pin).hexdigest(),
            expected_external_instance_id="i-0c676721165320da0",
            expected_source_commit="4966c5a7419ba62335eadc6b71ec0fe530270a13",
            now=now)

    def test_independently_signed_external_station_is_only_review_evidence(self):
        key, pin, observed, fields, now = example()
        result = self.verify(signed(key, fields), pin, observed, now)
        self.assertEqual(result["disposition"],
                         "reviewed-source-evidence-not-installation-authority")
        self.assertFalse(result["canonical_host_install_state_verified"])
        self.assertFalse(result["authorized_for_authority_installation"])
        self.assertFalse(result["authorized_for_credential_delivery"])
        self.assertEqual(result["command_center_installation_id"],
                         fields["command_center_installation_id"])
        self.assertNotEqual(fields["command_center_installation_id"],
                            fields["enrolled_consumer_installation_id"])

    def test_mismatched_or_candidate_approved_key_rejected(self):
        key, pin, observed, fields, now = example()
        raw = signed(key, fields)
        with self.assertRaises(check.OfflineIdentityDenied):
            check.verify(raw, pin, observed,
                         expected_operator_sha256="f"*64,
                         expected_external_instance_id=fields["external_host_instance_id"],
                         expected_source_commit=fields["station_source_commit"], now=now)
        with self.assertRaises(check.OfflineIdentityDenied):
            self.verify(raw, Ed25519PrivateKey.generate().public_key().public_bytes_raw(),
                        observed, now)
        changed = dict(fields, database_inode=1)
        with self.assertRaises(check.OfflineIdentityDenied):
            self.verify(signed(key, changed), pin, observed, now)

    def test_operator_key_is_not_the_certificate_signer_and_db_is_not_writable(self):
        key, pin, observed, fields, now = example()
        for patch in (
            {"certificate_signer_pin_sha256": hashlib.sha256(pin).hexdigest()},
            {"database_mode": 0o666},
        ):
            with self.subTest(patch=patch), self.assertRaises(
                    check.OfflineIdentityDenied):
                modified = dict(fields, **patch)
                self.verify(signed(key, modified), pin,
                            dict(observed, mode=modified["database_mode"]), now)

    def test_cannot_relabel_enrolled_host_as_command_center(self):
        key, pin, observed, fields, now = example()
        fields["command_center_host_id"] = fields["enrolled_consumer_host_id"]
        with self.assertRaises(check.OfflineIdentityDenied):
            self.verify(signed(key, fields), pin, observed, now)
        fields["command_center_host_id"] = "6a129eff-b8ac-434e-a9bd-e9c085bd5b0b"
        fields["command_center_installation_id"] = fields["enrolled_consumer_installation_id"]
        with self.assertRaises(check.OfflineIdentityDenied):
            self.verify(signed(key, fields), pin, observed, now)

    def test_fails_closed_on_stale_expired_identity_and_external_evidence(self):
        key, pin, observed, fields, now = example()
        for patch in [
            {"external_host_instance_id": "i-00000000000000000"},
            {"station_source_commit": "0"*40},
            {"station_role": "enrolled-host"},
            {"installation_mode": "non-resident"},
            {"state_mode": "canonical-host-install-state"},
            {"issued_at": now + 30},
            {"expires_at": now},
            {"expires_at": now + 40*86400},
            {"review_revision": 0},
            {"database_path": "/state/database.sqlite3"},
        ]:
            with self.subTest(patch=patch), self.assertRaises(
                    check.OfflineIdentityDenied):
                self.verify(signed(key, dict(fields, **patch)), pin, observed, now)
        with self.assertRaises(check.OfflineIdentityDenied):
            check.verify(signed(key, fields), pin, observed,
                         expected_operator_sha256=hashlib.sha256(pin).hexdigest(),
                         expected_external_instance_id=fields["external_host_instance_id"],
                         expected_source_commit="0"*40, now=now)

    def test_canonical_signature_and_frozen_inode_identity(self):
        key, pin, observed, fields, now = example()
        raw = signed(key, fields)
        for snapshot in [dict(observed, inode=observed["inode"]+1),
                         dict(observed, owner_uid=0),
                         dict(observed, parent_inode=observed["parent_inode"]+1),
                         dict(observed, mode=0o600)]:
            with self.subTest(snapshot=snapshot), self.assertRaises(
                    check.OfflineIdentityDenied):
                self.verify(raw, pin, snapshot, now)
        with self.assertRaises(check.OfflineIdentityDenied):
            self.verify(raw+b"\n", pin, observed, now)
        duplicate = raw.replace(b'"schema":', b'"schema":"duplicate","schema":', 1)
        with self.assertRaises(check.OfflineIdentityDenied):
            self.verify(duplicate, pin, observed, now)
        with self.assertRaises(check.OfflineIdentityDenied):
            self.verify(raw.replace(b"station-registry", b"station-registry"), pin,
                        dict(observed, device=0), now)

    def test_observation_refuses_symlink_hardlink_or_replaced_path(self):
        # A test under a repository-local directory avoids /tmp's world-writable
        # ancestor; observation never reads the DB bytes or modifies real STATE.
        with tempfile.TemporaryDirectory(dir=os.getcwd()) as directory:
            folder = Path(directory)
            real = folder / "database.sqlite3"
            real.write_bytes(b"fixture-not-a-database")
            report = check._observe_database(str(real))
            self.assertEqual(report["inode"], real.stat().st_ino)
            duplicate = folder / "other"
            os.link(real, duplicate)
            with self.assertRaises(check.OfflineIdentityDenied):
                check._observe_database(str(real))
            duplicate.unlink()
            alias = folder / "alias"
            alias.symlink_to(real)
            with self.assertRaises(check.OfflineIdentityDenied):
                check._observe_database(str(alias))
            observed = check._observe_database(str(real))
            replacement = folder / "replacement"
            replacement.write_bytes(b"replacement")
            os.replace(replacement, real)
            self.assertNotEqual(check._observe_database(str(real))["inode"],
                                observed["inode"])


if __name__ == "__main__":
    unittest.main()
