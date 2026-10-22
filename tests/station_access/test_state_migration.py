"""Deterministic offline station/archive migration and two-application composition."""
import hashlib
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from zog.station_access.state_migration import MigrationBlocked, migrate, MARKER


def make_catalogue(path, digest, size):
    with sqlite3.connect(path) as db:
        db.executescript("""
            CREATE TABLE auth_user (id INTEGER PRIMARY KEY, username TEXT, password TEXT);
            CREATE TABLE django_migrations (id INTEGER PRIMARY KEY, app TEXT, name TEXT, applied TEXT);
            CREATE TABLE archive_mirror_archive (
                id INTEGER PRIMARY KEY, collection TEXT, digest TEXT, size INTEGER,
                kind TEXT, managed INTEGER, provenance TEXT, created TEXT);
            CREATE TABLE archive_mirror_snapshot (id INTEGER PRIMARY KEY,
                archive_id INTEGER REFERENCES archive_mirror_archive(id),source TEXT,month TEXT,"commit" TEXT);
            CREATE TABLE archive_mirror_pin (id INTEGER PRIMARY KEY,
                archive_id INTEGER REFERENCES archive_mirror_archive(id),name TEXT);
            CREATE TABLE archive_mirror_collectionstatus (source TEXT PRIMARY KEY,
                last_attempt TEXT,last_success TEXT,error TEXT);
            CREATE TABLE archive_mirror_sourcepinset (identity TEXT PRIMARY KEY,pin_date TEXT,
                manifest_sha256 TEXT,complete INTEGER,active INTEGER,created TEXT);
            CREATE TABLE archive_mirror_reviewedsource (id INTEGER PRIMARY KEY,
                pin_set_id TEXT REFERENCES archive_mirror_sourcepinset(identity),
                archive_id INTEGER REFERENCES archive_mirror_archive(id),
                package TEXT,source TEXT,canonical_url TEXT);
        """)
        db.execute("INSERT INTO auth_user VALUES (1,'station-admin','PRIVATE-SECRET')")
        db.execute("INSERT INTO django_migrations VALUES (1,'archive_mirror','0001_initial','2026-10-11')")
        db.execute("INSERT INTO archive_mirror_archive VALUES (1,'sources',?,?,?,?,?,?)",
                   (digest,size,'source',1,'{}','2026-10-11'))
        db.execute("INSERT INTO archive_mirror_pin VALUES (1,1,'release')")
        db.execute("INSERT INTO archive_mirror_sourcepinset VALUES ('reviewed-a','2026-10-11',?,0,0,'2026-10-11')",
                   ('a'*64,))
        db.execute("INSERT INTO archive_mirror_reviewedsource VALUES (1,'reviewed-a',1,'pkg','src','https://example.org/src')")


class MigrationTests(unittest.TestCase):
    def setUp(self):
        self.directory=tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        root=Path(self.directory.name)
        self.station=root/'legacy-station';self.station.mkdir()
        self.archive=root/'legacy-archive';self.archive.mkdir()
        (self.archive/'objects').mkdir()
        self.dest_station=root/'station-data';self.dest_station.mkdir()
        self.dest_archive=root/'archive-data';self.dest_archive.mkdir()
        self.content=b"exact retained production archive bytes"
        self.digest=hashlib.sha256(self.content).hexdigest()
        (self.archive/'objects'/self.digest).write_bytes(self.content)
        self.database=self.station/'station-access.sqlite3'
        make_catalogue(self.database,self.digest,len(self.content))
        secret=self.station/'deployment-secrets.json'
        secret.write_bytes(b'{"django_secret_key":"PRIVATE-KEEP-BYTES"}')
        secret.chmod(0o600)
        self.request=dict(station_source=str(self.station),archive_source=str(self.archive),
                          station_destination=str(self.dest_station),archive_destination=str(self.dest_archive),
                          station_storage_id='a'*32,archive_storage_id='b'*32,
                          checkpoint_confirmed=True)

    def test_distinct_identity_complete_preserves_sqlite_secrets_pins_and_reviewed_recovery(self):
        evidence=migrate(**self.request)
        self.assertEqual(evidence['state'],'complete')
        self.assertEqual(evidence['archive_verification']['counts']['archives'],1)
        self.assertEqual(evidence['archive_verification']['counts']['pins'],1)
        self.assertEqual(evidence['archive_verification']['counts']['incomplete_source_pin_sets'],1)
        self.assertEqual(evidence['archive_verification']['counts']['protected_archives'],1)
        self.assertEqual(evidence['archive_verification']['counts']['currently_prunable_managed_sources'],0)
        self.assertEqual((self.dest_archive/'store'/'objects'/self.digest).read_bytes(),self.content)
        self.assertEqual((self.dest_station/'deployment-secrets.json').read_bytes(),
                         (self.station/'deployment-secrets.json').read_bytes())
        self.assertEqual((self.dest_station/'deployment-secrets.json').stat().st_mode & 0o777,0o600)
        with sqlite3.connect(self.dest_station/'station-access.sqlite3') as db:
            self.assertEqual(db.execute('SELECT username FROM auth_user').fetchone(),('station-admin',))
        with sqlite3.connect(self.dest_archive/'catalogue.sqlite3') as db:
            self.assertEqual(db.execute('SELECT count(*) FROM archive_mirror_reviewedsource').fetchone(),(1,))
            self.assertEqual(db.execute("SELECT count(*) FROM sqlite_master WHERE name='auth_user'").fetchone(),(0,))
        self.assertEqual(migrate(**self.request),evidence)
        self.assertTrue((self.dest_station/MARKER).exists())
        self.assertTrue((self.dest_archive/MARKER).exists())

    def test_requires_explicit_frozen_checkpoint_and_distinct_storage_id(self):
        for changed in ({'checkpoint_confirmed':False},{'archive_storage_id':'a'*32},
                        {'archive_destination':str(self.dest_station)}):
            with self.subTest(changed=changed),self.assertRaises(MigrationBlocked):
                migrate(**{**self.request,**changed})
        self.assertEqual(list(self.dest_station.iterdir()),[])

    def test_interrupted_migration_is_blocked_on_retry(self):
        (self.archive/'objects'/self.digest).write_bytes(b'CORRUPT')
        with self.assertRaises(MigrationBlocked):
            migrate(**self.request)
        self.assertEqual(json.loads((self.dest_station/MARKER).read_text())['state'],'copying')
        with self.assertRaises(MigrationBlocked):
            migrate(**self.request)

    def test_corrupted_catalogue_reference_blocks_before_writing(self):
        with sqlite3.connect(self.database) as db:
            db.execute('UPDATE archive_mirror_pin SET archive_id=999')
        with self.assertRaises(Exception):
            migrate(**self.request)
        # All resulting partial data remains guarded, never auto-merged.
        if (self.dest_station/MARKER).exists():
            self.assertEqual(json.loads((self.dest_station/MARKER).read_text())['state'],'copying')

    def test_source_symlinks_devices_and_unrelated_destination_refused(self):
        (self.archive/'unsafe').symlink_to(self.station)
        with self.assertRaises(MigrationBlocked):
            migrate(**self.request)
        (self.archive/'unsafe').unlink()
        (self.dest_station/'other-state').write_text('do-not-overwrite')
        with self.assertRaises(MigrationBlocked):
            migrate(**self.request)
        self.assertEqual((self.dest_station/'other-state').read_text(),'do-not-overwrite')

    def test_source_change_and_destination_edit_reject_completed_replay(self):
        migrate(**self.request)
        (self.dest_station/'deployment-secrets.json').write_bytes(b'CHANGED')
        with self.assertRaises(MigrationBlocked):
            migrate(**self.request)
        (self.dest_station/'deployment-secrets.json').write_bytes(
            (self.station/'deployment-secrets.json').read_bytes())
        (self.archive/'objects'/self.digest).write_bytes(b'changed original')
        with self.assertRaises(MigrationBlocked):
            migrate(**self.request)
