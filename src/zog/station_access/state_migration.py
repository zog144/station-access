"""Explicit, offline migration into two separately prepared storage identities.

The caller supplies frozen *copies* for rehearsal or a quiesced final checkpoint.
This tool never stops processes, mounts host paths or alters active controller state.
Interrupted copies cannot be retried without an explicit operator recovery.
"""
import argparse
import hashlib
import json
import os
import re
import sqlite3
import stat
from pathlib import Path

SCHEMA = "zog-station-state-migration-v1"
MARKER = ".zog-state-migration.json"
STORAGE_ID = re.compile(r"[a-f0-9]{32}\Z")
MAX_ENTRIES = 200000


class MigrationBlocked(ValueError):
    pass


def _sync(directory):
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try: os.fsync(fd)
    finally: os.close(fd)


def _write_marker(root, value):
    path = root / MARKER
    temporary = root / (MARKER + ".new")
    data = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    fd = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data); stream.flush(); os.fsync(stream.fileno())
        os.replace(temporary, path)
        _sync(root)
    finally: temporary.unlink(missing_ok=True)


def _checked_directory(path):
    raw = str(path)
    path = Path(raw)
    if not path.is_absolute() or raw != str(path) or str(path) == "/" or ".." in path.parts:
        raise MigrationBlocked("noncanonical directory")
    current = Path("/")
    for component in path.parts[1:]:
        current = current / component
        info = current.lstat()
        if not stat.S_ISDIR(info.st_mode):
            raise MigrationBlocked("redirected or special directory")
    info = path.stat()
    return path, (info.st_dev, info.st_ino)


def _sha(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def _inventory(root, *, ignore_marker=False):
    items = []
    def recurse(parent, prefix, depth):
        if depth > 32 or len(items) > MAX_ENTRIES:
            raise MigrationBlocked("migration inventory limit")
        for path in sorted(parent.iterdir()):
            if path.name.startswith(".zog-state-migration"):
                if ignore_marker and path.name == MARKER:
                    continue
                raise MigrationBlocked("unexpected migration marker in source")
            info = path.lstat()
            relative = prefix + path.name
            mode = stat.S_IMODE(info.st_mode)
            if mode & 0o002:
                raise MigrationBlocked("unsafe world-writable source")
            if stat.S_ISDIR(info.st_mode):
                items.append((relative + "/", mode, 0, ""))
                recurse(path, relative + "/", depth + 1)
            elif stat.S_ISREG(info.st_mode) and info.st_nlink == 1:
                if path.name.endswith(("-wal","-shm","-journal")):
                    raise MigrationBlocked("uncheckpointed SQLite journal")
                items.append((relative, mode, info.st_size, _sha(path)))
            else:
                raise MigrationBlocked("source symlink, hardlink or device")
            if len(items) > MAX_ENTRIES:
                raise MigrationBlocked("migration file count limit")
    recurse(root, "", 0)
    digest = hashlib.sha256(json.dumps(items, separators=(",", ":")).encode()).hexdigest()
    return digest, items


def _copy(source, destination, items, *, existing=False):
    if not existing:
        destination.mkdir(mode=0o700)
    elif not destination.is_dir() or destination.is_symlink():
        raise MigrationBlocked('prepared storage root changed')
    _sync(destination.parent)
    for rel, mode, length, digest in items:
        original = source / rel.rstrip("/")
        target = destination / rel.rstrip("/")
        if rel.endswith("/"):
            target.mkdir(mode=0o700)
            _sync(target.parent)
            continue
        before = original.stat(follow_symlinks=False)
        if rel.endswith(".sqlite3"):
            # SQLite's default mode on a newly created database can be 0644.
            # Pre-create private storage before the backup writes any page.
            secured = os.open(target, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
            os.close(secured)
            with sqlite3.connect(f"file:{original.as_posix()}?mode=ro", uri=True) as src:
                if src.execute("PRAGMA quick_check").fetchone() != ("ok",):
                    raise MigrationBlocked("source SQLite is corrupt")
                with sqlite3.connect(str(target)) as dst:
                    src.backup(dst)
                    if dst.execute("PRAGMA integrity_check").fetchone() != ("ok",):
                        raise MigrationBlocked("SQLite copy is corrupt")
            os.chmod(target, 0o600)
        else:
            source_fd = os.open(original, os.O_RDONLY | os.O_NOFOLLOW)
            try:
                with os.fdopen(source_fd, "rb", closefd=False) as reader:
                    meta = os.fstat(source_fd)
                    if not stat.S_ISREG(meta.st_mode) or meta.st_nlink != 1:
                        raise MigrationBlocked("source changed identity")
                    dest_fd = os.open(target, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
                    with os.fdopen(dest_fd, "wb") as writer:
                        while block := reader.read(1024 * 1024):
                            writer.write(block)
                        writer.flush(); os.fsync(writer.fileno())
                private = original.name in {
                    "deployment-secrets.json", "first-login.json", "identity.pem",
                } or original.suffix in {".pem", ".key"}
                os.chmod(target, 0o600 if private else mode & 0o755)
            finally: os.close(source_fd)
            if target.stat().st_size != length or _sha(target) != digest:
                raise MigrationBlocked("archive byte copy mismatch")
        after = original.stat(follow_symlinks=False)
        if (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns) != (
                after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns):
            raise MigrationBlocked("source changed during copy")
        _sync(target.parent)
    for rel,mode,_,_ in reversed(items):
        if rel.endswith("/"):
            path = destination / rel.rstrip("/")
            os.chmod(path, mode & 0o755)
            _sync(path)
    _sync(destination)


def migrate(*, station_source, archive_source, station_destination, archive_destination,
            station_storage_id, archive_storage_id, checkpoint_confirmed=False):
    if not checkpoint_confirmed:
        raise MigrationBlocked("explicit frozen checkpoint confirmation required")
    if (not isinstance(station_storage_id,str) or not STORAGE_ID.fullmatch(station_storage_id)
            or not isinstance(archive_storage_id,str) or not STORAGE_ID.fullmatch(archive_storage_id)
            or station_storage_id == archive_storage_id):
        raise MigrationBlocked("distinct controller storage identities required")
    roots = [_checked_directory(p) for p in (
        station_source, archive_source, station_destination, archive_destination)]
    paths = [p for p,_ in roots]
    if len({identity for _,identity in roots}) != 4:
        raise MigrationBlocked("storage identities overlap")
    for i,path in enumerate(paths):
        if any(i != j and (path in other.parents or other in path.parents)
               for j,other in enumerate(paths)):
            raise MigrationBlocked("nested production inputs or outputs")
    s, a, ds, da = paths
    station_fingerprint, station_files = _inventory(s)
    archive_fingerprint, archive_files = _inventory(a)
    database = s / "station-access.sqlite3"
    if not database.is_file():
        raise MigrationBlocked("station database checkpoint missing")
    from zog.archive_mirror.store_verification import has_catalogue, export_catalogue, verify_store
    standalone = a / "catalogue.sqlite3"
    catalogue_source = standalone if standalone.is_file() else database
    if not has_catalogue(catalogue_source):
        raise MigrationBlocked("catalogue schema unavailable; refuse archive metadata loss")
    bound = {
        "schema": SCHEMA,
        "storage_ids": [station_storage_id,archive_storage_id],
        "source_identities": [
            hashlib.sha256(f"{p}:{i[0]}:{i[1]}".encode()).hexdigest()
            for p,i in roots[:2]
        ],
        "destination_identities": [
            hashlib.sha256(f"{p}:{i[0]}:{i[1]}".encode()).hexdigest()
            for p,i in roots[2:]
        ],
        "source_manifest_sha256": [station_fingerprint, archive_fingerprint],
    }
    present = [(p/MARKER).exists() or (p/MARKER).is_symlink() for p in (ds,da)]
    if any(present):
        if not all(present):
            raise MigrationBlocked("one storage has an incomplete migration")
        records = []
        for root in (ds,da):
            marker = root / MARKER
            info = marker.lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077 or info.st_size > 8192:
                raise MigrationBlocked("unsafe migration evidence")
            records.append(json.loads(marker.read_text()))
        if (records[0] != records[1] or records[0].get("binding") != bound or
                records[0].get("state") != "complete"):
            raise MigrationBlocked("conflicting or incomplete migration; operator recovery required")
        observed = verify_store(da/"store", da/"catalogue.sqlite3")
        if _inventory(ds, ignore_marker=True)[0] != records[0]["station_destination_manifest"]:
            raise MigrationBlocked("completed station state changed")
        if _inventory(da/"store")[0] != records[0]["archive_destination_manifest"]:
            raise MigrationBlocked("completed archive files changed")
        if _sha(da/"catalogue.sqlite3") != records[0]["archive_verification"]["catalogue_sha256"]:
            raise MigrationBlocked("completed archive catalogue changed")
        if (observed["counts"] != records[0]["archive_verification"]["counts"] or
                observed["object_manifest_sha256"] != records[0]["archive_verification"]["object_manifest_sha256"]):
            raise MigrationBlocked("migrated archive changed after completion")
        return records[0]
    if any(next(root.iterdir(), None) is not None for root in (ds,da)):
        raise MigrationBlocked("destination is not new/empty")
    pending = {"schema":SCHEMA,"state":"copying","binding":bound}
    _write_marker(ds, pending); _write_marker(da, pending)
    # Both durable intent markers precede any copying. Incomplete migration
    # never autorestores, merges, resumes or cleans up application data.
    _copy(s, ds, station_files, existing=True)
    _copy(a, da/"store", archive_files)
    if standalone.is_file():
        with sqlite3.connect(f"file:{(da/'store'/'catalogue.sqlite3').as_posix()}?mode=ro",uri=True) as src:
            with sqlite3.connect(str(da/"catalogue.sqlite3")) as dst:
                src.backup(dst)
    else:
        export_catalogue(ds/"station-access.sqlite3", da/"catalogue.sqlite3")
    if _inventory(s)[0] != station_fingerprint or _inventory(a)[0] != archive_fingerprint:
        raise MigrationBlocked("source checkpoint changed")
    try:
        verified = verify_store(da/"store", da/"catalogue.sqlite3")
    except (ValueError, OSError, sqlite3.Error) as exc:
        raise MigrationBlocked("migrated archive verification failed; incomplete evidence retained") from exc
    report = {"schema":SCHEMA,"state":"complete","binding":bound,
              "archive_verification":verified,"station_sqlite_integrity":"ok",
              "station_destination_manifest":_inventory(ds, ignore_marker=True)[0],
              "archive_destination_manifest":_inventory(da/"store")[0]}
    _write_marker(ds,report); _write_marker(da,report)
    return report


def main(argv=None):
    parser = argparse.ArgumentParser()
    for key in ("station-source","archive-source","station-destination",
                "archive-destination","station-storage-id","archive-storage-id"):
        parser.add_argument("--"+key,required=True)
    parser.add_argument("--confirm-frozen-checkpoints",action="store_true")
    args=parser.parse_args(argv)
    try:
        result=migrate(station_source=args.station_source,archive_source=args.archive_source,
                       station_destination=args.station_destination,archive_destination=args.archive_destination,
                       station_storage_id=args.station_storage_id,archive_storage_id=args.archive_storage_id,
                       checkpoint_confirmed=args.confirm_frozen_checkpoints)
    except (OSError,ValueError,sqlite3.Error):
        print(json.dumps({"schema":SCHEMA,"state":"blocked","safe_to_cut_over":False}))
        return 2
    print(json.dumps({**result,"safe_to_cut_over":False},sort_keys=True))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
