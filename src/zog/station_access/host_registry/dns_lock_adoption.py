"""Explicit adoption of an already-existing, review-only DNS controller lock.

This is *not* controller bootstrap or legacy-controller migration. Nothing
creates, replaces, truncates or unlinks controller.lock. A human separately
approves the short-lived receipt before installing its durable inode marker.
"""
import fcntl
import hashlib
import json
import os
import re
import stat
import time
import uuid
from contextlib import contextmanager

from zog.network_register.contracts import NetworkError
from zog.network_register.ledger import digest

from . import dns_empty_bootstrap as bootstrap
from .dns_controller_lock import _details, _directory, _write_identity, writer_lock
from .dns_evidence import owner_authorized
from .identity import locked as identity_locked
from .models import SecurityAudit

KIND = "existing-empty-dns-lock-adoption"
SECONDS = 600
HASH = re.compile(r"[0-9a-f]{64}\Z")
REVIEW_FILE = re.compile(r"dns-review-([0-9a-f]{64})\.json\Z")
MARKER = "controller-lock-identity.json"


class LockAdoptionError(ValueError):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def _root():
    root, _ = bootstrap._paths()
    bootstrap._directory(root)  # Adoption never creates a directory.
    _directory(root)
    return root


def _read_bytes(path):
    """Read a protected, single-linked file without following a symlink."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            before = os.fstat(fd)
            current = os.stat(path, follow_symlinks=False)
            if (not stat.S_ISREG(before.st_mode)
                    or before.st_uid != os.geteuid()
                    or before.st_mode & 0o077 or before.st_nlink != 1
                    or (before.st_dev, before.st_ino) !=
                       (current.st_dev, current.st_ino)
                    or before.st_size > 65536):
                raise LockAdoptionError("unsafe-existing-evidence")
            raw = os.read(fd, 65537)
            if len(raw) != before.st_size:
                raise LockAdoptionError("changed-existing-evidence")
            after = os.fstat(fd)
            current = os.stat(path, follow_symlinks=False)
            if (after.st_size != before.st_size
                    or after.st_mtime_ns != before.st_mtime_ns
                    or (after.st_dev, after.st_ino) !=
                       (current.st_dev, current.st_ino)):
                raise LockAdoptionError("changed-existing-evidence")
            return raw, dict(device=before.st_dev, inode=before.st_ino,
                             size=before.st_size, mode=stat.S_IMODE(before.st_mode),
                             sha256=hashlib.sha256(raw).hexdigest())
        finally:
            os.close(fd)
    except OSError:
        raise LockAdoptionError("unavailable-existing-evidence") from None


@contextmanager
def _unbound_lock(root):
    path = root / "controller.lock"
    try:
        fd = os.open(path, os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError:
        raise LockAdoptionError("missing-or-unsafe-original-lock") from None
    try:
        details = _details(fd)
        original = os.fstat(fd)
        if (original.st_nlink != 1 or original.st_size != 0
                or stat.S_IMODE(original.st_mode) != 0o600):
            raise LockAdoptionError("unsafe-original-lock")
        _lock_same(path, fd, details)
        # Nonblocking acquisition refuses a currently active cooperative
        # writer, including an old revision that used this same inode.
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        _lock_same(path, fd, details)
        yield details
        _lock_same(path, fd, details)
    finally:
        os.close(fd)


def _lock_same(path, fd, expected):
    current = os.stat(path, follow_symlinks=False)
    recorded = _details(fd)
    if (not stat.S_ISREG(current.st_mode)
            or stat.S_IMODE(current.st_mode) != 0o600
            or current.st_uid != os.geteuid()
            or os.fstat(fd).st_nlink != 1
            or (current.st_dev, current.st_ino) !=
               (recorded["device"], recorded["inode"])
            or recorded != expected):
        raise LockAdoptionError("original-lock-changed")


def _snapshot(root, *, exclude=(), allow_marker=False):
    """Exact protected review-only namespace; never accept ledger/history."""
    entries = []
    for path in sorted(root.iterdir()):
        if path.name in exclude:
            continue
        if path.name == MARKER and allow_marker:
            continue
        if path.name == "controller.lock":
            raw, details = _read_bytes(path)
            if raw != b"" or details["mode"] != 0o600:
                raise LockAdoptionError("unsafe-original-lock")
        else:
            match = REVIEW_FILE.fullmatch(path.name)
            if not match:
                raise LockAdoptionError("foreign-controller-state")
            raw, details = _read_bytes(path)
            try:
                value = json.loads(raw)
            except (UnicodeError, ValueError, TypeError):
                raise LockAdoptionError("invalid-existing-review") from None
            if (type(value) is not dict or digest(value) != match.group(1)
                    or value.get("kind") not in
                    ("empty-shared-dns-bootstrap", KIND)):
                raise LockAdoptionError("invalid-existing-review")
            if value["kind"] == "empty-shared-dns-bootstrap":
                bootstrap._load_review(root, match.group(1))
        entries.append(dict(name=path.name, **details))
    if not any(item["name"] == "controller.lock" for item in entries):
        raise LockAdoptionError("missing-original-lock")
    st = os.lstat(root)
    return dict(root=dict(device=st.st_dev, inode=st.st_ino),
                entries=entries)


def _load(root, review_id):
    if type(review_id) is not str or not HASH.fullmatch(review_id):
        raise LockAdoptionError("invalid-adoption-review")
    path = root / ("dns-review-" + review_id + ".json")
    raw, _ = _read_bytes(path)
    try:
        data = json.loads(raw)
    except (ValueError, UnicodeError, TypeError):
        raise LockAdoptionError("invalid-adoption-review") from None
    if (type(data) is not dict or set(data) !=
            {"schema", "kind", "owner", "nonce", "expires_at", "snapshot"}
            or data["schema"] != 1 or data["kind"] != KIND
            or type(data["owner"]) is not int
            or type(data["expires_at"]) is not int
            or not isinstance(data["snapshot"], dict)
            or digest(data) != review_id):
        raise LockAdoptionError("invalid-adoption-review")
    return data


def _marker(root, review_id, lock):
    raw, _ = _read_bytes(root / MARKER)
    try:
        value = json.loads(raw)
    except (ValueError, UnicodeError, TypeError):
        raise LockAdoptionError("invalid-lock-marker") from None
    expected = dict(schema=1, device=lock["device"], inode=lock["inode"],
                    adoption_review_id=review_id)
    if value != expected:
        raise LockAdoptionError("foreign-or-incomplete-lock-marker")
    return expected


def _fsync_dir(root):
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def review(*, owner):
    owner_authorized(owner)
    root = _root()
    if os.path.lexists(root / MARKER):
        raise LockAdoptionError("lock-already-bound")
    if not bootstrap._fresh_database():
        raise LockAdoptionError("existing-dns-ownership")
    with _unbound_lock(root):
        if os.path.lexists(root / MARKER):
            raise LockAdoptionError("lock-already-bound")
        snapshot = _snapshot(root)
        value = dict(schema=1, kind=KIND, owner=owner,
                     nonce=str(uuid.uuid4()), expires_at=int(time.time()) + SECONDS,
                     snapshot=snapshot)
        key = digest(value)
        bootstrap._exclusive_json(root / ("dns-review-" + key + ".json"), value)
        return dict(review_id=key, expires_at=value["expires_at"],
                    owner=owner, lock=snapshot["entries"][next(
                        i for i, v in enumerate(snapshot["entries"])
                        if v["name"] == "controller.lock")],
                    evidence_count=len(snapshot["entries"]) - 1,
                    writer="uninitialized", provider_writes=0)


def commit(*, owner, review_id):
    owner_authorized(owner)
    root = _root()
    with _unbound_lock(root) as lock:
        data = _load(root, review_id)
        if data["owner"] != owner:
            raise LockAdoptionError("wrong-adoption-owner")
        path = root / MARKER
        exists = os.path.lexists(path)
        if not exists and int(time.time()) > data["expires_at"]:
            raise LockAdoptionError("adoption-review-expired")
        if not bootstrap._fresh_database():
            raise LockAdoptionError("existing-dns-ownership")
        snapshot = _snapshot(
            root, exclude=("dns-review-" + review_id + ".json",),
            allow_marker=exists)
        if snapshot != data["snapshot"]:
            raise LockAdoptionError("existing-evidence-changed")
        if exists:
            _marker(root, review_id, lock)
        else:
            # The identity marker is the final authority write. If a crash
            # leaves an incomplete marker, the next attempt blocks; neither
            # ordinary bootstrap nor this operation silently repairs it.
            _write_identity(path, dict(**lock, adoption_review_id=review_id))
            _fsync_dir(root)
            _marker(root, review_id, lock)
    with writer_lock(root):
        _marker(root, review_id, lock)
    with identity_locked():
        if not SecurityAudit.objects.filter(
                action="dns-controller-lock-adopted",
                details__review_id=review_id).exists():
            SecurityAudit.objects.create(
                actor="operator:" + str(owner),
                action="dns-controller-lock-adopted",
                details=dict(review_id=review_id, lock=lock, provider_writes=0))
    return dict(review_id=review_id, owner=owner, lock=lock,
                adopted=True, replayed=exists, writer="uninitialized",
                provider_writes=0)


def inspect(*, owner, review_id):
    owner_authorized(owner)
    root = _root()
    with writer_lock(root):
        data = _load(root, review_id)
        if data["owner"] != owner:
            raise LockAdoptionError("wrong-adoption-owner")
        lock = _details_for_inspection(root)
        _marker(root, review_id, lock)
        current = _snapshot(
            root, exclude=("dns-review-" + review_id + ".json",),
            allow_marker=True)
        if current != data["snapshot"]:
            raise LockAdoptionError("existing-evidence-changed")
        if not bootstrap._fresh_database():
            raise LockAdoptionError("existing-dns-ownership")
        return dict(review_id=review_id, owner=owner, lock=lock,
                    adopted=True, writer="uninitialized", provider_writes=0)


def _details_for_inspection(root):
    raw, details = _read_bytes(root / "controller.lock")
    if raw != b"" or details["mode"] != 0o600:
        raise LockAdoptionError("unsafe-original-lock")
    return {k: details[k] for k in ("device", "inode")}
