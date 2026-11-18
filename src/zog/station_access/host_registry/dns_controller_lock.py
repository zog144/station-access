"""One durable DNS writer lock identity, shared by bootstrap and all controllers.

Never re-create a lost lock after provisioning. Inode bindings are local host
state; moving/restoring a controller requires a separate reviewed procedure.
"""
import fcntl
import json
import os
import stat
from contextlib import contextmanager
from pathlib import Path

from zog.network_register.contracts import NetworkError



def _details(fd):
    v = os.fstat(fd)
    if (not stat.S_ISREG(v.st_mode) or v.st_uid != os.geteuid()
            or stat.S_IMODE(v.st_mode) != 0o600 or v.st_nlink != 1):
        raise NetworkError("storage")
    return {"device": v.st_dev, "inode": v.st_ino}


def _matches(path, fd, expected):
    recorded = _details(fd)
    try:
        current = os.stat(path, follow_symlinks=False)
    except OSError:
        raise NetworkError("storage") from None
    if (not stat.S_ISREG(current.st_mode) or current.st_uid != os.geteuid()
            or stat.S_IMODE(current.st_mode) != 0o600 or current.st_nlink != 1 or
            (current.st_dev, current.st_ino) !=
            (recorded["device"], recorded["inode"]) or recorded != expected):
        raise NetworkError("storage")


def _read_identity(root):
    """Reopen exactly the original marker (and adoption receipt, if present).

    Avoid prefix-only JSON reads and path-to-descriptor substitutions: a
    second writer must never bind to an unverified replacement inode.
    """
    path = root / "controller-lock-identity.json"
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            _details(fd)
            before = os.fstat(fd)
            if before.st_size <= 0 or before.st_size > 2048:
                raise NetworkError("storage")
            raw = os.read(fd, before.st_size + 1)
            identity = json.loads(raw)
            after = os.fstat(fd)
            current = os.stat(path, follow_symlinks=False)
            if (len(raw) != before.st_size or after.st_size != before.st_size
                    or after.st_mtime_ns != before.st_mtime_ns
                    or (after.st_dev, after.st_ino) !=
                       (current.st_dev, current.st_ino)):
                raise NetworkError("storage")
        finally:
            os.close(fd)
    except (OSError, ValueError, TypeError, UnicodeError):
        raise NetworkError("storage") from None
    if (type(identity) is not dict or set(identity) not in (
            {"schema", "device", "inode"},
            {"schema", "device", "inode", "adoption_review_id"})
            or identity["schema"] != 1 or
            type(identity["device"]) is not int or type(identity["inode"]) is not int
            or identity["device"] <= 0 or identity["inode"] <= 0):
        raise NetworkError("storage")
    if "adoption_review_id" in identity:
        import hashlib
        key = identity["adoption_review_id"]
        if (type(key) is not str or len(key) != 64
                or any(c not in "0123456789abcdef" for c in key)):
            raise NetworkError("storage")
        receipt = root / ("dns-review-" + key + ".json")
        try:
            rfd = os.open(receipt, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
            try:
                _details(rfd)
                st = os.fstat(rfd)
                if st.st_size <= 0 or st.st_size > 65536:
                    raise NetworkError("storage")
                content = os.read(rfd, st.st_size + 1)
                state = json.loads(content)
                later = os.fstat(rfd)
                now = os.stat(receipt, follow_symlinks=False)
            finally:
                os.close(rfd)
            if (len(content) != st.st_size
                    or later.st_size != st.st_size
                    or later.st_mtime_ns != st.st_mtime_ns
                    or (now.st_dev, now.st_ino) != (st.st_dev, st.st_ino)
                    or type(state) is not dict
                    or set(state) !=
                    {"schema", "kind", "owner", "nonce", "expires_at", "snapshot"}
                    or state.get("schema") != 1
                    or state.get("kind") != "existing-empty-dns-lock-adoption"
                    or hashlib.sha256(json.dumps(state, sort_keys=True,
                       separators=(",", ":"), allow_nan=False).encode()).hexdigest() != key
                    or not any(type(x) is dict
                        and x.get("name") == "controller.lock"
                        and x.get("device") == identity["device"]
                        and x.get("inode") == identity["inode"]
                        for x in state.get("snapshot", {}).get("entries", []))):
                raise NetworkError("storage")
        except (OSError, ValueError, TypeError, AttributeError, UnicodeError):
            raise NetworkError("storage") from None
    return {"device": identity["device"], "inode": identity["inode"]}


def _directory(root):
    try:
        st = os.lstat(root)
    except OSError:
        raise NetworkError("storage") from None
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.geteuid() or st.st_mode & 0o077:
        raise NetworkError("storage")


def _write_identity(path, identity):
    """Exclusively create durable immutable lock identity; never overwrite."""
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    except FileExistsError:
        raise NetworkError("storage") from None
    try:
        raw = json.dumps(dict(schema=1, **identity), sort_keys=True).encode() + b"\n"
        os.write(fd, raw)
        os.fsync(fd)
    finally:
        os.close(fd)


def initialize_lock(root):
    """Explicit initial provisioning only, under a protected directory.

    A partly created lock with no identity is an integrity fault, not a
    signal to recreate it. Must never be called by normal controller_lock.
    """
    root = Path(root)
    _directory(root)
    if any((root / name).exists() or (root / name).is_symlink()
           for name in ("controller.lock", "controller-lock-identity.json")):
        raise NetworkError("conflict")
    try:
        fd = os.open(root / "controller.lock",
                     os.O_CREAT | os.O_EXCL | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            identity = _details(fd)
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            _write_identity(root / "controller-lock-identity.json", identity)
            _matches(root / "controller.lock", fd, identity)
        finally:
            os.close(fd)
    except FileExistsError:
        raise NetworkError("conflict") from None
    directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


@contextmanager
def writer_lock(root):
    """Lock by durable inode, then recheck path-to-open-descriptor identity."""
    root = Path(root)
    _directory(root)
    expected = _read_identity(root)
    try:
        fd = os.open(root / "controller.lock", os.O_RDWR | os.O_NOFOLLOW)
    except OSError:
        raise NetworkError("storage") from None
    try:
        _matches(root / "controller.lock", fd, expected)
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        _matches(root / "controller.lock", fd, expected)
        yield root
        _matches(root / "controller.lock", fd, expected)
    finally:
        os.close(fd)
