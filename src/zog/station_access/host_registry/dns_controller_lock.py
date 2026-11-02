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
    if not stat.S_ISREG(v.st_mode) or v.st_uid != os.geteuid() or v.st_mode & 0o077:
        raise NetworkError("storage")
    return {"device": v.st_dev, "inode": v.st_ino}


def _matches(path, fd, expected):
    recorded = _details(fd)
    try:
        current = os.stat(path, follow_symlinks=False)
    except OSError:
        raise NetworkError("storage") from None
    if (not stat.S_ISREG(current.st_mode) or current.st_uid != os.geteuid()
            or current.st_mode & 0o077 or
            (current.st_dev, current.st_ino) !=
            (recorded["device"], recorded["inode"]) or recorded != expected):
        raise NetworkError("storage")


def _read_identity(root):
    path = root / "controller-lock-identity.json"
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            _details(fd)
            raw = os.read(fd, 2048)
            identity = json.loads(raw)
        finally:
            os.close(fd)
    except (OSError, ValueError, TypeError):
        raise NetworkError("storage") from None
    if (type(identity) is not dict or set(identity) != {"schema", "device", "inode"}
            or identity["schema"] != 1 or
            type(identity["device"]) is not int or type(identity["inode"]) is not int
            or identity["device"] <= 0 or identity["inode"] <= 0):
        raise NetworkError("storage")
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
