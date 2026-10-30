"""Root-private *candidate only* Credential Authority signer preparation.

No operator pin is generated; no authority or hostname grant is signed.
A candidate key under an existing inert offline directory is not trusted and
must not be copied to any live service without separately verified approval.
Any crash after creating the candidate directory is a permanent review hold;
no automatic repair, overwrite, or regeneration is performed.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .credential_v1_offline_identity import canonical

NAME = "credential-v1-signer-candidate"
SCHEMA = "zog-credential-v1-signing-key-candidate-v1"
PRIVATE_NAME = "authority-key.pem"
PUBLIC_NAME = "authority-ed25519.pub"
RECEIPT = "unapproved-candidate.json"


class OfflineCandidateDenied(ValueError):
    pass


def deny():
    raise OfflineCandidateDenied("offline-credential-signer-candidate-unavailable") from None


def _offline_parent(path):
    if (os.geteuid() != 0 or type(path) is not str
            or not path.startswith("/opt/station-trust/")
            or not Path(path).name.endswith("-offline")
            or len(path) > 300 or ".." in Path(path).parts
            or Path(path).as_posix() != path):
        deny()
    try:
        for parent in reversed(Path(path).parents):
            s = parent.lstat()
            if not stat.S_ISDIR(s.st_mode) or s.st_uid != 0 or s.st_mode & 0o022:
                deny()
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        s = os.fstat(fd)
        if (s.st_uid != 0 or s.st_gid != 0
                or stat.S_IMODE(s.st_mode) != 0o700
                or not stat.S_ISDIR(s.st_mode)):
            os.close(fd)
            deny()
        return fd
    except OSError:
        deny()


def _read(fd, name, mode, maximum):
    try:
        f = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
        try:
            s = os.fstat(f)
            if (not stat.S_ISREG(s.st_mode) or s.st_uid != 0 or s.st_gid != 0
                    or s.st_nlink != 1 or stat.S_IMODE(s.st_mode) != mode
                    or not 0 < s.st_size <= maximum):
                deny()
            data = os.read(f, maximum+1)
            if len(data) != s.st_size or len(data) > maximum:
                deny()
            return data
        finally:
            os.close(f)
    except OSError:
        deny()


def _create(fd, name, payload, mode):
    if type(payload) is not bytes or not 0 < len(payload) <= 8192:
        deny()
    file_fd = os.open(
        name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
        mode, dir_fd=fd)
    try:
        os.fchmod(file_fd, mode)
        cursor = memoryview(payload)
        while cursor:
            count = os.write(file_fd, cursor)
            if count <= 0:
                deny()
            cursor = cursor[count:]
        os.fsync(file_fd)
    finally:
        os.close(file_fd)
    os.fsync(fd)


def _candidate(key, source_commit):
    if (not isinstance(key, Ed25519PrivateKey) or type(source_commit) is not str
            or len(source_commit) != 40
            or any(ch not in "0123456789abcdef" for ch in source_commit)):
        deny()
    private = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption())
    public = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    receipt = {
        "schema": SCHEMA,
        "source_commit": source_commit,
        "public_pin_sha256": hashlib.sha256(public).hexdigest(),
        "authority_status": "unapproved-offline-candidate",
        "operator_approval_present": False,
        "root_grant_present": False,
        "credential_delivery_authorized": False,
        "installation_authorized": False,
    }
    return private, public, canonical(receipt)


def prepare(path, source_commit):
    root_fd = _offline_parent(path)
    try:
        # Any surviving pending directory is an irreversible review hold,
        # including an empty one. Never reuse or regenerate key material.
        os.mkdir(NAME, 0o700, dir_fd=root_fd)
        os.fsync(root_fd)
        sub = os.open(NAME, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=root_fd)
        try:
            st = os.fstat(sub)
            if (st.st_dev != os.fstat(root_fd).st_dev or st.st_uid != 0
                    or st.st_gid != 0 or stat.S_IMODE(st.st_mode) != 0o700):
                deny()
            pem, raw, receipt = _candidate(Ed25519PrivateKey.generate(), source_commit)
            _create(sub, PRIVATE_NAME, pem, 0o600)
            _create(sub, PUBLIC_NAME, raw, 0o444)
            _create(sub, RECEIPT, receipt, 0o600)
            os.fsync(sub)
            os.fsync(root_fd)
            return review(path, offline_root_fd=root_fd)
        finally:
            os.close(sub)
    except (OSError, ValueError):
        deny()
    finally:
        os.close(root_fd)


def review(path, *, offline_root_fd=None):
    owned = offline_root_fd is None
    fd = _offline_parent(path) if owned else offline_root_fd
    try:
        sub = os.open(NAME, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
        try:
            st = os.fstat(sub)
            if (st.st_uid != 0 or st.st_gid != 0
                    or stat.S_IMODE(st.st_mode) != 0o700
                    or st.st_dev != os.fstat(fd).st_dev
                    or set(os.listdir(sub)) != {PRIVATE_NAME, PUBLIC_NAME, RECEIPT}):
                deny()
            pem = _read(sub, PRIVATE_NAME, 0o600, 8192)
            pin = _read(sub, PUBLIC_NAME, 0o444, 32)
            raw_receipt = _read(sub, RECEIPT, 0o600, 4096)
            key = serialization.load_pem_private_key(pem, password=None)
            if not isinstance(key, Ed25519PrivateKey):
                deny()
            actual = key.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            value = json.loads(raw_receipt)
            if (actual != pin or len(pin) != 32
                    or type(value) is not dict or canonical(value) != raw_receipt
                    or set(value) != {"schema", "source_commit", "public_pin_sha256",
                                     "authority_status", "operator_approval_present",
                                     "root_grant_present", "credential_delivery_authorized",
                                     "installation_authorized"}
                    or value["schema"] != SCHEMA
                    or value["authority_status"] != "unapproved-offline-candidate"
                    or value["operator_approval_present"] is not False
                    or value["root_grant_present"] is not False
                    or value["credential_delivery_authorized"] is not False
                    or value["installation_authorized"] is not False
                    or value["public_pin_sha256"] != hashlib.sha256(pin).hexdigest()):
                deny()
            return {
                "schema": "zog-credential-v1-offline-signer-review-v1",
                "source_commit": value["source_commit"],
                "public_pin_sha256": value["public_pin_sha256"],
                "disposition": "root-private-unapproved-key-candidate",
                "operator_approval_present": False,
                "authorized_for_credential_delivery": False,
                "authorized_for_active_installation": False,
            }
        finally:
            os.close(sub)
    except (OSError, ValueError, TypeError, KeyError):
        deny()
    finally:
        if owned:
            os.close(fd)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Root-private inactive v1 signer proposal only")
    parser.add_argument("action", choices=("prepare", "inspect"))
    parser.add_argument("--offline-directory", required=True)
    parser.add_argument("--station-source-commit", required=False)
    args = parser.parse_args(argv)
    try:
        if args.action == "prepare":
            if args.station_source_commit is None:
                deny()
            result = prepare(args.offline_directory, args.station_source_commit)
        else:
            result = review(args.offline_directory)
            if (args.station_source_commit is not None and
                    result["source_commit"] != args.station_source_commit):
                deny()
        print(canonical(result).decode("ascii"))
        return 0
    except (OfflineCandidateDenied, OSError, ValueError):
        parser.error("offline signer remains blocked or requires independent review")


if __name__ == "__main__":
    raise SystemExit(main())
