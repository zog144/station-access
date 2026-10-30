"""Read-only trust/identity review for an externally managed Command-Center.

No privileged authority installer exists merely because a Host enrolls.
The station's existing application database is *not* canonical host-install
/state. An independently pinned operator signs its own Command-Center
installation claim; all claims remain review-only until native approval.
No keys, credentials, grants, users, DB rows, sockets or services are created.
"""
import argparse
import base64
import binascii
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import time
import uuid

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

SCHEMA = "zog-command-center-offline-installation-identity-v1"
DOMAIN = (SCHEMA + "\0").encode("ascii")
FIELDS = frozenset((
    "schema", "station_role", "installation_mode", "state_mode",
    "command_center_host_id", "command_center_installation_id",
    "external_host_instance_id", "external_host_evidence_sha256",
    "station_registry_id", "station_source_commit",
    "database_path", "database_device", "database_inode",
    "database_owner_uid", "database_mode",
    "database_parent_device", "database_parent_inode",
    "enrolled_consumer_host_id", "enrolled_consumer_installation_id",
    "enrolled_consumer_state_volume_id", "certificate_signer_pin_sha256",
    "review_revision", "issued_at", "expires_at", "signature_ed25519",
))
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_HEX40 = re.compile(r"[0-9a-f]{40}\Z")
_INSTANCE = re.compile(r"i-[a-f0-9]{8,32}\Z")
_REGISTRY = re.compile(r"[a-z][a-z0-9-]{0,63}\Z")


class OfflineIdentityDenied(ValueError):
    pass


def _deny():
    raise OfflineIdentityDenied("command-center-offline-identity-unverified") from None


def _unique(pairs):
    result = {}
    for name, value in pairs:
        if name in result:
            _deny()
        result[name] = value
    return result


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def _uuid(value):
    if type(value) is not str:
        _deny()
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError):
        _deny()
    if str(parsed) != value or parsed.version not in (4, 5):
        _deny()


def verify(attestation_bytes, independent_operator_public_key, observed, *,
           expected_operator_sha256, expected_external_instance_id,
           expected_source_commit, now=None):
    """Verify independent signature AND selected current filesystem identity.

    `observed` is collected by the privileged host owner, not from
    attestation metadata or an untrusted caller. An externally verified AWS
    instance identity is still a separate native provenance prerequisite.
    """
    now = int(time.time()) if now is None else now
    if (type(now) is not int or type(attestation_bytes) is not bytes
            or not 0 < len(attestation_bytes) <= 8192
            or type(independent_operator_public_key) is not bytes
            or len(independent_operator_public_key) != 32
            or type(expected_operator_sha256) is not str
            or not _HEX64.fullmatch(expected_operator_sha256)
            or type(expected_external_instance_id) is not str
            or not _INSTANCE.fullmatch(expected_external_instance_id)
            or type(expected_source_commit) is not str
            or not _HEX40.fullmatch(expected_source_commit)
            or type(observed) is not dict):
        _deny()
    if hashlib.sha256(independent_operator_public_key).hexdigest() != expected_operator_sha256:
        _deny()
    try:
        claim = json.loads(attestation_bytes, object_pairs_hook=_unique,
                           parse_constant=lambda _: _deny())
        if (type(claim) is not dict or set(claim) != FIELDS
                or canonical(claim) != attestation_bytes
                or claim["schema"] != SCHEMA
                or claim["station_role"] != "command-center-host"
                or claim["installation_mode"] != "externally-managed"
                or claim["state_mode"] != "existing-station-application-database"
                or claim["external_host_instance_id"] != expected_external_instance_id
                or claim["station_source_commit"] != expected_source_commit
                or not _HEX64.fullmatch(claim["external_host_evidence_sha256"])
                or not _HEX64.fullmatch(claim["certificate_signer_pin_sha256"])
                or claim["certificate_signer_pin_sha256"] == expected_operator_sha256
                or not _REGISTRY.fullmatch(claim["station_registry_id"])):
            _deny()
        for field in ("command_center_host_id", "command_center_installation_id",
                      "enrolled_consumer_host_id", "enrolled_consumer_installation_id",
                      "enrolled_consumer_state_volume_id"):
            _uuid(claim[field])
        if (claim["command_center_host_id"] == claim["enrolled_consumer_host_id"]
                or claim["command_center_installation_id"] ==
                   claim["enrolled_consumer_installation_id"]):
            _deny()
        for key in ("database_device", "database_inode", "database_owner_uid",
                    "database_mode", "database_parent_device", "database_parent_inode",
                    "review_revision", "issued_at", "expires_at"):
            if type(claim[key]) is not int or claim[key] < 0:
                _deny()
        if (claim["database_inode"] == 0 or claim["database_parent_inode"] == 0
                or claim["review_revision"] < 1
                or claim["issued_at"] > now
                or claim["expires_at"] <= now
                or claim["expires_at"] > claim["issued_at"] + 30 * 86400
                or claim["database_mode"] & 0o7022):
            _deny()
        path = claim["database_path"]
        if (type(path) is not str or not path.startswith("/")
                or len(path) > 512 or Path(path).as_posix() != path
                or ".." in Path(path).parts
                or path in ("/", "/state")):
            _deny()
        for name, key in (
            ("path", "database_path"), ("device", "database_device"),
            ("inode", "database_inode"), ("owner_uid", "database_owner_uid"),
            ("mode", "database_mode"), ("parent_device", "database_parent_device"),
            ("parent_inode", "database_parent_inode")):
            if observed.get(name) != claim[key]:
                _deny()
        proof = base64.b64decode(claim["signature_ed25519"], validate=True)
        if len(proof) != 64 or base64.b64encode(proof).decode("ascii") != claim["signature_ed25519"]:
            _deny()
        unsigned = dict(claim)
        unsigned.pop("signature_ed25519")
        Ed25519PublicKey.from_public_bytes(independent_operator_public_key).verify(
            proof, DOMAIN + canonical(unsigned))
    except (KeyError, ValueError, TypeError, UnicodeError, binascii.Error,
            OverflowError, InvalidSignature):
        _deny()
    return {
        "schema": "zog-command-center-offline-identity-review-v1",
        "disposition": "reviewed-source-evidence-not-installation-authority",
        "command_center_host_id": claim["command_center_host_id"],
        "command_center_installation_id": claim["command_center_installation_id"],
        "external_host_instance_id": claim["external_host_instance_id"],
        "station_source_commit": claim["station_source_commit"],
        "operator_pin_sha256": expected_operator_sha256,
        "signed_attestation_sha256": hashlib.sha256(attestation_bytes).hexdigest(),
        "review_revision": claim["review_revision"],
        "expires_at": claim["expires_at"],
        "database_device": claim["database_device"],
        "database_inode": claim["database_inode"],
        "canonical_host_install_state_verified": False,
        "authorized_for_authority_installation": False,
        "authorized_for_credential_delivery": False,
    }


def _protected_file(path, *, mode, maximum):
    """Privileged read, no symlink or hardlink; inspect descriptor before/after."""
    if type(path) is not str or not path.startswith("/") or len(path) > 512:
        _deny()
    try:
        for parent in reversed(Path(path).parents):
            st = parent.lstat()
            if (not stat.S_ISDIR(st.st_mode) or st.st_uid != 0
                    or stat.S_IMODE(st.st_mode) & 0o022):
                _deny()
        before = os.lstat(path)
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            s = os.fstat(fd)
            if (not stat.S_ISREG(s.st_mode) or s.st_uid != 0
                    or stat.S_IMODE(s.st_mode) != mode or s.st_nlink != 1
                    or (s.st_dev, s.st_ino) != (before.st_dev, before.st_ino)
                    or not 0 < s.st_size <= maximum):
                _deny()
            content = os.read(fd, maximum + 1)
            after = os.fstat(fd)
            current = os.lstat(path)
            if (len(content) != s.st_size or len(content) > maximum
                    or (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns) !=
                       (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
                    or (current.st_dev, current.st_ino) != (s.st_dev, s.st_ino)):
                _deny()
            return content
        finally:
            os.close(fd)
    except (OSError, ValueError):
        _deny()


def _observe_database(path):
    if type(path) is not str or not path.startswith("/") or len(path) > 512:
        _deny()
    try:
        parent = Path(path).parent
        for ancestor in reversed(parent.parents):
            st = ancestor.lstat()
            if (not stat.S_ISDIR(st.st_mode)
                    or stat.S_IMODE(st.st_mode) & 0o022):
                _deny()
        pd = parent.lstat()
        before = os.lstat(path)
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            f = os.fstat(fd)
            if (not stat.S_ISDIR(pd.st_mode)
                    or stat.S_IMODE(pd.st_mode) & 0o022
                    or not stat.S_ISREG(f.st_mode)
                    or f.st_nlink != 1
                    or (before.st_dev, before.st_ino) != (f.st_dev, f.st_ino)):
                _deny()
            return dict(path=path, device=f.st_dev, inode=f.st_ino,
                        owner_uid=f.st_uid, mode=stat.S_IMODE(f.st_mode),
                        parent_device=pd.st_dev, parent_inode=pd.st_ino)
        finally:
            os.close(fd)
    except (OSError, ValueError):
        _deny()


def main(argv=None):
    parser = argparse.ArgumentParser(description="Read-only offline Command-Center identity review")
    parser.add_argument("--signed-attestation", required=True)
    parser.add_argument("--existing-operator-public-pin", required=True)
    parser.add_argument("--expected-operator-pin-sha256", required=True)
    parser.add_argument("--expected-aws-instance-id", required=True)
    parser.add_argument("--expected-station-source-commit", required=True)
    args = parser.parse_args(argv)
    if os.geteuid() != 0:
        parser.error("protected root-owned identity review requires root")
    try:
        claim = _protected_file(args.signed_attestation, mode=0o600, maximum=8192)
        key = _protected_file(args.existing_operator_public_pin, mode=0o444, maximum=32)
        signed = json.loads(claim, object_pairs_hook=_unique)
        observed = _observe_database(signed["database_path"])
        report = verify(
            claim, key, observed,
            expected_operator_sha256=args.expected_operator_pin_sha256,
            expected_external_instance_id=args.expected_aws_instance_id,
            expected_source_commit=args.expected_station_source_commit)
    except (KeyError, ValueError, TypeError, UnicodeError, OSError):
        parser.error("offline Command-Center identity not independently verified")
    print(canonical(report).decode("ascii"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
