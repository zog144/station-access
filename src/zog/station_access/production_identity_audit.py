"""Read-only guest-visible DAC evidence for an externally verified application grant.

This is NOT the authoritative execution-identity registry or a provisioner.
The caller must independently obtain the numeric UID/GID from root-control's
protected grant and verify the *kernel* service credentials on the host.
Never chown, rewrite the grant, or declare a production cutover from this audit.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import stat

SCHEMA = "zog-station-execution-dac-audit-v1"


def _root_directory(path):
    path = Path(path)
    if not path.is_absolute() or ".." in path.parts or str(path) == "/":
        raise ValueError("noncanonical station state directory")
    current = Path("/")
    for part in path.parts[1:]:
        current = current / part
        info = current.lstat()
        if not stat.S_ISDIR(info.st_mode):
            raise ValueError("redirected or special station state directory")
    return path


def audit_station_state(state_directory, *, expected_uid, expected_gid, require_compiler_rpc=False):
    """Return sanitized observations only; no file changes or identity issuance."""
    if type(require_compiler_rpc) is not bool:
        raise ValueError("strict credential mode must be a boolean")
    if (type(expected_uid) is not int or type(expected_gid) is not int
            or expected_uid <= 0 or expected_gid <= 0):
        raise ValueError("non-root controller-bound numeric UID/GID required")
    state = _root_directory(state_directory)
    checks = {}

    def check(relative, *, directory=False, required=True, private=True):
        path = state if not relative else state / relative
        try:
            info = path.lstat()
        except FileNotFoundError:
            checks[relative or "state"] = "missing" if required else "absent"
            return False
        except OSError:
            checks[relative or "state"] = "unavailable"
            return False
        if not (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)):
            checks[relative or "state"] = "invalid-type"
            return False
        if info.st_uid != expected_uid or info.st_gid != expected_gid:
            checks[relative or "state"] = "owner-mismatch"
            return False
        if stat.S_IMODE(info.st_mode) & (0o077 if private else 0o022):
            checks[relative or "state"] = "unsafe-mode"
            return False
        if not directory and info.st_nlink != 1:
            checks[relative or "state"] = "unsafe-links"
            return False
        checks[relative or "state"] = "verified"
        return True

    check("", directory=True)
    check("station-access.sqlite3")
    for suffix in ("-wal", "-shm", "-journal"):
        check("station-access.sqlite3" + suffix, required=False)
    check("deployment-secrets.json")
    # A general state audit may run before observer provisioning. The
    # operator-requested candidate profile requires the *whole* bundle and
    # checks no extra files are hidden in that protected credential directory.
    rpc = state / "compiler-rpc"
    rpc_status = check("compiler-rpc", directory=True,
                       required=require_compiler_rpc) if (
                           require_compiler_rpc or rpc.exists() or rpc.is_symlink()
                       ) else False
    if not (require_compiler_rpc or rpc.exists() or rpc.is_symlink()):
        checks["compiler-rpc"] = "not-provisioned"
    if rpc_status:
        names = ("configuration.json", "client-key.pem",
                 "client-cert.pem", "server-ca.pem")
        for name in names:
            check("compiler-rpc/" + name, private=require_compiler_rpc or
                  name in ("configuration.json", "client-key.pem"))
        if require_compiler_rpc:
            try:
                actual = {item.name for item in rpc.iterdir()}
            except OSError:
                checks["compiler-rpc-contents"] = "unavailable"
            else:
                checks["compiler-rpc-contents"] = (
                    "verified" if actual == set(names) else "unexpected-or-missing")
    if require_compiler_rpc:
        # A WAL without its shared-memory companion (or the reverse) is not a
        # fully checked live database state. Ordinary diagnostic mode still
        # reports each sidecar's independent DAC.
        wal = checks["station-access.sqlite3-wal"]
        shm = checks["station-access.sqlite3-shm"]
        checks["sqlite-sidecar-pair"] = (
            "verified" if (wal == shm and wal in ("verified", "absent"))
            else "incomplete-or-mismatched")
        checks["sqlite-rollback-journal"] = (
            "verified" if checks["station-access.sqlite3-journal"] == "absent"
            else "operator-checkpoint-required")
    allowed = {"verified", "absent"}
    if not require_compiler_rpc:
        allowed.add("not-provisioned")
    passing = all(v in allowed for v in checks.values())
    return {
        "schema": SCHEMA,
        "state": "observed" if passing else "blocked",
        "checks": checks,
        "profile": "candidate" if require_compiler_rpc else "diagnostic",
        "authority": "non-authoritative-local-dac-observation",
        "safe_to_cut_over": False,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description="Read-only station DAC audit; never cutover approval")
    parser.add_argument("--state-directory", required=True)
    parser.add_argument("--expected-uid", required=True, type=int)
    parser.add_argument("--expected-gid", required=True, type=int)
    parser.add_argument("--require-compiler-rpc", action="store_true",
                        help="Require complete private observer material for an isolated candidate")
    args = parser.parse_args(argv)
    try:
        result = audit_station_state(args.state_directory,
                                     expected_uid=args.expected_uid,
                                     expected_gid=args.expected_gid,
                                     require_compiler_rpc=args.require_compiler_rpc)
    except (OSError, ValueError):
        result = {"schema": SCHEMA, "state": "blocked", "safe_to_cut_over": False}
    print(json.dumps(result, sort_keys=True))
    return 0 if result.get("state") == "observed" else 2


if __name__ == "__main__":
    raise SystemExit(main())
