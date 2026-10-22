"""Fail-closed production cutover resource inspection.

This legacy v1 diagnostic checks a historical Unix socket, NOT the accepted
host-deploy HTTPS compiler RPC. Use zog.station_access.compiler_rpc instead.

This is a read-only *consumer* of provisioned bindings, NOT authority to create
mounts or change host-deploy ownership. A successful report is necessary but is
not sufficient for nginx cutover: box-control/root-control must separately
verify the kernel mount identities and host-deploy must authorize the gateway.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import stat
import time
from pathlib import Path

SCHEMA = "zog-station-production-cutover-v1"
_GATEWAY = "host-deploy-owned-gateway"
_FACTORY = "zog.station_access.box_control.current:create_gateway"
_MAX_INTENT = 16384
_KEYS = frozenset({
    "schema", "station_state", "archive_store", "host_discover_credentials",
    "host_gateway_directory", "gateway_socket_name", "gateway_mode",
    "station_gateway_factory", "expected_host_id",
})


def _plain_directory(value, label):
    """Check path components *without* following links; do not reveal paths."""
    if not isinstance(value, str) or not value.startswith("/") or value.startswith("//"):
        return False, f"{label}-invalid"
    path = Path(value)
    if str(path) != value or ".." in path.parts or len(value) > 4096:
        return False, f"{label}-invalid"
    current = Path("/")
    try:
        for component in path.parts[1:]:
            current = current / component
            mode = os.lstat(current).st_mode
            if stat.S_ISLNK(mode) or not stat.S_ISDIR(mode):
                return False, f"{label}-redirected-or-not-directory"
    except OSError:
        return False, f"{label}-unavailable"
    return True, "available"


def _directory(path, label, *, must_write=False):
    ok, status = _plain_directory(path, label)
    if not ok:
        return status
    if not os.access(path, os.R_OK | os.X_OK):
        return f"{label}-unreadable"
    if must_write and not os.access(path, os.W_OK | os.X_OK):
        return f"{label}-not-writable"
    return "available"


def _parse_policy(policy, *, guest_root=Path('/')):
    if type(policy) is not dict or set(policy) != _KEYS or policy.get("schema") != SCHEMA:
        raise ValueError("unsupported production-cutover policy")
    if policy.get("gateway_mode") != _GATEWAY:
        raise ValueError("compiler control must use host-deploy-owned gateway")
    if policy.get("station_gateway_factory") != _FACTORY:
        raise ValueError("legacy external writer adapter is forbidden")
    socket_name = policy.get("gateway_socket_name")
    if (not isinstance(socket_name, str) or
            re.fullmatch(r"[a-z][a-z0-9-]{0,63}\.sock", socket_name) is None):
        raise ValueError("gateway socket must be a basename, never a host path")
    expected = policy.get("expected_host_id")
    try:
        import uuid
        if not isinstance(expected, str) or str(uuid.UUID(expected)) != expected:
            raise ValueError
    except (TypeError, ValueError, AttributeError) as exc:
        raise ValueError("invalid host identity") from exc
    for label in ("station_state", "archive_store",
                  "host_discover_credentials", "host_gateway_directory"):
        value = policy.get(label)
        if not isinstance(value, str) or not value.startswith("/") or value.startswith("//"):
            raise ValueError("invalid production cutover mount target")
    # guest_root is a test seam for isolated fixture roots. The production CLI
    # always uses the actual guest / and never overrides it.
    try:
        relative_intent = "/" + str(Path(policy["host_discover_credentials"]).relative_to(guest_root))
        relative_gateway = "/" + str(Path(policy["host_gateway_directory"]).relative_to(guest_root))
    except ValueError as exc:
        raise ValueError("resource destination is not inside guest namespace") from exc
    if relative_intent != "/run/zog-host/mirror-live":
        raise ValueError("mirror intent must use the approved host capability destination")
    if not relative_gateway.startswith("/run/"):
        raise ValueError("host gateway must be in private runtime /run")
    if policy["station_state"] == policy["archive_store"]:
        raise ValueError("station data and archive data must have distinct ownership")
    return policy


def _intent(directory, expected_host_id, *, clock):
    """Re-open by name each time: atomic host-discover replacement stays visible."""
    fd = None
    file_fd = None
    try:
        fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        file_fd = os.open(
            "mirror-intent.json", os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=fd,
        )
        st = os.fstat(file_fd)
        if (not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or
                st.st_size > _MAX_INTENT or stat.S_IMODE(st.st_mode) & 0o022):
            return "intent-invalid"
        data = os.read(file_fd, _MAX_INTENT + 1)
        if len(data) > _MAX_INTENT:
            return "intent-oversized"
        raw = json.loads(data)
        if not isinstance(raw, dict):
            return "intent-invalid"
        # The exact role envelope may evolve with host-discover. Do not grant
        # permissions from an unknown shape: report only liveness/binding.
        if raw.get("version") != 1 or raw.get("host_id") != expected_host_id:
            return "intent-host-or-version-mismatch"
        desired = raw.get("desired")
        if not isinstance(desired, dict):
            return "intent-invalid"
        lease = desired.get("lease_expires_at")
        if type(lease) not in (int, float) or not 0 < lease < 2**53:
            return "intent-invalid"
        if lease <= clock():
            return "intent-expired"
        if desired.get("selected") is not True:
            return "intent-unselected"
        return "intent-live"
    except (OSError, ValueError, TypeError, UnicodeError, json.JSONDecodeError):
        return "intent-unavailable"
    finally:
        if file_fd is not None:
            os.close(file_fd)
        if fd is not None:
            os.close(fd)


def _socket(directory, basename):
    try:
        socket_path = Path(directory) / basename
        st = os.lstat(socket_path)
        if not stat.S_ISSOCK(st.st_mode):
            return "gateway-not-socket"
        if st.st_mode & 0o002:
            return "gateway-world-writable"
        # Presence is not authorization. SO_PEERCRED and adopted workspace
        # ownership must still be checked by the client/host-deploy gateway.
        return "gateway-present-unverified"
    except OSError:
        return "gateway-unavailable"


def inspect(policy, *, clock=time.time, _guest_root=Path("/")):
    policy = _parse_policy(policy, guest_root=_guest_root)
    values = {
        "station_state": _directory(policy["station_state"], "station-state", must_write=True),
        "archive_store": _directory(policy["archive_store"], "archive-store", must_write=True),
        "host_discover_credentials": _directory(
            policy["host_discover_credentials"], "host-discover-credentials"
        ),
        "host_gateway_directory": _directory(
            policy["host_gateway_directory"], "host-gateway"
        ),
    }
    if values["host_discover_credentials"] == "available":
        values["mirror_intent"] = _intent(
            policy["host_discover_credentials"], policy["expected_host_id"], clock=clock
        )
    else:
        values["mirror_intent"] = "intent-unavailable"
    if values["host_gateway_directory"] == "available":
        values["compiler_gateway"] = _socket(
            policy["host_gateway_directory"], policy["gateway_socket_name"]
        )
    else:
        values["compiler_gateway"] = "gateway-unavailable"
    # Even all these local probes cannot verify actual kernel RO mount flags,
    # server authentication, ownership or exclusive database-writing rights.
    return {
        "schema": SCHEMA,
        "safe_to_cut_over": False,
        "status": "requires-authoritative-host-acceptance",
        "checks": values,
        "required_external_evidence": [
            "box-control-kernel-mount-observation",
            "host-deploy-adopted-owner-authorization",
            "gateway-peer-credential-verification",
            "exclusive-production-database-writer",
            "durable-service-reboot-acceptance",
        ],
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description="Legacy socket-era cutover diagnostic only; NOT the HTTPS compiler RPC probe")
    parser.add_argument("--policy", required=True, help="Admin-prepared guest-visible JSON policy")
    args = parser.parse_args(argv)
    try:
        policy_path = Path(args.policy)
        if policy_path.is_symlink() or not policy_path.is_file() or policy_path.stat().st_size > 16384:
            raise ValueError("invalid policy file")
        report = inspect(json.loads(policy_path.read_text(encoding="utf-8")))
    except (OSError, ValueError, UnicodeError, json.JSONDecodeError):
        print(json.dumps({"schema": SCHEMA, "safe_to_cut_over": False, "status": "preflight-unavailable"}))
        return 2
    print(json.dumps(report, sort_keys=True))
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
