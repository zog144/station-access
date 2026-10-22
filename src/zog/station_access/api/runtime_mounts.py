"""Allowlisted, bounded HTTP projection of trusted kernel mount observations.

The privileged reader is root-control, via box-control.  Station-access never
opens /proc, chooses a PID, or interprets a raw mountinfo/source path.  Preserve
status and non-atomicity; never turn unknown into verified observations.
"""
from __future__ import annotations

from math import isfinite

CONTRACT = "zog-runtime-mount-observation-v1"
STATUSES = frozenset({
    "observed", "partial", "absent", "previous-boot",
    "identity-unavailable", "changed-during-read", "integrity-fault",
    "unavailable", "legacy-unrecorded",
})
KINDS = frozenset({
    "runtime-root", "rootfs", "application-software-artifact",
    "application-software-view", "application-data", "workspace",
})
ACCESS = frozenset({"read-only", "read-write", "unknown"})
PRESENCE = frozenset({"present", "missing", "unknown", "inconsistent"})
BACKING = frozenset({"verified", "mismatch", "inconclusive"})


def _text(value, maximum=4096):
    if not isinstance(value, str) or len(value) > maximum or "\x00" in value:
        raise ValueError("unsupported runtime mount field")
    return value


def _mount(item):
    if not isinstance(item, dict):
        raise ValueError("invalid mount evidence")
    destination = _text(item.get("destination"))
    if not destination.startswith("/") or ".." in destination.split("/"):
        raise ValueError("unsafe mount destination")
    kind = _text(item.get("kind"), 128)
    expected = _text(item.get("expected_access"), 24)
    presence = _text(item.get("observed_presence"), 24)
    actual = _text(item.get("observed_access"), 24)
    backing = _text(item.get("backing_identity"), 24)
    if (expected not in ACCESS or actual not in ACCESS or
            presence not in PRESENCE or backing not in BACKING):
        raise ValueError("unknown mount evidence")
    # New upstream mount kinds may be safely rendered as 'other' without
    # exposing arbitrary source/provider metadata.
    return dict(
        destination=destination, kind=kind if kind in KINDS else "other",
        expected_access=expected, observed_presence=presence,
        observed_access=actual, backing_identity=backing,
    )


def _namespace(item):
    if not isinstance(item, dict):
        raise ValueError("invalid namespace observation")
    identity = _text(item.get("mount_namespace"), 128)
    if not identity.startswith("mnt:[") or not identity.endswith("]"):
        raise ValueError("invalid namespace identity")
    mounts = item.get("mounts")
    if not isinstance(mounts, list) or len(mounts) > 128:
        raise ValueError("unbounded mount observations")
    if type(item.get("truncated")) is not bool:
        raise ValueError("invalid truncation state")
    return dict(mount_namespace=identity, mounts=[_mount(x) for x in mounts],
                truncated=item["truncated"])


def project_runtime_mount_observation(raw, runtime_id):
    if not isinstance(raw, dict) or raw.get("schema") != CONTRACT or raw.get("runtime_id") != runtime_id:
        raise ValueError("unsupported or mismatched mount observation contract")
    if (raw.get("basis") != "kernel-mount-namespace" or
            raw.get("snapshot") != "non-atomic"):
        raise ValueError("unexpected observation evidence basis")
    observed_at = raw.get("observed_at")
    if type(observed_at) not in (float, int) or not isfinite(observed_at) or observed_at < 0:
        raise ValueError("invalid observation timestamp")
    status = raw.get("status")
    programs = raw.get("programs")
    if status not in STATUSES or not isinstance(programs, list) or len(programs) > 32:
        raise ValueError("unsupported runtime program observations")
    if type(raw.get("truncated")) is not bool:
        raise ValueError("invalid runtime truncation state")
    projected = []
    for program in programs:
        if not isinstance(program, dict) or program.get("status") not in STATUSES:
            raise ValueError("unsupported program mount status")
        name = _text(program.get("program"), 128)
        if type(program.get("truncated")) is not bool or type(program.get("multiple_mount_namespaces")) is not bool:
            raise ValueError("invalid program mount status flags")
        namespaces = program.get("mount_namespaces")
        mounts = program.get("mounts")
        if not isinstance(namespaces, list) or len(namespaces) > 8 or not isinstance(mounts, list) or len(mounts) > 128:
            raise ValueError("unbounded program mount observation")
        projected.append(dict(
            program=name, status=program["status"],
            truncated=program["truncated"],
            multiple_mount_namespaces=program["multiple_mount_namespaces"],
            mount_namespace=(None if program.get("mount_namespace") is None
                             else _text(program["mount_namespace"], 128)),
            mounts=[_mount(x) for x in mounts],
            mount_namespaces=[_namespace(x) for x in namespaces],
        ))
    return dict(
        schema=CONTRACT, runtime_id=runtime_id,
        basis="kernel-mount-namespace", snapshot="non-atomic",
        observed_at=observed_at, status=status,
        truncated=raw["truncated"], programs=projected,
    )
