"""Read-only controller-owner progress adapter for station administrators.

Transport and controller-owner identity are pinned through operator-reviewed
deployment settings. The browser cannot choose socket, UID, project, jobs,
host identity, software, process, log source or a mutation action.

The box-control client enforces wire shape, SO_PEERCRED controller UID,
freshness and bounded producer enums before we project any user-visible data.
"""
from __future__ import annotations

import re

from django.conf import settings

SCHEMA = "zog-station-application-progress-view-v1"
MESSAGES = {
    "build-awaiting-start": "Build request is waiting to start",
    "build-job-running": "Build command is running; completion is not estimated",
    "build-command-succeeded": "Build command succeeded; publication is not verified",
    "build-command-cancelled": "Build command was cancelled",
    "build-command-failed": "Build command failed",
    "build-outcome-uncertain": "Build command outcome needs reconciliation",
    "build-state-unrecognized": "Build state is not recognized",
    "build-state-unobserved": "Saved build state has no matching live observation",
    "build-evidence-unavailable": "Build job evidence is missing or inconsistent",
    "runtime-observation-unavailable": "Application runtime lacks current live evidence",
    "runtime-observed-active": "Application programs were observed active on this boot",
    "runtime-terminated-successfully": "Runtime terminated successfully; display readiness is not verified",
    "runtime-terminal-unverified": "Runtime completion is unverified",
    "runtime-failed": "Application runtime failed",
    "runtime-cleanup-or-state-uncertain": "Runtime cleanup or state is uncertain",
}
HEX = re.compile(r"[0-9a-f]{32}\Z")
RUNTIME = re.compile(r"[A-Za-z0-9-]{1,80}\Z")
PHASES = {"queued", "building", "launching"}
STATES = {"waiting", "running", "succeeded", "blocked", "failed",
          "cancelled", "uncertain", "unknown"}
ID_FIELDS = ("application", "operation_id", "controller_request_id",
             "runtime_id", "build_job_id", "selected_software_id")
LOCAL_SESSION = {
    "schema": "zog-local-session-capabilities-v1", "supported": False,
    "status": "not-implemented", "physical_seat": "unavailable",
    "virtual_seat": "unavailable", "login_role": "not-authorized",
    "workspace_v1_is_local_seat": False,
}


class ProgressUnavailable(Exception):
    pass


class BadCursor(ValueError):
    pass


def create_client():
    from zog.box_control.application_progress_client import ApplicationProgressClient
    socket = getattr(settings, "STATION_ACCESS_APPLICATION_PROGRESS_SOCKET", "")
    uid = getattr(settings, "STATION_ACCESS_APPLICATION_PROGRESS_CONTROLLER_UID", None)
    if not socket or type(uid) is not int or uid <= 0:
        raise ProgressUnavailable("controller observer is not configured")
    return ApplicationProgressClient(socket, controller_uid=uid, timeout_seconds=12)


def _unavailable():
    return {
        "schema": SCHEMA, "read_only": True,
        "availability": "unavailable", "observed_at": None,
        "snapshot_id": None, "boot_id": None,
        "host_id": None, "installation_id": None,
        "installation_state": "unobserved",
        "publication_state": "unobserved",
        "items": [], "page": None,
        "local_session": {"availability": "unavailable", "capabilities": None},
    }


def _cursors(after_build, after_runtime):
    if after_build is not None and not HEX.fullmatch(after_build):
        raise BadCursor("invalid-progress-cursor")
    if after_runtime is not None and not RUNTIME.fullmatch(after_runtime):
        raise BadCursor("invalid-progress-cursor")


def snapshot(*, after_build=None, after_runtime=None):
    """One bounded page, not an atomic controller/build/install snapshot."""
    _cursors(after_build, after_runtime)
    if not getattr(settings, "STATION_ACCESS_APPLICATION_PROGRESS_ENABLED", False):
        return _unavailable()
    try:
        client = create_client()
        view = client.snapshot(after_build=after_build, after_runtime=after_runtime, limit=4)
        # Source client is strict but do not accept a mock/older producer that
        # silently changes the vocabulary or adds unsafe display fields.
        if (type(view) is not dict
                or view.get("schema") != "zog-application-progress-v1"
                or view.get("host_id") is not None
                or view.get("installation_id") is not None
                or type(view.get("items")) is not list
                or len(view["items"]) > 8):
            raise ProgressUnavailable()
        items = []
        for item in view["items"]:
            if (type(item) is not dict or item.get("producer") != "box-control"
                    or item.get("phase") not in PHASES
                    or item.get("state") not in STATES
                    or item.get("message_code") not in MESSAGES
                    or item.get("progress") is not None
                    or any(item.get(key) is not None and type(item[key]) is not str
                           for key in ID_FIELDS)):
                raise ProgressUnavailable()
            items.append({
                "producer": "box-control",
                "application": item.get("application"),
                "operation_id": item.get("operation_id"),
                "build_job_id": item.get("build_job_id"),
                "runtime_id": item.get("runtime_id"),
                "controller_request_id": item.get("controller_request_id"),
                "selected_software_id": item.get("selected_software_id"),
                "phase": item["phase"], "state": item["state"],
                "message_code": item["message_code"],
                "message": MESSAGES[item["message_code"]],
            })
        page = view.get("page")
        if (type(page) is not dict or
                set(page) != {"build_has_more", "runtime_has_more",
                              "next_build", "next_runtime"}
                or type(page["build_has_more"]) is not bool
                or type(page["runtime_has_more"]) is not bool):
            raise ProgressUnavailable()
        _cursors(page["next_build"], page["next_runtime"])
        try:
            local = client.local_session()
            if local != LOCAL_SESSION:
                raise ProgressUnavailable()
            local_result = {"availability": "observed", "capabilities": LOCAL_SESSION}
        except Exception:
            local_result = {"availability": "unavailable", "capabilities": None}
        return {
            "schema": SCHEMA, "read_only": True,
            "availability": "observed",
            "observed_at": view["observed_at"],
            "snapshot_id": view["snapshot_id"],
            "boot_id": view["boot_id"],
            # Null is deliberate: neither host-install identity nor
            # command-center admission can be inferred from this producer.
            "host_id": None, "installation_id": None,
            "installation_state": "unobserved",
            "publication_state": "unobserved",
            "items": items, "page": page,
            "local_session": local_result,
        }
    except Exception:
        # No transport exception, socket location, project path, argv, log,
        # controller exception or unsanitized producer data leaves Django.
        return _unavailable()
