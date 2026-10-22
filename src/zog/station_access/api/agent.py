"""Workspace API 0.1: read-only, versioned machine inspection.

Principal authorization precedes controller access. No lifecycle methods are
invoked. A service grant is scoped to explicitly allowed Workspace UUIDs;
runtime inspection additionally requires authoritative controller membership.
"""
from __future__ import annotations

from dataclasses import asdict
from functools import wraps

from django.http import JsonResponse

from zog.station_access.models import VncWorkspace
from zog.station_access.box_control import BoxControlUnavailable, get_gateway
from zog.station_access.box_control.logs import LogsUnavailable, LogCursorExpired, validate_page
from zog.station_access.services.agent_credentials import (
    SCHEMA, SCOPES, authenticate, allows_workspace,
)
from zog.station_access.services.authorization import accessible_application_names
from .serializers import application_json, runtime_json

MAX_PAGE = 50


def _reply(data, status=200):
    body = {"schema": SCHEMA, **data}
    response = JsonResponse(body, status=status)
    response["Cache-Control"] = "no-store"
    response["X-Content-Type-Options"] = "nosniff"
    return response


def _error(code, status, *, retryable=False):
    return _reply({"error": {"code": code, "retryable": retryable}}, status=status)


def _require(scope):
    def decorate(fn):
        @wraps(fn)
        def wrapped(request, *args, **kwargs):
            if request.method != "GET":
                return _error("method_not_allowed", 405)
            principal = authenticate(request)
            if principal is None:
                return _error("authentication_required", 401)
            if scope is not None and scope not in principal.scopes:
                return _error("insufficient_scope", 403)
            return fn(request, principal, *args, **kwargs)
        return wrapped
    return decorate


def _workspace(principal, workspace_id):
    identity = str(workspace_id)
    if identity not in principal.workspace_ids:
        return None
    workspace = VncWorkspace.objects.filter(pk=workspace_id).first()
    if workspace is None or not allows_workspace(principal, workspace):
        return None
    return workspace


def _gateway():
    try:
        return get_gateway(), None
    except BoxControlUnavailable:
        return None, _error("observation_unavailable", 503, retryable=True)
    except Exception:
        return None, _error("observation_unavailable", 503, retryable=True)


def _controller_error(exc):
    try:
        from zog.box_control.errors import ProjectBusy
        if isinstance(exc, ProjectBusy):
            return _error("inspection_busy", 503, retryable=True)
    except ImportError:
        pass
    return _error("observation_unavailable", 503, retryable=True)


def _paging(request, *, maximum=MAX_PAGE):
    try:
        limit = int(request.GET.get("limit", "20"))
        after = int(request.GET.get("after", "0"))
        if not 1 <= limit <= maximum or not 0 <= after <= 100000:
            raise ValueError
        if str(limit) != request.GET.get("limit", str(limit)) or str(after) != request.GET.get("after", str(after)):
            raise ValueError
    except (TypeError, ValueError):
        return None
    return (after, limit)


def _page(items, bounds):
    after, limit = bounds
    values = items[after:after + limit]
    next_position = after + len(values)
    return {"items": values, "pagination": {
        "limit": limit, "next_cursor": str(next_position) if next_position < len(items) else None,
        "has_more": next_position < len(items),
    }}


def _expected_workspace(workspace):
    return {
        "id": str(workspace.pk), "name": workspace.name, "number": workspace.number,
        "desired": {"running": workspace.desired_running, "basis": "station-access-persisted"},
        "expected_launched": {
            "runtime_id": workspace.runtime_id, "instance_id": workspace.instance_id,
            "launch_pending": workspace.launch_pending, "basis": "station-access-persisted",
        },
        "recorded_updated_at": workspace.updated_at.isoformat(),
    }


def _systemd_observation(gateway, runtime_id):
    """Allowlisted controller summary; preserve integrity faults and unknowns."""
    if not runtime_id:
        return {"status": "not-requested", "basis": "not-probed", "observed_at": None}
    if gateway is None:
        return {"status": "unavailable", "basis": "not-probed", "observed_at": None}
    try:
        observe = getattr(gateway, "observe_runtime_state", None)
        if callable(observe):
            snapshot = observe(runtime_id)
            if snapshot.get("runtime_id") != runtime_id:
                raise ValueError("controller returned unrelated runtime")
            programs = snapshot.get("programs", [])
            if not isinstance(programs, list) or len(programs) > 32:
                raise ValueError("invalid controller program snapshot")
            statuses = [p.get("status") for p in programs]
            allowed = {"observed", "absent", "identity-unavailable", "previous-boot",
                       "integrity-fault", "unavailable"}
            if any(value not in allowed for value in statuses):
                raise ValueError("unexpected controller observation state")
            from math import isfinite
            at = snapshot.get("observed_at")
            if type(at) not in (int, float) or not isfinite(at) or at < 0:
                raise ValueError("invalid observation time")
            if "integrity-fault" in statuses:
                status = "integrity-fault"
            elif "unavailable" in statuses:
                status = "unavailable"
            elif "identity-unavailable" in statuses:
                status = "identity-unavailable"
            elif "previous-boot" in statuses:
                status = "previous-boot"
            elif statuses and all(s == "absent" for s in statuses):
                status = "absent"
            elif snapshot.get("status") == "observed":
                status = "observed"
            else:
                status = "partial"
            return {"status": status, "basis": "controller-systemd-snapshot",
                    "observed_at": at}
        current = gateway.get_current_runtime(runtime_id)
        if current is None or current.runtime_id != runtime_id:
            raise ValueError("current runtime identity unavailable")
        return {"status": current.state, "basis": "controller-systemd-snapshot",
                "observed_at": None}
    except Exception:
        return {"status": "unavailable", "basis": "not-probed", "observed_at": None}


def _workspace_observation(workspace, gateway):
    return _systemd_observation(gateway, workspace.runtime_id)


@_require(None)
def capabilities(request, principal):
    return _reply({
        "principal": {"kind": principal.principal_kind, "grant_id": principal.grant_id},
        "capabilities": {
            "workspace_inspection": "workspace:read" in principal.scopes,
            "application_inspection": "applications:read" in principal.scopes,
            "runtime_inspection": "runtimes:read" in principal.scopes,
            "logs": "logs:read" in principal.scopes,
            "launch": False, "stop": False, "desktop_input": False,
            "screenshots": False, "live_mount_observation": False,
        },
        "pagination": {"max_limit": MAX_PAGE, "cursor": "decimal-offset"},
        "evidence": {"controller_observation": "read-only", "kernel_mounts": "unsupported"},
    })


@_require("workspace:read")
def workspaces(request, principal):
    bounds = _paging(request)
    if bounds is None:
        return _error("invalid_pagination", 400)
    queryset = VncWorkspace.objects.filter(pk__in=principal.workspace_ids).order_by("number", "id")
    accessible = [w for w in queryset if allows_workspace(principal, w)]
    gateway, _error_ignored = _gateway()
    items = [{**_expected_workspace(w), "observed": _workspace_observation(w, gateway)}
             for w in accessible[bounds[0]:bounds[0]+bounds[1]]]
    page = _page(accessible, bounds)
    page["items"] = items
    return _reply({**page, "state_source": "persisted-and-advisory-observation"})


@_require("workspace:read")
def workspace_detail(request, principal, workspace_id):
    workspace = _workspace(principal, workspace_id)
    if workspace is None:
        return _error("not_found", 404)
    gateway, _err = _gateway()
    return _reply({"workspace": {
        **_expected_workspace(workspace),
        "observed": _workspace_observation(workspace, gateway),
    }})


def _members(workspace, gateway):
    """Never infer membership from a free-form runtime ID or global list."""
    if not workspace.controller_schema:
        return None
    values = gateway.workspace_application_runtimes(str(workspace.pk))
    members = []
    for value in values:
        if value.workspace_id != str(workspace.pk):
            raise ValueError("controller returned a foreign Workspace runtime")
        members.append(value)
    return members


def _member_runtime(workspace, gateway, runtime_id):
    # A matching station-access persisted field is NOT proof of runtime
    # membership; the controller's immutable launch binding is authoritative.
    # This also rejects legacy runtimes without an explicit Workspace UUID.
    if runtime_id == workspace.runtime_id:
        result = gateway.get_runtime(runtime_id)
        if (result is not None and result.runtime_id == runtime_id and
                result.workspace_id == str(workspace.pk) and
                result.application_name == workspace.application_name):
            return result
        return None
    values = _members(workspace, gateway)
    if values is None:
        return None
    return next((value for value in values
                 if value.runtime_id == runtime_id and
                 value.workspace_id == str(workspace.pk)), None)


@_require("applications:read")
def workspace_applications(request, principal, workspace_id):
    workspace = _workspace(principal, workspace_id)
    if workspace is None:
        return _error("not_found", 404)
    bounds = _paging(request)
    if bounds is None:
        return _error("invalid_pagination", 400)
    gateway, error = _gateway()
    if error:
        return error
    try:
        members = _members(workspace, gateway)
        names = {runtime.application_name for runtime in members} if members is not None else set()
        names.add(workspace.application_name)
        if principal.principal_kind == "user":
            from django.contrib.auth import get_user_model
            user = get_user_model().objects.get(pk=principal.principal_label)
            allowed = accessible_application_names(user)
            if allowed is None:
                names.update(a.name for a in gateway.list_applications())
            else:
                names.update(allowed)
        catalogue = [application_json(a) for a in gateway.list_applications() if a.name in names]
        catalogue.sort(key=lambda a: a["name"])
        page = _page(catalogue, bounds)
        return _reply({
            "workspace_id": str(workspace.pk),
            "membership": {
                "status": "recorded-controller" if members is not None else "unavailable",
                "basis": "controller-workspace-v1" if members is not None else "not-probed",
            },
            "catalogue_scope": "user-authorized" if principal.principal_kind == "user" else "workspace-bound-only",
            **page,
            "runtimes": [
                {"runtime_id": r.runtime_id, "application_name": r.application_name,
                 "state": r.state, "basis": "expected-launched"}
                for r in (members or ())[:MAX_PAGE]
            ],
            "runtimes_truncated": members is not None and len(members) > MAX_PAGE,
        })
    except Exception as exc:
        return _controller_error(exc)


def _read_runtime(request, principal, workspace_id, runtime_id):
    workspace = _workspace(principal, workspace_id)
    if workspace is None:
        return None, None, _error("not_found", 404)
    gateway, error = _gateway()
    if error:
        return None, None, error
    try:
        runtime = _member_runtime(workspace, gateway, runtime_id)
    except Exception as exc:
        return None, None, _controller_error(exc)
    if runtime is None or runtime.runtime_id != runtime_id:
        return None, None, _error("not_found", 404)
    return gateway, runtime, None


@_require("runtimes:read")
def runtime_detail(request, principal, workspace_id, runtime_id):
    gateway, runtime, error = _read_runtime(request, principal, workspace_id, runtime_id)
    if error:
        return error
    observed = _systemd_observation(gateway, runtime.runtime_id)
    payload = runtime_json(runtime)
    return _reply({"workspace_id": str(workspace_id),
                   "runtime": {
                       "runtime_id": payload["runtime_id"],
                       "application_name": payload["application_name"],
                       "instance_id": payload["instance_id"],
                       "expected_launched": {
                           "basis": "controller-persisted-runtime",
                           "state": payload["state"],
                           "generation": payload["generation"],
                           "software": payload["software"],
                           "created_at": payload["created_at"],
                           "completed_at": payload["completed_at"],
                       },
                       "observed": observed,
                       "integrity": {"status": "unavailable", "basis": "not-probed"},
                       "programs": [{
                           "name": p["name"], "state": p["state"], "result": p["result"],
                           "invocation_id": p["invocation_id"],
                       } for p in payload["programs"]],
                   }})


@_require("logs:read")
def runtime_logs(request, principal, workspace_id, runtime_id):
    gateway, runtime, error = _read_runtime(request, principal, workspace_id, runtime_id)
    if error:
        return error
    program = request.GET.get("program") or None
    if program and program not in {p.name for p in runtime.programs}:
        return _error("not_found", 404)
    cursor = request.GET.get("cursor") or None
    if cursor is not None and len(cursor) > 4096:
        return _error("invalid_log_query", 400)
    try:
        limit = int(request.GET.get("limit", "50"))
        if not 1 <= limit <= 100:
            raise ValueError
    except ValueError:
        return _error("invalid_log_query", 400)
    try:
        page = validate_page(
            gateway.read_logs(runtime.runtime_id, program=program, cursor=cursor, limit=limit),
            runtime, limit
        )
        if program and any(entry.program != program for entry in page.entries):
            raise LogsUnavailable("log returned an unrelated program")
    except LogCursorExpired:
        return _error("log_cursor_expired", 410)
    except LogsUnavailable:
        return _error("logs_unavailable", 503, retryable=True)
    except Exception as exc:
        return _controller_error(exc)
    return _reply({
        "workspace_id": str(workspace_id), "runtime_id": runtime.runtime_id,
        "logs": {
            "entries": [{
                "cursor": e.cursor, "timestamp": e.timestamp,
                "program": e.program, "priority": e.priority, "message": e.message,
                "invocation_id": e.invocation_id,
            } for e in page.entries],
            "next_cursor": page.next_cursor, "has_more": page.has_more,
            "source": page.source, "status": page.status,
            "basis": "journald-invocation" if page.source == "journald" else "test-fixture",
        },
    })
