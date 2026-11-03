"""Export *actual* station-access backend Workspace readiness API envelopes.

Run from a standalone checkout of selected station-access PR #20, without
calling VNC, making grants, or using a database. A full inspect() projection,
not hand-written TypeScript statuses, is serialized for the consumer suite.
"""
from __future__ import annotations

from datetime import datetime, timezone as datetime_timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
import json
import sys

import django

django.setup()
from zog.station_access.services import workspace_readiness as reader
from zog.station_access.services import workspace_diagnostics as diagnostics

INSTANT = datetime(2026, 11, 3, 12, 0, 0, tzinfo=datetime_timezone.utc)
STAMP = INSTANT.timestamp()
SCHEMA = reader.controller_workspaces.SCHEMA


class SelectedQuery:
    def __init__(self, record):
        self.record = record
        self.fields = ()
    def values(self, *fields):
        self.fields = fields
        return self
    def first(self):
        return {key: getattr(self.record, key) for key in self.fields}


class Workspace:
    pk = "workspace-one"
    application_name = "desktop"
    controller_schema = SCHEMA
    runtime_id = "desktop-one"
    endpoint_revision = 7
    vnc_socket = "/protected/runtime/vnc.sock"
    vnc_host = None
    vnc_port = None
    desired_running = True
    endpoint_ready = True
    launch_pending = False

    def __init__(self):
        self.objects = SimpleNamespace(filter=lambda **_: SelectedQuery(self))
        # inspect() obtains a class-level model manager like Django's ORM.
        type(self).objects = self.objects


def runtime(runtime_id="desktop-one"):
    return SimpleNamespace(
        runtime_id=runtime_id, workspace_id="workspace-one",
        application_name="desktop", state="running", terminal=False,
        cleanup_pending=False,
    )


def stage(**changes):
    row = dict(
        schema="zog-workspace-stage-readiness-v1",
        workspace_id="workspace-one", desktop_runtime_id="desktop-one",
        boot_id="a" * 32, incarnation="incarnation-1",
        endpoint_identity="b" * 64, observed_at=STAMP,
        x11=dict(status="confirmed", code="ok"),
        rfb=dict(status="failed", code="rfb-invalid"),
        advisory=True,
    )
    row.update(changes)
    return row


class Gateway:
    def __init__(self, *, down=False, replaced=False, stage_data=None):
        self.down = down
        self.replaced = replaced
        self.stage_data = stage_data
        self.runtime_checks = 0
        self.stage_checks = 0
    def require_workspace_contract(self):
        if self.down:
            raise RuntimeError("controller /protected/private/token is gone")
    def workspace_membership(self, workspace_id):
        assert workspace_id == "workspace-one"
        return []
    def get_current_runtime(self, runtime_id):
        assert runtime_id == "desktop-one"
        self.runtime_checks += 1
        if self.replaced and self.runtime_checks > 1:
            return runtime("other-desktop")
        return runtime()
    def workspace_desktop_readiness(self, workspace_id):
        assert workspace_id == "workspace-one"
        self.stage_checks += 1
        return self.stage_data


def scenario(*, down=False, replaced=False, stage_data=None, grant=False):
    workspace = Workspace()
    gateway = Gateway(down=down, replaced=replaced, stage_data=stage_data)
    with (
        patch.object(reader.timezone, "now", return_value=INSTANT),
        patch.object(reader, "launch_actions", return_value=[]),
        patch.object(reader, "preflight", return_value=None),
        patch.object(reader.controller_workspaces, "access", return_value=workspace.vnc_socket),
        patch.object(diagnostics.VncAccessGrant.objects, "filter") as matches,
    ):
        matches.return_value.exists.return_value = grant
        envelope = reader.inspect(workspace, gateway, object())
    assert gateway.stage_checks <= 1
    assert envelope["read_only"] is envelope["advisory"] is True
    assert envelope["diagnostics"]["schema"] == "station-workspace-diagnostics-v1"
    assert len(envelope["diagnostics"]["checks"]) == 5
    assert not any(x in json.dumps(envelope) for x in (
        "/protected/", "private/token", "b"*64))
    if down:
        matches.assert_not_called()
    return envelope


def main(destination):
    items = {
        "current": scenario(stage_data=stage(), grant=True),
        "rfb_recovered": scenario(
            stage_data=stage(rfb={"status": "confirmed", "code": "ok"}), grant=True),
        "stale_stage": scenario(stage_data=stage(observed_at=STAMP-30), grant=False),
        "foreign_stage": scenario(
            stage_data=stage(desktop_runtime_id="other-desktop"), grant=False),
        "runtime_replaced": scenario(stage_data=stage(), replaced=True, grant=False),
        "controller_unavailable": scenario(down=True),
    }
    check = lambda k, v: next(row for row in items[k]["diagnostics"]["checks"]
                               if row["condition"] == v)
    assert check("current","x11-authorization")["status"] == "confirmed"
    assert check("current","rfb-availability")["status"] == "failed"
    assert check("current","browser-grant")["source"] == "saved-record"
    assert check("stale_stage","x11-authorization")["status"] == "unknown"
    assert check("foreign_stage","rfb-availability")["status"] == "unknown"
    assert all(c["status"] == "unknown" for c in items["controller_unavailable"]["diagnostics"]["checks"])
    # A *replaced* runtime must not be represented as current despite the
    # aggregate check made before a live controller replaced it.
    assert check("runtime_replaced","accepted-runtime")["status"] != "confirmed", (
        "inconsistent controller replacement source projection")
    assert check("runtime_replaced","browser-grant")["status"] == "unknown"
    Path(destination).parent.mkdir(parents=True,exist_ok=True)
    Path(destination).write_text(json.dumps(items, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    if len(sys.argv)!=2:
        raise SystemExit("usage: python export_workspace_readiness.py OUTPUT_JSON")
    main(sys.argv[1])
