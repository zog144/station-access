#!/usr/bin/env python3
"""Execute actual PR #20 backend diagnostics/inspect source using inert interfaces.

Emits deterministic JSON HTTP-like response bodies for PR #21 frontend
integration. The Django model/controller imports are replaced with *minimal*
synthetic interfaces, but both real Python backend source files are executed.
No Django DB, VNC server, filesystem mutation, capability grant or network.
"""
import importlib.util
import json
import sys
import types
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

source = Path(sys.argv[1]).resolve()
out = Path(sys.argv[2]).resolve()
assert (source / "workspace_diagnostics.py").is_file()
assert (source / "workspace_readiness.py").is_file()
FIXED = datetime(2026, 11, 3, 13, 0, 0, tzinfo=timezone.utc)
BASE = "zog.station_access"
PKG = BASE + ".services"

# Prevent import of actual database, Django server and controller adapters.
for name in ("zog", BASE, PKG, "django", "django.utils"):
    item = types.ModuleType(name)
    item.__path__ = []
    sys.modules[name] = item
djtimezone = types.ModuleType("django.utils.timezone")
djtimezone.now = lambda: FIXED
sys.modules["django.utils.timezone"] = djtimezone
sys.modules["django.utils"].timezone = djtimezone

active = {"granted": False}
class GrantQuery:
    def exists(self):
        return active["granted"]
class GrantManager:
    def filter(self, **kwargs):
        assert kwargs["workspace"].runtime_id == "runtime-original"
        assert kwargs["endpoint_revision"] == 5
        assert kwargs["user"] == "owner"
        return GrantQuery()
models = types.ModuleType(BASE + ".models")
models.VncAccessGrant = type("VncAccessGrant", (), {"objects": GrantManager()})
sys.modules[models.__name__] = models

controller = types.ModuleType(PKG + ".controller_workspaces")
controller.SCHEMA = "zog-workspace-v1"
controller.access = lambda workspace, gateway: gateway.desktop_access(workspace)
sys.modules[controller.__name__] = controller
applications = types.ModuleType(PKG + ".workspace_applications")
applications.launch_actions = lambda workspace, user: []
sys.modules[applications.__name__] = applications

def load(name, filename):
    spec = importlib.util.spec_from_file_location(PKG + "." + name,
                                                   source / filename)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod
diagnostics = load("workspace_diagnostics", "workspace_diagnostics.py")
readiness = load("workspace_readiness", "workspace_readiness.py")
assert diagnostics.SCHEMA == "station-workspace-diagnostics-v1"
assert diagnostics.CONTROLLER_SCHEMA == "zog-workspace-stage-readiness-v1"

class WorkspaceQuery:
    def __init__(self, row):
        self.row = row
    def filter(self, **kw):
        assert kw == {"pk": "one"}
        return self
    def values(self, *fields):
        self.fields = fields
        return self
    def first(self):
        return {name: self.row[name] for name in self.fields}
class Workspace:
    objects = None
    pk = "one"
    runtime_id = "runtime-original"
    application_name = "desktop"
    controller_schema = controller.SCHEMA
    desired_running = True
    endpoint_ready = True
    endpoint_revision = 5
    vnc_socket = "/private/fixture-do-not-export"
    vnc_host = None
    vnc_port = None
    launch_pending = False

workspace = Workspace()
fields = ("runtime_id", "endpoint_revision", "vnc_socket",
          "controller_schema", "desired_running", "endpoint_ready")
original_row = {key: getattr(workspace, key) for key in fields}
Workspace.objects = WorkspaceQuery(original_row.copy())
runtime = SimpleNamespace(runtime_id="runtime-original",
                          workspace_id="one",application_name="desktop",
                          state="running",terminal=False,cleanup_pending=False)

def evidence(rfb="confirmed", age=0):
    return dict(schema=diagnostics.CONTROLLER_SCHEMA,
                workspace_id="one",desktop_runtime_id="runtime-original",
                boot_id="original-boot",incarnation="current-incarnation",
                endpoint_identity="a"*64,observed_at=FIXED.timestamp()-age,
                x11={"status":"confirmed","code":"ok"},
                rfb={"status":rfb,
                     "code":"ok" if rfb=="confirmed" else "rfb-invalid"},
                advisory=True)

class Gateway:
    def __init__(self, case):
        self.case = case
        self.reads = 0
    def require_workspace_contract(self):
        if self.case == "controller-offline":
            raise RuntimeError("private controller error")
    def preflight_workspace_application(self, application, workspace_id):
        assert application == "desktop" and workspace_id == "one"
        return {"schema":1,"application":application,"advisory":True,
                "status":"ready-to-attempt",
                "checks":[{"code":"image-inputs","status":"ready"}]}
    def workspace_membership(self, workspace_id):
        assert workspace_id == "one"
        return []
    def get_current_runtime(self, runtime_id):
        assert runtime_id == "runtime-original"
        self.reads += 1
        if self.case == "runtime-replaced" and self.reads > 1:
            return SimpleNamespace(**{**vars(runtime),
                                      "runtime_id":"replacement-runtime"})
        return runtime
    def desktop_access(self, workspace):
        if self.case == "rfb-failed":
            raise RuntimeError("private RFB socket")
        return workspace.vnc_socket
    def workspace_desktop_readiness(self, workspace_id):
        assert workspace_id == "one"
        if self.case == "endpoint-rotated":
            Workspace.objects.row["endpoint_revision"] = 6
        return evidence(
            rfb="failed" if self.case == "rfb-failed" else "confirmed",
            age=30 if self.case == "stale-probe" else 0)

def view(case):
    Workspace.objects.row = original_row.copy()
    active["granted"] = (case in ("healthy", "runtime-replaced",
                                 "endpoint-rotated"))
    return readiness.inspect(workspace, Gateway(case), "owner")

cases = ("healthy", "rfb-failed", "runtime-replaced", "endpoint-rotated",
         "stale-probe", "controller-offline")
reports = {case: view(case) for case in cases}
def check(name, condition):
    return next(item for item in reports[name]["diagnostics"]["checks"]
                if item["condition"] == condition)
assert check("healthy","browser-grant")["status"] == "confirmed"
assert check("rfb-failed","x11-authorization")["status"] == "confirmed"
assert check("rfb-failed","rfb-availability")["status"] == "failed"
for name in ("runtime-replaced", "endpoint-rotated"):
    assert reports[name]["desktop"] == "not-verified", name
    assert all(check(name, part)["status"] == "unknown" for part in (
        "accepted-runtime", "desktop-readiness", "x11-authorization",
        "rfb-availability", "browser-grant")), name
assert check("stale-probe","rfb-availability")["status"] == "unknown"
assert all(item["status"] == "unknown" for item in
           reports["controller-offline"]["diagnostics"]["checks"])
payload = json.dumps(reports, sort_keys=True, indent=2) + "\n"
assert "/private/" not in payload and "fixture-do-not-export" not in payload
assert "endpoint_identity" not in payload and "authorization" not in payload
out.parent.mkdir(parents=True,exist_ok=True)
out.write_text(payload)
print("Real Python backend inspect/project contract: "+", ".join(cases))
print("Generated exact bounded HTTP-like frontend response bodies; no grant minted")
