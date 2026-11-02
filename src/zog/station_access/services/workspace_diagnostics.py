"""Allowlisted, non-authorizing Workspace diagnostic projection.

Never split a combined desktop probe into invented X11 or RFB successes.
No launch, grant issuance, socket probing, or controller mutation occurs here.
"""
import math
import re
from django.utils import timezone
from zog.station_access.models import VncAccessGrant

SCHEMA = "station-workspace-diagnostics-v1"
CONTROLLER_SCHEMA = "zog-workspace-stage-readiness-v1"
# Only exact bounded codes of the selected root-control and box-control contracts.
STAGE_CODES = {
    "x11": {"confirmed": {"ok"}, "failed": {"x11-rejected", "endpoint-identity"},
            "unknown": {"probe-unavailable", "binding-unavailable"}},
    "rfb": {"confirmed": {"ok"}, "failed": {"rfb-invalid", "endpoint-identity"},
            "unknown": {"probe-unavailable", "binding-unavailable"}},
}
STAGE_EXPLANATIONS = {
    "x11": {
        "ok": "The selected desktop accepted the current X11 authorization probe.",
        "x11-rejected": "The selected X11 server rejected current authorization.",
        "endpoint-identity": "The X11 endpoint identity failed the controller peer check.",
        "probe-unavailable": "The current X11 authorization observation was unavailable.",
        "binding-unavailable": "The selected desktop X11 binding could not be verified.",
    },
    "rfb": {
        "ok": "The selected desktop supplied a valid RFB greeting.",
        "rfb-invalid": "The selected RFB endpoint returned an invalid greeting.",
        "endpoint-identity": "The RFB endpoint identity failed the controller peer check.",
        "probe-unavailable": "The current RFB observation was unavailable.",
        "binding-unavailable": "The selected desktop RFB binding could not be verified.",
    },
}


def _separate_stage_checks(raw, *, workspace_id, runtime_id, now=None):
    """Sanitize exact controller stage evidence; never pass through raw errors.

    Box-control reselects its boot, incarnation and runtime after root probing.
    Station also requires fresh opaque endpoint identity and selected runtime.
    """
    if now is None:
        now = timezone.now().timestamp()
    expected = {"schema", "workspace_id", "desktop_runtime_id", "boot_id",
                "incarnation", "endpoint_identity", "observed_at", "x11", "rfb",
                "advisory"}
    if (type(raw) is not dict or set(raw) != expected
            or raw.get("schema") != CONTROLLER_SCHEMA or raw.get("advisory") is not True
            or raw.get("workspace_id") != workspace_id
            or raw.get("desktop_runtime_id") != runtime_id
            or type(raw.get("boot_id")) is not str or not raw["boot_id"]
            or type(raw.get("incarnation")) is not str or not raw["incarnation"]
            or type(raw.get("endpoint_identity")) is not str
            or re.fullmatch(r"[0-9a-f]{64}", raw["endpoint_identity"]) is None
            or type(raw.get("observed_at")) not in (int, float)
            or not math.isfinite(raw["observed_at"])
            or not 0 <= now - raw["observed_at"] <= 5):
        return None
    observations = {}
    for key in ("x11", "rfb"):
        entry = raw.get(key)
        if (type(entry) is not dict or set(entry) != {"status", "code"}
                or entry.get("status") not in STAGE_CODES[key]
                or entry.get("code") not in STAGE_CODES[key][entry["status"]]):
            return None
        observations[key] = entry
    return observations



def _item(name, status, code, explanation, source):
    assert status in ("confirmed", "failed", "unknown")
    assert source in ("current-controller", "saved-record", "not-observed")
    return dict(condition=name, status=status, code=code,
                explanation=explanation, source=source)


def project(workspace, user, *, controller_available, runtime=None,
            runtime_identity_ok=None, desktop_access=None, stage_evidence=None):
    """Project observations made by the *current* read-only readiness request.

    desktop_access: True for an exact matched current controller desktop access
    check, False for a positively conflicting endpoint, None for unverified.
    """
    if not controller_available:
        runtime_check = _item("accepted-runtime", "unknown", "controller-unavailable",
                              "Controller is unavailable; the saved runtime ID is not live evidence.", "not-observed")
    elif not workspace.runtime_id or runtime is None:
        runtime_check = _item("accepted-runtime", "unknown", "runtime-not-observed",
                              "No current matching desktop runtime was observed.", "not-observed")
    elif runtime_identity_ok is False:
        runtime_check = _item("accepted-runtime", "failed", "runtime-identity-mismatch",
                              "Controller runtime identity does not match this Workspace.", "current-controller")
    elif runtime.terminal or runtime.state in ("failed", "terminated"):
        runtime_check = _item("accepted-runtime", "failed", "runtime-ended",
                              "The selected desktop runtime has ended.", "current-controller")
    elif runtime.state == "running" and not getattr(runtime, "cleanup_pending", False):
        runtime_check = _item("accepted-runtime", "confirmed", "runtime-running",
                              "The controller reports the exact selected desktop runtime running.", "current-controller")
    else:
        runtime_check = _item("accepted-runtime", "unknown", "runtime-not-running",
                              "The desktop has not reached a verified running state.", "current-controller")

    if runtime_check["status"] == "failed":
        desktop = _item("desktop-readiness", "failed", "desktop-runtime-invalid",
                        "Desktop readiness cannot hold when its selected runtime is invalid.", "current-controller")
    elif runtime_check["status"] != "confirmed":
        desktop = _item("desktop-readiness", "unknown", "desktop-not-observed",
                        "An active matching runtime is required before display readiness can be checked.", "not-observed")
    elif desktop_access is True:
        desktop = _item("desktop-readiness", "confirmed", "desktop-access-verified",
                        "The current controller access probe accepted the matching desktop endpoint.", "current-controller")
    elif desktop_access is False:
        desktop = _item("desktop-readiness", "failed", "desktop-endpoint-mismatch",
                        "Controller endpoint differs from this Workspace's saved endpoint.", "current-controller")
    else:
        desktop = _item("desktop-readiness", "unknown", "desktop-access-unknown",
                        "No matching current controller display-access proof is available.", "not-observed")

    # A combined desktop-ready flag never establishes independent stage success.
    x11 = _item("x11-authorization", "unknown", "x11-not-separately-observed",
                "Independent current X11 authorization evidence is unavailable.", "not-observed")
    rfb = _item("rfb-availability", "unknown", "rfb-not-separately-observed",
                "Independent current RFB availability evidence is unavailable.", "not-observed")
    if runtime_check["status"] == "confirmed" and desktop["status"] == "confirmed":
        separate = _separate_stage_checks(stage_evidence, workspace_id=str(workspace.pk),
                                           runtime_id=workspace.runtime_id)
        if separate is not None:
            def stage(name, condition):
                entry = separate[name]
                return _item(condition, entry["status"], entry["code"],
                             STAGE_EXPLANATIONS[name][entry["code"]],
                             "not-observed" if entry["status"] == "unknown" else "current-controller")
            x11 = stage("x11", "x11-authorization")
            rfb = stage("rfb", "rfb-availability")

    grant = _item("browser-grant", "unknown", "grant-not-verified",
                  "No current matching, unexpired browser grant has been verified.", "not-observed")
    if desktop["status"] == "confirmed" and workspace.endpoint_ready and workspace.runtime_id:
        try:
            # Read-only DB lookup; don't inspect/dereference secret token digests
            # or grant a new capability in a diagnostic endpoint.
            found = VncAccessGrant.objects.filter(
                workspace=workspace, user=user, revoked_at__isnull=True,
                expires_at__gt=timezone.now(), runtime_id=workspace.runtime_id,
                endpoint_revision=workspace.endpoint_revision,
                target_socket=workspace.vnc_socket,
                target_host=workspace.vnc_host or "",
                target_port=workspace.vnc_port,
            ).exists()
            if found:
                grant = _item("browser-grant", "confirmed", "grant-record-current",
                              "An unexpired, nonrevoked grant matches this runtime and endpoint. Browser connectivity is not proved.", "saved-record")
        except Exception:
            pass
    return dict(schema=SCHEMA, read_only=True, advisory=True,
                checks=[runtime_check, desktop, x11, rfb, grant])
