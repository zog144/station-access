"""Allowlisted, non-authorizing Workspace diagnostic projection.

Never split a combined desktop probe into invented X11 or RFB successes.
No launch, grant issuance, socket probing, or controller mutation occurs here.
"""
from django.utils import timezone
from zog.station_access.models import VncAccessGrant

SCHEMA = "station-workspace-diagnostics-v1"


def _item(name, status, code, explanation, source):
    assert status in ("confirmed", "failed", "unknown")
    assert source in ("current-controller", "saved-record", "not-observed")
    return dict(condition=name, status=status, code=code,
                explanation=explanation, source=source)


def project(workspace, user, *, controller_available, runtime=None,
            runtime_identity_ok=None, desktop_access=None):
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

    # The existing controller access check is a combined desktop observation.
    # Neither its 'ready' flag nor a saved socket path proves each condition.
    x11 = _item("x11-authorization", "unknown", "x11-not-separately-observed",
                "The controller has not supplied separate current X11 authorization evidence.", "not-observed")
    rfb = _item("rfb-availability", "unknown", "rfb-not-separately-observed",
                "The controller has not supplied a separate current RFB availability observation.", "not-observed")

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
