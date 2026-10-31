import hashlib
import secrets
from dataclasses import dataclass
from datetime import timedelta
from urllib.parse import urlencode

from django.conf import settings
from django.utils import timezone

from zog.station_access.box_control.port import BoxControlGateway
from zog.station_access.models import VncAccessGrant, VncWorkspace
from .locks import workspace_lock
from .workspaces import _readiness_lost


class VncAuthorizationError(PermissionError):
    pass


class VncUnavailableError(RuntimeError):
    pass


@dataclass(frozen=True)
class IssuedVncGrant:
    token: str
    expires_at: str
    novnc_url: str


def _digest(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def issue_vnc_grant(
    user, workspace: VncWorkspace, gateway: BoxControlGateway
) -> IssuedVncGrant:
    if not user.is_superuser and workspace.owner_id != user.pk:
        raise VncAuthorizationError("workspace is not owned by this user")
    if not user.is_active:
        raise VncAuthorizationError("user is inactive")

    # Serialize the probe and token creation against stop, reconciliation and
    # token resolution. Do not hold a DB transaction across controller calls.
    with workspace_lock(workspace.pk):
        workspace.refresh_from_db()
        if not workspace.desired_running or not workspace.runtime_id:
            _readiness_lost(workspace)
            raise VncUnavailableError("workspace is not running")
        if not workspace.endpoint_ready:
            # Also clean up legacy records that lost readiness without
            # revoking grants before this correction was installed.
            _readiness_lost(workspace)
            raise VncUnavailableError("workspace display is not ready")
        try:
            runtime = getattr(gateway, "get_current_runtime", gateway.get_runtime)(workspace.runtime_id)
            if (runtime is None or runtime.terminal
                    or runtime.application_name != workspace.application_name):
                raise VncUnavailableError("workspace runtime is not active or is inconsistent")
            if workspace.controller_schema:
                from .controller_workspaces import access
                if access(workspace, gateway) != workspace.vnc_socket:
                    raise VncUnavailableError("Desktop endpoint changed; request a new grant")
            elif (not workspace.vnc_host or workspace.vnc_port is None
                    or not 1 <= int(workspace.vnc_port) <= 65535):
                raise VncUnavailableError("workspace VNC endpoint is not bound")
        except Exception:
            # A failed X11/RFB/controller probe is a transition out of ready.
            # Never let an existing token resurrect if it later succeeds.
            _readiness_lost(workspace)
            raise VncUnavailableError("workspace desktop verification unavailable") from None

        now = timezone.now()
        VncAccessGrant.objects.filter(expires_at__lt=now - timedelta(minutes=5)).delete()
        token = secrets.token_urlsafe(32)
        expires_at = now + timedelta(seconds=settings.STATION_ACCESS_VNC_TOKEN_TTL_SECONDS)
        VncAccessGrant.objects.create(
            token_digest=_digest(token),
            user=user,
            workspace=workspace,
            runtime_id=runtime.runtime_id,
            endpoint_revision=workspace.endpoint_revision,
            target_host=workspace.vnc_host or "",
            target_socket=workspace.vnc_socket,
            target_port=workspace.vnc_port,
            expires_at=expires_at,
        )

    websocket_path = f"{settings.STATION_ACCESS_WEBSOCKIFY_PATH}?{urlencode({'token': token})}"
    novnc_query = urlencode({"autoconnect": "1", "resize": "scale", "path": websocket_path})
    return IssuedVncGrant(
        token=token,
        expires_at=expires_at.isoformat(),
        novnc_url=f"{settings.STATION_ACCESS_NOVNC_PATH}?{novnc_query}",
    )


def resolve_vnc_target(token: str, gateway: BoxControlGateway):
    now = timezone.now()
    try:
        initial = VncAccessGrant.objects.only("workspace_id").get(token_digest=_digest(token))
    except VncAccessGrant.DoesNotExist:
        return None

    # The untrusted token only selects the lock. Re-read grant and Workspace
    # inside it, so readiness loss cannot race an old token's endpoint check.
    with workspace_lock(initial.workspace_id):
        try:
            grant = VncAccessGrant.objects.select_related(
                "workspace", "workspace__owner", "user"
            ).get(token_digest=_digest(token), workspace_id=initial.workspace_id)
        except VncAccessGrant.DoesNotExist:
            return None
        workspace = grant.workspace
        if grant.revoked_at is not None or grant.expires_at <= now:
            return None
        if not grant.user.is_active or (workspace.owner_id != grant.user_id and not grant.user.is_superuser):
            return None
        if (not workspace.endpoint_ready or not workspace.desired_running
                or workspace.runtime_id != grant.runtime_id):
            _readiness_lost(workspace)
            return None
        if workspace.endpoint_revision != grant.endpoint_revision:
            return None
        if ((workspace.vnc_host or "") != grant.target_host
                or workspace.vnc_port != grant.target_port
                or workspace.vnc_socket != grant.target_socket):
            _readiness_lost(workspace)
            return None
        try:
            runtime = getattr(gateway, "get_current_runtime", gateway.get_runtime)(grant.runtime_id)
            if (runtime is None or runtime.terminal
                    or runtime.application_name != workspace.application_name):
                raise VncUnavailableError("desktop runtime is unavailable")
            if workspace.controller_schema:
                from .controller_workspaces import access
                if access(workspace, gateway) != grant.target_socket:
                    raise VncUnavailableError("desktop endpoint is inconsistent")
                return "unix_socket", grant.target_socket
        except Exception:
            _readiness_lost(workspace)
            return None
        return grant.target_host, grant.target_port


def revoke_vnc_token_on_controller_loss(token: str):
    """A rejected websockify gateway lookup is permanent for existing tokens.

    The controller might be offline before resolve_vnc_target can probe it.
    Bind to the saved workspace under its lock, then fence every old grant.
    No token, certificate, or controller secret is returned.
    """
    try:
        initial = VncAccessGrant.objects.only("workspace_id").get(token_digest=_digest(token))
    except VncAccessGrant.DoesNotExist:
        return
    with workspace_lock(initial.workspace_id):
        try:
            grant = VncAccessGrant.objects.select_related("workspace").get(
                token_digest=_digest(token), workspace_id=initial.workspace_id)
        except VncAccessGrant.DoesNotExist:
            return
        if grant.revoked_at is None and grant.expires_at > timezone.now():
            _readiness_lost(grant.workspace)
