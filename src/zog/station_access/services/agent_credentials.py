"""Workspace API v1 bearer-grant issuance and verification.

Neither raw credentials nor VNC grants are persisted or accepted. Creating and
revoking credentials are operator operations, *not* agent HTTP capabilities.
"""
from __future__ import annotations

import hashlib
import hmac
import re
import secrets
import uuid
from dataclasses import dataclass
from datetime import timedelta

from django.db import transaction
from django.utils import timezone

from zog.station_access.models import AgentAccessGrant, VncWorkspace

SCHEMA = "zog-workspace-api-v1"
SCOPES = frozenset({"workspace:read", "applications:read", "runtimes:read", "logs:read"})
PREFIX = "zog_agent_v1_"
TOKEN = re.compile(r"^zog_agent_v1_([a-f0-9]{32})\.([A-Za-z0-9_-]{43})$")
MAX_WORKSPACES = 32
MAX_AGE = timedelta(days=30)


@dataclass(frozen=True)
class AgentPrincipal:
    grant_id: str
    principal_kind: str
    principal_label: str
    workspace_ids: frozenset[str]
    scopes: frozenset[str]
    workspace_owners: dict[str, str | None]


def issue_grant(*, workspace_ids, scopes, expires_at, user=None, service_name=""):
    """Issue one 256-bit secret once, after validating all workspace and identity grants."""
    if (user is None) == (not service_name):
        raise ValueError("exactly one user or service principal is required")
    if user is not None and (not user.pk or not user.is_active):
        raise ValueError("user principal must exist and be active")
    if service_name and not re.fullmatch(r"[a-z][a-z0-9-]{0,63}", service_name):
        raise ValueError("invalid service identity")
    try:
        ids = [str(uuid.UUID(str(value))) for value in workspace_ids]
    except (TypeError, ValueError, AttributeError) as exc:
        raise ValueError("invalid workspace UUID") from exc
    if not 1 <= len(ids) <= MAX_WORKSPACES or len(set(ids)) != len(ids):
        raise ValueError("grant requires 1–32 unique workspace UUIDs")
    names = list(scopes)
    if not names or len(names) != len(set(names)) or not set(names) <= SCOPES:
        raise ValueError("invalid read-only scopes")
    now = timezone.now()
    if not now < expires_at <= now + MAX_AGE:
        raise ValueError("grant expiration must be in the future, within 30 days")
    queryset = VncWorkspace.objects.filter(pk__in=ids)
    if user is not None and not user.is_superuser:
        queryset = queryset.filter(owner=user)
    owners = {str(pk): str(owner) if owner is not None else None
              for pk, owner in queryset.values_list("pk", "owner_id")}
    if len(owners) != len(ids):
        raise ValueError("principal is not authorized for every requested workspace")
    raw = secrets.token_urlsafe(32)
    if len(raw) != 43:
        raise RuntimeError("unexpected credential entropy")
    digest = hashlib.sha256(raw.encode("ascii")).hexdigest()
    with transaction.atomic():
        grant = AgentAccessGrant.objects.create(
            token_digest=digest, principal_user=user,
            service_name=service_name, workspace_ids=sorted(ids),
            workspace_owners=owners, scopes=sorted(names), expires_at=expires_at,
        )
    return grant, f"{PREFIX}{grant.pk.hex}.{raw}"


def revoke_grant(grant_id):
    return AgentAccessGrant.objects.filter(pk=grant_id, revoked_at__isnull=True).update(
        revoked_at=timezone.now()
    )


def authenticate(request):
    """Authenticate *only* Authorization: Bearer; sessions are independent."""
    value = request.META.get("HTTP_AUTHORIZATION", "")
    if not isinstance(value, str) or len(value) > 180 or not value.startswith("Bearer "):
        return None
    match = TOKEN.fullmatch(value[7:])
    if match is None:
        return None
    try:
        grant = AgentAccessGrant.objects.select_related("principal_user").get(pk=uuid.UUID(hex=match[1]))
    except AgentAccessGrant.DoesNotExist:
        return None
    if not hmac.compare_digest(
        hashlib.sha256(match[2].encode("ascii")).hexdigest(), grant.token_digest
    ):
        return None
    if grant.revoked_at is not None or grant.expires_at <= timezone.now():
        return None
    user = grant.principal_user
    if user is not None and not user.is_active:
        return None
    if (user is None) == (not grant.service_name):
        return None
    scopes = grant.scopes
    workspaces = grant.workspace_ids
    owners = grant.workspace_owners
    if (not isinstance(scopes, list) or not scopes or
            any(not isinstance(scope, str) for scope in scopes) or
            not set(scopes) <= SCOPES or
            not isinstance(workspaces, list) or not 1 <= len(workspaces) <= MAX_WORKSPACES or
            any(not isinstance(wid, str) for wid in workspaces) or
            len(set(workspaces)) != len(workspaces) or
            not isinstance(owners, dict) or set(owners) != set(workspaces) or
            any(owner is not None and not isinstance(owner, str) for owner in owners.values())):
        return None
    return AgentPrincipal(
        grant_id=str(grant.pk),
        principal_kind="user" if user is not None else "service",
        principal_label=str(user.pk) if user is not None else grant.service_name,
        workspace_ids=frozenset(workspaces), scopes=frozenset(scopes),
        workspace_owners=owners,
    )


def allows_workspace(principal, workspace):
    if str(workspace.pk) not in principal.workspace_ids:
        return False
    if principal.workspace_owners.get(str(workspace.pk), object()) != (
        str(workspace.owner_id) if workspace.owner_id is not None else None
    ):
        return False
    if principal.principal_kind != "user":
        return True
    return (workspace.owner_id is not None and (
        str(workspace.owner_id) == principal.principal_label or
        # A user-bound superuser grant is still limited to explicit IDs.
        _active_admin(principal.principal_label)
    ))


def _active_admin(user_id):
    from django.contrib.auth import get_user_model
    return get_user_model().objects.filter(pk=user_id, is_active=True, is_superuser=True).exists()
