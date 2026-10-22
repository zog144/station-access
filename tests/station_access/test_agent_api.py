"""Workspace API v1: independent bearer client, authorization and read-only behavior."""
from dataclasses import replace
from datetime import timedelta
from types import SimpleNamespace
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.test import Client, TestCase
from django.utils import timezone

from zog.station_access.models import AgentAccessGrant
from zog.station_access.services.agent_credentials import issue_grant, revoke_grant
from zog.station_access.services.workspaces import create_workspace
from zog.station_access.box_control.fixture import FixtureGateway
from zog.station_access.box_control.logs import LogCursorExpired, LogsUnavailable


class WorkspaceAgentApiTests(TestCase):
    def setUp(self):
        User = get_user_model()
        self.alice = User.objects.create_user("alice-agent")
        self.bob = User.objects.create_user("bob-agent")
        self.other = create_workspace(owner=self.bob, name="Bob Workspace")
        self.workspace = create_workspace(owner=self.alice, name="Alice Workspace")
        self.gateway = FixtureGateway()
        self.gateway.calls = []
        launched = self.gateway.launch_application("vnc-workspace", request_id="desktop-req")
        self.desktop = replace(launched, workspace_id=str(self.workspace.pk))
        self.gateway.runtimes[self.desktop.runtime_id] = self.desktop
        self.workspace.runtime_id = self.desktop.runtime_id
        self.workspace.instance_id = self.desktop.instance_id
        self.workspace.save()
        self.prefix = "/api/agent/v1/"
        self.patch = patch("zog.station_access.api.agent.get_gateway", return_value=self.gateway)
        self.patch.start(); self.addCleanup(self.patch.stop)
        self.grant, self.secret = issue_grant(
            user=self.alice, workspace_ids=[self.workspace.pk],
            scopes=["workspace:read", "applications:read", "runtimes:read", "logs:read"],
            expires_at=timezone.now() + timedelta(hours=2),
        )
        self.client = Client()
        self.headers = {"HTTP_AUTHORIZATION": "Bearer " + self.secret}

    def get(self, path, params=None, headers=None):
        return self.client.get(self.prefix + path, params or {}, **(self.headers if headers is None else headers))

    def test_credential_is_never_persisted_and_browser_sessions_are_independent(self):
        self.assertNotIn(self.secret, str(AgentAccessGrant.objects.values().get(pk=self.grant.pk)))
        self.assertEqual(len(self.grant.token_digest), 64)
        self.assertNotEqual(self.grant.token_digest, self.secret)
        self.client.force_login(self.alice)
        self.assertEqual(self.client.get(self.prefix + "capabilities/").status_code, 401)
        self.assertEqual(self.get("capabilities/").status_code, 200)
        caps = self.get("capabilities/").json()
        self.assertEqual(caps["schema"], "zog-workspace-api-v1")
        self.assertFalse(caps["capabilities"]["launch"])
        self.assertTrue(caps["capabilities"]["logs"])
        self.assertEqual(self.client.get("/api/session/").status_code, 200)

    def test_user_grant_cannot_enumerate_other_workspace_even_with_known_uuid(self):
        collection = self.get("workspaces/")
        self.assertEqual(collection.status_code, 200)
        self.assertEqual([w["id"] for w in collection.json()["items"]], [str(self.workspace.pk)])
        self.assertEqual(self.get(f"workspaces/{self.other.pk}/").status_code, 404)
        self.assertEqual(self.get(f"workspaces/{self.other.pk}/applications/").status_code, 404)
        self.assertEqual(self.get(f"workspaces/{self.other.pk}/runtimes/{self.desktop.runtime_id}/").status_code, 404)
        self.assertEqual(self.get(f"workspaces/{self.other.pk}/runtimes/{self.desktop.runtime_id}/logs/").status_code, 404)
        self.assertNotIn(str(self.other.pk), str(collection.json()))
        self.assertEqual(collection["Cache-Control"], "no-store")

    def test_workspace_details_preserve_desired_expected_and_unavailable_observation(self):
        path = f"workspaces/{self.workspace.pk}/"
        result = self.get(path)
        self.assertEqual(result.status_code, 200)
        value = result.json()["workspace"]
        self.assertEqual(value["id"], str(self.workspace.pk))
        self.assertEqual(value["expected_launched"]["runtime_id"], self.desktop.runtime_id)
        self.assertEqual(value["desired"]["basis"], "station-access-persisted")
        self.assertIn(value["observed"]["basis"], ("controller-systemd-snapshot", "not-probed"))
        with patch.object(self.gateway, "get_current_runtime", side_effect=OSError("controller down"), create=True):
            unavailable = self.get(path).json()["workspace"]["observed"]
        self.assertEqual(unavailable["status"], "unavailable")
        self.assertEqual(unavailable["basis"], "not-probed")

    def test_service_credentials_revoke_expire_and_user_ownership_changes(self):
        admin_grant, admin_token = issue_grant(
            service_name="workspace-reader", workspace_ids=[self.other.pk],
            scopes=["workspace:read"], expires_at=timezone.now() + timedelta(hours=1),
        )
        service = {"HTTP_AUTHORIZATION": "Bearer " + admin_token}
        self.assertEqual(self.get("workspaces/", headers=service).status_code, 200)
        self.assertEqual([w["id"] for w in self.get("workspaces/", headers=service).json()["items"]],
                         [str(self.other.pk)])
        self.assertEqual(self.get(f"workspaces/{self.workspace.pk}/", headers=service).status_code, 404)
        self.assertEqual(self.get(f"workspaces/{self.other.pk}/applications/", headers=service).status_code, 403)
        revoke_grant(admin_grant.pk)
        self.assertEqual(self.get("workspaces/", headers=service).status_code, 401)
        AgentAccessGrant.objects.filter(pk=self.grant.pk).update(expires_at=timezone.now() - timedelta(seconds=1))
        self.assertEqual(self.get("workspaces/").status_code, 401)

    def test_scope_restriction_user_reassignment_and_invalid_tokens(self):
        narrow, token = issue_grant(user=self.alice, workspace_ids=[self.workspace.pk],
                                    scopes=["workspace:read"],
                                    expires_at=timezone.now()+timedelta(hours=1))
        hdr = {"HTTP_AUTHORIZATION":"Bearer "+token}
        self.assertEqual(self.get(f"workspaces/{self.workspace.pk}/", headers=hdr).status_code, 200)
        caps = self.get("capabilities/", headers=hdr)
        self.assertEqual(caps.status_code, 200)
        self.assertFalse(caps.json()["capabilities"]["logs"])
        self.assertEqual(self.get(f"workspaces/{self.workspace.pk}/applications/", headers=hdr).status_code, 403)
        self.assertEqual(self.get(f"workspaces/{self.workspace.pk}/runtimes/{self.desktop.runtime_id}/", headers=hdr).status_code, 403)
        self.assertEqual(self.get(f"workspaces/{self.workspace.pk}/runtimes/{self.desktop.runtime_id}/logs/", headers=hdr).status_code, 403)
        self.assertEqual(self.get("workspaces/", headers={"HTTP_AUTHORIZATION":"Bearer zog-agent-invalid"}).status_code, 401)
        self.workspace.owner = self.bob
        self.workspace.save()
        self.assertEqual(self.get(f"workspaces/{self.workspace.pk}/", headers=hdr).status_code, 404)
        self.assertEqual(self.get("workspaces/", headers=hdr).json()["items"], [])

    def test_pagination_bounds_and_get_never_mutates_lifecycle(self):
        with patch.object(self.gateway, "launch_application", side_effect=AssertionError("GET launched")), patch.object(
            self.gateway, "terminate_application_runtime", side_effect=AssertionError("GET terminated")
        ):
            first = self.get("workspaces/", {"limit": 1})
            self.assertEqual(first.status_code, 200)
            self.assertEqual(first.json()["pagination"]["limit"], 1)
            self.assertEqual(self.get("workspaces/", {"limit":51}).status_code, 400)
            self.assertEqual(self.get("workspaces/", {"after":"-1"}).status_code, 400)
            self.assertEqual(self.get("workspaces/", {"after":"absurd"}).status_code, 400)
            self.assertEqual(self.client.post(self.prefix+"workspaces/", **self.headers).status_code, 405)
            self.assertEqual(self.get(f"workspaces/{self.workspace.pk}/").status_code, 200)

    def test_controller_unavailable_and_busy_are_explicit_retryable_errors(self):
        with patch("zog.station_access.api.agent.get_gateway", side_effect=OSError("/secret/project")):
            response = self.get(f"workspaces/{self.workspace.pk}/applications/")
        self.assertEqual(response.status_code, 503)
        self.assertTrue(response.json()["error"]["retryable"])
        self.assertNotIn("/secret", response.content.decode())
        from zog.box_control.errors import ProjectBusy
        self.workspace.controller_schema = "zog-workspace-v1"
        self.workspace.save()
        with patch.object(self.gateway, "workspace_application_runtimes", side_effect=ProjectBusy("not now")):
            response = self.get(f"workspaces/{self.workspace.pk}/applications/")
        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.json()["error"]["code"], "inspection_busy")

    def test_controller_integrity_fault_preserved_without_raw_diagnostics(self):
        self.gateway.observe_runtime_state = lambda rid: {
            "runtime_id":rid, "status":"partial", "observed_at":1791650000.0,
            "fault":{"message":"/private/host-path"},
            "programs":[{"program":"desktop", "status":"integrity-fault",
                         "fault":{"details":"/private/root"}}]
        }
        result = self.get(f"workspaces/{self.workspace.pk}/").json()["workspace"]["observed"]
        self.assertEqual(result["status"], "integrity-fault")
        self.assertEqual(result["basis"], "controller-systemd-snapshot")
        self.assertEqual(result["observed_at"], 1791650000.0)
        self.assertNotIn("/private", str(result))
        self.assertNotIn("/private", self.get(f"workspaces/{self.workspace.pk}/").content.decode())

    def test_runtime_requires_exact_workspace_membership(self):
        self.workspace.controller_schema = "zog-workspace-v1"
        self.workspace.save()
        unrelated = self.gateway.launch_application("browser", request_id="unrelated")
        with patch.object(self.gateway, "workspace_application_runtimes", return_value=(unrelated,)):
            self.assertEqual(
                self.get(f"workspaces/{self.workspace.pk}/runtimes/{unrelated.runtime_id}/").status_code, 503
            )
        with patch.object(self.gateway, "workspace_application_runtimes", return_value=()):
            self.assertEqual(self.get(f"workspaces/{self.workspace.pk}/runtimes/{unrelated.runtime_id}/").status_code, 404)
        result = self.get(f"workspaces/{self.workspace.pk}/runtimes/{self.desktop.runtime_id}/")
        self.assertEqual(result.status_code, 200)
        body = result.json()["runtime"]
        self.assertEqual(body["expected_launched"]["generation"], "fixture")
        self.assertEqual(body["expected_launched"]["software"]["basis"], "expected-launched")
        self.assertEqual(body["integrity"]["status"], "unavailable")
        self.assertNotIn("command", str(body))
        self.assertNotIn("control_group", str(body))

    def test_bound_workspace_members_visible_to_service_but_foreign_runtime_is_not(self):
        from dataclasses import replace
        self.workspace.controller_schema = "zog-workspace-v1"
        self.workspace.save()
        bound = replace(self.gateway.launch_application("editor", request_id="bound"),
                        workspace_id=str(self.workspace.pk))
        foreign = replace(self.gateway.launch_application("browser", request_id="foreign"),
                          workspace_id=str(self.other.pk))
        grant, token = issue_grant(
            service_name="agent-tool", workspace_ids=[self.workspace.pk],
            scopes=["workspace:read", "applications:read", "runtimes:read", "logs:read"],
            expires_at=timezone.now() + timedelta(hours=1),
        )
        headers = {"HTTP_AUTHORIZATION": "Bearer " + token}
        with patch.object(self.gateway, "workspace_application_runtimes", return_value=(bound,)):
            result = self.get(f"workspaces/{self.workspace.pk}/applications/", headers=headers)
            self.assertEqual(result.status_code, 200)
            self.assertEqual(result.json()["membership"]["basis"], "controller-workspace-v1")
            self.assertEqual(result.json()["catalogue_scope"], "workspace-bound-only")
            self.assertEqual([r["runtime_id"] for r in result.json()["runtimes"]], [bound.runtime_id])
            self.assertEqual([a["name"] for a in result.json()["items"]], ["editor", "vnc-workspace"])
            self.assertEqual(self.get(
                f"workspaces/{self.workspace.pk}/runtimes/{bound.runtime_id}/",
                headers=headers,
            ).status_code, 200)
            self.assertEqual(self.get(
                f"workspaces/{self.workspace.pk}/runtimes/{foreign.runtime_id}/",
                headers=headers,
            ).status_code, 404)
            logs = self.get(f"workspaces/{self.workspace.pk}/runtimes/{bound.runtime_id}/logs/",
                            {"limit": 1}, headers=headers)
            self.assertEqual(logs.status_code, 200)
            self.assertEqual(len(logs.json()["logs"]["entries"]), 1)

    def test_persisted_desktop_id_without_controller_workspace_binding_is_denied(self):
        url = f"workspaces/{self.workspace.pk}/runtimes/{self.desktop.runtime_id}/"
        original = self.desktop
        self.gateway.runtimes[original.runtime_id] = replace(original, workspace_id=str(self.other.pk))
        try:
            self.assertEqual(self.get(url).status_code, 404)
            self.assertEqual(self.get(url + "logs/").status_code, 404)
            self.gateway.runtimes[original.runtime_id] = replace(original, workspace_id=None)
            self.assertEqual(self.get(url).status_code, 404)
        finally:
            self.gateway.runtimes[original.runtime_id] = original

    def test_service_grant_is_invalidated_on_workspace_owner_transfer(self):
        service, token = issue_grant(
            service_name="temporary-agent",
            workspace_ids=[self.other.pk], scopes=["workspace:read"],
            expires_at=timezone.now() + timedelta(hours=1),
        )
        headers = {"HTTP_AUTHORIZATION": "Bearer " + token}
        path = f"workspaces/{self.other.pk}/"
        self.assertEqual(self.get(path, headers=headers).status_code, 200)
        self.other.owner = self.alice
        self.other.save()
        self.assertEqual(self.get(path, headers=headers).status_code, 404)
        self.assertEqual(self.get("workspaces/", headers=headers).json()["items"], [])

    def test_vnc_grant_is_never_agent_authority(self):
        import hashlib
        import secrets
        from zog.station_access.models import VncAccessGrant
        temporary_vnc = secrets.token_urlsafe(32)
        VncAccessGrant.objects.create(
            token_digest=hashlib.sha256(temporary_vnc.encode()).hexdigest(),
            user=self.alice, workspace=self.workspace, runtime_id=self.desktop.runtime_id,
            endpoint_revision=0, target_host="127.0.0.1", expires_at=timezone.now()+timedelta(minutes=1),
        )
        self.assertEqual(self.get("workspaces/", headers={
            "HTTP_AUTHORIZATION": "Bearer " + temporary_vnc,
        }).status_code, 401)

    def test_log_scope_cursor_bounds_and_no_foreign_runtime(self):
        self.workspace.controller_schema = "zog-workspace-v1"
        self.workspace.save()
        path = f"workspaces/{self.workspace.pk}/runtimes/{self.desktop.runtime_id}/logs/"
        first = self.get(path, {"limit":2})
        self.assertEqual(first.status_code, 200)
        self.assertEqual(len(first.json()["logs"]["entries"]), 2)
        self.assertTrue(first.json()["logs"]["has_more"])
        after = first.json()["logs"]["next_cursor"]
        second = self.get(path, {"limit":2, "cursor":after})
        self.assertFalse({e["cursor"] for e in first.json()["logs"]["entries"]} &
                         {e["cursor"] for e in second.json()["logs"]["entries"]})
        self.assertEqual(self.get(path, {"limit":101}).status_code, 400)
        self.assertEqual(self.get(path, {"cursor":"x"*4097}).status_code, 400)
        self.assertEqual(self.get(path, {"program":"foreign-program"}).status_code, 404)
        self.assertEqual(self.get(path, {"cursor":"foreign:2"}).status_code, 410)
        with patch.object(self.gateway, "read_logs", side_effect=LogsUnavailable("host private")):
            self.assertEqual(self.get(path).json()["error"]["code"], "logs_unavailable")
        self.assertNotIn("host private", self.get(path).content.decode())

    def test_missing_controller_membership_does_not_infer_empty_authoritative_workspace(self):
        path = f"workspaces/{self.workspace.pk}/applications/"
        response = self.get(path)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["membership"]["status"], "unavailable")
        self.assertEqual(response.json()["runtimes"], [])

    def test_grant_creation_rejects_unsafe_scope_and_foreign_user_workspace(self):
        now = timezone.now() + timedelta(hours=1)
        with self.assertRaises(ValueError):
            issue_grant(user=self.alice, workspace_ids=[self.other.pk],
                        scopes=["workspace:read"], expires_at=now)
        with self.assertRaises(ValueError):
            issue_grant(user=self.alice, workspace_ids=[self.workspace.pk],
                        scopes=["workspace:read", "lifecycle:write"], expires_at=now)
        with self.assertRaises(ValueError):
            issue_grant(user=self.alice, workspace_ids=[self.workspace.pk],
                        scopes=["workspace:read"], expires_at=now+timedelta(days=31))
