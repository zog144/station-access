"""Workspace API 0.1.1 acceptance over a REAL loopback HTTP socket.

The client is stdlib urllib, no Django test Client/RequestFactory/WSGI shortcuts.
The server uses Django LiveServerTestCase; controller operations stay simulated.
"""
from dataclasses import replace
from datetime import timedelta
from pathlib import Path
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import LiveServerTestCase
from django.utils import timezone

from jsonschema import Draft202012Validator, FormatChecker

CONTRACT = Path(__file__).resolve().parents[2] / 'docs/station-access/contracts/workspace-agent-v1.schema.json'


from zog.station_access.box_control.fixture import FixtureGateway
from zog.station_access.models import AgentAccessGrant
from zog.station_access.services.agent_credentials import issue_grant, revoke_grant
from zog.station_access.services.workspaces import create_workspace

from tests.station_access.workspace_agent_http_client import WorkspaceApiClient


class IndependentWorkspaceHttpTests(LiveServerTestCase):
    def setUp(self):
        users = get_user_model()
        self.alice = users.objects.create_user("live-http-alice")
        self.bob = users.objects.create_user("live-http-bob")
        self.workspace = create_workspace(owner=self.alice, name="HTTP Workspace")
        self.foreign = create_workspace(owner=self.bob, name="Foreign Workspace")
        self.gateway = FixtureGateway()
        desktop = self.gateway.launch_application("vnc-workspace", request_id="http-desktop")
        desktop = replace(desktop, workspace_id=str(self.workspace.pk))
        self.gateway.runtimes[desktop.runtime_id] = desktop
        self.workspace.runtime_id = desktop.runtime_id
        self.workspace.instance_id = desktop.instance_id
        self.workspace.save()
        self.desktop = desktop
        self.gateway_patch = patch("zog.station_access.api.agent.get_gateway", return_value=self.gateway)
        self.gateway_patch.start()
        self.addCleanup(self.gateway_patch.stop)
        self.grant, self.token = issue_grant(
            user=self.alice, workspace_ids=[self.workspace.pk],
            scopes=["workspace:read", "applications:read", "runtimes:read", "logs:read"],
            expires_at=timezone.now() + timedelta(hours=1),
        )
        self.api = WorkspaceApiClient(self.live_server_url, self.token)
        import json
        self.contract = Draft202012Validator(json.loads(CONTRACT.read_text()), format_checker=FormatChecker())

    def check_contract(self, response):
        status, body, headers = response
        self.contract.validate(body)
        self.assertEqual(headers.get('Cache-Control'), 'no-store')
        return response

    def url(self, suffix=""):
        return "/api/agent/v1/" + suffix

    def test_http_response_schema_authentication_and_secret_non_disclosure(self):
        status, caps, headers = self.check_contract(self.api.get(self.url("capabilities/")))
        self.assertEqual(status, 200)
        self.assertEqual(caps["schema"], "zog-workspace-api-v1")
        self.assertTrue(caps["capabilities"]["logs"])
        self.assertEqual(headers.get("Cache-Control"), "no-store")
        self.assertEqual(headers.get("X-Content-Type-Options"), "nosniff")
        self.assertNotIn(self.token, str(caps))
        self.assertNotIn(self.token, str(AgentAccessGrant.objects.get(pk=self.grant.pk).__dict__))
        bad = WorkspaceApiClient(self.live_server_url, "not-a-real-agent-token")
        status, response, headers = self.check_contract(bad.get(self.url("workspaces/")))
        self.assertEqual((status, response["error"]["code"]), (401, "authentication_required"))
        self.assertEqual(headers.get("Cache-Control"), "no-store")

    def test_http_workspace_owner_scope_and_revocation(self):
        status, page, headers = self.check_contract(self.api.get(self.url("workspaces/"), {"limit": 1, "after": 0}))
        self.assertEqual(status, 200)
        self.assertEqual(page["pagination"]["limit"], 1)
        self.assertEqual([item["id"] for item in page["items"]], [str(self.workspace.pk)])
        self.assertNotIn(str(self.foreign.pk), str(page))
        path = self.url(f"workspaces/{self.foreign.pk}/")
        status, response, _ = self.api.get(path)
        self.assertEqual((status, response["error"]["code"]), (404, "not_found"))
        self.assertEqual(self.api.get(self.url("workspaces/"), {"limit": 51})[0], 400)
        revoke_grant(self.grant.pk)
        self.assertEqual(self.api.get(self.url("workspaces/"))[0], 401)

    def test_http_scoped_service_and_owner_transfer(self):
        grant, secret = issue_grant(
            service_name="tool-serve", workspace_ids=[self.foreign.pk],
            scopes=["workspace:read", "logs:read"],
            expires_at=timezone.now() + timedelta(hours=1),
        )
        client = WorkspaceApiClient(self.live_server_url, secret)
        status, caps, _ = client.get(self.url("capabilities/"))
        self.assertEqual(status, 200)
        self.assertFalse(caps["capabilities"]["runtime_inspection"])
        self.assertTrue(caps["capabilities"]["logs"])
        self.assertEqual(client.get(self.url(f"workspaces/{self.foreign.pk}/"))[0], 200)
        self.assertEqual(client.get(self.url(f"workspaces/{self.foreign.pk}/applications/"))[0], 403)
        self.foreign.owner = self.alice
        self.foreign.save()
        status, body, _ = client.get(self.url(f"workspaces/{self.foreign.pk}/"))
        self.assertEqual((status, body["error"]["code"]), (404, "not_found"))
        self.assertEqual(client.get(self.url("workspaces/"))[1]["items"], [])

    def test_http_runtime_identity_and_cursor_are_bound_to_workspace(self):
        root = self.url(f"workspaces/{self.workspace.pk}/runtimes/{self.desktop.runtime_id}/")
        status, detail, _ = self.check_contract(self.api.get(root))
        self.assertEqual(status, 200)
        self.assertEqual(detail["runtime"]["expected_launched"]["state"], "running")
        self.assertEqual(detail["runtime"]["expected_launched"]["software"]["basis"], "expected-launched")
        self.assertNotIn("command", str(detail))
        self.assertEqual(self.check_contract(self.api.get(root + "logs/", {"limit": 1}))[0], 200)
        cursor = self.api.get(root + "logs/", {"limit": 1})[1]["logs"]["next_cursor"]
        if cursor:
            self.assertEqual(self.api.get(root + "logs/", {"limit": 1, "cursor": cursor})[0], 200)
        self.assertEqual(self.api.get(root + "logs/", {"limit": 101})[0], 400)
        self.assertEqual(self.api.get(root + "logs/", {"cursor": "foreign:2"})[0], 410)
        # A matching station-access database ID is not controller membership.
        self.gateway.runtimes[self.desktop.runtime_id] = replace(
            self.desktop, workspace_id=str(self.foreign.pk))
        self.assertEqual(self.api.get(root)[0], 404)
        self.assertEqual(self.api.get(root + "logs/")[0], 404)

    def test_http_get_never_launches_and_controller_failure_does_not_leak_paths(self):
        with patch.object(self.gateway, "launch_application", side_effect=AssertionError("unexpected launch")), patch.object(
            self.gateway, "terminate_application_runtime", side_effect=AssertionError("unexpected stop")
        ):
            self.assertEqual(self.api.get(self.url("workspaces/"))[0], 200)
            self.assertEqual(self.api.get(self.url(f"workspaces/{self.workspace.pk}/"))[0], 200)
            self.assertEqual(self.api.get(self.url("capabilities/"))[0], 200)
        with patch("zog.station_access.api.agent.get_gateway", side_effect=OSError("/private/controller-secret")):
            status, body, _ = self.check_contract(self.api.get(self.url(f"workspaces/{self.workspace.pk}/applications/")))
        self.assertEqual((status, body["error"]["code"]), (503, "observation_unavailable"))
        self.assertTrue(body["error"]["retryable"])
        self.assertNotIn("/private", str(body))

    def test_http_credential_expiry_and_disabled_user(self):
        AgentAccessGrant.objects.filter(pk=self.grant.pk).update(
            expires_at=timezone.now() - timedelta(seconds=1))
        self.assertEqual(self.api.get(self.url("capabilities/"))[0], 401)
        AgentAccessGrant.objects.filter(pk=self.grant.pk).update(
            expires_at=timezone.now() + timedelta(hours=1))
        self.alice.is_active = False
        self.alice.save()
        self.assertEqual(self.api.get(self.url("workspaces/"))[0], 401)
