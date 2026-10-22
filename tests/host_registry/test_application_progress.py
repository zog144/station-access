"""Administrator-only application progress: no builds, no mutation, no raw errors."""
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings

from zog.station_access.host_registry.application_progress import (
    SCHEMA, snapshot,
)

BUILD="a"*32
RUNTIME="safe-runtime1"
NOW=datetime.now(timezone.utc).isoformat()


def observation(*, state="uncertain", code="build-outcome-uncertain",
                progress=None, build_id=BUILD, page=None, observed_at=None):
    now=observed_at or datetime.now(timezone.utc).isoformat()
    return {
        "schema": "zog-application-progress-v1",
        "host_id": None, "installation_id": None,
        "snapshot_id": "b"*32,"observed_at":now,
        "boot_id":None,
        "items":[{
            "application":None,"producer":"box-control",
            "operation_id":"build:"+build_id,
            "attempt_id":None,"stage_id":None,
            "package":None,"command_index":None,
            "build_job_id":build_id,"controller_request_id":"test-request",
            "runtime_id":None,"selected_software_id":None,
            "phase":"building","state":state,"observed_at":now,
            "evidence_ref":"build-job:"+build_id,
            "progress":progress,"message_code":code,
        }],
        "page":page or {
            "build_has_more":False,"runtime_has_more":False,
            "next_build":build_id,"next_runtime":None,
        },
    }


LOCAL={
    "schema": "zog-local-session-capabilities-v1",
    "supported":False,"status":"not-implemented",
    "physical_seat":"unavailable","virtual_seat":"unavailable",
    "login_role":"not-authorized","workspace_v1_is_local_seat":False,
}


@override_settings(
    STATION_ACCESS_APPLICATION_PROGRESS_ENABLED=True,
    STATION_ACCESS_APPLICATION_PROGRESS_SOCKET="/run/zog/approved-progress.sock",
    STATION_ACCESS_APPLICATION_PROGRESS_CONTROLLER_UID=1730,
)
class StationProgressTests(TestCase):
    def setUp(self):
        self.admin=get_user_model().objects.create_superuser(
            username="progress-admin",email="",password="fixture")
        self.client.force_login(self.admin)
        self.url="/api/setup/application-progress/"

    def test_bounded_authenticated_snapshot_is_not_installation_or_publication(self):
        with patch("zog.station_access.host_registry.application_progress.create_client") as factory:
            factory.return_value.snapshot.return_value=observation()
            factory.return_value.local_session.return_value=LOCAL
            result=self.client.get(self.url)
        self.assertEqual(result.status_code,200,result.content)
        self.assertEqual(result["Cache-Control"],"no-store")
        data=result.json()
        self.assertEqual(data["schema"],SCHEMA)
        self.assertTrue(data["read_only"])
        self.assertEqual(data["availability"],"observed")
        self.assertEqual(data["installation_state"],"unobserved")
        self.assertEqual(data["publication_state"],"unobserved")
        self.assertIsNone(data["host_id"])
        self.assertIsNone(data["installation_id"])
        self.assertEqual(data["items"][0]["state"],"uncertain")
        self.assertIsNone(data["items"][0]["application"])
        self.assertNotIn("progress",data["items"][0])
        self.assertNotIn("evidence_ref",data["items"][0])
        self.assertNotIn("test-private-path",str(data))
        self.assertEqual(data["local_session"]["capabilities"],LOCAL)
        factory.return_value.snapshot.assert_called_once_with(
            after_build=None,after_runtime=None,limit=4)
        factory.return_value.local_session.assert_called_once_with()

    def test_unconfigured_never_reads_controller(self):
        with override_settings(STATION_ACCESS_APPLICATION_PROGRESS_ENABLED=False),patch(
            "zog.station_access.host_registry.application_progress.create_client",
            side_effect=AssertionError("no controller")):
            result=self.client.get(self.url)
        self.assertEqual(result.status_code,200)
        self.assertEqual(result.json()["availability"],"unavailable")
        self.assertEqual(result.json()["items"],[])
        self.assertEqual(result.json()["local_session"]["availability"],"unavailable")

    def test_stale_missing_pruned_or_failed_controller_returns_unknown_not_success(self):
        with patch("zog.station_access.host_registry.application_progress.create_client") as factory:
            factory.side_effect=OSError("/protected/controller/project secret")
            result=self.client.get(self.url)
        self.assertEqual(result.json()["availability"],"unavailable")
        self.assertNotIn("/protected",result.content.decode())
        with patch("zog.station_access.host_registry.application_progress.create_client") as factory:
            factory.return_value.snapshot.return_value=observation(
                state="unknown",code="build-evidence-unavailable")
            factory.return_value.local_session.return_value=LOCAL
            result=self.client.get(self.url)
        self.assertEqual(result.json()["items"][0]["state"],"unknown")
        self.assertIn("missing or inconsistent",result.json()["items"][0]["message"])
        with patch("zog.station_access.host_registry.application_progress.create_client") as factory:
            factory.return_value.snapshot.return_value=observation(
                state="failed",code="build-command-failed")
            factory.return_value.local_session.return_value=LOCAL
            result=self.client.get(self.url)
        self.assertEqual(result.json()["items"][0]["state"],"failed")

    def test_successful_build_command_does_not_prove_software_publication(self):
        with patch("zog.station_access.host_registry.application_progress.create_client") as factory:
            factory.return_value.snapshot.return_value=observation(
                state="succeeded",code="build-command-succeeded")
            factory.return_value.local_session.return_value=LOCAL
            value=self.client.get(self.url).json()
        self.assertEqual(value["items"][0]["state"],"succeeded")
        self.assertIn("publication is not verified",value["items"][0]["message"])
        self.assertEqual(value["publication_state"],"unobserved")

    def test_invalid_schema_and_progress_fields_fail_closed(self):
        bad=observation()
        bad["items"][0]["message_code"]="private console journal "
        with patch("zog.station_access.host_registry.application_progress.create_client") as factory:
            factory.return_value.snapshot.return_value=bad
            self.assertEqual(self.client.get(self.url).json()["availability"],"unavailable")
        bad=observation(progress={"completed":99,"total":100,"unit":"guessed"})
        with patch("zog.station_access.host_registry.application_progress.create_client") as factory:
            factory.return_value.snapshot.return_value=bad
            self.assertEqual(self.client.get(self.url).json()["availability"],"unavailable")

    def test_cursor_is_explicitly_bounded_and_not_a_socket_selector(self):
        self.assertEqual(self.client.get(self.url+"?after_build=bad").status_code,400)
        self.assertEqual(self.client.get(self.url+"?socket=/tmp/other").status_code,400)
        with patch("zog.station_access.host_registry.application_progress.create_client") as factory:
            factory.return_value.snapshot.return_value=observation()
            factory.return_value.local_session.return_value=LOCAL
            value=self.client.get(self.url+"?after_build="+BUILD)
        self.assertEqual(value.status_code,200)
        factory.return_value.snapshot.assert_called_once_with(
            after_build=BUILD,after_runtime=None,limit=4)

    def test_authorization_only_superuser_no_post(self):
        self.client.logout()
        self.assertEqual(self.client.get(self.url).status_code,401)
        normal=get_user_model().objects.create_user(username="regular-viewer")
        self.client.force_login(normal)
        self.assertEqual(self.client.get(self.url).status_code,403)
        self.client.force_login(self.admin)
        self.assertEqual(self.client.post(self.url,content_type="application/json").status_code,405)
