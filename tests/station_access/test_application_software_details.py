"""Current software selection must never replace immutable launch-time evidence."""
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings

from zog.station_access.box_control.software import inspect_application
from zog.station_access.box_control.current import _runtime_summary, CurrentBoxControlGateway
from zog.station_access.api.serializers import runtime_json
from zog.box_control.model import ApplicationRuntimeState
from zog.box_control.runtime.reference import ApplicationRuntimeReference

_OLD = "sha256:" + "a" * 64
_CURRENT = "sha256:" + "b" * 64
_ARTIFACT = "sha256:" + "c" * 64


def controller(state, view=_CURRENT):
    project = SimpleNamespace(
        state_dir=state,
        application_dir=state / "definitions",
    )
    return SimpleNamespace(
        project=project,
        preflight_application_launch=lambda application: {"status": "ready-to-attempt"},
    ), lambda path: {"editor": SimpleNamespace(name="editor", software_view=view)}


def populated(state):
    directory = state / "image-build" / "application-software"
    (directory / "views" / _CURRENT[7:]).mkdir(parents=True)
    (directory / "artifacts").mkdir()
    return directory


def reference():
    return ApplicationRuntimeReference(
        runtime_id="runtime-old",
        application="editor",
        instance_id="editor",
        generation="generation-at-launch",
        state=ApplicationRuntimeState.RUNNING,
        software_view=_OLD,
        software_artifacts=(_ARTIFACT,),
        software_binding_digest="sha256:" + "d" * 64,
        software_manifest_digest="sha256:" + "e" * 64,
    )


class SoftwareDetailTests(TestCase):
    def test_absent_app_and_unselected_app_do_not_initialize_store(self):
        with TemporaryDirectory() as directory:
            state = Path(directory)
            control, discover = controller(state, view=None)
            self.assertIsNone(inspect_application(control, discover, "missing"))
            result = inspect_application(control, discover, "editor")
            self.assertEqual(result["state"], "not-selected")
            self.assertIsNone(result["view"])
            self.assertFalse((state / "image-build").exists())

    def test_selected_missing_publication_is_unavailable_not_verified(self):
        with TemporaryDirectory() as directory:
            state = Path(directory)
            control, discover = controller(state)
            result = inspect_application(control, discover, "editor")
            self.assertEqual(result["state"], "unavailable")
            self.assertEqual(result["artifacts"], [])
            self.assertEqual(result["mount_observation"], "not-probed")

    def test_detail_discloses_only_validated_and_allowlisted_evidence(self):
        with TemporaryDirectory() as directory:
            state = Path(directory)
            populated(state)
            control, discover = controller(state)
            view = SimpleNamespace(manifest={
                "application": "editor",
                "profile": "everything",
                "contract": "application-software-view-v1",
                "composition": [dict(kind="symlink")],
                "artifacts": [_ARTIFACT],
            })
            artifact = SimpleNamespace(manifest={
                "application": "editor",
                "revision": "revision-2",
                "architecture": "x86_64",
                "compatibility": {
                    "schema": 1, "mount_contract": "applications-v1",
                    "architecture": "x86_64",
                    "python": {"implementation": "cpython", "version": "3.13", "soabi": "cpython-313"},
                    "libraries": ["libc.so.6"],
                },
                "sources": [
                    {"name": "source", "url": "https://example.org/code.tar", "sha256": "f" * 64},
                    {"url": "file:///state/private-source", "sha256": "1" * 64},
                ],
                "notices": ["share/licenses/notice.txt"],
                "provenance": {"confidential_dir": "/state/internal"},
            })
            with patch("zog.station_access.box_control.software.read_view", return_value=view), patch(
                "zog.station_access.box_control.software.read_artifact", return_value=artifact
            ):
                result = inspect_application(control, discover, "editor")
            self.assertEqual(result["view"], _CURRENT)
            self.assertEqual(result["state"], "verified")
            self.assertEqual(result["profile"], "everything")
            self.assertEqual(result["launch_readiness"], "ready-to-attempt")
            self.assertEqual(result["artifacts"][0]["revision"], "revision-2")
            self.assertEqual(result["artifacts"][0]["compatibility"]["python"]["version"], "3.13")
            self.assertEqual(result["artifacts"][0]["notice_files"], ["share/licenses/notice.txt"])
            self.assertEqual(len(result["artifacts"][0]["https_sources"]), 1)
            self.assertNotIn("/state/", str(result))
            self.assertEqual(result["mount_observation"], "not-probed")

    def test_invalid_referenced_artifact_fail_closed(self):
        with TemporaryDirectory() as directory:
            state = Path(directory)
            populated(state)
            control, discover = controller(state)
            view = SimpleNamespace(manifest={
                "application": "editor", "profile": "everything", "contract": "test",
                "composition": [], "artifacts": [_ARTIFACT],
            })
            with patch("zog.station_access.box_control.software.read_view", return_value=view), patch(
                "zog.station_access.box_control.software.read_artifact",
                side_effect=ValueError("/state/private/failed")
            ):
                result = inspect_application(control, discover, "editor")
            self.assertEqual(result["state"], "unavailable")
            self.assertEqual(result["artifacts"], [])
            self.assertNotIn("/state/private", str(result))


class RuntimeBindingTests(TestCase):
    def test_actual_controller_reference_preserves_historical_software(self):
        launched = reference()
        summary = _runtime_summary(launched)
        payload = runtime_json(summary)
        self.assertEqual(payload["generation"], "generation-at-launch")
        self.assertEqual(payload["software"]["view"], _OLD)
        self.assertEqual(payload["software"]["artifacts"], [_ARTIFACT])
        self.assertEqual(payload["software"]["basis"], "expected-launched")
        self.assertEqual(payload["software"]["mount_observation"], "not-probed")
        self.assertEqual(payload["software"]["binding_digest"], "sha256:" + "d" * 64)

        gateway = CurrentBoxControlGateway.__new__(CurrentBoxControlGateway)
        gateway._control = SimpleNamespace(application_runtime=lambda rid: launched)
        fetched = gateway.get_runtime("runtime-old")
        self.assertEqual(fetched.software_view, _OLD)

    def test_existing_reference_without_binding_is_not_current_selection(self):
        legacy = SimpleNamespace(
            runtime_id="legacy", application="editor", instance_id="editor",
            state=SimpleNamespace(value="running"), generation="previous",
            created_at=1.0, completed_at=None, request_id=None,
            error=None, cleanup_error=None, workspace_binding=None,
            cleanup_pending=False, programs=(),
        )
        value = runtime_json(_runtime_summary(legacy))["software"]
        self.assertIsNone(value["view"])
        self.assertEqual(value["artifacts"], [])
        self.assertEqual(value["basis"], "expected-launched")


class SoftwareDetailApiTests(TestCase):
    def setUp(self):
        users = get_user_model()
        self.admin = users.objects.create_superuser("software-admin")
        self.member = users.objects.create_user("software-member")

    def test_detail_denies_unauthenticated_and_non_admin_before_gateway(self):
        with patch("zog.station_access.api.views.get_gateway", side_effect=AssertionError("not authorized")):
            self.assertEqual(self.client.get("/api/application-software/applications/editor/").status_code, 401)
            self.client.force_login(self.member)
            self.assertEqual(self.client.get("/api/application-software/applications/editor/").status_code, 403)

    def test_detail_does_not_cache_or_accept_mutations(self):
        self.client.force_login(self.admin)
        payload = {"schema": 1, "application": "editor", "state": "not-selected", "view": None}
        gateway = SimpleNamespace(inspect_application_software_detail=lambda name: payload if name == "editor" else None)
        with patch("zog.station_access.api.views.get_gateway", return_value=gateway):
            response = self.client.get("/api/application-software/applications/editor/")
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json()["application_software"], payload)
            self.assertIn("no-store", response["Cache-Control"])
            self.assertEqual(self.client.get("/api/application-software/applications/unknown/").status_code, 404)
            self.assertEqual(self.client.post("/api/application-software/applications/editor/").status_code, 405)

    def test_500_does_not_leak_host_private_paths(self):
        self.client.force_login(self.admin)
        gateway = SimpleNamespace(inspect_application_software_detail=lambda name: (_ for _ in ()).throw(OSError("/state/secrets")))
        with patch("zog.station_access.api.views.get_gateway", return_value=gateway):
            response = self.client.get("/api/application-software/applications/editor/")
        self.assertEqual(response.status_code, 503)
        self.assertNotIn("/state/secrets", response.content.decode())

    def test_application_detail_spa_route_supports_direct_refresh(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "index.html").write_text("<div id='root'></div>")
            with override_settings(STATION_ACCESS_FRONTEND_DIRECTORY=root):
                result = self.client.get("/application-software/applications/editor")
                self.assertEqual(result.status_code, 200)
                result.close()
