"""Read-only application software inspection and administrator boundary."""
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase

from zog.station_access.box_control.software import inspect


_ID = "sha256:" + "a" * 64
_ARTIFACT = "sha256:" + "b" * 64


def _control(path, *, view=_ID):
    project = SimpleNamespace(
        state_dir=path,
        application_dir=path / "application-declarations",
    )
    control = SimpleNamespace(
        project=project,
        application_runtimes=lambda: {
            "one": SimpleNamespace(software_view=view),
            "two": SimpleNamespace(software_view=None),
        },
        preflight_application_launch=lambda name: {"status": "ready-to-attempt"},
    )
    discover = lambda root: {"editor": SimpleNamespace(name="editor", software_view=view)}
    return control, discover


class SoftwareProjectionTests(TestCase):
    def test_unpublished_selection_is_not_reported_as_verified(self):
        with TemporaryDirectory() as directory:
            control, discover = _control(Path(directory))
            result = inspect(control, discover)
            self.assertEqual(result["store"], "unavailable")
            self.assertEqual(result["views"][0]["state"], "unavailable")
            self.assertEqual(result["views"][0]["launch_readiness"], "not-verified")
            self.assertEqual(result["views"][0]["runtime_count"], 1)
            self.assertEqual(result["mount_observation"], "not-probed")
            self.assertFalse((Path(directory) / "image-build").exists())

    def test_validated_publication_projects_only_safe_fields(self):
        with TemporaryDirectory() as directory:
            state = Path(directory)
            root = state / "image-build" / "application-software"
            (root / "views" / _ID[7:]).mkdir(parents=True)
            (root / "artifacts").mkdir()
            control, discover = _control(state)
            view = SimpleNamespace(manifest={
                "application": "editor", "profile": "everything",
                "artifacts": [_ARTIFACT], "composition": [{"kind": "symlink"}],
            })
            artifact = SimpleNamespace(manifest={
                "application": "editor", "revision": "v1", "architecture": "x86_64",
                "sources": [
                    {"name": "upstream", "url": "https://example.org/source", "sha256": "c" * 64},
                    {"url": "file:///private/root/source", "sha256": "d" * 64},
                    {"url": "https://example.org/?private=opaque", "sha256": "e" * 64},
                ],
                "notices": ["share/licenses/notice.txt"],
                "provenance": {"private_path": "/do-not-expose"},
            })
            with patch("zog.station_access.box_control.software.read_view", return_value=view) as verified, patch(
                "zog.station_access.box_control.software.read_artifact", return_value=artifact
            ) as artifact_reader:
                data = inspect(control, discover)
            verified.assert_called_once()
            artifact_reader.assert_called()
            self.assertEqual(data["views"][0]["state"], "verified")
            self.assertEqual(data["views"][0]["launch_readiness"], "ready-to-attempt")
            self.assertEqual(data["views"][0]["runtime_count"], 1)
            self.assertEqual(data["artifacts"][0]["source_count"], 3)
            self.assertEqual(len(data["artifacts"][0]["https_sources"]), 1)
            self.assertEqual(data["artifacts"][0]["notice_count"], 1)
            self.assertNotIn("/private/", str(data))
            self.assertNotIn("/do-not-expose", str(data))
            self.assertEqual(data["mount_observation"], "not-probed")

    def test_invalid_manifest_is_not_promoted_and_never_leaks_error_paths(self):
        with TemporaryDirectory() as directory:
            state = Path(directory)
            root = state / "image-build" / "application-software"
            (root / "views" / _ID[7:]).mkdir(parents=True)
            (root / "artifacts").mkdir()
            control, discover = _control(state)
            with patch("zog.station_access.box_control.software.read_view", side_effect=ValueError("/private/token")):
                result = inspect(control, discover)
            self.assertEqual(result["views"][0]["state"], "unavailable")
            self.assertNotIn("/private/token", str(result))

    def test_symlink_store_is_not_traversed(self):
        with TemporaryDirectory() as directory:
            base = Path(directory)
            outside = base / "outside"
            (outside / "views").mkdir(parents=True)
            (outside / "artifacts").mkdir()
            (base / "image-build").mkdir()
            (base / "image-build" / "application-software").symlink_to(outside)
            control, discover = _control(base)
            with patch("zog.station_access.box_control.software.read_view", side_effect=AssertionError("must not read")):
                result = inspect(control, discover)
            self.assertEqual(result["store"], "unavailable")
            self.assertEqual(result["views"][0]["state"], "unavailable")


class SoftwareApiTests(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user("software-reader")
        self.admin = get_user_model().objects.create_superuser("software-admin")

    def test_requires_admin_before_controller_access(self):
        with patch("zog.station_access.api.views.get_gateway", side_effect=AssertionError("must not inspect")):
            self.assertEqual(self.client.get("/api/application-software/").status_code, 401)
            self.client.force_login(self.user)
            self.assertEqual(self.client.get("/api/application-software/").status_code, 403)

    def test_read_only_result_is_not_cached(self):
        self.client.force_login(self.admin)
        payload = {"schema": 1, "read_only": True, "views": [], "artifacts": []}
        gateway = SimpleNamespace(inspect_application_software=lambda: payload)
        with patch("zog.station_access.api.views.get_gateway", return_value=gateway):
            result = self.client.get("/api/application-software/")
        self.assertEqual(result.status_code, 200)
        self.assertEqual(result.json(), payload)
        self.assertIn("no-store", result["Cache-Control"])
        self.assertEqual(self.client.post("/api/application-software/").status_code, 405)

    def test_inspection_failure_does_not_leak_local_path(self):
        self.client.force_login(self.admin)
        gateway = SimpleNamespace(inspect_application_software=lambda: (_ for _ in ()).throw(OSError("/private/key")))
        with patch("zog.station_access.api.views.get_gateway", return_value=gateway):
            result = self.client.get("/api/application-software/")
        self.assertEqual(result.status_code, 503)
        self.assertNotIn("/private/key", result.content.decode())
