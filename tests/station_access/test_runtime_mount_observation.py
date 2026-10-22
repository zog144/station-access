"""Kernel mount observation API: authorization, bounded projection and uncertainty."""
from types import SimpleNamespace
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase

from zog.station_access.api.runtime_mounts import project_runtime_mount_observation

RUNTIME = "runtime-A"
BASE = {
    "schema": "zog-runtime-mount-observation-v1",
    "runtime_id": RUNTIME,
    "basis": "kernel-mount-namespace",
    "snapshot": "non-atomic",
    "observed_at": 1791650000.125,
    "recorded_boot_id": "b" * 32,
    "status": "observed",
    "truncated": False,
    "private_host_source": "/secret-host-root",
    "programs": [{
        "program": "web",
        "unit_name": "zog-private-unit.service",
        "recorded_invocation_id": "a" * 32,
        "status": "observed",
        "mount_namespace": "mnt:[123456]",
        "multiple_mount_namespaces": False,
        "truncated": False,
        "mounts": [{
            "destination": "/applications/station-access",
            "kind": "application-software-view",
            "expected_access": "read-only",
            "observed_presence": "present",
            "observed_access": "read-only",
            "backing_identity": "verified",
            "private_host_source": "/do-not-serialize"
        }],
        "mount_namespaces": [{
            "mount_namespace": "mnt:[123456]",
            "truncated": False,
            "representative_process": {"pid": 7, "start_time_ticks": 123},
            "mounts": [{
                "destination": "/applications/station-access",
                "kind": "application-software-view",
                "expected_access": "read-only",
                "observed_presence": "present",
                "observed_access": "read-only",
                "backing_identity": "verified"
            }]
        }]
    }]
}


def payload():
    import copy
    return copy.deepcopy(BASE)


class ProjectionTests(TestCase):
    def test_verified_projection_is_bounded_to_safe_fields(self):
        value = project_runtime_mount_observation(payload(), RUNTIME)
        self.assertEqual(value["basis"], "kernel-mount-namespace")
        self.assertEqual(value["snapshot"], "non-atomic")
        self.assertEqual(value["status"], "observed")
        self.assertEqual(value["programs"][0]["mounts"][0]["backing_identity"], "verified")
        self.assertNotIn("recorded_boot_id", value)
        self.assertNotIn("unit_name", value["programs"][0])
        self.assertNotIn("representative_process", str(value))
        self.assertNotIn("private_host_source", str(value))
        self.assertNotIn("/secret-host-root", str(value))

    def test_multi_namespace_and_partial_uncertainty_are_retained(self):
        data = payload()
        program = data["programs"][0]
        program["status"] = "partial"
        program["multiple_mount_namespaces"] = True
        program["truncated"] = True
        program["mount_namespaces"].append({
            "mount_namespace": "mnt:[987654]",
            "mounts": [{
                "destination": "/data",
                "kind": "application-data",
                "expected_access": "read-write",
                "observed_presence": "unknown",
                "observed_access": "unknown",
                "backing_identity": "inconclusive",
            }],
            "truncated": True,
        })
        data["status"] = "partial"
        data["truncated"] = True
        result = project_runtime_mount_observation(data, RUNTIME)
        self.assertEqual(result["status"], "partial")
        self.assertTrue(result["programs"][0]["multiple_mount_namespaces"])
        self.assertTrue(result["programs"][0]["truncated"])
        self.assertEqual(len(result["programs"][0]["mount_namespaces"]), 2)
        self.assertEqual(result["programs"][0]["mount_namespaces"][1]["mounts"][0]["observed_presence"], "unknown")

    def test_integrity_fault_and_previous_boot_remain_distinct(self):
        for status in ("integrity-fault", "absent", "previous-boot", "legacy-unrecorded",
                       "identity-unavailable", "changed-during-read", "unavailable"):
            data = payload()
            data["status"] = status
            data["programs"][0]["status"] = status
            self.assertEqual(project_runtime_mount_observation(data, RUNTIME)["status"], status)

    def test_rejects_incorrect_identity_contract_or_unbounded_input(self):
        for key, value in (("schema", "wrong"), ("runtime_id", "other"),
                           ("basis", "expected-launched"), ("snapshot", "atomic"),
                           ("programs", [{}] * 33), ("observed_at", float("nan"))):
            data = payload()
            data[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                project_runtime_mount_observation(data, RUNTIME)

    def test_rejects_unsafe_destinations_unknown_access_and_excessive_mounts(self):
        for field, value in (("destination", "/applications/../etc"),
                             ("observed_access", "maybe"),
                             ("backing_identity", "healthy")):
            data = payload()
            data["programs"][0]["mounts"][0][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                project_runtime_mount_observation(data, RUNTIME)
        data = payload()
        data["programs"][0]["mounts"] = data["programs"][0]["mounts"] * 129
        with self.assertRaises(ValueError):
            project_runtime_mount_observation(data, RUNTIME)


class RuntimeMountApiTests(TestCase):
    def setUp(self):
        users = get_user_model()
        self.admin = users.objects.create_superuser("mount-admin")
        self.owner = users.objects.create_user("mount-owner")
        self.url = f"/api/runtimes/{RUNTIME}/mounts/"

    def test_denied_before_instantiating_privileged_gateway(self):
        with patch("zog.station_access.api.views.get_gateway", side_effect=AssertionError("must not call")):
            self.assertEqual(self.client.get(self.url).status_code, 401)
            self.client.force_login(self.owner)
            self.assertEqual(self.client.get(self.url).status_code, 403)

    def test_unknown_runtime_never_starts_observation(self):
        self.client.force_login(self.admin)
        gateway = SimpleNamespace(
            get_runtime=lambda rid: None,
            observe_application_runtime_mounts=lambda rid: (_ for _ in ()).throw(AssertionError("unexpected observation")),
        )
        with patch("zog.station_access.api.views.get_gateway", return_value=gateway):
            self.assertEqual(self.client.get(self.url).status_code, 404)

    def test_admin_observation_is_read_only_not_cached_and_identity_scoped(self):
        self.client.force_login(self.admin)
        calls = []
        gateway = SimpleNamespace(
            get_runtime=lambda rid: SimpleNamespace(runtime_id=rid, application_name="editor"),
            observe_application_runtime_mounts=lambda rid: (calls.append(rid) or payload()),
        )
        with patch("zog.station_access.api.views.get_gateway", return_value=gateway):
            response = self.client.get(self.url)
            self.assertEqual(self.client.post(self.url).status_code, 405)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(calls, [RUNTIME])
        self.assertIn("no-store", response["Cache-Control"])
        self.assertEqual(response.json()["observation"]["status"], "observed")
        self.assertNotIn("/secret-host-root", response.content.decode())

    def test_unavailable_and_wrong_runtime_do_not_leak_privileged_details(self):
        self.client.force_login(self.admin)
        for result in (ValueError("/proc/1234/mountinfo is private"), payload()):
            if isinstance(result, dict):
                result["runtime_id"] = "another-runtime"
            def observe(runtime_id, result=result):
                if isinstance(result, Exception):
                    raise result
                return result
            gateway = SimpleNamespace(
                get_runtime=lambda rid: SimpleNamespace(runtime_id=rid, application_name="editor"),
                observe_application_runtime_mounts=observe,
            )
            with patch("zog.station_access.api.views.get_gateway", return_value=gateway):
                response = self.client.get(self.url)
            self.assertEqual(response.status_code, 503)
            self.assertNotIn("/proc/", response.content.decode())
            self.assertNotIn("another-runtime", response.content.decode())
