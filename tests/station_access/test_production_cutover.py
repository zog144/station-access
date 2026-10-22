"""Production cutover probes never invent mount/host ownership authority."""
import json
import os
import socket
import tempfile
import time
import uuid
from pathlib import Path
from unittest import TestCase
from unittest.mock import patch

from zog.station_access.production_cutover import inspect, _intent, _parse_policy

HOST = "d270fc26-2e8d-42d4-8188-d94bead264bd"


def config(root):
    return {
        "schema": "zog-station-production-cutover-v1",
        "station_state": str(root / "station"),
        "archive_store": str(root / "archives"),
        "host_discover_credentials": str(root / "run" / "zog-host" / "mirror-live"),
        "host_gateway_directory": str(root / "run" / "gateway"),
        "gateway_socket_name": "controller.sock",
        "gateway_mode": "host-deploy-owned-gateway",
        "station_gateway_factory": "zog.station_access.box_control.current:create_gateway",
        "expected_host_id": HOST,
    }


class CutoverBindingTests(TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.policy = config(self.root)
        for label in ("station_state","archive_store","host_discover_credentials","host_gateway_directory"):
            Path(self.policy[label]).mkdir(parents=True, exist_ok=True)

    def write_intent(self, lease):
        path = Path(self.policy["host_discover_credentials"])
        temporary = path / "replacing.json"
        temporary.write_text(json.dumps({
            "version":1,"host_id":HOST,
            "desired":{"lease_expires_at":lease,"selected":True},
            "SECRET_DO_NOT_PRINT":"private",
        }))
        temporary.replace(path / "mirror-intent.json")

    def test_atomic_replacement_is_visible_on_every_read(self):
        now = time.time()
        self.write_intent(now + 300)
        self.assertEqual(_intent(self.policy["host_discover_credentials"], HOST, clock=lambda:now),"intent-live")
        self.write_intent(now - 10)
        self.assertEqual(_intent(self.policy["host_discover_credentials"], HOST, clock=lambda:now),"intent-expired")

    def test_no_host_or_secret_content_is_exported(self):
        self.write_intent(time.time() + 100)
        report = inspect(self.policy, _guest_root=self.root)
        self.assertEqual(report["checks"]["mirror_intent"],"intent-live")
        self.assertFalse(report["safe_to_cut_over"])
        self.assertNotIn("private", json.dumps(report))
        self.assertNotIn(str(self.root), json.dumps(report))
        self.assertNotIn("SECRET_DO_NOT_PRINT", json.dumps(report))

    def test_legacy_adapter_and_unsafe_gateway_are_rejected(self):
        for key, value in (
            ("station_gateway_factory", "compiler_gateway:create_gateway"),
            ("gateway_mode","legacy-direct-socket"),
            ("gateway_socket_name","../../root-control.sock"),
        ):
            original = self.policy[key]
            self.policy[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                _parse_policy(self.policy, guest_root=self.root)
            self.policy[key] = original

    def test_undeclared_mirror_export_destination_is_denied(self):
        self.policy["host_discover_credentials"] = str(self.root / "run" / "other")
        with self.assertRaises(ValueError):
            inspect(self.policy, _guest_root=self.root)

    def test_unselected_intent_is_not_mistaken_for_active_role(self):
        now = time.time()
        self.write_intent(now + 300)
        directory = Path(self.policy["host_discover_credentials"])
        body = json.loads((directory / "mirror-intent.json").read_text())
        body["desired"]["selected"] = False
        temporary = directory / "next.json"
        temporary.write_text(json.dumps(body))
        temporary.replace(directory / "mirror-intent.json")
        self.assertEqual(_intent(str(directory), HOST, clock=lambda: now), "intent-unselected")

    def test_redirected_directories_fail_closed(self):
        hidden = self.root / "hidden"
        hidden.mkdir()
        directory = Path(self.policy["host_discover_credentials"])
        directory.rmdir()
        directory.symlink_to(hidden, target_is_directory=True)
        report = inspect(self.policy, _guest_root=self.root)
        self.assertEqual(report["checks"]["mirror_intent"], "intent-unavailable")

    def test_missing_gateway_does_not_claim_authorization(self):
        report = inspect(self.policy, _guest_root=self.root)
        self.assertEqual(report["checks"]["compiler_gateway"], "gateway-unavailable")
        self.assertIn("gateway-peer-credential-verification", report["required_external_evidence"])

    def test_live_gateway_socket_still_requires_peer_auth_and_host_ownership(self):
        path = Path(self.policy["host_gateway_directory"]) / "controller.sock"
        with socket.socket(socket.AF_UNIX) as server:
            server.bind(str(path))
            report = inspect(self.policy, _guest_root=self.root)
        self.assertEqual(report["checks"]["compiler_gateway"],"gateway-present-unverified")
        self.assertFalse(report["safe_to_cut_over"])
