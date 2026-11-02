"""Fail-closed source regressions for the Workspace diagnostic projection."""
from types import SimpleNamespace
from copy import deepcopy
from time import time
from unittest.mock import patch

from django.test import SimpleTestCase

from zog.station_access.services.workspace_diagnostics import project


def workspace(**updates):
    value = dict(pk="workspace-one", runtime_id="desktop-one", endpoint_ready=True, endpoint_revision=7,
                 vnc_socket="/private/socket", vnc_host=None, vnc_port=None)
    value.update(updates)
    return SimpleNamespace(**value)


def runtime(**updates):
    value = dict(state="running", terminal=False, cleanup_pending=False)
    value.update(updates)
    return SimpleNamespace(**value)


def checks(result):
    assert result["read_only"] is True and result["advisory"] is True
    assert len(result["checks"]) == 5
    assert [c["condition"] for c in result["checks"]] == [
        "accepted-runtime", "desktop-readiness", "x11-authorization",
        "rfb-availability", "browser-grant",
    ]
    assert all(set(c) == {"condition", "status", "code", "explanation", "source"}
               for c in result["checks"])
    return {c["condition"]: c for c in result["checks"]}


class WorkspaceDiagnosticTests(SimpleTestCase):
    def test_offline_cannot_promote_saved_runtime_or_socket_to_success(self):
        with patch("zog.station_access.services.workspace_diagnostics.VncAccessGrant.objects.filter") as query:
            report = checks(project(workspace(), object(), controller_available=False))
        assert all(item["status"] == "unknown" for item in report.values())
        assert report["accepted-runtime"]["code"] == "controller-unavailable"
        query.assert_not_called()

    def test_verified_controller_desktop_does_not_invent_x11_or_rfb_proof(self):
        with patch("zog.station_access.services.workspace_diagnostics.VncAccessGrant.objects.filter") as query:
            query.return_value.exists.return_value = True
            report = checks(project(workspace(), object(), controller_available=True,
                                    runtime=runtime(), runtime_identity_ok=True, desktop_access=True))
        assert report["accepted-runtime"]["status"] == "confirmed"
        assert report["desktop-readiness"]["status"] == "confirmed"
        assert report["x11-authorization"]["status"] == "unknown"
        assert report["rfb-availability"]["status"] == "unknown"
        assert report["browser-grant"]["status"] == "confirmed"
        assert report["browser-grant"]["source"] == "saved-record"
        assert "Browser connectivity is not proved" in report["browser-grant"]["explanation"]
        assert query.call_args.kwargs["endpoint_revision"] == 7
        assert query.call_args.kwargs["target_socket"] == "/private/socket"
        assert "/private/socket" not in str(report)

    def test_mismatched_runtime_and_endpoint_deny_grant_success(self):
        with patch("zog.station_access.services.workspace_diagnostics.VncAccessGrant.objects.filter") as query:
            for identity, access in ((False, True), (True, False)):
                report = checks(project(workspace(), object(), controller_available=True,
                                        runtime=runtime(), runtime_identity_ok=identity,
                                        desktop_access=access))
                assert report["desktop-readiness"]["status"] != "confirmed"
                assert report["browser-grant"]["status"] == "unknown"
            query.assert_not_called()

    def test_stopped_or_cleanup_pending_runtime_is_not_a_live_success(self):
        with patch("zog.station_access.services.workspace_diagnostics.VncAccessGrant.objects.filter") as query:
            for current in (runtime(state="terminated", terminal=True),
                            runtime(state="running", cleanup_pending=True),
                            runtime(state="starting")):
                report = checks(project(workspace(), object(), controller_available=True,
                                        runtime=current, runtime_identity_ok=True, desktop_access=True))
                assert report["accepted-runtime"]["status"] != "confirmed"
                assert report["desktop-readiness"]["status"] != "confirmed"
            query.assert_not_called()

    def test_expired_or_missing_grant_stays_unknown_and_does_not_issue_one(self):
        with patch("zog.station_access.services.workspace_diagnostics.VncAccessGrant.objects.filter") as query:
            query.return_value.exists.return_value = False
            report = checks(project(workspace(), object(), controller_available=True,
                                    runtime=runtime(), runtime_identity_ok=True, desktop_access=True))
            assert report["browser-grant"]["status"] == "unknown"
            query.return_value.exists.side_effect = RuntimeError("secret /private/path")
            report = checks(project(workspace(), object(), controller_available=True,
                                    runtime=runtime(), runtime_identity_ok=True, desktop_access=True))
            assert "secret" not in str(report)
            assert "/private/path" not in str(report)


def proof(**overrides):
    data = dict(schema="zog-workspace-stage-readiness-v1",
                workspace_id="workspace-one", desktop_runtime_id="desktop-one",
                boot_id="current-boot", incarnation="incarnation-one",
                endpoint_identity="a" * 64, observed_at=time(),
                x11=dict(status="confirmed", code="ok"),
                rfb=dict(status="confirmed", code="ok"), advisory=True)
    data.update(overrides)
    return data


class IndependentStageTests(SimpleTestCase):
    def observed(self, report):
        with patch("zog.station_access.services.workspace_diagnostics.VncAccessGrant.objects.filter") as grants:
            grants.return_value.exists.return_value = False
            return checks(project(workspace(), object(), controller_available=True,
                                  runtime=runtime(), runtime_identity_ok=True,
                                  desktop_access=True, stage_evidence=report))

    def test_exact_current_independent_probes_are_projected(self):
        entries = self.observed(proof())
        assert entries["x11-authorization"]["status"] == "confirmed"
        assert entries["rfb-availability"]["status"] == "confirmed"
        assert entries["x11-authorization"]["source"] == "current-controller"
        assert "current X11" in entries["x11-authorization"]["explanation"]
        assert "a" * 64 not in str(entries)

    def test_rf_b_banner_failure_is_attributed_only_to_rfb(self):
        entries = self.observed(proof(rfb=dict(status="failed", code="rfb-invalid")))
        assert entries["x11-authorization"]["status"] == "confirmed"
        assert entries["rfb-availability"]["status"] == "failed"
        assert entries["rfb-availability"]["code"] == "rfb-invalid"

    def test_rotated_x11_authority_cancels_both_stage_probes(self):
        entries = self.observed(proof(
            x11=dict(status="unknown", code="binding-unavailable"),
            rfb=dict(status="unknown", code="binding-unavailable")))
        assert entries["x11-authorization"]["status"] == "unknown"
        assert entries["rfb-availability"]["status"] == "unknown"

    def test_missing_controller_runtime_and_endpoint_cannot_promote_stage(self):
        inputs = [
            dict(controller_available=False, runtime=None, runtime_identity_ok=None, desktop_access=None),
            dict(controller_available=True, runtime=None, runtime_identity_ok=None, desktop_access=None),
            dict(controller_available=True, runtime=runtime(), runtime_identity_ok=False, desktop_access=True),
            dict(controller_available=True, runtime=runtime(), runtime_identity_ok=True, desktop_access=False),
            dict(controller_available=True, runtime=runtime(state="terminated", terminal=True),
                 runtime_identity_ok=True, desktop_access=True),
        ]
        for item in inputs:
            with self.subTest(item=item), patch("zog.station_access.services.workspace_diagnostics.VncAccessGrant.objects.filter") as grants:
                report = checks(project(workspace(), object(), stage_evidence=proof(), **item))
                assert report["x11-authorization"]["status"] == "unknown"
                assert report["rfb-availability"]["status"] == "unknown"
                grants.assert_not_called()

    def test_foreign_replaced_or_stale_evidence_is_all_unknown(self):
        for change in [
            dict(desktop_runtime_id="replacement-desktop"),
            dict(workspace_id="foreign-workspace"),
            dict(observed_at=time() - 30),
            dict(observed_at=time() + 30),
            dict(boot_id=""),
            dict(incarnation=""),
            dict(endpoint_identity=None),
            dict(endpoint_identity="/private/socket"),
            dict(x11=dict(status="confirmed", code="rfb-invalid")),
            dict(rfb=dict(status="confirmed", code="private-cookie")),
            dict(x11=dict(status=["confirmed"], code="ok")),
            dict(rfb=dict(status="confirmed", code=["ok"])),
            dict(schema="forged"),
            dict(advisory=False),
            dict(private_socket="/private/secret"),
        ]:
            with self.subTest(change=change):
                report = self.observed(proof(**change))
                assert report["x11-authorization"]["status"] == "unknown"
                assert report["rfb-availability"]["status"] == "unknown"
                assert "/private/" not in str(report)
