"""Fail-closed source regressions for the Workspace diagnostic projection."""
from types import SimpleNamespace
from unittest.mock import patch

from django.test import SimpleTestCase

from zog.station_access.services.workspace_diagnostics import project


def workspace(**updates):
    value = dict(runtime_id="desktop-one", endpoint_ready=True, endpoint_revision=7,
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
