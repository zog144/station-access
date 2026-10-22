"""Authorized, non-binding DNS preview through the reviewed shared writer.

Provider fixtures record all mutation calls. No preview may invoke them or
change the persisted assignment/operation state.
"""
import copy
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase
from zog.network_register.contracts import NetworkError
from tests.host_registry import test_dns_cutover as f
from zog.station_access.host_registry import dns_preview
from zog.station_access.host_registry.models import DnsAssignment, Host, ProviderCredential


class ReconciliationPreviewTests(TestCase):
    review = f.CutoverTests.review
    commit = f.CutoverTests.commit

    def setUp(self):
        f.CutoverTests.setUp(self)
        self.commit()
        self.url = f"/api/hosts/{self.host.pk}/dns-preview/"

    def inspect(self):
        return dns_preview.inspect(
            self.config, self.host.pk, actor_id=self.admin.pk, **self.kw)

    def test_provider_candidate_read_does_not_change_assignment_or_ledger(self):
        before = list(DnsAssignment.objects.values())
        records = f.CutoverTests.local_records(self)
        result = self.inspect()
        self.assertEqual(result["schema"], 1)
        self.assertTrue(result["read_only"])
        self.assertEqual(result["outcome"], "candidate")
        self.assertEqual(result["proposed_action"], "update")
        self.assertEqual(result["observed_count"], 1)
        self.assertEqual(result["desired"]["ttl"], 300)
        self.assertEqual(result["last_applied"]["ttl"], 60)
        self.assertFalse(self.provider.calls)
        self.assertEqual(before, list(DnsAssignment.objects.values()))
        self.assertEqual(records, f.CutoverTests.local_records(self))

    def test_foreign_record_blocks_without_mutation_or_reconciliation(self):
        self.provider.rows[0]["content"] = "9.9.9.9"
        result = self.inspect()
        self.assertEqual(result["outcome"], "blocked")
        self.assertEqual(result["reason"], "owned-record-drift")
        self.assertFalse(result["observed"][0]["matches_last_applied"])
        self.assertFalse(self.provider.calls)

    def test_stale_host_evidence_never_becomes_unpublish(self):
        Host.objects.filter(pk=self.host.pk).update(signed_dns_observed_at=None)
        with self.assertRaises(NetworkError):
            self.inspect()
        self.assertFalse(self.provider.calls)

    def test_explicitly_disabled_publication_is_only_delete_intent(self):
        DnsAssignment.objects.filter(pk=self.host.pk).update(enabled=False, revision=2)
        result = self.inspect()
        self.assertEqual(result["desired"], None)
        self.assertEqual(result["proposed_action"], "delete")
        self.assertTrue(result["read_only"])
        self.assertFalse(self.provider.calls)

    def test_provider_read_race_never_returns_a_candidate(self):
        def change():
            DnsAssignment.objects.filter(pk=self.host.pk).update(enabled=False,revision=2)
        self.provider.on_list = change
        try:
            result = self.inspect()
        except NetworkError:
            return
        self.assertNotEqual(result["outcome"], "candidate")
        self.assertFalse(self.provider.calls)

    def test_view_requires_active_admin_and_get_only(self):
        self.assertEqual(self.client.get(self.url).status_code, 401)
        ordinary = get_user_model().objects.create_user(
            username="dns-reader", password="fixture-password")
        self.client.force_login(ordinary)
        self.assertEqual(self.client.get(self.url).status_code, 403)
        self.client.force_login(self.admin)
        self.assertEqual(self.client.post(self.url).status_code, 405)
        with patch("zog.station_access.host_registry.dns_preview_views.configuration",
                   return_value=self.config), patch(
                       "zog.station_access.host_registry.dns_preview_views.inspect",
                       side_effect=lambda *a, **kw: self.inspect()) as inspect:
            response = self.client.get(self.url)
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json()["preview"]["outcome"], "candidate")
            self.assertIn("no-store", response["Cache-Control"])
            self.assertEqual(inspect.call_args.kwargs["actor_id"], self.admin.pk)
            self.assertFalse(self.provider.calls)

    def test_view_failures_are_bounded_and_never_disclose_provider_error(self):
        self.client.force_login(self.admin)
        with patch("zog.station_access.host_registry.dns_preview_views.configuration",
                   return_value=self.config), patch(
                       "zog.station_access.host_registry.dns_preview_views.inspect",
                       side_effect=ValueError("sensitive-provider-response")):
            response = self.client.get(self.url)
            self.assertEqual(response.status_code, 503)
            self.assertNotIn("sensitive-provider-response",response.content.decode())
            self.assertIn("no-store",response["Cache-Control"])
