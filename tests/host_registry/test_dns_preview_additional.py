"""Additional destination preview must be scoped to its own host and owner."""
from unittest.mock import patch
from django.test import TestCase
from zog.network_register.contracts import NetworkError
from tests.host_registry import test_dns_destinations as f
from zog.station_access.host_registry.dns_preview import inspect
from zog.station_access.host_registry.models import DnsAssignment, AdditionalDnsAssignment


class AdditionalPreviewTests(TestCase):
    review = f.DestinationTests.review
    commit = f.DestinationTests.commit
    change = f.DestinationTests.change

    def setUp(self):
        f.DestinationTests.setUp(self)
        self.change("reserve", "compiler")
        self.url = f"/api/hosts/{self.host.pk}/dns-destinations/additional/preview/"

    def test_read_only_create_candidate_and_distinct_destination(self):
        old_primary = list(DnsAssignment.objects.values())
        old_extra = list(AdditionalDnsAssignment.objects.values())
        output = inspect(self.config, self.host.pk, actor_id=self.admin.pk,
                         binding_id="additional", **self.kw2)
        self.assertEqual(output["outcome"], "candidate")
        self.assertEqual(output["proposed_action"], "create")
        self.assertEqual(output["observed_count"], 0)
        self.assertEqual(output["provider"], "cloudflare")
        self.assertEqual(output["hostname"], "compiler.extra.example.uk")
        self.assertEqual(self.extra.calls, [])
        self.assertEqual(list(DnsAssignment.objects.values()), old_primary)
        self.assertEqual(list(AdditionalDnsAssignment.objects.values()), old_extra)

    def test_wrong_destination_and_owner_never_access_provider(self):
        with self.assertRaises(NetworkError):
            inspect(self.config, self.host.pk, actor_id=self.admin.pk + 1,
                    binding_id="additional", **self.kw2)
        self.assertEqual(self.extra.calls, [])
        self.client.force_login(self.admin)
        with patch("zog.station_access.host_registry.dns_preview_views.configuration",
                   return_value=self.config), patch(
                       "zog.station_access.host_registry.dns_preview_views.inspect",
                       side_effect=lambda *a, **kw: inspect(
                           self.config, self.host.pk, **self.kw2,
                           actor_id=kw["actor_id"],binding_id=kw["binding_id"])):
            response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["preview"]["proposed_action"], "create")
        self.assertIn("no-store", response["Cache-Control"])
        self.assertEqual(self.extra.calls, [])
