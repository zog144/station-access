"""Certificate setup: proposal only, no autonomous issuance, delivery or role change."""
import json
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import Client, TestCase
from zog.certify_manage.model import Authorization
from zog.station_access.host_registry.models import (
    CertificateSetupProposal, MirrorRole, DnsAssignment, DeploymentJob, SecurityAudit
)

URL = "/api/setup/certificates/"
REQUEST = URL + "request/"
POLICY = {
    "schema": "zog-certify-manage-v1",
    "certificate_id": "station-web",
    "hostnames": ["station.example.org"],
    "email": "ops@example.org",
    "acme_directory": "https://acme.example.org/directory",
    "challenge": "http-01",
    "dns_plugin": None,
}


class CertificateSetupTests(TestCase):
    def setUp(self):
        self.admin = get_user_model().objects.create_superuser(
            username="certificate-admin", email="", password="fixture")
        self.client.force_login(self.admin)

    def save(self, policy=POLICY, revision=0):
        return self.client.post(URL,
             data=json.dumps({"revision": revision, "proposal": policy}),
             content_type="application/json")

    def test_missing_proposal_and_separate_unknown_lifecycle_not_readiness(self):
        value = self.client.get(URL)
        self.assertEqual(value.status_code, 200)
        self.assertEqual(value["Cache-Control"], "no-store")
        result = value.json()
        self.assertEqual(result["authorization"], "operator-proposal-only")
        self.assertFalse(result["owner_request_available"])
        self.assertIsNone(result["proposal"])
        self.assertEqual(result["https_readiness"], "not_verified")
        for stage in ("issued", "delivered", "nginx_loaded", "browser_verified"):
            self.assertEqual(result["lifecycle"][stage], "not_observed")
        self.assertEqual(result["certificate"]["renewal"], "not_observed")
        self.assertIsNone(result["certificate"]["expires_at"])
        self.assertEqual(CertificateSetupProposal.objects.count(), 0)

    def test_operator_can_save_only_producer_validated_proposal(self):
        reviewed = Authorization.from_dict(POLICY)
        with patch("subprocess.run", side_effect=AssertionError("Certbot forbidden")), \
             patch("os.system", side_effect=AssertionError("system command forbidden")):
            value = self.save()
        self.assertEqual(value.status_code, 200)
        data = value.json()
        self.assertEqual(data["proposal"], reviewed.canonical())
        self.assertEqual(data["revision"], 1)
        self.assertEqual(data["authorization"], "operator-proposal-only")
        self.assertFalse(data["owner_request_available"])
        self.assertEqual(data["https_readiness"], "not_verified")
        self.assertEqual(CertificateSetupProposal.objects.count(), 1)
        self.assertEqual(CertificateSetupProposal.objects.get().proposed_policy,
                         reviewed.canonical())
        self.assertEqual(DeploymentJob.objects.count(), 0)
        self.assertEqual(SecurityAudit.objects.count(), 0)
        self.assertEqual(DnsAssignment.objects.count(), 0)
        self.assertEqual(MirrorRole.objects.count(), 0)
        self.assertEqual(self.client.get(URL).json()["proposal"], reviewed.canonical())

    def test_dns01_cloudflare_proposal_not_dns_credential_or_issuance(self):
        policy = dict(POLICY, challenge="dns-01", dns_plugin="dns-cloudflare")
        self.assertEqual(self.save(policy).status_code, 200)
        for bad in (
            dict(POLICY, dns_plugin="dns-cloudflare"),
            dict(policy, dns_plugin="dns-route53"),
            dict(policy, hostnames=["*.example.org", "station.example.org"]),
            dict(policy, acme_directory="http://acme.example.org/directory"),
            dict(policy, acme_directory="https://acme.example.org/directory?token=secret"),
            dict(policy, token="fixture-private-token"),
            dict(policy, certificate_id="some-other-service"),
            dict(policy, hostnames=["localhost"]),
            dict(policy, hostnames=["127.0.0.1"]),
        ):
            with self.subTest(bad=bad):
                failed = self.save(bad, revision=1)
                self.assertEqual(failed.status_code, 400, failed.content)
                self.assertNotIn("fixture-private-token", failed.content.decode())
        self.assertEqual(CertificateSetupProposal.objects.get().revision, 1)

    def test_unknown_fields_and_wrong_revision_do_not_replace_proposal(self):
        self.assertEqual(self.save().status_code, 200)
        original = CertificateSetupProposal.objects.get().proposed_policy
        self.assertEqual(self.save(POLICY, revision=0).status_code, 409)
        self.assertEqual(self.save(POLICY, revision=True).status_code, 400)
        result = self.client.post(URL, json.dumps({
            "revision": 1, "proposal": POLICY, "certbot_args": "--expand"}),
            content_type="application/json")
        self.assertEqual(result.status_code, 400)
        self.assertEqual(CertificateSetupProposal.objects.get().proposed_policy, original)
        self.assertEqual(CertificateSetupProposal.objects.get().revision, 1)

    def test_owner_request_for_prepare_issue_reconcile_fails_closed(self):
        self.assertEqual(self.save().status_code, 200)
        before = CertificateSetupProposal.objects.get()
        for action in ("prepare", "issue", "reconcile", "nginx-reload", "shell"):
            with self.subTest(action=action), \
                 patch("subprocess.run", side_effect=AssertionError("subprocess forbidden")), \
                 patch("os.system", side_effect=AssertionError("shell forbidden")):
                response = self.client.post(REQUEST,
                    data=json.dumps({"action": action, "args": ["--force"]}),
                    content_type="application/json")
                self.assertEqual(response.status_code, 503)
                result = response.json()
                self.assertEqual(result["code"], "owner-interface-unavailable")
                self.assertFalse(result["safe_to_issue"])
                self.assertIn("no-store", response["Cache-Control"])
        after = CertificateSetupProposal.objects.get()
        self.assertEqual((before.revision, before.proposed_policy),
                         (after.revision, after.proposed_policy))
        self.assertEqual(DeploymentJob.objects.count(), 0)
        self.assertEqual(MirrorRole.objects.count(), 0)

    def test_auth_method_csrf_and_status_redaction(self):
        self.client.logout()
        self.assertEqual(self.client.get(URL).status_code, 401)
        self.assertEqual(self.save().status_code, 401)
        self.assertEqual(self.client.post(REQUEST).status_code, 401)
        normal = get_user_model().objects.create_user(username="normal")
        self.client.force_login(normal)
        self.assertEqual(self.client.get(URL).status_code, 403)
        self.assertEqual(self.save().status_code, 403)
        self.assertEqual(self.client.post(REQUEST).status_code, 403)
        self.client.force_login(self.admin)
        self.assertEqual(self.client.put(URL).status_code, 405)
        self.assertEqual(self.client.get(REQUEST).status_code, 405)
        strict = Client(enforce_csrf_checks=True)
        strict.force_login(self.admin)
        self.assertEqual(strict.post(URL,json.dumps({"revision":0,"proposal":POLICY}),
                                     content_type="application/json").status_code,403)
        self.assertEqual(CertificateSetupProposal.objects.count(), 0)
