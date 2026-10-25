"""Certificate assignment authority and signed retrieval — offline only."""
import base64
from io import StringIO
import json
import tempfile
import uuid
from datetime import timedelta
from contextlib import nullcontext
import time
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import TestCase, override_settings
from django.utils import timezone
from zog.host_identify import signatures
from zog.host_discover.certificate_assignment import make_request, validate_envelope, validate_response
from zog.station_access.host_registry.models import (
    Host, HostIdentity, ManagedAdmission, SecurityGate, ProviderCredential,
    DnsDestination, AdditionalDnsAssignment, ProviderAccessCheck, CertificateAssignment,
    CertificateAssignmentAction, SecurityAudit,
)
from zog.station_access.host_registry.certificate_assignment_signing import (
    canonical, managed_authority_pin, SigningUnavailable,
)
from zog.station_access.host_registry.certificate_assignment import SCHEMA

ORIGIN = "https://registry.example.test"
LOCAL = "00000000-0000-4000-8000-000000000123"
MANAGED = "00000000-0000-4000-8000-000000000456"


@override_settings(
    HOST_IDENTITY_ORIGIN=ORIGIN,
    HOST_LOCAL_CERTIFICATE_INSTALLATION_ID=LOCAL,
    HOST_CERTIFICATE_ASSIGNMENT_SIGNER_ID="station-certificate-1",
    HOST_CERTIFICATE_ASSIGNMENT_ENABLED=True,
    HOST_MANAGED_ADMISSION_ENABLED=True,
    ALLOWED_HOSTS=["registry.example.test", "testserver"],
)
class AssignmentTests(TestCase):
    def setUp(self):
        # Migration 0004 already seeds this singleton for migrated databases.
        SecurityGate.objects.get_or_create(pk=1)
        self.admin = get_user_model().objects.create_superuser(
            username="cert-admin", password="test-password", email="")
        self.client.force_login(self.admin)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        key = Ed25519PrivateKey.generate()
        path = Path(self.tmp.name)/"cert-signing.pem"
        path.write_bytes(key.private_bytes(
            serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()))
        path.chmod(0o600)
        self.override = override_settings(
            HOST_CERTIFICATE_ASSIGNMENT_SIGNING_KEY_FILE=str(path),
            HOST_MANAGED_SIGNING_KEY_FILE=str(path))
        self.override.enable()
        self.addCleanup(self.override.disable)
        self.receipt_key = key.public_key()
        self.owner_config = patch(
            "zog.station_access.host_registry.dns_reconcile.configuration",
            return_value={"state_directory": str(Path(self.tmp.name))})
        self.owner_lock = patch(
            "zog.station_access.host_registry.dns_reconcile.controller_lock",
            side_effect=lambda config, modes: nullcontext())
        self.owner_config.start()
        self.owner_lock.start()
        self.addCleanup(self.owner_config.stop)
        self.addCleanup(self.owner_lock.stop)
        self.session = "managed-session-fixture"
        self.host_key = Ed25519PrivateKey.generate()
        finger = signatures.fingerprint(self.host_key.public_key())
        self.host = Host.objects.create(label="Host under test")
        HostIdentity.objects.create(
            host=self.host,fingerprint=finger,
            public_key=signatures.public_text(self.host_key.public_key()),
            status="approved",approved_at=timezone.now(),approved_by="cert-admin")
        ManagedAdmission.objects.create(
            host=self.host,fingerprint=finger,
            installation_id=uuid.UUID(MANAGED),
            state_volume_id=uuid.uuid4(),authority_id=uuid.uuid4(),
            registry_id="central",epoch=1,checkpoint=uuid.uuid4(),
            request={},claims={'jti':self.session,'exp':time.time()+3600,
                              'fingerprint':finger,'installation_id':MANAGED,
                              'registry_id':'central'})
        self.credential = ProviderCredential.objects.create(
            provider="cloudflare",label="Reviewed Cloudflare",
            account_id="a"*32,revision=4,key_id="vault-key",
            ciphertext="fixture-not-read")
        self.zone="example.test"
        self.binding = DnsDestination.objects.create(
            id="selected-cert-zone",enabled=True,ledger_path="fixture.sqlite3",
            selection={
                "owner_user_id":self.admin.pk,
                "credential_id":str(self.credential.pk),
                "credential_revision":4,
                "zone_id":"zone-identifier",
                "zone_name":self.zone,
                "prefix":"extra.example.test",
            })
        ProviderAccessCheck.objects.create(
            credential=self.credential, credential_revision=4,
            started_at=timezone.now(),finished_at=timezone.now(),
            status="passed",domains=[
                {"id":"zone-identifier","name":self.zone,"status":"active"}])
        self.name="managed.extra.example.test"
        self.dns=AdditionalDnsAssignment.objects.create(
            binding=self.binding,host=self.host,phase="ready",
            name=self.name,owner_id="fixture-managed",
            enabled=True,revision=3,applied_revision=3,
            status="synchronized",record_id="provider-record-1")
        self.policy={
            "schema":"zog-certify-manage-v1","certificate_id":"station-web",
            "hostnames":[self.name],"email":"ops@example.test",
            "acme_directory":"https://acme.example.test/directory",
            "challenge":"dns-01","dns_plugin":"dns-cloudflare",
        }
        self.params={
            "schema":SCHEMA,"action":"approve","origin":"managed",
            "host_id":str(self.host.pk),"binding_id":self.binding.pk,
            "credential_id":str(self.credential.pk),
            "credential_revision":4,"zone_id":"zone-identifier",
            "zone_name":self.zone,"policy":self.policy,
            "expires_at":(timezone.now()+timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "expected_revision":0,"operation_id":str(uuid.uuid4()),
        }
        self.admin_url="/api/setup/certificate-assignments/"
        self.host_url=f"/api/hosts/{self.host.pk}/certificate-assignment/"


    def approved_dns01_name(self):
        """Review/commit a generic Host's exact DNS-01 name; never seed A records."""
        from zog.station_access.host_registry import managed_dns01_hostname as owner
        from zog.station_access.host_registry.models import ManagedDns01Hostname
        from contextlib import nullcontext
        from unittest.mock import patch
        name = "issuer.example.test"
        proposal = {
            "schema": 1, "owner_user_id": self.admin.pk,
            "credential_id": str(self.credential.pk),
            "credential_revision": self.credential.revision,
            "zone_id": "zone-identifier", "zone_name": self.zone,
            "prefix": name, "binding_id": "review-test-binding",
            "binding_revision": 1, "nameservers": ["ns1.example.test"],
            "host_ids": [],
        }
        config = {
            "domain": self.zone, "suffix": "hosts.example.test",
            "state_directory": str(Path(self.tmp.name)),
        }
        fp = signatures.fingerprint(self.host_key.public_key())
        admission = ManagedAdmission.objects.get(host=self.host)
        mocks = [
            patch.object(owner, "configuration", return_value=config),
            patch.object(owner, "controller_lock", side_effect=lambda config, modes: nullcontext(Path(self.tmp.name))),
            patch.object(owner.dns_setup, "candidate", return_value=proposal),
            patch.object(owner.dns_setup, "validate"),
            patch.object(owner.dns_setup, "scope_available"),
        ]
        from contextlib import ExitStack
        with ExitStack() as stack:
            for mocked in mocks:
                stack.enter_context(mocked)
            reviewed = owner.review(
                owner=self.admin.pk, host_id=str(self.host.pk),
                installation_id=MANAGED, fingerprint=fp,
                registry_id=admission.registry_id, hostname=name,
                credential_id=str(self.credential.pk),
                credential_revision=self.credential.revision,
                zone_id="zone-identifier",
            )
            self.assertEqual(reviewed["provider_writes"], 0)
            self.assertFalse(ManagedDns01Hostname.objects.exists())
            receipt = owner.commit(owner=self.admin.pk, review_id=reviewed["review_id"])
            self.assertEqual(receipt["provider_writes"], 0)
            self.assertFalse(receipt["replayed"])
            again = owner.commit(owner=self.admin.pk, review_id=reviewed["review_id"])
            self.assertTrue(again["replayed"])
        self.assertEqual(ManagedDns01Hostname.objects.count(), 1)
        self.assertEqual(self.host.provider, "generic")
        self.assertFalse(self.host.dns_assignment if hasattr(self.host, "dns_assignment") else False)
        grant = ManagedDns01Hostname.objects.get(host=self.host)
        self.assertEqual(grant.fingerprint, fp)
        self.assertEqual(grant.installation_id, uuid.UUID(MANAGED))
        self.assertEqual(grant.review_id, reviewed["review_id"])
        return grant

    def test_generic_managed_dns01_bound_name_signing_no_a_record(self):
        from zog.station_access.host_registry import certificate_assignment as assign
        from zog.station_access.host_registry.models import ManagedDns01Hostname, DnsAssignment, CertificateAssignment
        grant = self.approved_dns01_name()
        self.assertFalse(DnsAssignment.objects.filter(host=self.host).exists())
        self.params["binding_id"] = "managed-dns01"
        self.params["policy"]["hostnames"] = [grant.hostname]
        self.params["policy"]["challenge"] = "dns-01"
        self.params["policy"]["dns_plugin"] = "dns-cloudflare"
        approved = self.submit()
        self.assertEqual(approved.status_code, 200, approved.content)
        signed = self.assert_receipt(approved.json()["receipt"])
        self.assertEqual(signed["host_id"], str(self.host.pk))
        self.assertEqual(signed["installation_id"], MANAGED)
        self.assertEqual(CertificateAssignment.objects.get(host=self.host).binding_id, "managed-dns01")
        self.assertEqual(assign.current(self.host)["state"], "approved")
        grant.active = False
        grant.save(update_fields=["active"])
        self.assertEqual(assign.current(self.host)["state"], "conflict")

    def test_generic_dns01_refuses_http_and_unreviewed_hostname(self):
        grant = self.approved_dns01_name()
        self.params["binding_id"] = "managed-dns01"
        self.params["policy"]["hostnames"] = [grant.hostname]
        self.params["policy"]["challenge"] = "http-01"
        self.params["policy"]["dns_plugin"] = None
        self.assertEqual(self.submit().json()["code"], "zone-not-approved")
        self.params["policy"]["challenge"] = "dns-01"
        self.params["policy"]["dns_plugin"] = "dns-cloudflare"
        self.params["policy"]["hostnames"] = ["other.example.test"]
        self.assertEqual(self.submit().json()["code"], "hostname-authority-unavailable")
        self.params["policy"]["hostnames"] = [grant.hostname]
        self.params["credential_revision"] += 1
        self.assertEqual(self.submit().json()["code"], "hostname-authority-unavailable")
        self.params["credential_revision"] -= 1
        ManagedAdmission.objects.filter(host=self.host).update(installation_id=uuid.uuid4())
        self.assertEqual(self.submit().json()["code"], "hostname-authority-unavailable")

    def test_dns01_grant_fences_state_authority_registry_and_session_changes(self):
        from zog.station_access.host_registry.models import ManagedDns01Hostname
        from zog.station_access.host_registry.dns_setup import scope_available, Blocked
        grant = self.approved_dns01_name()
        self.params["binding_id"] = "managed-dns01"
        self.params["policy"]["hostnames"] = [grant.hostname]
        self.params["policy"]["challenge"] = "dns-01"
        self.params["policy"]["dns_plugin"] = "dns-cloudflare"
        self.assertEqual(self.submit().status_code, 200)
        from zog.station_access.host_registry import certificate_assignment as assignment
        admission = ManagedAdmission.objects.get(host=self.host)
        initial = {
            "state_volume_id": admission.state_volume_id,
            "authority_id": admission.authority_id,
            "registry_id": admission.registry_id,
            "claims": dict(admission.claims),
        }
        cases = [
            ("state_volume_id", uuid.uuid4()),
            ("authority_id", uuid.uuid4()),
            ("registry_id", "different-registry"),
            ("claims", dict(initial["claims"], exp=0)),
        ]
        for field, replacement in cases:
            with self.subTest(field=field):
                setattr(admission, field, replacement)
                admission.save(update_fields=[field])
                self.assertEqual(assignment.current(self.host)["state"], "conflict")
                self.params["operation_id"] = str(uuid.uuid4())
                self.assertEqual(self.submit().json()["code"], "hostname-authority-unavailable")
                setattr(admission, field, initial[field])
                admission.save(update_fields=[field])
                self.assertEqual(assignment.current(self.host)["state"], "approved")
        self.host.provider = "aws"
        self.host.save(update_fields=["provider"])
        self.assertEqual(assignment.current(self.host)["state"], "conflict")
        self.host.provider = "generic"
        self.host.save(update_fields=["provider"])
        self.assertEqual(assignment.current(self.host)["state"], "approved")
        self.assertEqual(ManagedDns01Hostname.objects.get(host=self.host).hostname, grant.hostname)
        with self.assertRaises(Blocked):
            scope_available(
                {"suffix": "hosts.example.test"},
                grant.hostname,
            )

    def test_dns01_grant_refuses_expired_host_session_and_revokes_safely(self):
        from zog.station_access.host_registry import managed_dns01_hostname as owner
        from zog.station_access.host_registry.models import CertificateAssignment
        grant = self.approved_dns01_name()
        self.params["binding_id"] = "managed-dns01"
        self.params["policy"]["hostnames"] = [grant.hostname]
        self.params["policy"]["challenge"] = "dns-01"
        self.params["policy"]["dns_plugin"] = "dns-cloudflare"
        self.assertEqual(self.submit().status_code, 200)
        with patch.object(owner, "configuration", return_value={"domain": self.zone}):
            with patch.object(owner, "controller_lock", side_effect=lambda config, modes: nullcontext()):
                with self.assertRaisesRegex(owner.HostnameError, "certificate-revoke-required"):
                    owner.revoke(owner=self.admin.pk, host_id=str(self.host.pk), expected_revision=1)
                revoked = dict(self.params, action="revoke", expected_revision=1,
                               operation_id=str(uuid.uuid4()))
                self.assertEqual(self.submit(revoked).status_code, 200)
                receipt = owner.revoke(owner=self.admin.pk,
                                       host_id=str(self.host.pk), expected_revision=1)
                self.assertFalse(receipt["active"])
        self.assertFalse(CertificateAssignment.objects.filter(host=self.host,state="approved").exists())
        self.params["operation_id"] = str(uuid.uuid4())
        self.assertEqual(self.submit().json()["code"], "hostname-authority-unavailable")

    def submit(self, payload=None):
        return self.client.post(self.admin_url, canonical(payload or self.params),
                                content_type="application/json")

    def assert_receipt(self, receipt, *, origin="managed"):
        if origin == "managed":
            self.assertEqual(receipt["schema"],"zog-certificate-assignment-envelope-v1")
            self.assertEqual(receipt["key_id"],signatures.fingerprint(self.receipt_key))
            return validate_envelope(
                receipt,self.receipt_key,expected_host=str(self.host.pk),
                expected_installation=MANAGED)
        self.assertEqual(receipt["schema"],"zog-certificate-assignment-receipt-v1")
        self.receipt_key.verify(base64.b64decode(receipt["signature_ed25519"]),
                                canonical(receipt["statement"]))
        self.assertEqual(receipt["statement"]["signer_id"],"station-certificate-1")
        return receipt["statement"]

    def host_request(self, payload=None, key=None, message=None):
        request_data=payload or make_request(
            str(self.host.pk),None,installation_id=MANAGED,
            managed_session=self.session)
        prepared=message or signatures.sign(
            ORIGIN+self.host_url,canonical(request_data),
            key or self.host_key,str(self.host.pk))
        headers={
            "HTTP_"+name.upper().replace("-","_"):value
            for name,value in prepared.headers.items()
            if name.lower() not in ("content-type","content-length")
        }
        headers["HTTP_HOST"]="registry.example.test"
        return self.client.post(
            prepared.path_url,data=prepared.body,content_type="application/json",
            **headers)

    def test_managed_signer_root_pin_candidate_requires_reviewed_binding(self):
        """Provisioning candidate does not become trusted host root authority."""
        from zog.station_access.host_registry.certificate_assignment_signing import managed_authority_pin
        host_id = str(self.host.pk)
        fingerprint = signatures.fingerprint(self.host_key.public_key())
        key_id = signatures.fingerprint(self.receipt_key)
        expected = dict(host_id=host_id, installation_id=MANAGED,
                        registry_id="central", host_fingerprint=fingerprint,
                        expected_key_id=key_id)
        # The pin is prepared before enabling the assignment producer; only
        # the native owner can install it and authorize operational enablement.
        with override_settings(HOST_CERTIFICATE_ASSIGNMENT_ENABLED=False):
            pin = managed_authority_pin(**expected)
        self.assertEqual(set(pin), {
            "schema", "kind", "registry_id",
            "authority_public_key", "authority_key_id"})
        self.assertEqual(pin["schema"], 1)
        self.assertEqual(pin["kind"], "zog-certificate-assignment-authority-pin")
        self.assertEqual(pin["registry_id"], "central")
        self.assertEqual(pin["authority_key_id"], key_id)
        self.assertEqual(signatures.public_text(self.receipt_key),
                         pin["authority_public_key"])

        output = StringIO()
        call_command("export_managed_certificate_authority_pin",
                     host_id=host_id, installation_id=MANAGED,
                     registry_id="central", host_fingerprint=fingerprint,
                     expected_key_id=key_id, stdout=output)
        self.assertEqual(json.loads(output.getvalue()), pin)
        self.assertEqual(CertificateAssignment.objects.count(), 0)
        self.assertEqual(CertificateAssignmentAction.objects.count(), 0)

        # The same actual station key must sign the managed assignment, but
        # no client/web request may change the root pin candidate.
        response = self.submit()
        self.assertEqual(response.status_code, 200, response.content)
        envelope = response.json()["receipt"]
        self.assertEqual(envelope["key_id"], pin["authority_key_id"])
        self.assert_receipt(envelope)

        for changes in (
            {"host_id": str(uuid.uuid4())},
            {"installation_id": LOCAL},
            {"registry_id": "foreign"},
            {"host_fingerprint": "0" * 64},
            {"expected_key_id": "0" * 64},
        ):
            with self.subTest(changes=changes):
                with self.assertRaises(SigningUnavailable):
                    managed_authority_pin(**dict(expected, **changes))
        with self.assertRaises(CommandError):
            call_command("export_managed_certificate_authority_pin",
                         host_id=host_id, installation_id=MANAGED,
                         registry_id="central", host_fingerprint=fingerprint,
                         expected_key_id="0" * 64, stdout=StringIO())
        with override_settings(HOST_MANAGED_ADMISSION_ENABLED=False):
            with self.assertRaises(SigningUnavailable):
                managed_authority_pin(**expected)
        ManagedAdmission.objects.filter(host=self.host).update(
            claims={"jti": self.session, "exp": time.time() - 1,
                    "fingerprint": fingerprint, "installation_id": MANAGED,
                    "registry_id": "central"})
        with self.assertRaises(SigningUnavailable):
            managed_authority_pin(**expected)
        ManagedAdmission.objects.filter(host=self.host).update(
            claims={"jti": self.session, "exp": time.time() + 3600,
                    "fingerprint": fingerprint, "installation_id": MANAGED,
                    "registry_id": "central"})
        HostIdentity.objects.filter(host=self.host).update(status="revoked")
        with self.assertRaises(SigningUnavailable):
            managed_authority_pin(**expected)

    def test_managed_approval_signed_fetch_and_replay_protection(self):
        result=self.submit()
        self.assertEqual(result.status_code,200,result.content)
        receipt=result.json()["receipt"]
        statement=self.assert_receipt(receipt)
        self.assertEqual(statement["host_id"],str(self.host.pk))
        self.assertEqual(statement["installation_id"],MANAGED)
        self.assertEqual(statement["credential_revision"],4)
        self.assertEqual(statement["consumer"],"host-nginx-https")
        self.assertEqual(statement["authority_origin"],"command-center")
        self.assertEqual(self.submit().json()["receipt"],receipt)
        self.assertEqual(CertificateAssignment.objects.count(),1)
        self.assertEqual(CertificateAssignmentAction.objects.count(),1)
        signed=signatures.sign(ORIGIN+self.host_url,
            canonical(make_request(str(self.host.pk),None,
                installation_id=MANAGED,managed_session=self.session)),
            self.host_key,str(self.host.pk))
        fetched=self.host_request(message=signed)
        self.assertEqual(fetched.status_code,200,fetched.content)
        self.assertEqual(fetched.json()["schema"],"zog-host-certificate-assignment-response-v1")
        self.assertEqual(fetched.json()["state"],"receipt")
        self.assertEqual(fetched.json()["envelope"],receipt)
        self.assertEqual(fetched["Cache-Control"],"no-store")
        self.assertEqual(self.host_request(message=signed).status_code,403)
        known={"revision":statement["revision"],"operation_id":statement["operation_id"]}
        response=self.host_request(make_request(
            str(self.host.pk),known,installation_id=MANAGED,managed_session=self.session))
        self.assertEqual(response.status_code,200,response.content)
        self.assertEqual(response.json()["state"],"unchanged")
        self.assertIsNone(response.json()["envelope"])

    def test_expiry_revocation_and_superseded_retries(self):
        first=self.submit()
        self.assertEqual(first.status_code,200,first.content)
        row=CertificateAssignment.objects.get()
        row.expires_at=timezone.now()-timedelta(seconds=1)
        row.save(update_fields=["expires_at"])
        self.assertEqual(self.host_request().json()["state"],"receipt")
        row.expires_at=timezone.now()+timedelta(days=7)
        row.save(update_fields=["expires_at"])
        revoke=dict(self.params,action="revoke",expected_revision=1,
                    operation_id=str(uuid.uuid4()))
        result=self.submit(revoke)
        self.assertEqual(result.status_code,200,result.content)
        receipt=result.json()["receipt"]
        statement=self.assert_receipt(receipt)
        self.assertEqual(statement["status"],"revoked")
        self.assertEqual(statement["revision"],2)
        self.assertEqual(self.host_request().json()["state"],"receipt")
        self.assertEqual(self.submit(revoke).json()["receipt"],receipt)
        # Exact retry of the former approval must not resurrect it, and
        # a superseded *state conflict* maps to HTTP 409 rather than 400.
        superseded = self.submit()
        self.assertEqual(superseded.status_code,409,superseded.content)
        self.assertEqual(superseded.json()["code"],"operation-superseded")
        self.assertEqual(superseded["Cache-Control"],"no-store")
        self.assertEqual(CertificateAssignment.objects.count(),1)
        self.assertEqual(CertificateAssignmentAction.objects.count(),2)
        current = CertificateAssignment.objects.get()
        self.assertEqual(current.state,"revoked")
        self.assertEqual(current.revision,2)
        self.assertEqual(current.receipt,receipt)

    def test_managed_capability_opt_in_and_strict_signed_contract(self):
        # Host-discover itself validates the response schema/envelope, not
        # a station-specific approximation of that producer contract.
        disabled=make_request(
            str(self.host.pk),None,installation_id=MANAGED,
            managed_session=self.session)
        with override_settings(HOST_CERTIFICATE_ASSIGNMENT_ENABLED=False):
            self.assertEqual(self.host_request(disabled).status_code,503)
            self.assertEqual(self.submit().status_code,400)
        self.assertEqual(self.host_request(disabled).status_code,200)
        self.assertEqual(self.host_request(disabled).json()["state"],"unassigned")
        self.assertEqual(self.submit().status_code,200)
        response=self.host_request(disabled)
        self.assertEqual(response.status_code,200)
        result=validate_response(response.json(),known_revision=0,
                                 expected_host=str(self.host.pk))
        self.assertEqual(result["state"],"receipt")
        value=validate_envelope(result["envelope"],self.receipt_key,
            expected_host=str(self.host.pk),expected_installation=MANAGED)
        self.assertEqual(value["revision"],1)
        self.assertEqual(value["status"],"approved")
        self.assertEqual(value["dns_mode"],"local-cloudflare")
        self.assertEqual(value["dns_zone"],"example.test")

    def test_managed_retrieval_denies_wrong_session_or_rollback(self):
        self.assertEqual(self.submit().status_code,200)
        bad=make_request(str(self.host.pk),None,installation_id=MANAGED,
                         managed_session="wrong-session")
        self.assertEqual(self.host_request(bad).status_code,403)
        bad=make_request(str(self.host.pk),None,
                         installation_id=str(uuid.uuid4()),
                         managed_session=self.session)
        self.assertEqual(self.host_request(bad).status_code,403)
        old=make_request(str(self.host.pk),{
            "revision":2,"operation_id":str(uuid.uuid4())},
            installation_id=MANAGED,managed_session=self.session)
        self.assertEqual(self.host_request(old).status_code,409)

    def test_local_without_command_center_enrollment_or_host_id(self):
        local=dict(self.params,origin="local",host_id=None,
                   operation_id=str(uuid.uuid4()))
        local["policy"]=dict(self.policy,hostnames=["local.extra.example.test"])
        self.dns.delete()
        HostIdentity.objects.all().delete()
        ManagedAdmission.objects.all().delete()
        Host.objects.all().delete()
        self.assertEqual(Host.objects.count(),0)
        result=self.submit(local)
        self.assertEqual(result.status_code,200,result.content)
        stmt=result.json()["receipt"]["statement"]
        self.assert_receipt(result.json()["receipt"],origin="local")
        self.assertEqual(stmt["installation_id"],LOCAL)
        self.assertIsNone(stmt["host_id"])
        self.assertEqual(stmt["consumer"],"station-nginx-https")
        self.assertEqual(stmt["origin"],"local")
        from zog.station_access.host_registry.management.commands.read_local_certificate_assignment import local_status
        local_receipt=local_status()
        self.assertEqual(local_receipt["state"],"approved")
        self.assertEqual(local_receipt["receipt"],result.json()["receipt"])
        # A previously valid local receipt may no longer be returned as
        # approved once the credential check is withdrawn.
        ProviderAccessCheck.objects.all().delete()
        self.assertEqual(local_status()["state"],"conflict")
        self.assertIsNone(local_status()["receipt"])

    def test_stale_and_conflicting_authority_denied_without_dns_writes(self):
        for mutation in (
            {"credential_revision":3},
            {"credential_id":str(uuid.uuid4())},
            {"zone_id":"different-zone"},
            {"zone_name":"wrong.example.test"},
            {"binding_id":"unknown-zone"},
            {"host_id":str(uuid.uuid4())},
            {"expires_at":"2020-01-01T00:00:00Z"},
            {"expected_revision":1},
        ):
            with self.subTest(mutation=mutation):
                data=dict(self.params,**mutation,operation_id=str(uuid.uuid4()))
                self.assertIn(self.submit(data).status_code,(400,409))
        self.assertEqual(CertificateAssignment.objects.count(),0)
        self.assertEqual(CertificateAssignmentAction.objects.count(),0)
        self.dns.status="pending";self.dns.save(update_fields=["status"])
        self.assertEqual(self.submit().status_code,409)
        self.assertEqual(SecurityAudit.objects.count(),0)
        self.assertEqual(CertificateAssignment.objects.count(),0)

    def test_retrieval_fences_credential_dns_and_host_identity_drift(self):
        self.assertEqual(self.submit().status_code,200)
        ProviderCredential.objects.filter(pk=self.credential.pk).update(revision=5)
        self.assertEqual(self.host_request().status_code,409)
        ProviderCredential.objects.filter(pk=self.credential.pk).update(revision=4)
        AdditionalDnsAssignment.objects.filter(pk=self.dns.pk).update(enabled=False)
        self.assertEqual(self.host_request().status_code,409)
        AdditionalDnsAssignment.objects.filter(pk=self.dns.pk).update(enabled=True)
        HostIdentity.objects.filter(host=self.host).update(status="revoked")
        self.assertEqual(self.host_request().status_code,403)

    def test_wrong_key_or_replay_and_mutated_request_rejected(self):
        self.assertEqual(self.submit().status_code,200)
        self.assertEqual(self.host_request(key=Ed25519PrivateKey.generate()).status_code,403)
        forged=signatures.sign(ORIGIN+self.host_url,b"{}",
                              self.host_key,str(self.host.pk))
        self.assertEqual(self.host_request(message=forged).status_code,400)
        self.assertEqual(self.client.post(self.host_url,
            data=canonical(make_request(str(self.host.pk),None,installation_id=MANAGED,managed_session=self.session)),
            content_type="application/json").status_code,403)

    def test_duplicate_operation_conflict_and_missing_signer_fail_closed(self):
        first=self.submit()
        self.assertEqual(first.status_code,200)
        wrong=dict(self.params,expires_at="2030-01-01T00:00:00Z")
        self.assertEqual(self.submit(wrong).status_code,409)
        local=dict(self.params,origin="local",host_id=None,
                   operation_id=str(uuid.uuid4()))
        local["policy"]=dict(self.policy,hostnames=["local.extra.example.test"])
        with override_settings(HOST_CERTIFICATE_ASSIGNMENT_SIGNING_KEY_FILE=""):
            self.assertIn(self.submit(local).status_code,(400,503))
        self.assertEqual(CertificateAssignment.objects.count(),1)

    def test_local_assignment_without_recent_provider_access_is_rejected(self):
        local=dict(self.params,origin="local",host_id=None,
                   operation_id=str(uuid.uuid4()))
        local["policy"]=dict(self.policy,hostnames=["local.extra.example.test"])
        ProviderAccessCheck.objects.all().delete()
        self.assertEqual(self.submit(local).status_code,400)
        self.assertEqual(CertificateAssignment.objects.count(),0)
        self.assertEqual(CertificateAssignmentAction.objects.count(),0)

    def test_local_managed_conflict_is_not_silently_overwritten(self):
        first=self.submit()
        self.assertEqual(first.status_code,200)
        local=dict(self.params,origin="local",host_id=None,
                   operation_id=str(uuid.uuid4()))
        local["policy"]=dict(self.policy,hostnames=[self.name])
        self.assertEqual(self.submit(local).status_code,409)
        self.assertEqual(CertificateAssignment.objects.count(),1)

    def test_admin_only_csrf_and_no_direct_issuer_execution(self):
        with patch("subprocess.run",side_effect=AssertionError("no issuer")):
            self.assertEqual(self.submit().status_code,200)
        self.client.logout()
        self.assertEqual(self.client.get(self.admin_url).status_code,401)
        self.assertEqual(self.submit().status_code,401)
        ordinary=get_user_model().objects.create_user(username="ordinary")
        self.client.force_login(ordinary)
        self.assertEqual(self.submit().status_code,403)
        self.assertEqual(self.client.get(self.admin_url).status_code,403)
