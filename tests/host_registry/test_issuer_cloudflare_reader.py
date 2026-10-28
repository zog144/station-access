"""Local Cloudflare reader: fixed-authorization, vault-only secret channel tests."""
import hashlib
import json
import os
import socket
import stat
import struct
import tempfile
import time
import uuid
from datetime import timedelta
from pathlib import Path
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.utils import timezone
from zog.station_access.host_registry.certificate_assignment_signing import canonical
from zog.station_access.host_registry.issuer_cloudflare_reader import (
    ReaderDenied, ROOT_SCHEMA, PROJECTION_SCHEMA, REQUEST_SCHEMA,
    authorization_id, read_approved_token, serve_once, _private_projection,
)
from zog.station_access.host_registry.models import (
    CertificateAssignment, DnsDestination, ProviderCredential,
    ProviderAccessCheck, SecurityAudit, IssuerTokenReadNonce, Host,
    HostIdentity, ManagedAdmission, ManagedDns01Hostname
)

TOKEN = "CF_TokenFixture23456789001234567890"
LOCAL_ID = "00000000-0000-4000-8000-000000000888"
ASSIGN_ID = "00000000-0000-4000-8000-000000000889"
CRED_ID = "00000000-0000-4000-8000-000000000887"


@override_settings(HOST_LOCAL_CERTIFICATE_INSTALLATION_ID=LOCAL_ID,
                   HOST_ISSUER_CREDENTIAL_READER_UID=1700)
class CloudflareReaderTests(TestCase):
    def setUp(self):
        from zog.station_access.host_registry.models import SecurityGate
        SecurityGate.objects.get_or_create(pk=1)
        self.admin = get_user_model().objects.create_superuser(
            username="reader-admin",password="fixture",email="")
        self.credential = ProviderCredential.objects.create(
            id=uuid.UUID(CRED_ID),label="Issuer dedicated",provider="cloudflare",
            account_id="a"*32,revision=4,key_id="vault-1",
            ciphertext="encrypted-source-fixture")
        self.binding = DnsDestination.objects.create(
            id="reader-zone",enabled=True,ledger_path="immutable-test-ledger",
            selection={"owner_user_id":self.admin.pk,
                       "credential_id":CRED_ID,"credential_revision":4,
                       "zone_id":"zone1","zone_name":"example.org",
                       "prefix":"extra.example.org"})
        ProviderAccessCheck.objects.create(
            credential=self.credential,credential_revision=4,
            started_at=timezone.now(),finished_at=timezone.now(),
            status="passed",domains=[{"id":"zone1","name":"example.org","status":"active"}])
        policy={"schema":"zog-certify-manage-v1","certificate_id":"station-web",
                "hostnames":["local.extra.example.org"],"email":"ops@example.org",
                "acme_directory":"https://acme.example.org/directory",
                "challenge":"dns-01","dns_plugin":"dns-cloudflare"}
        self.assignment=CertificateAssignment.objects.create(
            id=uuid.UUID(ASSIGN_ID),origin="local",host=None,
            installation_id=uuid.UUID(LOCAL_ID),hostname=policy["hostnames"][0],
            binding_id=self.binding.pk,credential=self.credential,
            credential_revision=4,zone_id="zone1",zone_name="example.org",
            expires_at=timezone.now()+timedelta(days=2),
            revision=2,state="approved",
            statement={"schema":"zog-certificate-assignment-v1",
                       "policy":policy,"host_fingerprint":None},
            receipt={"schema":"zog-certificate-assignment-receipt-v1",
                     "statement":{"revision":2,"state":"approved"},
                     "signature_ed25519":"fixture-only"})
        SecurityAudit.objects.create(actor=str(self.admin.pk),
                                     action="certificate-assign",
                                     details={"assignment_id":ASSIGN_ID,"revision":2})
        self.a={
            "schema":ROOT_SCHEMA,"state":"approved","project":"/zog/owner",
            "certificate_id":"station-web","assignment_id":ASSIGN_ID,
            "assignment_revision":2,"credential_id":CRED_ID,
            "credential_revision":4,"zone_id":"zone1","zone_name":"example.org",
            "grant_id":"a"*32,"storage_id":"b"*32,
            "policy_sha256":hashlib.sha256(canonical(policy)).hexdigest(),
            "receipt_sha256":hashlib.sha256(canonical(self.assignment.receipt)).hexdigest(),
            "expires_at":int((timezone.now()+timedelta(days=1)).timestamp()),
        }
        self.projection={
            "schema":PROJECTION_SCHEMA, "authorization":self.a,
            "origin":"local","installation_id":LOCAL_ID,
            "host_id":None,"account_id":"a"*32,"owner_user_id":self.admin.pk}
        self.patch_projection=patch(
            "zog.station_access.host_registry.issuer_cloudflare_reader._private_projection",
            return_value=self.projection)
        self.patch_decrypt=patch(
            "zog.station_access.host_registry.issuer_cloudflare_reader.decrypt_provider",
            return_value={"api_token":TOKEN})
        self.patch_projection.start()
        self.patch_decrypt.start()
        self.patch_uid = patch("zog.station_access.host_registry.issuer_cloudflare_reader.os.geteuid", return_value=1700)
        self.patch_uid.start()
        self.addCleanup(self.patch_uid.stop)
        self.addCleanup(self.patch_projection.stop)
        self.addCleanup(self.patch_decrypt.stop)

    def request(self, *, nonce=None, auth=None):
        return {"schema":REQUEST_SCHEMA,
                "operation":"read-approved-cloudflare-issuer-token",
                "authorization_id":auth or authorization_id(self.projection),
                "nonce":nonce or os.urandom(16).hex()}

    def denied(self, value=None):
        with self.assertRaisesRegex(ReaderDenied, "issuer credential reader unavailable"):
            read_approved_token(value or self.request())

    def test_exact_local_approval_returns_only_token_bytes_and_persists_nonce(self):
        request=self.request()
        self.assertEqual(read_approved_token(request),TOKEN.encode("ascii"))
        self.assertEqual(IssuerTokenReadNonce.objects.count(),1)
        self.denied(request)
        # Neither plaintext nor token digest belongs in durable nonce data.
        row=IssuerTokenReadNonce.objects.get()
        self.assertEqual(row.authorization_id, authorization_id(self.projection))
        self.assertNotIn(TOKEN,str(row.__dict__))

    def test_invalid_request_or_wrong_authorization_id(self):
        for change in ({"authorization_id":"0"*64},
                       {"operation":"read-arbitrary-vault-token"},
                       {"schema":"wrong"},
                       {"nonce":"g"*32},
                       {"extra":"arbitrary/path"}):
            with self.subTest(change=change):
                self.denied(dict(self.request(),**change))
        self.assertFalse(IssuerTokenReadNonce.objects.exists())

    def test_credential_rotation_revocation_expiry_and_zone_changes_block(self):
        def rotate(): ProviderCredential.objects.filter(pk=CRED_ID).update(revision=5)
        for change in (
            rotate,
            lambda:CertificateAssignment.objects.filter(pk=ASSIGN_ID).update(state="revoked"),
            lambda:CertificateAssignment.objects.filter(pk=ASSIGN_ID).update(
                expires_at=timezone.now()-timedelta(seconds=1)),
            lambda:DnsDestination.objects.filter(pk=self.binding.pk).update(enabled=False),
            lambda:ProviderAccessCheck.objects.filter(credential=self.credential).delete(),
            lambda:SecurityAudit.objects.filter(action="certificate-assign").delete(),
        ):
            with self.subTest(change=change.__name__):
                # Django TestCase savepoint preserves each independent check.
                from django.db import transaction
                with transaction.atomic():
                    change()
                    self.denied()
                    transaction.set_rollback(True)

    def test_wrong_provider_account_owner_or_cross_zone(self):
        for change in (
            lambda:ProviderCredential.objects.filter(pk=CRED_ID).update(provider="porkbun"),
            lambda:ProviderCredential.objects.filter(pk=CRED_ID).update(account_id="b"*32),
            lambda:DnsDestination.objects.filter(pk=self.binding.pk).update(
                selection=dict(self.binding.selection,zone_id="other-zone")),
            lambda:DnsDestination.objects.filter(pk=self.binding.pk).update(
                selection=dict(self.binding.selection,owner_user_id=self.admin.pk+1)),
        ):
            from django.db import transaction
            with transaction.atomic():
                change()
                self.denied()
                transaction.set_rollback(True)

    def test_unavailable_vault_bad_token_and_midread_rotation(self):
        src="zog.station_access.host_registry.issuer_cloudflare_reader.decrypt_provider"
        with patch(src,side_effect=ValueError("private-super-secret-token")):
            self.denied()
        for candidate in ("short", "bad\nnewline"+"A"*20, "x"*4097):
            with patch(src,return_value={"api_token":candidate}):
                self.denied()
        def moving_vault(row):
            ProviderCredential.objects.filter(pk=row.pk).update(revision=5)
            return {"api_token":TOKEN}
        with patch(src,side_effect=moving_vault):
            self.denied()
        self.assertFalse(IssuerTokenReadNonce.objects.values_list(
            "authorization_id",flat=True).filter(authorization_id=TOKEN).exists())

    def test_projection_identity_is_checked_before_decrypt_and_after_rotation(self):
        with patch("zog.station_access.host_registry.issuer_cloudflare_reader._private_projection",
                   side_effect=[self.projection,dict(self.projection,account_id="b"*32)]):
            self.denied()
        changed=dict(self.projection,owner_user_id=self.admin.pk+1)
        with patch("zog.station_access.host_registry.issuer_cloudflare_reader._private_projection",
                   return_value=changed):
            self.denied(self.request(auth=authorization_id(changed)))

    def test_root_approval_unavailable_or_malformed_never_falls_back(self):
        with patch("zog.station_access.host_registry.issuer_cloudflare_reader._private_projection",
                   side_effect=ReaderDenied("issuer credential reader unavailable")):
            self.denied()
        with patch("zog.station_access.host_registry.issuer_cloudflare_reader._private_projection",
                   return_value=dict(self.projection,authorization=dict(self.a,receipt_sha256="0"*64))):
            self.denied()

    def test_socket_peer_uid_gate_precedes_parsing_and_secret_lookup(self):
        class Connection:
            def __init__(self,uid,payload):
                self.uid,self.payload,self.sent=uid,payload,b""
            def __enter__(self):return self
            def __exit__(self,*args):pass
            def getsockopt(self,*args):return struct.pack("3i",123,self.uid,123)
            def settimeout(self,*args):pass
            def recv(self,*args):
                value=self.payload
                self.payload=b""
                return value
            def sendall(self,data):self.sent+=data
        class Listener:
            def __init__(self,connection):self.connection=connection
            def accept(self):return self.connection,None
        payload=canonical(self.request())+b"\n"
        conn=Connection(12345,payload)
        with patch("zog.station_access.host_registry.issuer_cloudflare_reader.read_approved_token",
                   side_effect=AssertionError("must not read vault")):
            serve_once(Listener(conn))
        self.assertEqual(conn.sent,b"")
        good=Connection(0,payload)
        serve_once(Listener(good))
        self.assertEqual(good.sent,TOKEN.encode())

    def _managed_dns01(self):
        """Real reviewed name authority, not a DnsDestination or A record."""
        host = Host.objects.create(label="generic issuer", provider="generic")
        fingerprint = "f" * 64
        HostIdentity.objects.create(
            host=host, fingerprint=fingerprint, public_key="A" * 44,
            status="approved", approved_at=timezone.now(), approved_by="reader-admin")
        admission = ManagedAdmission.objects.create(
            host=host, fingerprint=fingerprint,
            installation_id=uuid.uuid4(), state_volume_id=uuid.uuid4(),
            authority_id=uuid.uuid4(), registry_id="test-registry",
            epoch=1, checkpoint=uuid.uuid4(), request={},
            claims={"jti": "live-issuer-session", "exp": time.time() + 3600})
        hostname = "issuer.example.org"
        grant = ManagedDns01Hostname.objects.create(
            host=host, hostname=hostname, fingerprint=fingerprint,
            installation_id=admission.installation_id,
            state_volume_id=admission.state_volume_id,
            authority_id=admission.authority_id,
            registry_id=admission.registry_id,
            credential=self.credential, credential_revision=4,
            zone_id="zone1", zone_name="example.org",
            owner_user_id=self.admin.pk, review_id="f" * 64)
        policy = dict(self.assignment.statement["policy"], hostnames=[hostname])
        self.assignment.origin = "managed"
        self.assignment.host = host
        self.assignment.installation_id = admission.installation_id
        self.assignment.hostname = hostname
        self.assignment.binding_id = "managed-dns01"
        self.assignment.statement = {
            **self.assignment.statement, "policy": policy,
            "origin": "managed", "host_id": str(host.pk),
            "installation_id": str(admission.installation_id),
            "binding_id": "managed-dns01", "host_fingerprint": fingerprint}
        self.assignment.save()
        self.a["policy_sha256"] = hashlib.sha256(canonical(policy)).hexdigest()
        self.projection["origin"] = "managed"
        self.projection["host_id"] = str(host.pk)
        self.projection["installation_id"] = str(admission.installation_id)
        self.binding.delete()
        return host, admission, grant

    def test_managed_dns01_approved_name_returns_token_without_legacy_destination(self):
        host, admission, grant = self._managed_dns01()
        self.assertFalse(DnsDestination.objects.exists())
        self.assertFalse(host.additional_dns_assignments.exists())
        self.assertEqual(read_approved_token(self.request()), TOKEN.encode())
        self.assertEqual(IssuerTokenReadNonce.objects.count(), 1)
        self.assertEqual(ManagedDns01Hostname.objects.get(host=host).pk, host.pk)

    def test_managed_dns01_rejects_changed_authority_before_decrypt(self):
        host, admission, grant = self._managed_dns01()
        from django.db import transaction
        def changed_grant():
            ManagedDns01Hostname.objects.filter(host=host).update(active=False)
        def changed_zone():
            ManagedDns01Hostname.objects.filter(host=host).update(zone_id="foreign-zone")
        def changed_owner():
            ManagedDns01Hostname.objects.filter(host=host).update(owner_user_id=self.admin.pk + 1)
        def changed_credential():
            ManagedDns01Hostname.objects.filter(host=host).update(credential_revision=9)
        def changed_installation():
            ManagedAdmission.objects.filter(host=host).update(installation_id=uuid.uuid4())
        def changed_state():
            ManagedAdmission.objects.filter(host=host).update(state_volume_id=uuid.uuid4())
        def changed_authority():
            ManagedAdmission.objects.filter(host=host).update(authority_id=uuid.uuid4())
        def changed_registry():
            ManagedAdmission.objects.filter(host=host).update(registry_id="different")
        def expired_session():
            ManagedAdmission.objects.filter(host=host).update(
                claims={"jti": "live-issuer-session", "exp": 0})
        def revoked_key():
            HostIdentity.objects.filter(host=host).update(status="revoked")
        def wrong_host_mode():
            Host.objects.filter(pk=host.pk).update(provider="aws")
        def wrong_signed_binding():
            CertificateAssignment.objects.filter(pk=self.assignment.pk).update(
                statement=dict(self.assignment.statement, binding_id="legacy-destination"))
        def wrong_signed_fingerprint():
            CertificateAssignment.objects.filter(pk=self.assignment.pk).update(
                statement=dict(self.assignment.statement, host_fingerprint="0"*64))
        for change in (
                changed_grant, changed_zone, changed_owner, changed_credential,
                changed_installation, changed_state, changed_authority,
                changed_registry, expired_session, revoked_key, wrong_host_mode,
                wrong_signed_binding, wrong_signed_fingerprint):
            with self.subTest(change=change.__name__), transaction.atomic():
                change()
                with patch("zog.station_access.host_registry.issuer_cloudflare_reader.decrypt_provider",
                           side_effect=AssertionError("must refuse before decryption")):
                    self.denied()
                transaction.set_rollback(True)

    def test_managed_dns01_cannot_be_used_by_local_or_legacy_assignment(self):
        self._managed_dns01()
        from django.db import transaction
        for field, val in (("origin", "local"), ("binding_id", "unreviewed")):
            with self.subTest(field=field), transaction.atomic():
                CertificateAssignment.objects.filter(pk=self.assignment.pk).update(**{field: val})
                self.denied()
                transaction.set_rollback(True)
        self.assertFalse(DnsDestination.objects.exists())

    def test_no_token_or_provider_text_in_exception(self):
        with patch("zog.station_access.host_registry.issuer_cloudflare_reader.decrypt_provider",
                   side_effect=RuntimeError("SENSITIVE PROVIDER FAILURE "+TOKEN)):
            try:
                read_approved_token(self.request())
            except ReaderDenied as exc:
                self.assertNotIn(TOKEN,str(exc))
                self.assertNotIn("SENSITIVE",str(exc))
            else:
                self.fail("Must deny vault failure")



class CloudflareListenerIdentityTests(TestCase):
    """Real Linux AF_UNIX descriptors differ from their bound path inode."""

    def test_exact_bound_listener_is_accepted_without_inode_equivalence(self):
        from zog.station_access.host_registry.issuer_cloudflare_reader import _verify_listener_socket

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "reader.sock"
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
                listener.bind(str(path))
                path.chmod(0o600)
                listener.listen(1)
                fd_info = os.fstat(listener.fileno())
                name_info = path.lstat()
                self.assertTrue(stat.S_ISSOCK(fd_info.st_mode))
                self.assertTrue(stat.S_ISSOCK(name_info.st_mode))
                self.assertNotEqual((fd_info.st_dev, fd_info.st_ino),
                                    (name_info.st_dev, name_info.st_ino))
                self.assertIs(
                    _verify_listener_socket(listener, str(path), os.geteuid()),
                    listener)

                for invalid_path in (str(path) + ".other", "/run/not-this-reader.sock"):
                    with self.subTest(path=invalid_path):
                        with self.assertRaises(ReaderDenied):
                            _verify_listener_socket(listener, invalid_path, os.geteuid())
                with self.assertRaises(ReaderDenied):
                    _verify_listener_socket(listener, str(path), os.geteuid() + 1)
                path.chmod(0o666)
                with self.assertRaises(ReaderDenied):
                    _verify_listener_socket(listener, str(path), os.geteuid())
                path.chmod(0o600)
                path.unlink()
                path.symlink_to(Path(directory) / "substitute")
                with self.assertRaises(ReaderDenied):
                    _verify_listener_socket(listener, str(path), os.geteuid())

    def test_unlistened_and_non_unix_descriptors_are_rejected(self):
        from zog.station_access.host_registry.issuer_cloudflare_reader import _verify_listener_socket

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "reader.sock"
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as unlistened:
                unlistened.bind(str(path))
                path.chmod(0o600)
                with self.assertRaises(ReaderDenied):
                    _verify_listener_socket(unlistened, str(path), os.geteuid())
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as tcp:
                with self.assertRaises(ReaderDenied):
                    _verify_listener_socket(tcp, str(path), os.geteuid())
