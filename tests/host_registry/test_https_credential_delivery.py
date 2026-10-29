"""HTTPS credential producer source acceptance. No real Cloudflare token."""
import base64
import hashlib
import json
import os
import time
import uuid
from datetime import timedelta
from unittest.mock import patch

from django.test import TestCase, SimpleTestCase, override_settings
from django.utils import timezone
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from zog.host_identify import signatures
from zog.station_access.credential_delivery_protocol import (
    SCHEMA, PURPOSE, PATH, HEADERS, parse, envelope, unpack,
    DeliveryDenied,
)
from zog.station_access import credential_https_ingress
from zog.station_access.host_registry import credential_https_authority as authority
from zog.station_access.host_registry import administrator_credential_profile as admin
from zog.station_access.host_registry.models import (
    Host, HostIdentity, SecurityGate, HttpsCredentialDeliveryNonce,
    HttpsCredentialDeliveryRevision,
)

ORIGIN = "https://command-center.example.test"
H = "00000000-0000-4000-8000-000000000111"
I = "00000000-0000-4000-8000-000000000112"
S = "00000000-0000-4000-8000-000000000113"
A = "00000000-0000-4000-8000-000000000114"
AUTH = "a"*64


def request(**changes):
    payload = dict(schema=SCHEMA, purpose=PURPOSE,
        host_id=H, installation_id=I, state_volume_id=S,
        registry_id="command-center", consumer="certify-manage",
        destination="issuer-dns-cloudflare", authorization_id=AUTH,
        assignment_id=A, assignment_revision=3,
        credential_revision=4, nonce="e"*32,
        consumer_key_fingerprint="d"*64,
        consumer_signature_ed25519=base64.b64encode(b"0"*64).decode())
    payload.update(changes)
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


def proposal(**changes):
    value = dict(schema=admin.SCHEMA, purpose=admin.PURPOSE,
        operation="first-provision", host_id=H, installation_id=I,
        state_volume_id=S, account="station-admin", credential_revision=4,
        operator_approval_sha256="a"*64,
        destination="protected-station-admin-state",
        source_kind="first-login-verified-export",
        source_password_verified=True, receiver_grant_id="f"*32,
        account_revision=3, session_revocation_required=True)
    value.update(changes)
    return value


class ProtocolTests(TestCase):
    def test_strict_cloudflare_only_request_and_envelope(self):
        raw = request()
        headers = {k: "test" for k in HEADERS}
        headers["Content-Type"] = "application/json"
        self.assertEqual(parse(raw)["purpose"], PURPOSE)
        body, head, value = unpack(envelope(raw, headers).rstrip(b"\n"))
        self.assertEqual((body, value["host_id"]), (raw, H))

    def test_other_purposes_and_expanded_requests_never_admit(self):
        for change in (
            {"purpose":"station-administrator-bootstrap"},
            {"purpose":"archive-mirror"},
            {"destination":"anywhere"},
            {"consumer":"browser"},
            {"host_id":"not-uuid"},
            {"credential_revision":True},
            {"consumer_signature_ed25519":"bad"},
            {"consumer_key_fingerprint":"broken"},
            {"nonce":"x"*32},
            {"remote_path":"/secrets"},
        ):
            with self.subTest(change=change), self.assertRaises(DeliveryDenied):
                parse(request(**change))
        for bad in (b'{"schema":"x","schema":"y"}', b'{"a":NaN}',
                    b" "*2049, b"", b"\xff"):
            with self.assertRaises(DeliveryDenied):
                parse(bad)
        headers = {k:"x" for k in HEADERS}
        headers["Content-Type"] = "application/json"
        headers["Signature"] = "evil\r\nX-Injected: yes"
        with self.assertRaises(DeliveryDenied):
            envelope(request(), headers)

    def test_ordinary_wsgi_routes_and_browser_sessions_never_touch_broker(self):
        from io import BytesIO
        statuses = []
        base = dict(REQUEST_METHOD="POST", PATH_INFO=PATH, QUERY_STRING="",
                    CONTENT_TYPE="application/json", CONTENT_LENGTH=str(len(request())),
                    **{"wsgi.input":BytesIO(request()), "wsgi.url_scheme":"https"})
        with patch.dict(os.environ, {"ZOG_CREDENTIAL_HTTPS_INGRESS_ENABLED":"1"}), \
             patch.object(credential_https_ingress, "relay",
                          side_effect=AssertionError("broker invoked")):
            for extra in ({"PATH_INFO":"/api/hosts/"}, {"HTTP_COOKIE":"sessionid=bad"},
                          {"REQUEST_METHOD":"GET"}, {"QUERY_STRING":"debug=1"}):
                environment = dict(base, **extra)
                self.assertEqual(b"".join(credential_https_ingress.application(
                    environment, lambda s,h: statuses.append(s))), b"")
                self.assertEqual(statuses[-1], "403 Forbidden")

    def test_owner_protected_first_login_export_is_not_a_hash_recovery(self):
        import tempfile
        from pathlib import Path
        from django.core.management import call_command
        from django.core.management.base import CommandError
        from django.contrib.auth import get_user_model
        user=get_user_model().objects.create_superuser(
            username="station-admin", email="", password="FirstLoginVerified123!")
        with tempfile.TemporaryDirectory() as folder:
            base=Path(folder)
            source=base/"FIRST-LOGIN.txt"
            source.write_text("Username: station-admin\nPassword: FirstLoginVerified123!\n")
            source.chmod(0o600)
            output=base/"export.json"
            call_command("export_station_login", source=str(source), output=str(output))
            self.assertEqual(json.loads(output.read_text())["password"],
                             "FirstLoginVerified123!")
            user.set_password("RotatedNeverExportFromHash123!")
            user.save(update_fields=["password"])
            with self.assertRaises(CommandError):
                call_command("export_station_login", source=str(source),
                             output=str(output))
            # An old export is retained historical secret, not rewritten by
            # a Django password change and never a reusable approval grant.
            self.assertEqual(json.loads(output.read_text())["password"],
                             "FirstLoginVerified123!")

    def test_admin_provisioning_requires_separate_approval_and_is_disabled(self):
        valid = admin.validate_proposal(proposal())
        self.assertFalse(valid["remote_delivery_authorized"])
        for diff in ({"account":"other-admin"}, {"source_kind":"django-password-hash"},
                     {"source_password_verified":False}, {"destination":"browser"},
                     {"operator_approval_sha256":"0"}, {"credential_revision":0},
                     {"session_revocation_required":False},
                     {"purpose":"archive-mirror"}, {"password":"plaintext"}):
            with self.subTest(diff=diff), self.assertRaises(DeliveryDenied):
                admin.validate_proposal(proposal(**diff))


@override_settings(HOST_IDENTITY_ORIGIN=ORIGIN, HOST_HTTPS_CREDENTIAL_LIVE_ENABLED=True)
class BrokerTests(TestCase):
    def setUp(self):
        SecurityGate.objects.get_or_create(pk=1)
        self.key=Ed25519PrivateKey.generate()
        self.fp=signatures.fingerprint(self.key.public_key())
        self.consumer_key=Ed25519PrivateKey.generate()
        from cryptography.hazmat.primitives import serialization
        self.consumer_public=self.consumer_key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.consumer_fp=hashlib.sha256(self.consumer_public).hexdigest()
        self.host=Host.objects.create(id=uuid.UUID(H), label="issuer", provider="generic")
        HostIdentity.objects.create(host=self.host, fingerprint=self.fp,
            public_key=signatures.public_text(self.key.public_key()),
            status="approved", approved_by="test", approved_at=timezone.now())
        self.grant=dict(
            schema=authority.GRANT_SCHEMA, state="approved", purpose=PURPOSE,
            consumer="certify-manage", destination="issuer-dns-cloudflare",
            host_id=H, fingerprint=self.fp, installation_id=I,
            state_volume_id=S, registry_id="command-center", authority_id=I,
            assignment_id=A, assignment_revision=3, credential_revision=4,
            authorization_id=AUTH, grant_id="a"*32, storage_id="b"*32,
            consumer_public_key=base64.b64encode(self.consumer_public).decode(),
            consumer_key_fingerprint=self.consumer_fp, consumer_key_revision=1,
            operator_approval_sha256="b"*64,
            independent_signer_pin_sha256="c"*64, revision=2,
            expires_at=int(time.time())+3600)
        self.headers = dict(signatures.sign(ORIGIN+PATH,request(),self.key,H).headers)

    def _signed(self, body=None, key=None):
        from zog.station_access.host_registry.certificate_assignment_signing import canonical
        data=json.loads(body or request())
        data["consumer_key_fingerprint"]=self.consumer_fp
        claims=dict(data)
        claims.pop("consumer_signature_ed25519")
        data["consumer_signature_ed25519"]=base64.b64encode(
            self.consumer_key.sign(
                b"zog-credential-delivery-consumer-v1\0" + canonical(claims))).decode()
        value=canonical(data)
        signed=signatures.sign(ORIGIN+PATH,value,key or self.key,H)
        return envelope(value, {h:signed.headers[h] for h in HEADERS}).rstrip(b"\n")

    def test_independent_consumer_proof_is_checked_separately(self):
        _, _, data=unpack(self._signed())
        authority._verify_consumer(self.grant, data)
        foreign=dict(data, consumer_key_fingerprint="f"*64)
        with self.assertRaises(DeliveryDenied):
            authority._verify_consumer(self.grant, foreign)
        changed=dict(data, credential_revision=55)
        with self.assertRaises(DeliveryDenied):
            authority._verify_consumer(self.grant, changed)
        foreign_key=dict(self.grant, consumer_public_key=base64.b64encode(
            Ed25519PrivateKey.generate().public_key().public_bytes_raw()).decode())
        with self.assertRaises(DeliveryDenied):
            authority._verify_consumer(foreign_key, data)

    def test_disabled_root_broker_never_queries_vault(self):
        with override_settings(HOST_HTTPS_CREDENTIAL_LIVE_ENABLED=False):
            with patch.object(authority, "_read_local_token",
                              side_effect=AssertionError("vault reached")):
                with self.assertRaises(DeliveryDenied):
                    authority.authorize_and_read(self._signed())

    def test_signed_approved_host_and_broker_policy_only(self):
        with patch.object(authority.os,"geteuid",return_value=0), \
             patch.object(authority,"_authority",return_value=self.grant), \
             patch.object(authority,"_consume",return_value="digest") as consume, \
             patch.object(authority,"_read_local_token",return_value=b"CF_FAKE_TEST_TOKEN_1234567890"), \
             patch.object(authority,"_current") as current, \
             patch.object(authority,"_projection",return_value={}):
            result=authority.authorize_and_read(self._signed())
            self.assertEqual(result,b"CF_FAKE_TEST_TOKEN_1234567890")
            consume.assert_called_once()
            current.assert_called_once()
            bad_key=Ed25519PrivateKey.generate()
            with self.assertRaises(Exception):
                authority.authorize_and_read(self._signed(key=bad_key))

    def test_durable_nonce_grant_revision_and_replay(self):
        data=parse(request())
        with patch.object(authority,"_current"), patch.object(
                authority,"_projection",return_value={}):
            authority._consume(self.grant,data,self.fp,"signed-once",
                               timezone.now()+timedelta(seconds=120))
            self.assertEqual(HttpsCredentialDeliveryNonce.objects.count(),1)
            self.assertEqual(HttpsCredentialDeliveryRevision.objects.count(),1)
            with self.assertRaises(DeliveryDenied):
                authority._consume(self.grant,data,self.fp,"signed-twice",
                                   timezone.now()+timedelta(seconds=120))
            self.assertEqual(HttpsCredentialDeliveryNonce.objects.count(),1)
            rotated=dict(self.grant,revision=3,credential_revision=5)
            changed=dict(data,credential_revision=5,nonce="d"*32)
            authority._consume(rotated,changed,self.fp,"signed-three",
                               timezone.now()+timedelta(seconds=120))
            self.assertEqual(HttpsCredentialDeliveryRevision.objects.get(
                host_id=H).credential_revision,5)
            with self.assertRaises(DeliveryDenied):
                authority._consume(self.grant,dict(data,nonce="b"*32),
                    self.fp,"signed-four",timezone.now()+timedelta(seconds=120))

    def test_signed_revocation_tombstone_blocks_old_grant_after_reboot(self):
        revoked=dict(self.grant, state="revoked", revision=3)
        with patch.object(authority.os, "geteuid", return_value=0), \
             patch.object(authority, "_authority", return_value=revoked):
            result=authority.reconcile_signed_revocation()
        self.assertEqual(result["status"],"revoked")
        history=HttpsCredentialDeliveryRevision.objects.get(host_id=H)
        self.assertTrue(history.revoked)
        self.assertEqual(history.grant_revision,3)
        # An operator cannot revive the old approved revision by restoring
        # the old root-owned file, even after the service restarts.
        with patch.object(authority, "_current"), \
             patch.object(authority, "_projection", return_value={}):
            with self.assertRaises(DeliveryDenied):
                authority._consume(self.grant,parse(request()),self.fp,
                    "signed-reboot",timezone.now()+timedelta(seconds=120))

    def test_independent_operator_signature_accepts_exact_grant_only(self):
        import base64, hashlib
        from cryptography.hazmat.primitives import serialization
        from zog.station_access.host_registry.certificate_assignment_signing import canonical
        key = Ed25519PrivateKey.generate()
        packet = dict(self.grant)
        packet.pop("operator_approval_sha256")
        packet["independent_signer_pin_sha256"] = hashlib.sha256(
            b"trusted prior signer").hexdigest()
        approval = {
            "schema": "zog-credential-delivery-operator-approval-v1",
            "grant_sha256": hashlib.sha256(canonical(packet)).hexdigest(),
            "signature_ed25519": base64.b64encode(
                key.sign(b"zog-credential-delivery-operator-approval-v1\0"
                         + canonical(packet))).decode(),
        }
        signed = dict(self.grant,
            operator_approval_sha256=hashlib.sha256(canonical(approval)).hexdigest(),
            independent_signer_pin_sha256=hashlib.sha256(b"trusted prior signer").hexdigest())
        public = key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        blobs = {
            "HOST_CREDENTIAL_HTTPS_OPERATOR_APPROVAL_FILE": canonical(approval),
            "HOST_CREDENTIAL_HTTPS_OPERATOR_PIN_FILE": public,
            "HOST_CREDENTIAL_HTTPS_SIGNER_PIN_FILE": b"trusted prior signer",
        }
        def protected(path, mode, maximum=8192):
            return blobs[next(k for k in blobs if k in path)]
        with override_settings(
                HOST_CREDENTIAL_HTTPS_OPERATOR_APPROVAL_FILE="/test/HOST_CREDENTIAL_HTTPS_OPERATOR_APPROVAL_FILE",
                HOST_CREDENTIAL_HTTPS_OPERATOR_PIN_FILE="/test/HOST_CREDENTIAL_HTTPS_OPERATOR_PIN_FILE",
                HOST_CREDENTIAL_HTTPS_SIGNER_PIN_FILE="/test/HOST_CREDENTIAL_HTTPS_SIGNER_PIN_FILE"), \
             patch.object(authority, "_protected", side_effect=protected):
            authority._independent_approval(signed)
            with self.assertRaises(DeliveryDenied):
                authority._independent_approval(dict(signed, credential_revision=8))
            with self.assertRaises(DeliveryDenied):
                authority._independent_approval(dict(
                    signed, independent_signer_pin_sha256="f"*64))

    def test_root_operator_approval_not_self_issued(self):
        with patch.object(authority,"_json_root",return_value=self.grant), \
             patch.object(authority,"_independent_approval",
                          side_effect=DeliveryDenied("not independently signed")):
            with self.assertRaises(DeliveryDenied):
                authority._authority()
