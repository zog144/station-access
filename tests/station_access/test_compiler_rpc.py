"""Compiler observer RPC: real mutual TLS, authorized HTTP and fail-closed no-writer."""
import datetime
import hashlib
import json
import os
import socket
import ssl
import tempfile
import threading
from pathlib import Path
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings

from zog.station_access.compiler_rpc import (
    CompilerObserver, CompilerRPCUnavailable, CONTRACT, CONFIG_SCHEMA,
)

WORKSPACE = "00000000000040008000000000000001" # synthetic 32-hex fixture only
REQUEST = "a" * 32


def _identity(ca_key, ca_cert, common_name, usage, *, san=None, lifetime_days=(-1, 1)):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.datetime.now(datetime.timezone.utc)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    builder = (x509.CertificateBuilder()
        .subject_name(name).issuer_name(ca_cert.subject)
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now + datetime.timedelta(days=lifetime_days[0]))
        .not_valid_after(now + datetime.timedelta(days=lifetime_days[1]))
        .add_extension(x509.ExtendedKeyUsage([usage]), critical=False))
    if san:
        builder = builder.add_extension(x509.SubjectAlternativeName(
            [x509.DNSName(san)]), critical=False)
    return key, builder.sign(ca_key, hashes.SHA256())


def _pem(key, certificate):
    return (certificate.public_bytes(serialization.Encoding.PEM),
            key.private_bytes(serialization.Encoding.PEM,
                              serialization.PrivateFormat.PKCS8,
                              serialization.NoEncryption()))


class _RPCFixture:
    def __init__(self, state, *, client_cert=True):
        self.state = Path(state)
        self.private = self.state / "compiler-rpc"
        self.private.mkdir(mode=0o700)
        self.private.chmod(0o700)
        self.messages = []
        self.result = {"schema": CONTRACT, "status": "completed", "result": {
            "workspace_id":WORKSPACE, "ownership":"owned",
            "compiler":"registered", "visibility":"owner-ledger",
        }}
        ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        now = datetime.datetime.now(datetime.timezone.utc)
        root = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test owner CA")])
        ca = (x509.CertificateBuilder().subject_name(root).issuer_name(root)
              .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
              .not_valid_before(now-datetime.timedelta(days=1))
              .not_valid_after(now+datetime.timedelta(days=1))
              .add_extension(x509.BasicConstraints(ca=True,path_length=None),critical=True)
              .sign(ca_key,hashes.SHA256()))
        self._write("server-ca.pem",ca.public_bytes(serialization.Encoding.PEM),0o600)
        server_key, server_cert = _identity(ca_key,ca,"localhost",
                                            ExtendedKeyUsageOID.SERVER_AUTH,san="localhost")
        client_key, client = _identity(ca_key,ca,"station-observer",
                                        ExtendedKeyUsageOID.CLIENT_AUTH)
        self.ca_key, self.ca_cert = ca_key, ca
        self.client_der = client.public_bytes(serialization.Encoding.DER)
        self.server_cert, self.server_key = _pem(server_key,server_cert)
        self._write("client-cert.pem",_pem(client_key,client)[0],0o600)
        if client_cert:
            self._write("client-key.pem",_pem(client_key,client)[1],0o600)
        self.server = None

    def _write(self,name,data,mode):
        path=self.private/name
        path.write_bytes(data)
        path.chmod(mode)
        return path

    def configure(self,port,hostname="localhost"):
        self._write("configuration.json",json.dumps({
            "schema": CONFIG_SCHEMA,
            "endpoint":f"https://{hostname}:{port}/v1/compiler/rpc",
            "workspace_id":WORKSPACE,
        }).encode(),0o600)

    def listen(self):
        fixture=self
        class Handler(BaseHTTPRequestHandler):
            def log_message(self,*args): pass
            def do_POST(self):
                count=int(self.headers.get("Content-Length","-1"))
                if count < 0 or count > 4096 or self.path != "/v1/compiler/rpc":
                    self.send_error(400)
                    return
                raw=self.rfile.read(count)
                # The test owner accepts only the explicitly pinned client
                # fingerprint. This validates that a CA-valid foreign identity
                # is not automatically an observer.
                fingerprint = hashlib.sha256(
                    self.connection.getpeercert(binary_form=True)).digest()
                authorized = fingerprint == hashlib.sha256(fixture.client_der).digest()
                if authorized:
                    fixture.messages.append(json.loads(raw))
                message = fixture.result if authorized else {
                    "schema": CONTRACT, "status": "not-authorized"}
                body=json.dumps(message).encode()
                self.send_response(200 if message["status"]=="completed" else
                                   403 if message["status"]=="not-authorized" else 409)
                self.send_header("Content-Type","application/json")
                self.send_header("Content-Length",str(len(body)))
                self.send_header("Cache-Control","no-store")
                self.end_headers()
                self.wfile.write(body)
        self.server=ThreadingHTTPServer(("127.0.0.1",0),Handler)
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version=ssl.TLSVersion.TLSv1_2
        context.verify_mode=ssl.CERT_REQUIRED
        self._write("test-server-cert.pem",self.server_cert,0o600)
        self._write("test-server-key.pem",self.server_key,0o600)
        context.load_cert_chain(str(self.private/"test-server-cert.pem"),
                                str(self.private/"test-server-key.pem"))
        context.load_verify_locations(cafile=str(self.private/"server-ca.pem"))
        self.server.socket=context.wrap_socket(self.server.socket,server_side=True)
        thread=threading.Thread(target=self.server.serve_forever,daemon=True)
        thread.start()
        self.thread=thread
        return self.server.server_address[1]

    def stop(self):
        if self.server:
            self.server.shutdown()
            self.server.server_close()
            self.thread.join(timeout=5)
            self.server=None


class CompilerRPCConsumerTests(TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.state=Path(self.tmp.name)
        self.fixture=_RPCFixture(self.state)
        self.addCleanup(self.fixture.stop)
        self.port=self.fixture.listen()
        self.fixture.configure(self.port)
        self.settings_override=override_settings(STATE_DIRECTORY=self.state)
        self.settings_override.enable()
        self.addCleanup(self.settings_override.disable)
        users=get_user_model()
        self.admin=users.objects.create_superuser(username="rpc-admin",email="",password="secret")
        self.normal=users.objects.create_user(username="rpc-user",password="secret")

    def test_real_mutual_tls_compiler_observation_and_bounded_http(self):
        self.client.force_login(self.admin)
        reply=self.client.get("/api/compiler/status/")
        self.assertEqual(reply.status_code,200)
        self.assertEqual(reply["Cache-Control"],"no-store")
        self.assertEqual(reply.json(),{
            "schema":CONTRACT,"state":"observed","ownership":"owned",
            "compiler":"registered","evidence_basis":"owner-ledger",
            "live_host_health":"not-observed",
        })
        self.assertEqual(self.fixture.messages,[{
            "schema":CONTRACT,"operation":"compiler.status","parameters":{},
        }])
        self.assertNotIn(WORKSPACE,reply.content.decode())

    def test_dispatch_status_only_with_request_id_and_protected_fields(self):
        self.fixture.result={"schema":CONTRACT,"status":"completed","result":{
            "request":{"request_id":REQUEST,"operation":"build",
                       "admission":"admitted","dispatch":"submitted","completion":"pending"},
            "dispatch":{"phase":"submitted","binding_sha256":"b"*64,"submitted":True},
        }}
        self.client.force_login(self.admin)
        reply=self.client.get(f"/api/compiler/dispatches/{REQUEST}/")
        self.assertEqual(reply.status_code,200)
        self.assertEqual(reply.json()["request_id"],REQUEST)
        self.assertNotIn("binding_sha256",reply.content.decode())
        self.assertEqual(self.fixture.messages[0]["operation"],"dispatch.status")
        self.assertEqual(self.fixture.messages[0]["parameters"],{"request_id":REQUEST})
        rejected=self.client.get("/api/compiler/dispatches/invalid/")
        self.assertEqual(rejected.status_code,400)
        self.assertEqual(len(self.fixture.messages),1)

    def test_missing_certificate_and_bad_dns_never_fall_back(self):
        self.client.force_login(self.admin)
        (self.fixture.private/"client-key.pem").unlink()
        self.assertEqual(self.client.get("/api/compiler/status/").status_code,503)
        self.assertEqual(self.fixture.messages,[])
        self.fixture._write("client-key.pem",b"not a key",0o600)
        self.assertEqual(self.client.get("/api/compiler/status/").status_code,503)
        self.assertEqual(self.fixture.messages,[])
        # Changed hostname is rejected by TLS certificate validation.
        self.fixture.configure(self.port,hostname="127.0.0.1")
        self.assertEqual(self.client.get("/api/compiler/status/").status_code,503)
        self.assertEqual(self.fixture.messages,[])

    def test_only_administrator_can_invoke_rpc(self):
        self.assertEqual(self.client.get("/api/compiler/status/").status_code,401)
        self.assertEqual(self.client.get(f"/api/compiler/dispatches/{REQUEST}/").status_code,401)
        self.client.force_login(self.normal)
        self.assertEqual(self.client.get("/api/compiler/status/").status_code,403)
        self.assertEqual(self.client.get(f"/api/compiler/dispatches/{REQUEST}/").status_code,403)
        self.assertEqual(self.fixture.messages,[])
        self.client.force_login(self.admin)
        self.assertEqual(self.client.post("/api/compiler/status/").status_code,405)
        self.assertEqual(self.fixture.messages,[])

    def test_owner_mismatch_and_safe_failure_do_not_leak(self):
        self.client.force_login(self.admin)
        self.fixture.result={"schema":CONTRACT,"status":"completed","result":{
            "workspace_id":"0"*32,"ownership":"owned","compiler":"registered",
            "visibility":"owner-ledger","secret":"/var/lib/SECRET",
        }}
        reply=self.client.get("/api/compiler/status/")
        self.assertEqual(reply.status_code,409)
        self.assertNotIn("SECRET",reply.content.decode())
        self.fixture.result={"schema":CONTRACT,"status":"ownership-epoch-mismatch"}
        reply=self.client.get("/api/compiler/status/")
        self.assertEqual(reply.status_code,409)
        self.assertEqual(reply.json()["error"],"ownership-epoch-mismatch")
        self.fixture.result={"schema":CONTRACT,"status":"uncertain"}
        self.assertEqual(self.client.get("/api/compiler/status/").status_code,409)
        self.fixture.result={"schema":CONTRACT,"status":"not-authorized"}
        self.assertEqual(self.client.get("/api/compiler/status/").status_code,403)

    def test_mutations_cannot_be_requested_by_station_client(self):
        observer=CompilerObserver.from_state_directory(self.state)
        for op in ("dispatch.prepare","dispatch.submit","dispatch.observe",
                   "raw.ssm","shell.execute"):
            with self.subTest(op=op),self.assertRaises(CompilerRPCUnavailable):
                observer._request(op,{"request_id":REQUEST})
        self.assertEqual(self.fixture.messages,[])
        self.assertFalse(hasattr(observer,"submit"))
        self.assertFalse(hasattr(observer,"prepare"))
        self.assertFalse(hasattr(observer,"observe"))

    def test_untrusted_config_paths_symlinks_and_key_permissions(self):
        self.client.force_login(self.admin)
        configuration=self.fixture.private/"configuration.json"
        configuration.write_text(json.dumps({
            "schema":CONFIG_SCHEMA,"endpoint":f"https://localhost:{self.port}/v1/compiler/rpc",
            "workspace_id":WORKSPACE,"instance_id":"i-SECRET",
        }))
        configuration.chmod(0o600)
        self.assertEqual(self.client.get("/api/compiler/status/").status_code,503)
        self.assertEqual(self.fixture.messages,[])
        configuration.unlink()
        configuration.symlink_to(self.fixture.private/"server-ca.pem")
        self.assertEqual(self.client.get("/api/compiler/status/").status_code,503)
        self.assertEqual(self.fixture.messages,[])
        configuration.unlink()
        self.fixture.configure(self.port)
        (self.fixture.private/"client-key.pem").chmod(0o644)
        self.assertEqual(self.client.get("/api/compiler/status/").status_code,503)
        self.assertEqual(self.fixture.messages,[])

    def test_isolated_cli_probe_returns_non_cutover_evidence(self):
        from contextlib import redirect_stdout
        from io import StringIO
        from zog.station_access.compiler_rpc import main
        stream = StringIO()
        with redirect_stdout(stream):
            code=main(["--state-directory",str(self.state)])
        self.assertEqual(code,0)
        evidence=json.loads(stream.getvalue())
        self.assertFalse(evidence["safe_to_cut_over"])
        self.assertEqual(evidence["compiler"],"registered")
        self.assertEqual(evidence["live_host_health"],"not-observed")
        self.assertNotIn(WORKSPACE,stream.getvalue())
        (self.fixture.private/"client-key.pem").unlink()
        stream=StringIO()
        with redirect_stdout(stream):
            code=main(["--state-directory",str(self.state)])
        self.assertEqual(code,2)
        self.assertEqual(json.loads(stream.getvalue())["error"],"unavailable")

    def test_ca_valid_unallowlisted_client_identity_cannot_inspect(self):
        alternate_key, alternate_cert = _identity(
            self.fixture.ca_key, self.fixture.ca_cert, "other-application",
            ExtendedKeyUsageOID.CLIENT_AUTH)
        certificate, key = _pem(alternate_key, alternate_cert)
        self.fixture._write("client-cert.pem", certificate, 0o600)
        self.fixture._write("client-key.pem", key, 0o600)
        self.client.force_login(self.admin)
        response = self.client.get("/api/compiler/status/")
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.json()["error"], "not-authorized")
        self.assertEqual(self.fixture.messages, [])

    def test_expired_or_wrong_usage_client_certificate_fails_closed(self):
        self.client.force_login(self.admin)
        for label, usage, lifetime in (
            ("expired", ExtendedKeyUsageOID.CLIENT_AUTH, (-3, -2)),
            ("wrong-usage", ExtendedKeyUsageOID.SERVER_AUTH, (-1, 1)),
        ):
            with self.subTest(case=label):
                other_key, other_cert = _identity(
                    self.fixture.ca_key, self.fixture.ca_cert, "untrusted-observer",
                    usage, lifetime_days=lifetime)
                cert, key = _pem(other_key, other_cert)
                self.fixture._write("client-cert.pem", cert, 0o600)
                self.fixture._write("client-key.pem", key, 0o600)
                response = self.client.get("/api/compiler/status/")
                self.assertNotEqual(response.status_code, 200)
                self.assertEqual(response.json()["state"], "unavailable")
                self.assertEqual(self.fixture.messages, [])

    def test_timeout_and_restart_never_substitute_a_writer_or_stale_health(self):
        self.client.force_login(self.admin)
        with patch("zog.station_access.compiler_rpc.http.client.HTTPSConnection",
                   side_effect=TimeoutError("private transport diagnostics")):
            response = self.client.get("/api/compiler/status/")
        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.json()["state"], "unavailable")
        self.assertNotIn("private transport diagnostics", response.content.decode())
        self.assertEqual(self.fixture.messages, [])
        # Real fixture stop/restart; the private certificate and workspace
        # selection stay fixed, and no mutation operation can be substituted.
        self.fixture.stop()
        new_port = self.fixture.listen()
        self.fixture.configure(new_port)
        response = self.client.get("/api/compiler/status/")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["live_host_health"], "not-observed")
        self.assertEqual([item["operation"] for item in self.fixture.messages],
                         ["compiler.status"])
