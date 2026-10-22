"""Issuer-only local Cloudflare token reader — never a Django HTTP endpoint.

A dedicated *vault* execution identity receives one inherited AF_UNIX stream
listener on descriptor 3. The socket must be private, and peer credentials
must prove the privileged provisioning UID *before reading request bytes*.
Root provisions the nonsecret, read-only authorization projection. It never
contains API token bytes. Root must independently recheck its own authoritative
approval/ledger after the read and before an issuer-file installation.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import socket
import stat
import struct
from datetime import timedelta
from pathlib import Path

from django.conf import settings
from django.db import IntegrityError, OperationalError
from django.utils import timezone

from .certificate_assignment_signing import canonical
from .identity import locked
from .models import (CertificateAssignment, DnsAssignment, DnsDestination,
                     AdditionalDnsAssignment, HostIdentity, ManagedAdmission,
                     ProviderCredential, ProviderAccessCheck,
                     IssuerTokenReadNonce, SecurityAudit)
from .setup_configuration import decrypt_provider
from .provider_checks import serialize

REQUEST_SCHEMA = "zog-station-issuer-cloudflare-read-v1"
PROJECTION_SCHEMA = "zog-station-issuer-reader-authorization-v1"
ROOT_SCHEMA = "zog-issuer-cloudflare-credential-v1"
UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\Z")
HEX = re.compile(r"[0-9a-f]{64}\Z")
TOKEN = re.compile(rb"[A-Za-z0-9_-]{20,4096}\Z")
ZONE = re.compile(r"[a-z0-9-]+(?:\.[a-z0-9-]+)+\Z")
ROOT_FIELDS = frozenset(("schema", "state", "project", "certificate_id",
    "assignment_id", "assignment_revision", "credential_id",
    "credential_revision", "zone_id", "zone_name", "grant_id",
    "storage_id", "policy_sha256", "receipt_sha256", "expires_at"))
PROJECT_FIELDS = frozenset(("schema", "authorization", "origin",
    "installation_id", "host_id", "account_id", "owner_user_id"))

class ReaderDenied(Exception):
    """Fixed, secret-free failure, without underlying exception chains."""


def _deny():
    raise ReaderDenied("issuer credential reader unavailable") from None


def _private_projection():
    path_str = getattr(settings, "HOST_ISSUER_CREDENTIAL_AUTHORIZATION_FILE", "")
    if not isinstance(path_str, str) or not path_str.startswith("/") or len(path_str) > 512:
        _deny()
    path = Path(path_str)
    # Every parent is root-controlled, with no symlink or writable group.
    for parent in reversed(path.parents):
        try:
            mode = parent.lstat()
            if not stat.S_ISDIR(mode.st_mode) or mode.st_uid != 0 or mode.st_mode & 0o022:
                _deny()
        except OSError:
            _deny()
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        with os.fdopen(fd, "rb") as stream:
            mode = os.fstat(stream.fileno())
            if (not stat.S_ISREG(mode.st_mode) or mode.st_uid != 0
                    or mode.st_gid != os.getegid()
                    or stat.S_IMODE(mode.st_mode) != 0o440
                    or mode.st_nlink != 1 or mode.st_size > 8192):
                _deny()
            raw = stream.read(8193)
            if len(raw) > 8192:
                _deny()
        data = json.loads(raw)
    except (OSError, ValueError, UnicodeError, TypeError):
        _deny()
    if not isinstance(data, dict) or set(data) != PROJECT_FIELDS or data["schema"] != PROJECTION_SCHEMA:
        _deny()
    a = data["authorization"]
    if not isinstance(a, dict) or set(a) != ROOT_FIELDS or (
            a["schema"] != ROOT_SCHEMA or a["state"] != "approved"
            or a["certificate_id"] != "station-web"
            or not isinstance(a["project"], str) or not a["project"].startswith("/")
            or any(not isinstance(a[k], str) or not UUID.fullmatch(a[k])
                   for k in ("assignment_id", "credential_id"))
            or any(type(a[k]) is not int or a[k] < 1
                   for k in ("assignment_revision", "credential_revision"))
            or any(not isinstance(a[k], str) or not HEX.fullmatch(a[k])
                   for k in ("policy_sha256", "receipt_sha256"))
            or any(not isinstance(a[k], str) or not re.fullmatch(r"[0-9a-f]{32}", a[k])
                   for k in ("grant_id", "storage_id"))
            or not isinstance(a["zone_id"], str)
            or not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", a["zone_id"])
            or not isinstance(a["zone_name"], str) or not ZONE.fullmatch(a["zone_name"])
            or type(a["expires_at"]) is not int
            or a["expires_at"] <= int(timezone.now().timestamp())):
        _deny()
    if (data["origin"] not in ("local", "managed")
            or not isinstance(data["installation_id"], str)
            or not UUID.fullmatch(data["installation_id"])
            or (data["host_id"] is not None and
                (not isinstance(data["host_id"], str) or not UUID.fullmatch(data["host_id"])))
            or ((data["origin"] == "local") != (data["host_id"] is None))
            or not isinstance(data["account_id"], str)
            or not re.fullmatch(r"[0-9a-f]{32}", data["account_id"])
            or type(data["owner_user_id"]) is not int or data["owner_user_id"] < 1):
        _deny()
    return data


def authorization_id(projection):
    """Digest of root-authoritative nonsecret approval, not a token hash."""
    return hashlib.sha256(canonical(projection["authorization"])).hexdigest()


def _assignment(projection):
    a = projection["authorization"]
    row = CertificateAssignment.objects.select_related("credential", "host").filter(
        pk=a["assignment_id"], origin=projection["origin"],
        installation_id=projection["installation_id"], state="approved",
        revision=a["assignment_revision"], credential_id=a["credential_id"],
        credential_revision=a["credential_revision"],
        zone_id=a["zone_id"], zone_name=a["zone_name"]).first()
    if CertificateAssignment.objects.filter(
            installation_id=projection["installation_id"],
            revision__gt=a["assignment_revision"]).exists():
        _deny()
    if row is None or row.expires_at <= timezone.now() or (
            row.expires_at.timestamp() < a["expires_at"]):
        _deny()
    if str(row.host_id) != str(projection["host_id"]):
        _deny()
    policy = row.statement.get("policy")
    if type(policy) is not dict or policy.get("certificate_id") != "station-web" or (
            policy.get("challenge") != "dns-01"
            or policy.get("dns_plugin") != "dns-cloudflare"
            or policy.get("hostnames") != [row.hostname]):
        _deny()
    if hashlib.sha256(canonical(policy)).hexdigest() != a["policy_sha256"]:
        _deny()
    if hashlib.sha256(canonical(row.receipt)).hexdigest() != a["receipt_sha256"]:
        _deny()
    # The same administrator must own the reviewed DNS destination and the
    # original signed certificate-intent approval. Audit is nonsecret.
    accepted = SecurityAudit.objects.filter(
        action="certificate-assign", actor=str(projection["owner_user_id"]),
        details__assignment_id=str(row.pk)).exists()
    if not accepted:
        _deny()
    credential = row.credential
    if (credential.provider != "cloudflare"
            or credential.revision != a["credential_revision"]
            or credential.account_id != projection["account_id"]):
        _deny()
    if row.origin == "local":
        if str(getattr(settings, "HOST_LOCAL_CERTIFICATE_INSTALLATION_ID", "")) != projection["installation_id"]:
            _deny()
        if (DnsAssignment.objects.filter(name=row.hostname).exists()
                or AdditionalDnsAssignment.objects.filter(name=row.hostname).exists()):
            _deny()
    else:
        host = row.host
        if (host is None or host.archived_at is not None
                or not HostIdentity.objects.filter(
                    host=host, status="approved",
                    fingerprint=row.statement.get("host_fingerprint")).exists()
                or not ManagedAdmission.objects.filter(
                    host=host, installation_id=row.installation_id).exists()):
            _deny()
    binding = DnsDestination.objects.filter(pk=row.binding_id, enabled=True).first()
    if binding is None or not isinstance(binding.selection, dict):
        _deny()
    selected = binding.selection
    if (selected.get("owner_user_id") != projection["owner_user_id"]
            or selected.get("credential_id") != str(credential.pk)
            or selected.get("credential_revision") != credential.revision
            or selected.get("zone_id") != a["zone_id"]
            or selected.get("zone_name") != a["zone_name"]):
        _deny()
    if row.origin == "managed":
        record = AdditionalDnsAssignment.objects.filter(
            host=row.host,binding=binding,phase="ready",name=row.hostname,
            enabled=True,status="synchronized").first()
        if (record is None or record.applied_revision != record.revision
                or not record.record_id):
            _deny()
    else:
        prefix = selected.get("prefix")
        if (not isinstance(prefix,str) or row.hostname.count(".") != prefix.count(".")+1
                or not row.hostname.endswith("." + prefix)):
            _deny()
    check = serialize(credential)
    if (check["status"] != "passed" or not check["fresh"]
            or not any(d.get("id")==a["zone_id"] and
                       d.get("name")==a["zone_name"] and
                       d.get("status")=="active" for d in check["domains"])):
        _deny()
    return row, credential


def read_approved_token(request):
    """Never return except to the already SO_PEERCRED-authorized socket peer.

    Replay storage commits before decrypt, and station SecurityGate blocks
    concurrent station credential revisions and assignment revocation.
    """
    reader_uid = getattr(settings, "HOST_ISSUER_CREDENTIAL_READER_UID", None)
    if (type(reader_uid) is not int or reader_uid <= 0
            or os.geteuid() != reader_uid):
        _deny()
    if (type(request) is not dict or set(request) !=
            {"schema", "operation", "authorization_id", "nonce"}
            or request.get("schema") != REQUEST_SCHEMA
            or request.get("operation") != "read-approved-cloudflare-issuer-token"
            or not isinstance(request.get("authorization_id"),str)
            or not HEX.fullmatch(request["authorization_id"])
            or not isinstance(request.get("nonce"),str)
            or not re.fullmatch(r"[0-9a-f]{32}",request["nonce"])):
        _deny()
    with locked():
        projection = _private_projection()
        if authorization_id(projection) != request["authorization_id"]:
            _deny()
        # Reject replay across service restarts. Never log the authorization
        # request or secret; discard old nonces only after 48h.
        IssuerTokenReadNonce.objects.filter(created_at__lt=timezone.now()-timedelta(hours=48)).delete()
        if IssuerTokenReadNonce.objects.count() >= 10000 or IssuerTokenReadNonce.objects.filter(
                nonce=request["nonce"]).exists():
            _deny()
        IssuerTokenReadNonce.objects.create(
            nonce=request["nonce"],authorization_id=request["authorization_id"])
    # Never hold a station security transaction across expensive vault reads;
    # verify the exact live credential and projection once more afterwards.
    try:
        _assignment(projection)
        row = ProviderCredential.objects.get(pk=projection["authorization"]["credential_id"])
        token = decrypt_provider(row)["api_token"]
        if type(token) is not str:
            _deny()
        token_bytes = token.encode("ascii")
        if not TOKEN.fullmatch(token_bytes):
            _deny()
        with locked():
            if _private_projection() != projection:
                _deny()
            _assignment(projection)
            current = ProviderCredential.objects.get(pk=row.pk)
            if (current.revision != row.revision or current.provider != row.provider
                    or current.account_id != row.account_id
                    or current.key_id != row.key_id or current.ciphertext != row.ciphertext):
                _deny()
        return token_bytes
    except Exception:
        _deny()


def _listener():
    expected = getattr(settings, "HOST_ISSUER_CREDENTIAL_SOCKET_PATH", "")
    required_uid = getattr(settings, "HOST_ISSUER_CREDENTIAL_READER_UID", None)
    if (not isinstance(expected,str) or not expected.startswith("/")
            or len(expected)>100 or type(required_uid) is not int
            or required_uid <= 0 or os.geteuid() != required_uid):
        _deny()
    listener = socket.socket(fileno=3)
    if (listener.family != socket.AF_UNIX or
            listener.getsockopt(socket.SOL_SOCKET,socket.SO_TYPE) != socket.SOCK_STREAM
            or listener.getsockname() != expected):
        _deny()
    location = Path(expected)
    for parent in reversed(location.parents):
        info = parent.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_mode & 0o022
                or info.st_uid not in (0, required_uid)):
            _deny()
    info = location.lstat()
    live = os.fstat(listener.fileno())
    if (not stat.S_ISSOCK(info.st_mode)
            or (info.st_dev,info.st_ino) != (live.st_dev,live.st_ino)
            or info.st_uid != required_uid or stat.S_IMODE(info.st_mode)!=0o600):
        _deny()
    return listener


def serve_once(listener):
    """One privileged request; empty response on every failure, no logging."""
    connection, _ = listener.accept()
    with connection:
        try:
            if not hasattr(socket,"SO_PEERCRED"):
                _deny()
            creds = connection.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12)
            _,uid,_ = struct.unpack("3i",creds)
            if uid != 0:
                _deny()
            connection.settimeout(3)
            raw = bytearray()
            while len(raw)<=1024:
                part = connection.recv(1025-len(raw))
                if not part:
                    break
                raw.extend(part)
            if not raw or len(raw)>1024 or not raw.endswith(b"\n"):
                _deny()
            def unique(fields):
                result = {}
                for key, value in fields:
                    if key in result:
                        _deny()
                    result[key] = value
                return result
            data = json.loads(raw, object_pairs_hook=unique)
            token = read_approved_token(data)
            # Exactly the approved token bytes, not JSON, PEM, or INI wrapper.
            connection.sendall(token)
        except Exception:
            # A failed request returns zero bytes. The root installer's
            # token validator rejects it. Never write exception text.
            pass


def main():
    from django import setup
    setup()
    listener = _listener()
    # Systemd owns the socket lifecycle; no station application path or
    # arbitrary client-requested service socket is created by this reader.
    while True:
        serve_once(listener)


if __name__ == "__main__":
    main()
