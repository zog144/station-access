"""Systemd-socket-selected root-only local broker for unified HTTPS v1."""
import json
import os
import socket
import stat
import struct
from pathlib import Path

from django.conf import settings
from . import credential_v1_authority as authority

MAX_FRAME = 70000
MAX_REPLY = 25000
HEADERS = frozenset(("Content-Type", "Content-Digest", "X-Host-Id", "X-Host-Key",
                     "Signature", "Signature-Input"))
ROUTES = frozenset((
    "/.well-known/zog/credential-delivery/v1",
    "/.well-known/zog/credential-delivery/v1/receipt",
    "/.well-known/zog/credential-delivery/v1/cancel",
))


def deny():
    raise ValueError("credential-broker-unavailable")


def _unique(pairs):
    found = {}
    for k, v in pairs:
        if k in found:
            deny()
        found[k] = v
    return found


def _frame(raw):
    if type(raw) is not bytes or not 0 < len(raw) <= MAX_FRAME:
        deny()
    try:
        data = json.loads(raw, object_pairs_hook=_unique,
                          parse_constant=lambda _: deny())
        if (type(data) is not dict
                or set(data) != {"schema", "route", "body", "headers"}
                or data["schema"] != "zog-credential-v1-ingress-frame"
                or data["route"] not in ROUTES
                or type(data["body"]) is not str
                or type(data["headers"]) is not dict
                or set(data["headers"]) != HEADERS
                or any(type(x) is not str or len(x) > 1024 or
                       any(c in x for c in ("\r", "\n", "\x00"))
                       for x in data["headers"].values())
                or data["headers"]["Content-Type"] != "application/json"):
            deny()
        body = data["body"].encode("ascii")
        if len(body) > 65536:
            deny()
        from zog.station_access.credential_v1_https_ingress import _frame as ingress_frame
        if ingress_frame(data["route"], body, data["headers"]).rstrip(b"\n") != raw:
            deny()
        return data["route"], data["headers"], body
    except (TypeError, ValueError, UnicodeError):
        deny()


def check_listener(listener, path):
    """The kernel's sockfs inode and bound filesystem inode are distinct."""
    if os.geteuid() != 0 or type(path) is not str or not path.startswith("/"):
        deny()
    stat_fd = os.fstat(listener.fileno())
    stat_path = os.lstat(path)
    if (listener.family != socket.AF_UNIX
            or listener.type != socket.SOCK_STREAM
            or listener.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN) != 1
            or listener.getsockname() != path
            or not stat.S_ISSOCK(stat_fd.st_mode)
            or not stat.S_ISSOCK(stat_path.st_mode)
            or stat_path.st_uid != 0
            or stat.S_IMODE(stat_path.st_mode) != 0o660):
        deny()
    # Check protected parent ancestry, not filesystem/socket inode equality.
    for parent in reversed(Path(path).parents):
        item = parent.lstat()
        if (not stat.S_ISDIR(item.st_mode) or item.st_uid != 0
                or item.st_mode & 0o022):
            deny()


def serve_once(listener):
    connection, _ = listener.accept()
    with connection:
        try:
            permitted_uid = getattr(settings, "HOST_CREDENTIAL_HTTPS_INGRESS_UID", None)
            if type(permitted_uid) is not int or permitted_uid <= 0:
                deny()
            raw = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED,
                                        struct.calcsize("3i"))
            uid = struct.unpack("3i", raw)[1]
            if uid != permitted_uid:
                deny()
            connection.settimeout(12)
            data = bytearray()
            while len(data) <= MAX_FRAME:
                chunk = connection.recv(MAX_FRAME+1-len(data))
                if not chunk:
                    break
                data.extend(chunk)
            if not data or len(data) > MAX_FRAME or data[-1:] != b"\n":
                deny()
            route, headers, body = _frame(bytes(data[:-1]))
            status, result = authority.handle(route, headers, body)
            if status == 200 and type(result) is bytes and 0 < len(result) <= MAX_REPLY:
                connection.sendall(b"J" + result)
            elif status == 204 and result == b"":
                connection.sendall(b"A")
            else:
                deny()
        except Exception:
            # Fail closed with no browser-, socket- or journal-visible policy
            # diagnostics, local secret material or source traceback.
            pass
