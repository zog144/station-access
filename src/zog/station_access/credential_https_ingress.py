"""Isolated, unprivileged WSGI HTTPS ingress, *not* a Django browser API.

Reverse proxy pins one exact route to this dedicated app on a private Unix
listener. Only a separately privileged local broker can authorize secrets.
No vault, Django settings, user sessions, or root privileges are imported.
"""
import os
import re
import socket
import stat
import struct
from .credential_delivery_protocol import (
    PATH, HEADERS, MAX_REQUEST, MAX_SECRET, DeliveryDenied, envelope, deny,
)

SOCKET_ENV = "ZOG_CREDENTIAL_DELIVERY_BROKER_SOCKET"
ENABLED = "ZOG_CREDENTIAL_HTTPS_INGRESS_ENABLED"


def relay(body, headers, *, socket_path):
    if not socket_path.startswith("/") or len(socket_path) > 256:
        deny()
    message = envelope(body, headers)
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        client.settimeout(4)
        client.connect(socket_path)
        # Kernel local peer, not an X-Forwarded-* header or caller-supplied ID.
        _, uid, _ = struct.unpack("3i", client.getsockopt(
            socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")))
        if uid != 0:
            deny()
        client.sendall(message)
        client.shutdown(socket.SHUT_WR)
        result = bytearray()
        while len(result) <= MAX_SECRET:
            chunk = client.recv(MAX_SECRET + 1 - len(result))
            if not chunk:
                break
            result.extend(chunk)
        if not 20 <= len(result) <= MAX_SECRET or not re.fullmatch(
                rb"[A-Za-z0-9_-]{20,4096}", bytes(result)):
            deny()
        # The broker returns a token only after all gates pass. No diagnostics.
        return bytes(result)
    finally:
        client.close()


def application(environ, start_response):
    headers = [("Cache-Control", "no-store, no-cache, must-revalidate"),
               ("Pragma", "no-cache"), ("X-Content-Type-Options", "nosniff"),
               ("Referrer-Policy", "no-referrer")]
    try:
        if (os.environ.get(ENABLED) != "1"
                or environ.get("REQUEST_METHOD") != "POST"
                or environ.get("PATH_INFO") != PATH
                or environ.get("QUERY_STRING")
                or environ.get("CONTENT_TYPE") != "application/json"
                or environ.get("wsgi.url_scheme") != "https"
                or environ.get("HTTP_COOKIE")
                or environ.get("HTTP_AUTHORIZATION")
                or environ.get("CONTENT_LENGTH") is None):
            deny()
        size = int(environ["CONTENT_LENGTH"])
        if not 0 < size <= MAX_REQUEST:
            deny()
        body = environ["wsgi.input"].read(size + 1)
        if len(body) != size:
            deny()
        signed = {h: (environ.get("CONTENT_TYPE") if h == "Content-Type"
                       else environ.get("HTTP_" + h.upper().replace("-", "_")))
                  for h in HEADERS}
        value = relay(body, signed, socket_path=os.environ.get(SOCKET_ENV, ""))
        start_response("200 OK", headers + [
            ("Content-Type", "application/octet-stream"),
            ("Content-Length", str(len(value)))])
        return [value]
    except Exception:
        # Never include an underlying exception or signed request in HTTP.
        start_response("403 Forbidden", headers + [
            ("Content-Type", "application/octet-stream"),
            ("Content-Length", "0")])
        return [b""]
