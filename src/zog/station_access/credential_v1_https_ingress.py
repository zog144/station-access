"""Dedicated, non-Django WSGI HTTPS ingress for canonical credential v1.

No database, signer, root, vault or Django imports. This process is separately
confined behind the installed HTTPS reverse proxy and private Unix listener.
Disabled until native owner provisions and explicitly approves all boundaries.
"""
import json
import os
import socket
import struct

PATH = "/.well-known/zog/credential-delivery/v1"
ROUTES = (PATH, PATH + "/receipt", PATH + "/cancel")
HEADERS = ("Content-Type", "Content-Digest", "X-Host-Id", "X-Host-Key",
           "Signature", "Signature-Input")
MAX_BODY = 65536
MAX_FRAME = 70000
MAX_RESPONSE = 25000
ENABLED = "ZOG_CREDENTIAL_V1_HTTPS_INGRESS_ENABLED"
SOCKET_PATH = "ZOG_CREDENTIAL_V1_BROKER_SOCKET"


def _deny():
    raise ValueError("credential-unavailable")


def _frame(route, raw, headers):
    if (route not in ROUTES or type(raw) is not bytes
            or not 0 < len(raw) <= MAX_BODY or type(headers) is not dict
            or set(headers) != set(HEADERS)
            or headers["Content-Type"] != "application/json"
            or any(type(v) is not str or len(v) > 1024 or
                   any(c in v for c in ("\r", "\n", "\x00"))
                   for v in headers.values())):
        _deny()
    try:
        text = raw.decode("ascii")
        value = json.loads(text)
        if (type(value) is not dict or
                json.dumps(value, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=True).encode() != raw):
            _deny()
        frame = json.dumps({
            "schema": "zog-credential-v1-ingress-frame",
            "route": route, "body": text, "headers": headers},
            sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    except (ValueError, TypeError, UnicodeError):
        _deny()
    if len(frame) > MAX_FRAME:
        _deny()
    return frame + b"\n"


def relay(route, raw, headers, *, path):
    if type(path) is not str or not path.startswith("/") or len(path) > 256:
        _deny()
    frame = _frame(route, raw, headers)
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        connection.settimeout(12)
        connection.connect(path)
        peer = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED,
                                     struct.calcsize("3i"))
        _pid, uid, _gid = struct.unpack("3i", peer)
        if uid != 0:
            _deny()
        connection.sendall(frame)
        connection.shutdown(socket.SHUT_WR)
        return _consume_broker_reply(connection, route)
    finally:
        connection.close()


def _consume_broker_reply(connection, route):
    # AF_UNIX SOCK_STREAM is a byte stream, not a record transport. A single
    # recv() may contain only a prefix of a signed delivery. Read until EOF
    # with a strict total bound; truncated or oversized replies fail closed.
    chunks = bytearray()
    while len(chunks) <= MAX_RESPONSE:
        part = connection.recv(MAX_RESPONSE + 1 - len(chunks))
        if not part:
            break
        chunks.extend(part)
    if not chunks or len(chunks) > MAX_RESPONSE:
        _deny()
    response = bytes(chunks)
    if route == PATH:
        if not response.startswith(b"J"):
            _deny()
        body = response[1:]
        try:
            result = json.loads(body)
            if (type(result) is not dict
                    or result.get("schema") != "zog-credential-delivery-envelope-v1"
                    or json.dumps(result, sort_keys=True, separators=(",", ":"),
                                  ensure_ascii=True).encode("ascii") != body):
                _deny()
        except (ValueError, TypeError, UnicodeError):
            _deny()
        return 200, body
    if response != b"A":
        _deny()
    return 204, b""
    finally:
        connection.close()


def application(environ, start_response):
    common = [("Cache-Control", "no-store, no-cache, must-revalidate"),
              ("Pragma", "no-cache"), ("X-Content-Type-Options", "nosniff"),
              ("Referrer-Policy", "no-referrer")]
    try:
        if (os.environ.get(ENABLED) != "1"
                or environ.get("REQUEST_METHOD") != "POST"
                or environ.get("PATH_INFO") not in ROUTES
                or environ.get("QUERY_STRING")
                or environ.get("wsgi.url_scheme") != "https"
                or environ.get("CONTENT_TYPE") != "application/json"
                or environ.get("HTTP_COOKIE")
                or environ.get("HTTP_AUTHORIZATION")
                or environ.get("CONTENT_LENGTH") is None):
            _deny()
        size = int(environ["CONTENT_LENGTH"])
        if not 0 < size <= MAX_BODY:
            _deny()
        body = environ["wsgi.input"].read(size+1)
        if len(body) != size:
            _deny()
        headers = {
            key: (environ["CONTENT_TYPE"] if key == "Content-Type"
                  else environ.get("HTTP_" + key.upper().replace("-", "-").replace("-", "_")))
            for key in HEADERS
        }
        status, result = relay(environ["PATH_INFO"], body, headers,
                               path=os.environ.get(SOCKET_PATH, ""))
        start_response("200 OK" if status == 200 else "204 No Content", common + [
            ("Content-Type", "application/json" if status == 200 else "application/octet-stream"),
            ("Content-Length", str(len(result)))])
        return [result]
    except Exception:
        start_response("403 Forbidden", common + [
            ("Content-Type", "application/octet-stream"),
            ("Content-Length", "0")])
        return [b""]
