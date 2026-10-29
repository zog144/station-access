"""Versioned bounded wire contract; no Django, vault access or host secrets.

The unprivileged HTTP ingress must not be able to manufacture authorization:
all raw signed headers and body are verified again by the isolated broker.
"""
import base64
import binascii
import json
import re
import uuid

SCHEMA = "zog-credential-delivery-request-v1"
PURPOSE = "issuer-cloudflare-dns01"
CONSUMER = "certify-manage"
DESTINATION = "issuer-dns-cloudflare"
PATH = "/.well-known/zog/credential-delivery/v1"
MAX_REQUEST = 2048
MAX_ENVELOPE = 4096
MAX_SECRET = 4096
HEX = re.compile(r"[0-9a-f]{64}\Z")
NONCE = re.compile(r"[0-9a-f]{32}\Z")
FIELDS = frozenset(("schema", "purpose", "host_id", "installation_id",
    "state_volume_id", "registry_id", "consumer", "destination",
    "authorization_id", "assignment_id", "assignment_revision",
    "credential_revision", "nonce", "consumer_key_fingerprint",
    "consumer_signature_ed25519"))
HEADERS = ("Content-Type", "Content-Digest", "X-Host-Id", "X-Host-Key",
           "Signature", "Signature-Input")


class DeliveryDenied(ValueError):
    pass


def deny():
    raise DeliveryDenied("credential delivery unavailable") from None


def canonical_uuid(value):
    if type(value) is not str:
        deny()
    try:
        if str(uuid.UUID(value)) != value:
            deny()
    except (ValueError, AttributeError):
        deny()
    return value


def unique(pairs):
    data = {}
    for key, value in pairs:
        if key in data:
            deny()
        data[key] = value
    return data


def parse(raw):
    if type(raw) is not bytes or not 0 < len(raw) <= MAX_REQUEST:
        deny()
    try:
        data = json.loads(raw.decode("utf-8"), object_pairs_hook=unique,
                          parse_constant=lambda _: deny())
    except (ValueError, UnicodeError, TypeError):
        deny()
    if type(data) is not dict or set(data) != FIELDS:
        deny()
    if (data["schema"] != SCHEMA or data["purpose"] != PURPOSE
            or data["consumer"] != CONSUMER or data["destination"] != DESTINATION
            or type(data["registry_id"]) is not str
            or not re.fullmatch(r"[a-z][a-z0-9-]{0,63}", data["registry_id"])
            or type(data["consumer_key_fingerprint"]) is not str
            or not HEX.fullmatch(data["consumer_key_fingerprint"])
            or type(data["authorization_id"]) is not str
            or not HEX.fullmatch(data["authorization_id"])
            or type(data["nonce"]) is not str or not NONCE.fullmatch(data["nonce"])
            or any(type(data[k]) is not int or data[k] < 1 or data[k] >= 2**53
                   for k in ("assignment_revision", "credential_revision"))):
        deny()
    for key in ("host_id", "installation_id", "state_volume_id", "assignment_id"):
        canonical_uuid(data[key])
    try:
        proof = base64.b64decode(data["consumer_signature_ed25519"], validate=True)
        if len(proof) != 64 or base64.b64encode(proof).decode("ascii") != data["consumer_signature_ed25519"]:
            deny()
    except (ValueError, TypeError, binascii.Error):
        deny()
    return data


def envelope(raw, headers):
    parse(raw)
    if (type(headers) is not dict or set(headers) != set(HEADERS)
            or any(type(v) is not str or len(v) > 1024 or
                   any(c in v for c in ("\r", "\n", "\x00"))
                   for v in headers.values())
            or headers["Content-Type"] != "application/json"):
        deny()
    payload = json.dumps({"schema": "zog-credential-delivery-ingress-v1",
                          "headers": headers, "body": raw.decode("utf-8")},
                         sort_keys=True, separators=(",", ":")).encode()
    if len(payload) > MAX_ENVELOPE:
        deny()
    return payload + b"\n"


def unpack(raw):
    if type(raw) is not bytes or not 0 < len(raw) <= MAX_ENVELOPE:
        deny()
    try:
        data = json.loads(raw, object_pairs_hook=unique)
        if (type(data) is not dict or set(data) != {"schema", "body", "headers"}
                or data["schema"] != "zog-credential-delivery-ingress-v1"
                or type(data["body"]) is not str):
            deny()
        body = data["body"].encode("utf-8")
        envelope(body, data["headers"])
        return body, data["headers"], parse(body)
    except (ValueError, TypeError, UnicodeError):
        deny()
