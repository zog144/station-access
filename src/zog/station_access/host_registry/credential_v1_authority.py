"""Explicitly disabled-by-default canonical credential v1 root authority.

This module never runs as a Django view. A dedicated nonroot HTTPS ingress
passes one bounded signed HTTP frame to an independently installed root-owned
local broker. All policy, signer keys, vault calls and STATE ledger are local.
"""
import base64
import hashlib
import json
import os
import secrets
import time
import uuid
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from django.conf import settings
from zog.host_identify import credential_delivery as cd
from zog.host_identify import signatures
from .models import Host, HostIdentity, ManagedAdmission
from . import credential_https_authority as legacy
from . import credential_v1_state as store

PURPOSE = "issuer-cloudflare-dns01"
CONSUMER = "certify-manage"


def deny():
    raise ValueError("credential-authority-unavailable") from None


def _enabled():
    if (os.geteuid() != 0
            or not getattr(settings, "HOST_CREDENTIAL_V1_BROKER_ENABLED", False)
            or not getattr(settings, "HOST_CREDENTIAL_V1_LIVE_ENABLED", False)):
        deny()


def _signer(grant):
    # Operator-signed root grant separately binds the pinned station key.
    pin = legacy._protected(getattr(
        settings, "HOST_CREDENTIAL_HTTPS_SIGNER_PIN_FILE", ""), 0o444)
    if len(pin) != 32 or hashlib.sha256(pin).hexdigest() != grant[
            "independent_signer_pin_sha256"]:
        deny()
    raw = legacy._protected(getattr(
        settings, "HOST_CREDENTIAL_V1_SIGNING_KEY_FILE", ""), 0o600)
    key = serialization.load_pem_private_key(raw, password=None)
    if not isinstance(key, Ed25519PrivateKey):
        deny()
    actual = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    if not secrets.compare_digest(actual, pin):
        deny()
    return key


def _identity_and_authorization(*, permit_revoked=False):
    grant = legacy._authority(allow_revoked=permit_revoked)
    key = _signer(grant)
    signed = json.loads(legacy._protected(getattr(
        settings, "HOST_CREDENTIAL_V1_AUTHORIZATION_FILE", ""), 0o600))
    if type(signed) is not dict:
        deny()
    origin = signatures.origin(settings.HOST_IDENTITY_ORIGIN)
    # A different UUID in canonical authorization is intentional: it is
    # independently selected by root, NOT the old local vault policy digest.
    credential_id = "cloudflare-" + str(uuid.UUID(
        str(legacy._projection()["authorization"]["credential_id"]))).replace("-", "")
    expected = {
        "host_id": grant["host_id"], "host_fingerprint": grant["fingerprint"],
        "installation_id": grant["installation_id"],
        "state_volume_id": grant["state_volume_id"],
        "registry_id": grant["registry_id"], "consumer": CONSUMER,
        "purpose": PURPOSE, "credential_id": credential_id,
    }
    auth = cd.verify_authorization(
        signed, key.public_key(), expected_issuer=origin,
        expected_binding=expected)
    if (auth["revision"] != grant["revision"]
            or auth["credential_revision"] != grant["credential_revision"]
            or ((auth["status"] == "revoked") != (grant["state"] == "revoked"))
            or auth["expires_at"] > grant["expires_at"]):
        deny()
    return grant, auth, key


def _current(grant, auth):
    if legacy._authority() != grant:
        deny()
    projection = legacy._projection()
    if (projection["origin"] != "managed"
            or projection["host_id"] != grant["host_id"]
            or projection["installation_id"] != grant["installation_id"]
            or legacy.authorization_id(projection) != grant["authorization_id"]):
        deny()
    approved = projection["authorization"]
    for field in ("assignment_id", "assignment_revision",
                  "credential_revision", "grant_id", "storage_id"):
        if approved[field] != grant[field]:
            deny()
    row, _credential = legacy._assignment(projection)
    if (row.binding_id != "managed-dns01"
            or str(row.pk) != grant["assignment_id"]
            or str(row.host_id) != grant["host_id"]
            or auth["credential_id"] != "cloudflare-" +
                str(row.credential_id).replace("-", "")):
        deny()
    host = Host.objects.filter(pk=grant["host_id"], provider="generic",
                               archived_at__isnull=True).first()
    if host is None:
        deny()
    known = HostIdentity.objects.filter(
        host=host, fingerprint=grant["fingerprint"], status="approved").first()
    session = ManagedAdmission.objects.filter(host=host).first()
    if (known is None or session is None
            or session.fingerprint != grant["fingerprint"]
            or str(session.installation_id) != grant["installation_id"]
            or str(session.state_volume_id) != grant["state_volume_id"]
            or session.registry_id != grant["registry_id"]
            or str(session.authority_id) != grant["authority_id"]
            or type(session.claims) is not dict
            or session.claims.get("fingerprint") != grant["fingerprint"]
            or session.claims.get("installation_id") != grant["installation_id"]
            or session.claims.get("registry_id") != grant["registry_id"]
            or type(session.claims.get("jti")) is not str
            or not session.claims["jti"]
            or session.claims.get("exp", 0) <= time.time()):
        deny()
    return signatures.public_key(known.public_key)


def _context():
    grant, authorization, signer = _identity_and_authorization()
    if authorization["status"] != "approved":
        deny()
    return grant, authorization, signer, _current(grant, authorization)


def handle(route, headers, body):
    """Only the kernel-peer-validated root broker may invoke this operation.

    The HTTP layer returns signed JSON for delivery or a 204 receipt/cancel.
    No automatic retry and no implicit renewal/Certbot activity are allowed.
    """
    _enabled()
    from zog.station_access.credential_https_interop import (
        PATH, RECEIPT_PATH, CANCEL_PATH)
    if route not in (PATH, RECEIPT_PATH, CANCEL_PATH):
        deny()
    grant, authorization, signer, host_key = _context()
    origin = signatures.origin(settings.HOST_IDENTITY_ORIGIN)
    url = origin + route
    # Prevent a file/grant rotation while processing from being silently
    # accepted: re-read all protected source evidence before response.
    if route == PATH:
        request_id = store.request_admit(
            auth=authorization, url=url, headers=headers, body=body,
            host_key=host_key, origin=origin)
        # Consume a distinct local issuer-reader nonce; a failure retains
        # 'pending' in the durable ledger and does not authorize a replay.
        token = legacy._read_local_token(grant["authorization_id"])
        if not isinstance(token, bytes) or not 1 <= len(token) <= cd.MAX_SECRET:
            deny()
        later_grant, later_auth, later_signer, _ = _context()
        if later_grant != grant or later_auth != authorization or (
                signatures.fingerprint(later_signer.public_key()) !=
                signatures.fingerprint(signer.public_key())):
            deny()
        from .models import HttpsCredentialV1Operation
        request = HttpsCredentialV1Operation.objects.get(
            request_id=request_id).request
        now = int(time.time())
        delivery = {
            "schema": cd.DELIVERY_SCHEMA,
            "request_id": request_id, "delivery_id": str(uuid.uuid4()),
            "authorization_id": authorization["authorization_id"],
            "authorization_revision": authorization["revision"],
            "credential_id": authorization["credential_id"],
            "credential_revision": authorization["credential_revision"],
            "consumer": CONSUMER, "purpose": PURPOSE,
            "issued_at": now, "expires_at": min(now+60, authorization["expires_at"]),
            "secret_format": "base64",
            "secret": base64.b64encode(token).decode("ascii"),
        }
        return 200, store.delivery_commit(
            auth=authorization, request_id=request_id, value=delivery,
            signing_key=signer, now=now)
    if route == RECEIPT_PATH:
        store.receipt_commit(auth=authorization, url=url, headers=headers,
                             body=body, host_key=host_key, origin=origin)
        return 204, b""
    store.cancel_commit(auth=authorization, url=url, headers=headers,
                        body=body, host_key=host_key, origin=origin)
    return 204, b""


def reconcile_reviewed_authorization():
    """Explicit root-only adoption of independently signed revocation.

    This does not inspect a secret, call a consumer, or open an HTTPS route.
    """
    if os.geteuid() != 0:
        deny()
    _grant, auth, _key = _identity_and_authorization(permit_revoked=True)
    return store.reconcile_authorization(auth)
