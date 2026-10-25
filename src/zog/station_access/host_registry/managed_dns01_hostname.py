"""Bounded, owner-reviewed DNS-01 hostname intent for a managed generic Host.

This does NOT publish A/AAAA records, grant issuer execution, initialize the
central DNS writer or synthesize a hostname from AWS/provider observations.
Reviews are provider GET-only and hash-bound, with an independent controller
lock and a persistent no-reassignment owner fence.
"""
import re
import time
import uuid
from pathlib import Path

from django.utils import timezone
from zog.network_register.contracts import NetworkError
from zog.network_register.ledger import digest
from zog.network_register.state import save
from . import dns_setup
from .dns_evidence import owner_authorized
from .dns_reconcile import configuration, controller_lock
from .identity import locked, audit
from .managed_views import allowed
from .models import (
    Host, HostIdentity, ManagedAdmission, ProviderCredential,
    DnsAssignment, AdditionalDnsAssignment, CertificateAssignment,
    ManagedDns01Hostname,
)

BINDING = "managed-dns01"
NAME = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\Z")


class HostnameError(ValueError):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def _uuid(value):
    try:
        parsed = uuid.UUID(str(value))
    except (ValueError, TypeError, AttributeError):
        raise HostnameError("invalid-identity") from None
    if str(parsed) != str(value):
        raise HostnameError("invalid-identity")
    return parsed


def _host(host_id, installation_id, fingerprint, registry_id):
    host = Host.objects.filter(pk=_uuid(host_id), archived_at__isnull=True).first()
    if not host or not isinstance(fingerprint, str) or not re.fullmatch(r"[a-f0-9]{64}", fingerprint):
        raise HostnameError("identity-unavailable")
    admission = ManagedAdmission.objects.filter(host=host).first()
    key = HostIdentity.objects.filter(host=host, fingerprint=fingerprint, status="approved").first()
    if (not admission or not key or admission.fingerprint != fingerprint
            or admission.installation_id != _uuid(installation_id)
            or admission.registry_id != registry_id
            or not allowed(str(host.pk), fingerprint, admission.claims.get("jti"))):
        raise HostnameError("installation-unavailable")
    return host, admission


def _candidate(actor, hostname, credential_id, revision, zone_id, *, provider_factory=None, collector=None):
    if not isinstance(hostname, str) or len(hostname) > 253:
        raise HostnameError("invalid-hostname")
    label, dot, domain = hostname.partition(".")
    if not dot or not NAME.fullmatch(label) or not domain:
        raise HostnameError("invalid-hostname")
    data = dns_setup.candidate(
        actor, _uuid(credential_id), revision, zone_id, label,
        provider_factory=provider_factory,
    )
    if (data["prefix"] != hostname or data["zone_name"] != domain
            or data["credential_id"] != str(credential_id)):
        raise HostnameError("zone-mismatch")
    dns_setup.scope_available(configuration(), hostname)
    dns_setup.validate(data, collector=collector, provider_factory=provider_factory)
    return data


def _available_name(host, name):
    # A/AAAA owner and certificate-only owner are distinct, mutually
    # exclusive. The shared controller lock serializes other DNS operations.
    if (DnsAssignment.objects.filter(name=name).exists()
            or AdditionalDnsAssignment.objects.filter(name=name).exists()
            or ManagedDns01Hostname.objects.filter(hostname=name).exclude(host=host).exists()
            or CertificateAssignment.objects.filter(hostname=name).exclude(host=host).exists()):
        raise HostnameError("hostname-conflict")


def review(*, owner, host_id, installation_id, fingerprint, registry_id,
           hostname, credential_id, credential_revision, zone_id,
           provider_factory=None, collector=None):
    config = configuration()
    if not config:
        raise HostnameError("dns-owner-unavailable")
    owner_authorized(owner)
    with controller_lock(config, modes=("shared",)) as root:
        host, admission = _host(host_id, installation_id, fingerprint, registry_id)
        if host.provider != "generic":
            raise HostnameError("unsupported-host-mode")
        _available_name(host, hostname)
        data = _candidate(owner, hostname, credential_id, credential_revision, zone_id,
                          provider_factory=provider_factory, collector=collector)
        if data["zone_name"] != config["domain"]:
            raise HostnameError("zone-mismatch")
        value = {
            "schema": 1, "kind": "managed-dns01-hostname", "nonce": str(uuid.uuid4()),
            "owner": owner, "host_id": str(host.pk),
            "installation_id": str(admission.installation_id),
            "fingerprint": fingerprint, "registry_id": registry_id,
            "hostname": hostname, "selection": data,
            "expires_at": time.time() + 600,
        }
        review_id = digest(value)
        save(root / ("dns01-hostname-review-" + review_id + ".json"), value)
        return {
            "review_id": review_id, "expires_at": value["expires_at"],
            "hostname": hostname, "host_id": str(host.pk),
            "installation_id": str(admission.installation_id),
            "zone_id": data["zone_id"], "zone_name": data["zone_name"],
            "provider_writes": 0, "binding_id": BINDING,
        }


def commit(*, owner, review_id, provider_factory=None, collector=None):
    config = configuration()
    if not config:
        raise HostnameError("dns-owner-unavailable")
    owner_authorized(owner)
    if not isinstance(review_id, str) or not re.fullmatch(r"[0-9a-f]{64}", review_id):
        raise HostnameError("invalid-review")
    with controller_lock(config, modes=("shared",)) as root:
        path = root / ("dns01-hostname-review-" + review_id + ".json")
        try:
            from zog.host_install.state_contract import decode
            value = decode(path.read_bytes())
        except (OSError, ValueError, TypeError):
            raise HostnameError("review-unavailable") from None
        if (digest(value) != review_id or value.get("schema") != 1
                or value.get("kind") != "managed-dns01-hostname"
                or value.get("owner") != owner):
            raise HostnameError("invalid-review")
        host, admission = _host(
            value["host_id"], value["installation_id"],
            value["fingerprint"], value["registry_id"],
        )
        if host.provider != "generic":
            raise HostnameError("unsupported-host-mode")
        selected = value["selection"]
        existing = ManagedDns01Hostname.objects.filter(host=host).first()
        if existing:
            if (existing.review_id == review_id and existing.active
                    and existing.hostname == value["hostname"]
                    and existing.installation_id == admission.installation_id
                    and existing.fingerprint == value["fingerprint"]):
                return {"binding_id": BINDING, "host_id": str(host.pk),
                        "hostname": existing.hostname, "revision": existing.revision,
                        "replayed": True, "provider_writes": 0}
            raise HostnameError("hostname-conflict")
        if not isinstance(value.get("expires_at"), (int, float)) or time.time() > value["expires_at"]:
            raise HostnameError("review-expired")
        if (selected.get("owner_user_id") != owner
                or selected.get("prefix") != value["hostname"]
                or selected.get("zone_name") != config["domain"]
                or selected.get("credential_id") is None):
            raise HostnameError("invalid-review")
        _available_name(host, value["hostname"])
        observed = dns_setup.candidate(
            owner, _uuid(selected["credential_id"]), selected["credential_revision"],
            selected["zone_id"], value["hostname"].split(".", 1)[0],
            binding_id=selected["binding_id"], provider_factory=provider_factory,
        )
        if observed != selected:
            raise HostnameError("review-changed")
        dns_setup.scope_available(config, value["hostname"])
        dns_setup.validate(observed, collector=collector, provider_factory=provider_factory)
        with locked():
            owner_authorized(owner)
            _host(value["host_id"], value["installation_id"], value["fingerprint"], value["registry_id"])
            _available_name(host, value["hostname"])
            if ManagedDns01Hostname.objects.filter(host=host).exists():
                raise HostnameError("hostname-conflict")
            record = ManagedDns01Hostname.objects.create(
                host=host, hostname=value["hostname"], fingerprint=value["fingerprint"],
                installation_id=admission.installation_id, registry_id=value["registry_id"],
                credential_id=_uuid(selected["credential_id"]),
                credential_revision=selected["credential_revision"],
                zone_id=selected["zone_id"], zone_name=selected["zone_name"],
                owner_user_id=owner, review_id=review_id,
            )
            audit("operator:" + str(owner), "managed-dns01-hostname-bind",
                  fingerprint=value["fingerprint"], host=host,
                  hostname=value["hostname"], zone_id=record.zone_id, review_id=review_id)
        return {"binding_id": BINDING, "host_id": str(host.pk),
                "hostname": record.hostname, "revision": record.revision,
                "replayed": False, "provider_writes": 0}


def revoke(*, owner, host_id, expected_revision):
    config = configuration()
    if not config:
        raise HostnameError("dns-owner-unavailable")
    with controller_lock(config, modes=("shared",)), locked():
        owner_authorized(owner)
        record = ManagedDns01Hostname.objects.filter(host_id=_uuid(host_id)).first()
        if (not record or record.owner_user_id != owner or not record.active
                or type(expected_revision) is not int or record.revision != expected_revision):
            raise HostnameError("binding-conflict")
        if CertificateAssignment.objects.filter(
                origin="managed", host_id=host_id, hostname=record.hostname,
                state="approved").exists():
            raise HostnameError("certificate-revoke-required")
        record.active = False
        record.revision += 1
        record.save(update_fields=["active", "revision"])
        audit("operator:" + str(owner), "managed-dns01-hostname-revoke",
              host=record.host, hostname=record.hostname, revision=record.revision)
        return {"binding_id": BINDING, "host_id": str(record.host_id),
                "revision": record.revision, "active": False, "provider_writes": 0}


def selected(host, hostname, credential_id, revision, zone_id, zone_name, owner):
    """Strict replay-time check used by both signing and signed retrieval."""
    grant = ManagedDns01Hostname.objects.filter(host=host, active=True).first()
    if (grant is None or grant.hostname != hostname or grant.owner_user_id != owner
            or str(grant.credential_id) != str(credential_id)
            or grant.credential_revision != revision
            or (grant.zone_id, grant.zone_name) != (zone_id, zone_name)
            or host.archived_at):
        return None
    admission = ManagedAdmission.objects.filter(host=host).first()
    if (admission is None or admission.installation_id != grant.installation_id
            or admission.fingerprint != grant.fingerprint
            or admission.registry_id != grant.registry_id
            or not HostIdentity.objects.filter(
                host=host, status="approved", fingerprint=grant.fingerprint).exists()
            or not allowed(str(host.pk), grant.fingerprint, admission.claims.get("jti"))):
        return None
    credential = ProviderCredential.objects.filter(
        pk=grant.credential_id, revision=grant.credential_revision,
        provider="cloudflare",
    ).first()
    return credential
