"""Versioned, reversible certificate hostname assignment authority.

This is a station intent/retrieval contract. It cannot invoke the issuer,
authorize a privileged host command, publish nginx TLS or touch DNS.
"""
import hashlib
import re
import uuid
from datetime import timedelta
from django.conf import settings
from django.utils import timezone
from zog.certify_manage.model import Authorization
from .certificate_assignment_signing import canonical, sign, managed_enabled
from .identity import locked, audit
from .models import (
    CertificateAssignment, CertificateAssignmentAction, DnsAssignment,
    AdditionalDnsAssignment, DnsDestination, ProviderCredential, Host,
    HostIdentity, ManagedAdmission,
)

SCHEMA = "zog-certificate-assignment-v1"
CONSUMERS = {"managed": "host-nginx-https", "local": "station-nginx-https"}
HEX = re.compile(r"[0-9a-f]{64}\Z")


class AssignmentError(ValueError):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def _uuid(value):
    if not isinstance(value, str):
        raise AssignmentError("invalid-request")
    try:
        u = uuid.UUID(value)
    except (ValueError, AttributeError):
        raise AssignmentError("invalid-request") from None
    if str(u) != value:
        raise AssignmentError("invalid-request")
    return u


def _source(origin, host_id, binding_id, hostname, credential_id, revision, zone_id, zone_name, actor):
    """Read the reviewed station DNS identity, never trust caller's zone claim."""
    if origin == "managed":
        if host_id is None:
            raise AssignmentError("identity-required")
        host = Host.objects.filter(pk=_uuid(host_id), archived_at__isnull=True).first()
        if not host or not HostIdentity.objects.filter(host=host, status="approved").exists():
            raise AssignmentError("identity-unavailable")
        admission = ManagedAdmission.objects.filter(host=host).first()
        if not admission or not HostIdentity.objects.filter(
                host=host,status="approved",fingerprint=admission.fingerprint).exists():
            raise AssignmentError("installation-unavailable")
        installation_id = admission.installation_id
    elif origin == "local":
        if host_id is not None:
            raise AssignmentError("identity-conflict")
        local_id = getattr(settings, "HOST_LOCAL_CERTIFICATE_INSTALLATION_ID", "")
        installation_id = _uuid(local_id)
        host = None
    else:
        raise AssignmentError("invalid-origin")

    if binding_id == "primary":
        if origin != "managed":
            raise AssignmentError("zone-not-approved")
        from .dns_reconcile import configuration
        from .dns_cutover import controller_state, load_review
        from pathlib import Path
        config = configuration()
        if not config:
            raise AssignmentError("zone-not-approved")
        try:
            root = Path(config["state_directory"])
            state = controller_state(config)
            selected = load_review(root, state["review_id"])["selection"]
            from .dns_evidence import selection
            current = selection(selected)
            credential = ProviderCredential.objects.get(pk=selected["credential_id"])
            approved_zone_id = selected["zone_id"]
            approved_zone_name = selected["zone_name"]
            if (current.owner_user_id != actor
                    or credential.pk != _uuid(credential_id)
                    or selected["credential_revision"] != revision
                    or current.connection.provider != "cloudflare"):
                raise AssignmentError("zone-not-approved")
        except AssignmentError:
            raise
        except Exception:
            raise AssignmentError("zone-not-approved") from None
        assignment = DnsAssignment.objects.filter(host=host).first()
    else:
        target = DnsDestination.objects.filter(pk=binding_id, enabled=True).first()
        if not target:
            raise AssignmentError("zone-not-approved")
        selection = target.selection
        if (not isinstance(selection, dict)
                or selection.get("owner_user_id") != actor
                or selection.get("credential_id") != credential_id
                or selection.get("credential_revision") != revision):
            raise AssignmentError("zone-not-approved")
        credential = ProviderCredential.objects.filter(pk=_uuid(credential_id)).first()
        approved_zone_id, approved_zone_name = selection.get("zone_id"), selection.get("zone_name")
        if origin == "managed":
            prefix = selection.get("prefix")
            if (not isinstance(prefix, str)
                    or not hostname.endswith("." + prefix)
                    or hostname.count(".") != prefix.count(".") + 1):
                raise AssignmentError("zone-not-approved")
            assignment = AdditionalDnsAssignment.objects.filter(
                binding=target, host=host, phase="ready").first()
        else:
            assignment = None
            prefix = selection.get("prefix")
            # Standalone can select an exact hostname in an operator-reviewed
            # prefix, but may not claim a name reserved for another host.
            if (not isinstance(prefix, str) or not hostname.endswith("." + prefix)
                    or hostname.count(".") != prefix.count(".") + 1):
                raise AssignmentError("zone-not-approved")
            # Local certificate intent cannot claim a managed host's existing
            # DNS name, even if the operator controls the same DNS account.
            if (DnsAssignment.objects.filter(name=hostname).exists()
                    or AdditionalDnsAssignment.objects.filter(name=hostname).exists()):
                raise AssignmentError("assignment-conflict")

    if (not credential or credential.provider != "cloudflare"
            or credential.revision != revision
            or not isinstance(approved_zone_id, str) or not approved_zone_id
            or not isinstance(approved_zone_name, str)
            or (zone_id, zone_name) != (approved_zone_id, approved_zone_name)):
        raise AssignmentError("credential-or-zone-changed")
    if origin == "managed" and (
            not assignment or assignment.name != hostname
            or not assignment.enabled or assignment.status != "synchronized"
            or assignment.applied_revision != assignment.revision
            or not assignment.record_id):
        raise AssignmentError("dns-not-confirmed")
    if not hostname.endswith("." + zone_name):
        raise AssignmentError("zone-not-approved")
    if origin == "local":
        # A reviewed destination alone cannot prove that its separately
        # selected Cloudflare account can still read this specific zone.
        # This is READ access only; DNS-write authority must be rechecked
        # by the privileged issuer owner before any ACME operation.
        from .provider_checks import serialize
        check = serialize(credential)
        if (check["status"] != "passed" or not check["fresh"]
                or not any(z.get("id") == zone_id and
                           z.get("name") == zone_name and z.get("status") == "active"
                           for z in check["domains"])):
            raise AssignmentError("provider-access-unverified")
    return host, installation_id, credential


def _inputs(value):
    fields = {"schema", "action", "origin", "host_id", "binding_id", "policy",
              "credential_id", "credential_revision", "zone_id", "zone_name",
              "expires_at", "expected_revision", "operation_id"}
    if type(value) is not dict or set(value) != fields or value.get("schema") != SCHEMA:
        raise AssignmentError("invalid-request")
    if value["action"] not in ("approve", "revoke") or value["origin"] not in CONSUMERS:
        raise AssignmentError("invalid-request")
    if (type(value["credential_revision"]) is not int
            or value["credential_revision"] < 1
            or type(value["expected_revision"]) is not int
            or value["expected_revision"] < 0):
        raise AssignmentError("invalid-request")
    _uuid(value["operation_id"])
    return value


def _expiry(raw, now):
    from datetime import datetime, timezone as utc
    if not isinstance(raw, str) or len(raw) != 20 or not raw.endswith("Z"):
        raise AssignmentError("invalid-expiry")
    try:
        end = datetime.strptime(raw, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=utc.utc)
    except ValueError:
        raise AssignmentError("invalid-expiry") from None
    if not now + timedelta(minutes=10) <= end <= now + timedelta(days=30):
        raise AssignmentError("invalid-expiry")
    return end


def change(value, actor):
    value = _inputs(value)
    payload_digest = hashlib.sha256(canonical(value)).hexdigest()
    operation_id = _uuid(value["operation_id"])
    # Match the reviewed name owner's lock order: DNS controller first,
    # then the station security gate. A host assignment cannot race an
    # unpublication or a controller owner-mode transition.
    if value["origin"] == "managed" and not managed_enabled():
        raise AssignmentError("producer-disabled")
    # Both local and managed authority consume reviewed DNS zones, so neither
    # may issue/revoke a statement concurrently with the elected DNS owner.
    # No unsafe fallback lock or filename derived from the browser is allowed.
    from .dns_reconcile import configuration, controller_lock
    config = configuration()
    if not config:
        raise AssignmentError("dns-owner-unavailable")
    owner_guard = controller_lock(config, modes=("shared",))
    with owner_guard, locked():
        existing_op = CertificateAssignmentAction.objects.filter(operation_id=operation_id).first()
        if existing_op:
            if existing_op.payload_sha256 != payload_digest:
                raise AssignmentError("operation-conflict")
            # Never resurrect an approval from a historical idempotency record
            # after its assignment was subsequently revoked or superseded.
            prior = (existing_op.receipt["assignment"]
                     if value["origin"] == "managed"
                     else existing_op.receipt["statement"])
            prior_state = prior["status"] if value["origin"] == "managed" else prior["state"]
            if prior_state == "approved":
                # An operation reply is idempotent but never resurrects a
                # former grant after revocation or successor publication.
                old = CertificateAssignment.objects.filter(
                    installation_id=_uuid(prior["installation_id"]),
                    state="approved",revision=prior["revision"]).first()
                if old is None or CertificateAssignment.objects.filter(
                        installation_id=old.installation_id,
                        revision__gt=prior["revision"]).exists():
                    raise AssignmentError("operation-superseded")
            return existing_op.receipt
        if value["action"] == "revoke":
            if value["origin"] == "managed":
                target = CertificateAssignment.objects.filter(
                    origin="managed", host_id=_uuid(value["host_id"]),
                    state="approved").first()
            else:
                if value["host_id"] is not None:
                    raise AssignmentError("identity-conflict")
                target = CertificateAssignment.objects.filter(
                    origin="local",
                    installation_id=_uuid(getattr(
                        settings, "HOST_LOCAL_CERTIFICATE_INSTALLATION_ID", "")),
                    state="approved").first()
            # Explicitly bind revocation to the current assignment and its
            # full immutable policy/zone/credential. No wildcard revocations.
            if not target:
                raise AssignmentError("assignment-not-found")
            if value["expected_revision"] != target.revision:
                raise AssignmentError("revision-conflict")
            auth = Authorization.from_dict(value["policy"])
            if (target.hostname != auth.hostnames[0] or
                    target.statement.get("policy") != auth.canonical()
                    or target.binding_id != value["binding_id"]
                    or str(target.credential_id) != value["credential_id"]
                    or target.credential_revision != value["credential_revision"]
                    or (target.zone_id,target.zone_name) != (value["zone_id"],value["zone_name"])):
                raise AssignmentError("assignment-conflict")
            signed = dict(target.statement,
                state="revoked", revision=target.revision+1,
                operation_id=str(operation_id),
                revoked_at=timezone.now().isoformat())
            receipt = sign(signed)
            target.state = "revoked"
            target.revision += 1
            target.statement, target.receipt = signed, receipt
            target.save(update_fields=["state","revision","statement","receipt","updated_at"])
            audit(str(actor), "certificate-revoke", host=target.host,
                  assignment_id=str(target.pk), revision=target.revision)
        else:
            auth = Authorization.from_dict(value["policy"])
            if len(auth.hostnames) != 1 or auth.certificate_id != "station-web":
                raise AssignmentError("certificate-id-conflict")
            now = timezone.now()
            expiry = _expiry(value["expires_at"], now)
            hostname = auth.hostnames[0]
            host, installation_id, credential = _source(
                value["origin"], value["host_id"], value["binding_id"], hostname,
                value["credential_id"], value["credential_revision"],
                value["zone_id"], value["zone_name"], actor)
            latest = CertificateAssignment.objects.filter(
                installation_id=installation_id).order_by("-revision","-updated_at").first()
            if latest and latest.state == "approved":
                # Replacement first requires a higher-revision signed revocation.
                raise AssignmentError("assignment-conflict")
            prior_revision = latest.revision if latest else 0
            if value["expected_revision"] != prior_revision:
                raise AssignmentError("revision-conflict")
            revision_number = prior_revision + 1
            if revision_number > 2**53-1:
                raise AssignmentError("revision-exhausted")
            if CertificateAssignment.objects.filter(
                    hostname=hostname).exclude(installation_id=installation_id).exists() or CertificateAssignment.objects.filter(
                    state="approved", installation_id=installation_id).exists():
                raise AssignmentError("assignment-conflict")
            finger = None
            if host is not None:
                finger = HostIdentity.objects.get(host=host,status="approved").fingerprint
            statement = {
                "schema": SCHEMA, "origin": value["origin"],
                "assignment_id": str(uuid.uuid4()),
                "installation_id": str(installation_id),
                "host_id": str(host.pk) if host else None,
                "host_fingerprint": finger,
                "credential_id": str(credential.pk),
                "credential_revision": credential.revision,
                "zone_id": value["zone_id"], "zone_name": value["zone_name"],
                "binding_id": value["binding_id"],
                "policy": auth.canonical(),
                "consumer": CONSUMERS[value["origin"]],
                "revision": revision_number, "state": "approved",
                "approved_at": now.isoformat(),
                "expires_at": expiry.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "operation_id": str(operation_id),
            }
            receipt = sign(statement)
            CertificateAssignment.objects.create(
                id=uuid.UUID(statement["assignment_id"]), origin=value["origin"],
                host=host, installation_id=installation_id,
                hostname=hostname, binding_id=value["binding_id"],
                credential=credential, credential_revision=credential.revision,
                zone_id=value["zone_id"], zone_name=value["zone_name"],
                revision=revision_number,
                expires_at=expiry, statement=statement, receipt=receipt)
            audit(str(actor), "certificate-assign", host=host,
                  assignment_id=statement["assignment_id"], revision=revision_number)
        CertificateAssignmentAction.objects.create(
            operation_id=operation_id, payload_sha256=payload_digest, receipt=receipt)
        return receipt


def current(host, fingerprint=None):
    """Read only; expiry/revocation/identity state is never masked by cache."""
    row = CertificateAssignment.objects.filter(origin="managed",host=host).order_by(
        "-revision","-updated_at").first()
    if row is None:
        return {"state": "unassigned", "receipt": None}
    if row.state != "approved":
        return {"state": "revoked", "receipt": row.receipt}
    if row.expires_at <= timezone.now():
        return {"state": "expired", "receipt": row.receipt}
    if (host.archived_at or not HostIdentity.objects.filter(
            host=host,status="approved",fingerprint=row.statement["host_fingerprint"]).exists()
            or not ManagedAdmission.objects.filter(
                host=host,installation_id=row.installation_id).exists()):
        return {"state": "conflict", "receipt": None}
    if fingerprint is not None and fingerprint != row.statement["host_fingerprint"]:
        return {"state": "conflict", "receipt": None}
    credential = ProviderCredential.objects.filter(
        pk=row.credential_id, revision=row.credential_revision).first()
    if not credential or credential.provider != "cloudflare":
        return {"state": "conflict", "receipt": None}
    # Local Django projections remain evidence, not new DNS observations.
    # Any withdrawal or revision change fences the prior assignment receipt.
    if row.binding_id == "primary":
        dns = DnsAssignment.objects.filter(host=host).first()
    else:
        binding = DnsDestination.objects.filter(pk=row.binding_id, enabled=True).first()
        if not binding or binding.selection.get("credential_id") != str(row.credential_id) or (
                binding.selection.get("credential_revision") != row.credential_revision
                or binding.selection.get("zone_id") != row.zone_id
                or binding.selection.get("zone_name") != row.zone_name):
            return {"state": "conflict", "receipt": None}
        dns = AdditionalDnsAssignment.objects.filter(
            binding=binding,host=host,phase="ready").first()
    if (not dns or not dns.enabled or dns.name != row.hostname
            or dns.status != "synchronized"
            or dns.applied_revision != dns.revision or not dns.record_id):
        return {"state": "conflict", "receipt": None}
    return {"state": "approved", "receipt": row.receipt}
