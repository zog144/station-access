"""Authenticated, replay-protected certificate assignment retrieval and admin decisions."""
from django.conf import settings
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_GET, require_POST, require_http_methods
from django.db import OperationalError
from zog.host_identify import signatures
from .views import administrator, body
from . import certificate_assignment as assignment, identity
from .models import HostIdentity, Host, CertificateAssignment, DnsDestination, ManagedAdmission, DnsAssignment, AdditionalDnsAssignment, ProviderCredential


def response(data,status=200):
    result = JsonResponse(data,status=status)
    result["Cache-Control"] = "no-store"
    result["X-Content-Type-Options"] = "nosniff"
    return result


@require_http_methods(["GET","POST"])
@administrator
def administration(request):
    if request.method == "GET":
        rows = CertificateAssignment.objects.order_by("-updated_at")[:100]
        # Expose reviewed station DNS selectors for the admin form, never
        # vault secrets, token files, arbitrary provider URLs or paths.
        bindings = []
        for target in DnsDestination.objects.filter(enabled=True)[:100]:
            selected = target.selection
            if (type(selected) is not dict or
                    selected.get("owner_user_id") != request.user.pk):
                continue
            credential = ProviderCredential.objects.filter(
                pk=selected.get("credential_id"),
                revision=selected.get("credential_revision"),
                provider="cloudflare").first()
            if not credential:
                continue
            bindings.append({
                "binding_id":target.pk,
                "zone_id":selected.get("zone_id"),
                "zone_name":selected.get("zone_name"),
                "prefix":selected.get("prefix"),
                "credential_id":str(credential.pk),
                "credential_revision":credential.revision,
            })
        hosts=[]
        for admission in ManagedAdmission.objects.select_related("host").all()[:100]:
            host=admission.host
            if host.archived_at or not HostIdentity.objects.filter(
                    host=host,status="approved",
                    fingerprint=admission.fingerprint).exists():
                continue
            names = list(DnsAssignment.objects.filter(host=host,enabled=True).values_list("name",flat=True))
            names += list(AdditionalDnsAssignment.objects.filter(
                host=host,enabled=True,phase="ready").values_list("name",flat=True))
            hosts.append({"host_id":str(host.pk),"installation_id":str(admission.installation_id),
                          "label":host.label[:100],"dns_names":names[:20]})
        return response({"schema": assignment.SCHEMA, "read_only": True,
            "bindings": bindings, "hosts":hosts,
            "assignments": [{
                "assignment_id": str(row.pk), "origin": row.origin,
                "host_id": str(row.host_id) if row.host_id else None,
                "installation_id": str(row.installation_id),
                "hostname": row.hostname, "consumer": row.statement.get("consumer"),
                "zone_name": row.zone_name, "zone_id": row.zone_id,
                "binding_id": row.binding_id,
                "credential_id": str(row.credential_id),
                "credential_revision": row.credential_revision,
                "revision": row.revision, "state": row.state,
                "expires_at": row.expires_at.isoformat(),
                "policy": row.statement.get("policy"),
                "receipt": row.receipt,
            } for row in rows]})
    try:
        result = assignment.change(body(request), request.user.pk)
        return response({"receipt": result})
    except assignment.AssignmentError as error:
        code = error.code
        # A retry of an approval superseded by a higher-revision
        # revocation is a state conflict, not malformed request syntax.
        # Keep the fail-closed assignment/replay rejection unchanged.
        conflict = ("conflict" in code or code in (
            "dns-not-confirmed", "assignment-not-found", "operation-superseded"))
        return response({"code": code, "detail": "Certificate assignment refused"},
                        409 if conflict else 400)
    except (ValueError,KeyError,TypeError):
        return response({"code": "invalid-request", "detail": "Certificate assignment refused"},400)
    except OperationalError:
        return response({"code": "storage-unavailable", "detail": "Certificate assignment unavailable"},503)
    except Exception:
        # Missing protected signer, unreadable policy or unexpected provider
        # metadata must never escape a traceback or become a best-effort grant.
        return response({"code": "authority-unavailable",
                         "detail": "Certificate assignment authority unavailable"},503)


@csrf_exempt
@require_POST
def retrieve(request, host_id):
    """Exact host-discover managed certificate assignment v1 producer.

    Signed HostIdentity HTTP request + current managed session + nonce
    replay protection. Never conflate transport authorization with a signed
    installable policy; the host independently verifies the envelope.
    """
    from .certificate_assignment_signing import managed_enabled
    from .managed_views import allowed
    from .dns_reconcile import configuration, controller_lock

    if not managed_enabled():
        return response({"code": "certificate-assignment-disabled"}, 503)
    try:
        data = body(request)
        expected = {"schema", "host_id", "installation_id",
                    "known_revision", "known_operation_id", "managed_session"}
        if type(data) is not dict or set(data) != expected or (
                data["schema"] != "zog-host-certificate-assignment-request-v1"
                or data["host_id"] != str(host_id)):
            return response({"detail": "Host authorization denied"}, 400)
        if (data["installation_id"] is not None and
                str(assignment._uuid(data["installation_id"])) != data["installation_id"]):
            return response({"detail": "Host authorization denied"}, 400)
        known = data["known_revision"]
        if type(known) is not int or not 0 <= known <= 2**53 - 1:
            return response({"detail": "Host authorization denied"}, 400)
        if ((known == 0) != (data["known_operation_id"] is None) or
                (known and str(assignment._uuid(data["known_operation_id"])) !=
                 data["known_operation_id"])):
            return response({"detail": "Host authorization denied"}, 400)
        session = data["managed_session"]
        if not isinstance(session, str) or not session:
            return response({"detail": "Host authorization denied"}, 403)
        fingerprint = request.headers.get("X-Host-Key", "")
        if not assignment.HEX.fullmatch(fingerprint):
            return response({"detail": "Host authorization denied"}, 403)
        initial = HostIdentity.objects.filter(
            pk=fingerprint, host_id=host_id, status="approved").first()
        if initial is None:
            return response({"detail": "Host authorization denied"}, 403)
        nonce, expiry = identity.proof(
            request, signatures.public_key(initial.public_key), str(host_id))
        config = configuration()
        if not config:
            return response({"code": "dns-owner-unavailable"}, 503)
        # Lock ordering matches the admin mutation path: DNS/FQDN owner first,
        # then station's authoritative host identity/security gate.
        with controller_lock(config, modes=("shared",)), identity.locked():
            current_key = HostIdentity.objects.filter(
                pk=fingerprint, host_id=host_id, status="approved",
                public_key=initial.public_key).first()
            host = Host.objects.filter(pk=host_id, archived_at__isnull=True).first()
            if not current_key or not host or not allowed(host_id, fingerprint, session):
                return response({"detail": "Host authorization denied"}, 403)
            admission = ManagedAdmission.objects.filter(host=host).first()
            if (admission is None or admission.fingerprint != fingerprint or
                    data["installation_id"] != str(admission.installation_id)):
                return response({"detail": "Host authorization denied"}, 403)
            identity.consume(fingerprint, nonce, expiry)
            current_assignment = assignment.current(host, fingerprint)
            if current_assignment["state"] == "conflict":
                return response({"code": "certificate-assignment-conflict"}, 409)
            receipt = current_assignment["receipt"]
            if receipt is None:
                if known:
                    return response({"code": "certificate-assignment-history-conflict"}, 409)
                state, revision, envelope = "unassigned", 0, None
            else:
                statement = receipt["assignment"]
                revision = statement["revision"]
                if known > revision:
                    return response({"code": "certificate-assignment-rollback"}, 409)
                if known == revision:
                    if data["known_operation_id"] != statement["operation_id"]:
                        return response({"code": "certificate-assignment-history-conflict"}, 409)
                    state, envelope = "unchanged", None
                else:
                    state, envelope = "receipt", receipt
        return response({
            "schema": "zog-host-certificate-assignment-response-v1",
            "host_id": str(host_id), "state": state,
            "revision": revision, "envelope": envelope,
        })
    except (OperationalError, OSError, BlockingIOError, RuntimeError):
        return response({"code": "certificate-assignment-unavailable"}, 503)
    except Exception:
        return response({"detail": "Host authorization denied"}, 403)
