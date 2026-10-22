"""Read-only, owner-scoped DNS preview endpoints; no mutation routes."""
from django.core.exceptions import ObjectDoesNotExist
from django.http import JsonResponse
from django.views.decorators.cache import never_cache
from django.views.decorators.http import require_GET
from zog.network_register.contracts import NetworkError

from .views import administrator
from .dns_reconcile import configuration
from .dns_preview import inspect


@never_cache
@require_GET
@administrator
def preview(request, host_id, binding_id=None):
    try:
        config = configuration()
        if not config:
            return JsonResponse({"detail": "DNS preview is not configured"}, status=503)
        data = inspect(config, host_id, actor_id=request.user.pk,
                       binding_id=binding_id)
        # Network-register's strict, bounded, sanitized schema-1 DTO.
        return JsonResponse({"preview": data})
    except ObjectDoesNotExist:
        return JsonResponse({"detail": "DNS assignment unavailable"}, status=404)
    except NetworkError as error:
        # No raw provider messages, tokens, zone credentials, host evidence,
        # operator paths, or ledger data ever escape an unsuccessful preview.
        code = error.code if error.code in {
            "permission", "conflict", "storage", "validation",
            "unsupported", "not-found", "authentication",
            "rate-limit", "transient", "uncertain",
        } else "unavailable"
        status = 403 if code == "permission" else 404 if code == "not-found" else (
            503 if code in ("storage", "transient", "unavailable") else 409)
        return JsonResponse({"detail": "DNS inspection unavailable",
                             "code": code}, status=status)
    except BlockingIOError:
        return JsonResponse({"detail": "DNS controller busy", "code": "busy"}, status=409)
    except (OSError, ValueError, KeyError, TypeError):
        return JsonResponse({"detail": "DNS inspection unavailable",
                             "code": "unavailable"}, status=503)
