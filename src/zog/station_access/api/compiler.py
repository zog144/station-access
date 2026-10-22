"""Administrator-only read-only compiler visibility from host-deploy owner RPC.

Never passes request-controlled hosts, workspace IDs, epochs, source paths or
mutations to the observer. Django session authentication is independent of mTLS.
"""
from django.conf import settings
from django.http import JsonResponse
from django.views.decorators.http import require_GET

from zog.station_access.compiler_rpc import CompilerObserver, CompilerRPCUnavailable


def _reply(body, http_status=200):
    response = JsonResponse(body, status=http_status)
    response["Cache-Control"] = "no-store"
    response["X-Content-Type-Options"] = "nosniff"
    return response


def _authorize(request):
    if not request.user.is_authenticated or not request.user.is_active:
        return _reply({"error": "authentication_required"}, 401)
    if not request.user.is_superuser:
        return _reply({"error": "administrator_required"}, 403)
    return None


def _failure(error):
    code = error.category
    http_status = {
        "not-owned": 409, "ownership-epoch-mismatch": 409,
        "uncertain": 409, "not-authorized": 403,
        "invalid-operation": 400, "unavailable": 503,
    }.get(code, 503)
    return _reply({"schema": "host-deploy-compiler-rpc-v1",
                   "state": "unavailable", "error": code}, http_status)


@require_GET
def status(request):
    denied = _authorize(request)
    if denied is not None:
        return denied
    try:
        observer = CompilerObserver.from_state_directory(settings.STATE_DIRECTORY)
        value = observer.compiler_status()
    except CompilerRPCUnavailable as error:
        return _failure(error)
    except Exception:
        return _failure(CompilerRPCUnavailable())
    return _reply(value)


@require_GET
def dispatch(request, request_id):
    denied = _authorize(request)
    if denied is not None:
        return denied
    try:
        observer = CompilerObserver.from_state_directory(settings.STATE_DIRECTORY)
        value = observer.dispatch_status(request_id)
    except CompilerRPCUnavailable as error:
        return _failure(error)
    except Exception:
        return _failure(CompilerRPCUnavailable())
    return _reply(value)
