"""Administrator-only certificate setup; no direct issuance or proxy writes."""
from django.http import JsonResponse
from django.views.decorators.http import require_http_methods
from zog.certify_manage.model import PolicyError
from .views import administrator, body
from .certificate_setup import snapshot, save_proposal, refuse_owner_request, ProposalConflict


def _reply(payload, status=200):
    value = JsonResponse(payload, status=status)
    value["Cache-Control"] = "no-store"
    value["X-Content-Type-Options"] = "nosniff"
    return value


@require_http_methods(["GET", "POST"])
@administrator
def certificates(request):
    if request.method == "GET":
        return _reply(snapshot())
    try:
        value = body(request)
        # Deliberately only stores an operator proposal. This endpoint does
        # not invoke Certbot, enqueue a host job, or create an issuer policy.
        return _reply(save_proposal(value))
    except ProposalConflict:
        return _reply({"code": "proposal-revision-changed",
                       "detail": "Refresh the certificate proposal before saving"}, 409)
    except (PolicyError, ValueError, TypeError):
        return _reply({"code": "invalid-proposal",
                       "detail": "Review the hostname, ACME directory, challenge and provider"}, 400)


@require_http_methods(["POST"])
@administrator
def request_certificate(request):
    # Reject before parsing untrusted payload or writing an attempt. The only
    # approved authority is host-deploy; its request API is not available yet.
    return _reply(refuse_owner_request(), 503)
