"""Administrator-only bounded UI observation, not a controller capability."""
from django.http import JsonResponse
from django.views.decorators.http import require_GET

from .application_progress import BadCursor, snapshot
from .views import administrator


@require_GET
@administrator
def application_progress(request):
    if set(request.GET) - {"after_build", "after_runtime"} or any(
            len(request.GET.getlist(key)) != 1 for key in request.GET):
        result = JsonResponse({"code": "invalid-progress-cursor"}, status=400)
    else:
        try:
            result = JsonResponse(snapshot(
                after_build=request.GET.get("after_build") or None,
                after_runtime=request.GET.get("after_runtime") or None))
        except BadCursor:
            result = JsonResponse({"code": "invalid-progress-cursor"}, status=400)
    result["Cache-Control"] = "no-store"
    result["X-Content-Type-Options"] = "nosniff"
    return result
