from django.urls import path
from . import agent

urlpatterns = [
    path("capabilities/", agent.capabilities),
    path("workspaces/", agent.workspaces),
    path("workspaces/<uuid:workspace_id>/", agent.workspace_detail),
    path("workspaces/<uuid:workspace_id>/applications/", agent.workspace_applications),
    path("workspaces/<uuid:workspace_id>/runtimes/<str:runtime_id>/", agent.runtime_detail),
    path("workspaces/<uuid:workspace_id>/runtimes/<str:runtime_id>/logs/", agent.runtime_logs),
]
