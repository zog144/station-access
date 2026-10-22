# Read-only Workspace API machine grants: persistent digest and explicit scopes.
import uuid
import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("station_access", "0004_workspace_controller_adapter"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name="AgentAccessGrant",
            fields=[
                ("id", models.UUIDField(primary_key=True, serialize=False, editable=False, default=uuid.uuid4)),
                ("token_digest", models.CharField(max_length=64, unique=True, editable=False)),
                ("service_name", models.CharField(max_length=128, blank=True)),
                ("workspace_ids", models.JSONField(default=list)),
                ("scopes", models.JSONField(default=list)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("expires_at", models.DateTimeField(db_index=True)),
                ("revoked_at", models.DateTimeField(blank=True, null=True)),
                ("principal_user", models.ForeignKey(to=settings.AUTH_USER_MODEL, null=True, blank=True,
                    on_delete=django.db.models.deletion.CASCADE, related_name="workspace_agent_grants")),
            ],
            options={"indexes": [models.Index(fields=("expires_at", "revoked_at"), name="station_agent_expiry_idx")]},
        )
    ]
