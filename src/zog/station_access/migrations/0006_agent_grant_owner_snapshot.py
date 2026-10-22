"""Bind agent grants to original workspace ownership (fail closed on migration)."""
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("station_access", "0005_agent_access_grant")]

    operations = [
        migrations.AddField(
            model_name="agentaccessgrant",
            name="workspace_owners",
            field=models.JSONField(default=dict),
        ),
    ]
