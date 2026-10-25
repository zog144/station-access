"""Explicit managed DNS-01 hostname owner, independent of AWS A-record state."""
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    dependencies = [("host_registry", "0016_issuertokenreadnonce")]

    operations = [
        migrations.CreateModel(
            name="ManagedDns01Hostname",
            fields=[
                ("host", models.OneToOneField(primary_key=True, serialize=False, on_delete=django.db.models.deletion.PROTECT, to="host_registry.host")),
                ("hostname", models.CharField(max_length=253, unique=True)),
                ("fingerprint", models.CharField(max_length=64)),
                ("installation_id", models.UUIDField()),
                ("registry_id", models.CharField(max_length=64)),
                ("credential_revision", models.PositiveBigIntegerField()),
                ("zone_id", models.CharField(max_length=100)),
                ("zone_name", models.CharField(max_length=253)),
                ("owner_user_id", models.PositiveBigIntegerField()),
                ("review_id", models.CharField(max_length=64)),
                ("active", models.BooleanField(default=True)),
                ("revision", models.PositiveBigIntegerField(default=1)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("credential", models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, to="host_registry.providercredential")),
            ],
        ),
    ]
