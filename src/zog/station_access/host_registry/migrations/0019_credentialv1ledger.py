from django.db import migrations, models
import django.db.models.deletion

class Migration(migrations.Migration):
    dependencies = [("host_registry", "0018_httpscredentialdelivery")]
    operations = [
        migrations.CreateModel(name="HttpsCredentialV1Ledger", fields=[
            ("subject_sha256", models.CharField(primary_key=True, serialize=False, max_length=64)),
            ("host_id", models.UUIDField(db_index=True)),
            ("credential_id", models.CharField(max_length=63)),
            ("authorization_id", models.UUIDField()),
            ("authorization_sha256", models.CharField(max_length=64)),
            ("state", models.JSONField()),
            ("updated_at", models.DateTimeField(auto_now=True)),
        ]),
        migrations.CreateModel(name="HttpsCredentialV1Operation", fields=[
            ("request_id", models.UUIDField(primary_key=True, serialize=False)),
            ("request", models.JSONField()),
            ("delivery_metadata", models.JSONField(default=dict)),
            ("created_at", models.DateTimeField(auto_now_add=True)),
            ("ledger", models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, to="host_registry.httpscredentialv1ledger")),
        ]),
    ]
