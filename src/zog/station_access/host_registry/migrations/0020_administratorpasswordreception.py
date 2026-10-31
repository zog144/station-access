from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    dependencies = [
        ("host_registry", "0019_credentialv1ledger"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]
    operations = [
        migrations.CreateModel(
            name="AdministratorPasswordReception",
            fields=[
                ("request_id", models.UUIDField(primary_key=True, serialize=False)),
                ("delivery_id", models.UUIDField(unique=True)),
                ("authorization_id", models.UUIDField()),
                ("authorization_revision", models.PositiveBigIntegerField()),
                ("credential_revision", models.PositiveBigIntegerField()),
                ("approved_policy_sha256", models.CharField(max_length=64)),
                ("account_revision_before", models.CharField(max_length=64)),
                ("account_revision_after", models.CharField(max_length=64)),
                ("installed_at", models.DateTimeField()),
                ("user", models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.AddConstraint(
            model_name="administratorpasswordreception",
            constraint=models.UniqueConstraint(
                fields=("user", "credential_revision"),
                name="station_admin_cred_user_revision_unique",
            ),
        ),
    ]
