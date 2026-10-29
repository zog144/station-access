from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("host_registry", "0017_manageddns01hostname")]

    operations = [
        migrations.CreateModel(
            name="HttpsCredentialDeliveryNonce",
            fields=[
                ("nonce", models.CharField(primary_key=True, serialize=False, max_length=32)),
                ("host_id", models.UUIDField()),
                ("authorization_id", models.CharField(max_length=64)),
                ("credential_revision", models.PositiveBigIntegerField()),
                ("created_at", models.DateTimeField(auto_now_add=True, db_index=True)),
            ],
        ),
        migrations.CreateModel(
            name="HttpsCredentialDeliveryRevision",
            fields=[
                ("host_id", models.UUIDField(primary_key=True, serialize=False)),
                ("grant_revision", models.PositiveBigIntegerField()),
                ("grant_sha256", models.CharField(max_length=64)),
                ("credential_revision", models.PositiveBigIntegerField()),
                ("updated_at", models.DateTimeField(auto_now=True)),
            ],
        ),
    ]
