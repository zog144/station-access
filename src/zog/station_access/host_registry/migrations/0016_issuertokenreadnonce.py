"""Durable nonsecret anti-replay journal for issuer vault reader."""
from django.db import migrations,models

class Migration(migrations.Migration):
    dependencies=[("host_registry","0015_certificateassignment")]
    operations=[migrations.CreateModel(
        name="IssuerTokenReadNonce",
        fields=[
            ("nonce",models.CharField(primary_key=True,max_length=32,serialize=False)),
            ("authorization_id",models.CharField(max_length=64)),
            ("created_at",models.DateTimeField(auto_now_add=True,db_index=True)),
        ],
    )]
