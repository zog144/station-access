"""Durable administrator certificate preference, never issuance authority."""
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [('host_registry', '0013_dnsdestination_additionaldnsassignment')]
    operations = [
        migrations.CreateModel(
            name='CertificateSetupProposal',
            fields=[
                ('id', models.PositiveSmallIntegerField(default=1, editable=False, primary_key=True, serialize=False)),
                ('proposed_policy', models.JSONField(default=dict)),
                ('revision', models.PositiveBigIntegerField(default=0)),
                ('updated_at', models.DateTimeField(auto_now=True)),
            ],
        ),
    ]
