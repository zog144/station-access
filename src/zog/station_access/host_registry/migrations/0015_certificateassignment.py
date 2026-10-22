"""Separate certificate hostname authority receipt and durable request replay."""
import uuid
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    dependencies = [('host_registry', '0014_certificatesetupproposal')]
    operations = [
        migrations.CreateModel(
            name='CertificateAssignment',
            fields=[
                ('id', models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False, serialize=False)),
                ('origin', models.CharField(max_length=16)),
                ('installation_id', models.UUIDField()),
                ('hostname', models.CharField(max_length=253)),
                ('binding_id', models.CharField(max_length=100)),
                ('credential_revision', models.PositiveBigIntegerField()),
                ('zone_id', models.CharField(max_length=100)),
                ('zone_name', models.CharField(max_length=253)),
                ('revision', models.PositiveBigIntegerField(default=1)),
                ('state', models.CharField(default='approved', max_length=16)),
                ('expires_at', models.DateTimeField()),
                ('statement', models.JSONField(default=dict)),
                ('receipt', models.JSONField(default=dict)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('host', models.ForeignKey(null=True, on_delete=django.db.models.deletion.PROTECT, to='host_registry.host')),
                ('credential', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, to='host_registry.providercredential')),
            ],
        ),
        migrations.CreateModel(
            name='CertificateAssignmentAction',
            fields=[
                ('operation_id', models.UUIDField(primary_key=True, serialize=False)),
                ('payload_sha256', models.CharField(max_length=64)),
                ('receipt', models.JSONField()),
            ],
        ),
    ]
