"""Read local signed certificate intent for a separately authorized host owner.

Never turn the Django proposal or receipt into root policy here.
"""
import json
import uuid
from django.conf import settings
from django.core.management.base import BaseCommand
from django.utils import timezone
from zog.station_access.host_registry.certificate_assignment import SCHEMA
from zog.station_access.host_registry.models import (
    CertificateAssignment, DnsDestination, ProviderCredential
)


def local_status():
    local = getattr(settings, "HOST_LOCAL_CERTIFICATE_INSTALLATION_ID", "")
    try:
        installation = uuid.UUID(local)
        if str(installation) != local:
            raise ValueError()
    except (ValueError, TypeError, AttributeError):
        return {"schema": SCHEMA, "state": "installation-unavailable", "receipt": None}
    row = CertificateAssignment.objects.filter(
        origin="local",installation_id=installation).order_by("-updated_at","-id").first()
    if row is None:
        return {"schema": SCHEMA, "state": "unassigned", "receipt": None}
    if row.state == "revoked":
        return {"schema": SCHEMA, "state": "revoked", "receipt": row.receipt}
    if row.state != "approved" or row.expires_at <= timezone.now():
        return {"schema": SCHEMA, "state": "expired", "receipt": row.receipt}
    binding = DnsDestination.objects.filter(pk=row.binding_id,enabled=True).first()
    selected = binding.selection if binding else {}
    valid = (
        isinstance(selected,dict)
        and selected.get("zone_id") == row.zone_id
        and selected.get("zone_name") == row.zone_name
        and selected.get("credential_id") == str(row.credential_id)
        and selected.get("credential_revision") == row.credential_revision
        and ProviderCredential.objects.filter(pk=row.credential_id,
                  revision=row.credential_revision, provider="cloudflare").exists()
    )
    if valid:
        from zog.station_access.host_registry.provider_checks import serialize
        credential = ProviderCredential.objects.get(pk=row.credential_id)
        check = serialize(credential)
        valid = (
            check["status"] == "passed" and check["fresh"]
            and any(zone.get("id") == row.zone_id
                    and zone.get("name") == row.zone_name
                    and zone.get("status") == "active"
                    for zone in check["domains"])
        )
    if not valid:
        return {"schema": SCHEMA, "state": "conflict", "receipt": None}
    return {"schema": SCHEMA, "state": "approved", "receipt": row.receipt}


class Command(BaseCommand):
    help = "Read local signed certificate intent (no issuer/owner action)"

    def handle(self,*args,**options):
        self.stdout.write(json.dumps(local_status(),sort_keys=True,separators=(",",":")))
