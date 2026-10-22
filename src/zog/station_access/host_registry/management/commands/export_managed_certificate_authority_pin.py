"""Read-only local candidate for host-install's independently reviewed root pin.

This command neither installs authority nor enables hostname assignments.
Only the trusted installer may place the reviewed result in root-owned state.
"""
import json

from django.core.management.base import BaseCommand, CommandError
from zog.station_access.host_registry.certificate_assignment_signing import (
    SigningUnavailable, managed_authority_pin,
)


class Command(BaseCommand):
    help = "Export a reviewed managed certificate signer pin candidate (no host installation)"

    def add_arguments(self, parser):
        parser.add_argument("--host-id", required=True)
        parser.add_argument("--installation-id", required=True)
        parser.add_argument("--registry-id", required=True)
        parser.add_argument("--host-fingerprint", required=True)
        parser.add_argument("--expected-key-id", required=True)

    def handle(self, *args, **options):
        try:
            pin = managed_authority_pin(
                host_id=options["host_id"],
                installation_id=options["installation_id"],
                registry_id=options["registry_id"],
                host_fingerprint=options["host_fingerprint"],
                expected_key_id=options["expected_key_id"],
            )
        except SigningUnavailable as error:
            raise CommandError(str(error)) from None
        self.stdout.write(json.dumps(pin, sort_keys=True, separators=(",", ":")))
