"""Root owner-selected, secret-free signed authority revision reconciliation."""
import hashlib
import json
import os
import re

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError


class Command(BaseCommand):
    help = "Dry-run or persist separately signed Credential Authority revocation"

    def add_arguments(self, parser):
        parser.add_argument("--expected-envelope-sha256", required=True)
        parser.add_argument("--commit", action="store_true")

    def handle(self, *args, **options):
        from zog.station_access.host_registry import (
            credential_v1_authority as authority)
        from zog.station_access.host_registry import (
            credential_https_authority as protected)
        if (os.geteuid() != 0 or not re.fullmatch(
                r"[0-9a-f]{64}", options["expected_envelope_sha256"])):
            raise CommandError("Protected reconciliation unavailable")
        try:
            raw = protected._protected(getattr(
                settings, "HOST_CREDENTIAL_V1_AUTHORIZATION_FILE", ""), 0o600)
            if hashlib.sha256(raw).hexdigest() != options[
                    "expected_envelope_sha256"]:
                raise ValueError()
            grant, auth, _key = authority._identity_and_authorization(
                permit_revoked=True)
            if auth["status"] != "revoked" or grant["state"] != "revoked":
                raise ValueError()
            if options["commit"]:
                status, revision = authority.reconcile_reviewed_authorization()
            else:
                status, revision = "review-only", auth["revision"]
            self.stdout.write(
                f"status={status} revision={revision} "
                "credential_delivered=false")
        except Exception:
            raise CommandError("Protected reconciliation unavailable") from None
