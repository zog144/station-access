"""Operator-selected, root-only signed HTTPS credential grant revocation.

No token retrieval or credential transmission. A new approval revision must
first be installed and reviewed through an independent trusted channel.
"""
import hashlib
import os
import re
from django.core.management.base import BaseCommand, CommandError
from zog.station_access.host_registry import credential_https_authority as authority
from zog.station_access.host_registry.certificate_assignment_signing import canonical


class Command(BaseCommand):
    help = "Inspect or durably adopt a separately signed revoked credential grant"

    def add_arguments(self, parser):
        parser.add_argument("--expected-grant-sha256", required=True)
        parser.add_argument("--commit", action="store_true")

    def handle(self, *args, **options):
        digest = options["expected_grant_sha256"]
        if (os.geteuid() != 0 or type(digest) is not str
                or re.fullmatch("[0-9a-f]{64}", digest) is None):
            raise CommandError("Protected revocation unavailable")
        try:
            value = authority._authority(allow_revoked=True)
            if (value["state"] != "revoked" or
                    hashlib.sha256(canonical(value)).hexdigest() != digest):
                raise ValueError()
            if options["commit"]:
                result = authority.reconcile_signed_revocation()
            else:
                result = {"status":"review-only", "host_id":value["host_id"],
                          "grant_revision":value["revision"],
                          "credential_transferred":False}
            self.stdout.write(
                f"status={result['status']} host_id={result['host_id']} "
                f"grant_revision={result['grant_revision']} "
                "credential_transferred=false")
        except Exception:
            raise CommandError("Protected revocation unavailable") from None
