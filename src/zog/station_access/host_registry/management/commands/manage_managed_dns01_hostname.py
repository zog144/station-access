"""Operator-only reviewed DNS-01 name binding; no provider writes or issuer calls."""
import json
from django.core.management.base import BaseCommand, CommandError
from zog.station_access.host_registry import managed_dns01_hostname as authority


class Command(BaseCommand):
    help = "Review, commit or revoke an installation-bound DNS-01 hostname"

    def add_arguments(self, p):
        sub = p.add_subparsers(dest="action", required=True)
        rev = sub.add_parser("review")
        rev.add_argument("--owner", type=int, required=True)
        rev.add_argument("--host", required=True)
        rev.add_argument("--installation", required=True)
        rev.add_argument("--fingerprint", required=True)
        rev.add_argument("--registry", required=True)
        rev.add_argument("--hostname", required=True)
        rev.add_argument("--credential", required=True)
        rev.add_argument("--credential-revision", type=int, required=True)
        rev.add_argument("--zone-id", required=True)
        com = sub.add_parser("commit")
        com.add_argument("--owner", type=int, required=True)
        com.add_argument("--review-id", required=True)
        rem = sub.add_parser("revoke")
        rem.add_argument("--owner", type=int, required=True)
        rem.add_argument("--host", required=True)
        rem.add_argument("--expected-revision", type=int, required=True)

    def handle(self, *args, **o):
        try:
            if o["action"] == "review":
                result = authority.review(
                    owner=o["owner"], host_id=o["host"],
                    installation_id=o["installation"], fingerprint=o["fingerprint"],
                    registry_id=o["registry"], hostname=o["hostname"],
                    credential_id=o["credential"],
                    credential_revision=o["credential_revision"], zone_id=o["zone_id"],
                )
            elif o["action"] == "commit":
                result = authority.commit(owner=o["owner"], review_id=o["review_id"])
            else:
                result = authority.revoke(
                    owner=o["owner"], host_id=o["host"],
                    expected_revision=o["expected_revision"],
                )
        except Exception as exc:
            raise CommandError(
                "Managed DNS-01 hostname authority blocked: "
                + getattr(exc, "code", type(exc).__name__)
            ) from None
        self.stdout.write(json.dumps(result, sort_keys=True, separators=(",", ":")))
