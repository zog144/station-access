"""Operator-controlled empty shared DNS writer bootstrap, no provider writes."""
import json
from django.core.management.base import BaseCommand, CommandError
from zog.station_access.host_registry import dns_empty_bootstrap as bootstrap


class Command(BaseCommand):
    help = "Review, commit or inspect a fresh empty shared DNS controller"

    def add_arguments(self, parser):
        sub = parser.add_subparsers(dest="action", required=True)
        review = sub.add_parser("review")
        review.add_argument("--owner", required=True, type=int)
        review.add_argument("--credential", required=True)
        review.add_argument("--credential-revision", required=True, type=int)
        review.add_argument("--zone-id", required=True)
        review.add_argument("--prefix-label", required=True)
        commit = sub.add_parser("commit")
        commit.add_argument("--owner", required=True, type=int)
        commit.add_argument("--review-id", required=True)
        inspect = sub.add_parser("inspect")
        inspect.add_argument("--owner", required=True, type=int)
        inspect.add_argument("--review-id", required=True)

    def handle(self, *args, **options):
        try:
            action = options["action"]
            if action == "review":
                result = bootstrap.review(
                    owner=options["owner"],
                    credential_id=options["credential"],
                    credential_revision=options["credential_revision"],
                    zone_id=options["zone_id"],
                    prefix_label=options["prefix_label"],
                )
            elif action == "commit":
                result = bootstrap.commit(owner=options["owner"],
                                          review_id=options["review_id"])
            else:
                result = bootstrap.inspect(owner=options["owner"],
                                           review_id=options["review_id"])
        except Exception as error:
            # Never return provider API responses, protected state or secrets.
            raise CommandError("Empty DNS controller bootstrap blocked: "
                               + getattr(error, "code", type(error).__name__)) from None
        self.stdout.write(json.dumps(result, sort_keys=True, separators=(",", ":")))
