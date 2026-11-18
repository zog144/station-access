"""Explicit review / approved commit / read-only inspect of an old DNS lock."""
import json
from django.core.management.base import BaseCommand, CommandError
from zog.station_access.host_registry import dns_lock_adoption as adoption


class Command(BaseCommand):
    help = "Adopt a preexisting unbound DNS lock; never creates or replaces it"

    def add_arguments(self, parser):
        actions = parser.add_subparsers(dest="action", required=True)
        review = actions.add_parser("review")
        review.add_argument("--owner", required=True, type=int)
        for name in ("commit", "inspect"):
            part = actions.add_parser(name)
            part.add_argument("--owner", required=True, type=int)
            part.add_argument("--review-id", required=True)

    def handle(self, *args, **options):
        try:
            fn = getattr(adoption, options["action"])
            args = {"owner": options["owner"]}
            if options["action"] != "review":
                args["review_id"] = options["review_id"]
            result = fn(**args)
        except Exception as error:
            raise CommandError("DNS lock adoption blocked: "
                               + getattr(error, "code", type(error).__name__)) from None
        self.stdout.write(json.dumps(result, sort_keys=True, separators=(",", ":")))
