"""Local operator-only Workspace API grant management; never an agent endpoint."""
from datetime import timedelta
from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone
from zog.station_access.services.agent_credentials import issue_grant, revoke_grant, SCOPES


class Command(BaseCommand):
    help = "Issue/revoke scoped read-only Workspace API credentials; printed only once"

    def add_arguments(self, parser):
        sub = parser.add_subparsers(dest="action", required=True)
        issue = sub.add_parser("issue")
        who = issue.add_mutually_exclusive_group(required=True)
        who.add_argument("--username")
        who.add_argument("--service")
        issue.add_argument("--workspace", action="append", required=True, help="UUID; repeat to grant more")
        issue.add_argument("--scope", action="append", choices=sorted(SCOPES), required=True)
        issue.add_argument("--hours", type=int, default=24)
        revoke = sub.add_parser("revoke")
        revoke.add_argument("grant_id")

    def handle(self, *args, **options):
        if options["action"] == "revoke":
            try:
                count = revoke_grant(options["grant_id"])
            except (TypeError, ValueError) as exc:
                raise CommandError("Invalid grant ID") from exc
            if not count:
                raise CommandError("Grant not found or already revoked")
            self.stdout.write("Revoked")
            return
        if not 1 <= options["hours"] <= 720:
            raise CommandError("Grant lifetime must be between 1 and 720 hours")
        user = None
        if options.get("username"):
            user = get_user_model().objects.filter(username=options["username"]).first()
            if user is None:
                raise CommandError("Unknown user")
        try:
            grant, token = issue_grant(
                user=user, service_name=options.get("service") or "",
                workspace_ids=options["workspace"], scopes=options["scope"],
                expires_at=timezone.now() + timedelta(hours=options["hours"]),
            )
        except ValueError as exc:
            raise CommandError(str(exc)) from exc
        self.stdout.write(f"Grant ID: {grant.pk}")
        self.stdout.write(f"Expires: {grant.expires_at.isoformat()}")
        self.stdout.write("One-time bearer credential (do not log/store in Git):")
        self.stdout.write(token)
