"""Explicit root-only systemd AF_UNIX socket activation; no network bind."""
import os
import socket
from django.conf import settings
from django.core.management.base import BaseCommand, CommandError


class Command(BaseCommand):
    help = "Serve native-gated canonical HTTPS credential broker from socket fd 3"

    def handle(self, *args, **options):
        from zog.station_access.host_registry.credential_v1_broker import (
            check_listener, serve_once)
        if (os.geteuid() != 0
                or not getattr(settings, "HOST_CREDENTIAL_V1_BROKER_ENABLED", False)
                or not getattr(settings, "HOST_CREDENTIAL_V1_LIVE_ENABLED", False)
                or os.environ.get("LISTEN_PID") != str(os.getpid())
                or os.environ.get("LISTEN_FDS") != "1"):
            raise CommandError("Credential authority native gate unavailable")
        listener = socket.fromfd(3, socket.AF_UNIX, socket.SOCK_STREAM)
        path = getattr(settings, "HOST_CREDENTIAL_V1_BROKER_BOUND_PATH", "")
        try:
            check_listener(listener, path)
        except Exception:
            raise CommandError("Protected broker socket invalid") from None
        while True:
            serve_once(listener)
