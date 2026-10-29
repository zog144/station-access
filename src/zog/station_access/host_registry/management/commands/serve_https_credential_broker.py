"""Privileged, systemd-socket-activated *local-only* credential broker."""
import os
import socket
from django.core.management.base import BaseCommand, CommandError


class Command(BaseCommand):
    help = "Serve disabled-by-default HTTPS credential admission on protected AF_UNIX"

    def handle(self, *args, **options):
        from django.conf import settings
        from zog.station_access.host_registry.credential_https_authority import serve_once
        if os.geteuid() != 0:
            raise CommandError("Protected local broker requires root service identity")
        if not getattr(settings, "HOST_CREDENTIAL_HTTPS_BROKER_ENABLED", False):
            raise CommandError("Protected local broker not enabled")
        if int(os.environ.get("LISTEN_FDS", "0")) != 1 or int(
                os.environ.get("LISTEN_PID", "0")) != os.getpid():
            raise CommandError("Expected exactly one inherited systemd socket")
        listener = socket.fromfd(3, socket.AF_UNIX, socket.SOCK_STREAM)
        if listener.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) != socket.SOCK_STREAM:
            raise CommandError("Invalid protected socket")
        while True:
            serve_once(listener)
