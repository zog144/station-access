"""Systemd socket-activated, vault-identity-only secret reader."""
from django.core.management.base import BaseCommand

class Command(BaseCommand):
    help = "Serve authenticated local issuer-only Cloudflare token requests"

    def handle(self, *args, **kwargs):
        from zog.station_access.host_registry.issuer_cloudflare_reader import _listener, serve_once
        listener = _listener()
        while True:
            serve_once(listener)
