"""Installed-only WSGI entry point; not a Django URL or browser API."""
from zog.station_access.credential_v1_https_ingress import application

__all__ = ["application"]
