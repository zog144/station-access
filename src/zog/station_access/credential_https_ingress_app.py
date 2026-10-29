"""WSGI entry point for independently isolated nginx / HTTPS routing.

Run only in a dedicated UID with no station Django environment, no vault
mounts, and a private nginx socket. Browser/Django routes never import it.
"""
from zog.station_access.credential_https_ingress import application

__all__ = ["application"]
