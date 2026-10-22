"""Fixture-only HTTPS reverse proxy, CSRF and cookie checks.

This does not attest TLS certificates or an nginx deployment. Only trusted
nginx is permitted to overwrite the forwarded-proto header in production.
"""
import json

from django.contrib.auth import get_user_model
from django.test import Client, RequestFactory, TestCase, override_settings


ORIGIN = "https://portal.example.test:8443"
HOST = "portal.example.test:8443"
PROXY = {"HTTP_HOST": HOST, "HTTP_X_FORWARDED_PROTO": "https"}


@override_settings(
    ALLOWED_HOSTS=["portal.example.test"],
    CSRF_TRUSTED_ORIGINS=[ORIGIN],
    SESSION_COOKIE_SECURE=True,
    CSRF_COOKIE_SECURE=True,
    SECURE_PROXY_SSL_HEADER=("HTTP_X_FORWARDED_PROTO", "https"),
)
class ProductionProxySecurityTests(TestCase):
    def setUp(self):
        get_user_model().objects.create_superuser(
            username="proxy-admin", email="", password="fixture-secret-only")

    def test_trusted_https_origin_authenticates_with_secure_csrf_session_cookies(self):
        client = Client(enforce_csrf_checks=True)
        session = client.get("/api/session/", **PROXY)
        self.assertEqual(session.status_code, 200)
        self.assertTrue(session.cookies["csrftoken"]["secure"])
        self.assertFalse(session.json()["authenticated"])
        token = session.cookies["csrftoken"].value
        response = client.post(
            "/api/login/", data=json.dumps({
                "username": "proxy-admin", "password": "fixture-secret-only"
            }), content_type="application/json",
            HTTP_ORIGIN=ORIGIN, HTTP_X_CSRFTOKEN=token, **PROXY)
        self.assertEqual(response.status_code, 200, response.content[:256])
        self.assertTrue(response.json()["authenticated"])
        self.assertTrue(response.cookies["sessionid"]["secure"])
        response = client.get("/api/session/", **PROXY)
        self.assertTrue(response.json()["authenticated"])
        # Django rotates the CSRF token after successful authentication.
        token = client.cookies["csrftoken"].value
        logout = client.post("/api/logout/", data=b"{}",
                             content_type="application/json",
                             HTTP_ORIGIN=ORIGIN, HTTP_X_CSRFTOKEN=token, **PROXY)
        self.assertEqual(logout.status_code, 200)
        self.assertFalse(logout.json()["authenticated"])

    def test_foreign_origin_denied_before_login_or_session(self):
        client = Client(enforce_csrf_checks=True)
        session = client.get("/api/session/", **PROXY)
        token = session.cookies["csrftoken"].value
        response = client.post(
            "/api/login/", data=json.dumps({
                "username": "proxy-admin", "password": "fixture-secret-only"
            }), content_type="application/json",
            HTTP_ORIGIN="https://foreign.example.test",
            HTTP_X_CSRFTOKEN=token, **PROXY)
        self.assertEqual(response.status_code, 403)
        self.assertFalse(client.get("/api/session/", **PROXY).json()["authenticated"])

    def test_only_exact_proxy_https_protocol_is_trusted(self):
        factory = RequestFactory()
        secure = factory.get("/api/session/", **PROXY)
        plain = factory.get("/api/session/", HTTP_HOST=HOST,
                            HTTP_X_FORWARDED_PROTO="http")
        self.assertTrue(secure.is_secure())
        self.assertFalse(plain.is_secure())
