"""Exercise retained administrator login after the real offline two-store migration.

Source-only test: disposable SQLite, archive catalogue and loopback Waitress.
No host grants, root-control identity provisioning, nginx or production files.
"""
from contextlib import contextmanager
from http.cookiejar import CookieJar
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from urllib.error import HTTPError, URLError
from urllib.request import Request, build_opener, HTTPCookieProcessor

from zog.box_control.specification import parse_application
from zog.station_access.state_migration import migrate
from tests.station_access.test_state_migration import make_catalogue

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "src"
TEMPLATE = ROOT / "integration/production/station-access/application.py"
USERNAME = "retained-admin"
PASSWORD = "disposable-regression-password-only"


def _environment(state, frontend=None):
    env = os.environ.copy()
    env["PYTHONPATH"] = os.pathsep.join(filter(None, (str(SOURCE), str(ROOT),
                                                       env.get("PYTHONPATH", ""))))
    env["DJANGO_SETTINGS_MODULE"] = "zog.station_access.project.settings"
    env["STATION_ACCESS_STATE_DIRECTORY"] = str(state)
    env["STATION_ACCESS_DEBUG"] = "0"
    env["STATION_ACCESS_ALLOWED_HOSTS"] = "127.0.0.1,localhost"
    env.pop("STATION_ACCESS_FRONTEND_INSTALLATION", None)
    env.pop("ARCHIVE_MIRROR_CONFIGURATION", None)
    if frontend is not None:
        env["STATION_ACCESS_FRONTEND_DIRECTORY"] = str(frontend)
    return env


def _command(state, *, port, initialize_only=False):
    spec = parse_application(TEMPLATE)
    assert spec.execution_identity == "application"
    web = spec.programs[0]
    command = web.command
    assert command[:3] == ("/usr/bin/python3", "-m", "zog.station_access.cli")
    assert command[3:] == (
        "--host", "127.0.0.1", "--port", "8000",
        "--state-directory", "/var/lib/station-access",
    )
    # Only executable location, loopback port and writable mount prefix are
    # rebound for the temporary test. Preserve actual -m entry and arguments.
    args = [sys.executable, *command[1:]]
    args[args.index("--port") + 1] = str(port)
    args[args.index("--state-directory") + 1] = str(state)
    if initialize_only:
        args.append("--initialize-only")
    return args


def _port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@contextmanager
def _server(state, frontend, port):
    process = subprocess.Popen(
        _command(state, port=port),
        env=_environment(state, frontend), stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, text=True,
    )
    try:
        deadline = time.monotonic() + 90
        ready = False
        while time.monotonic() < deadline:
            if process.poll() is not None:
                stdout, stderr = process.communicate(timeout=5)
                raise AssertionError(
                    f"station production module exited before HTTP readiness: "
                    f"{process.returncode}, {stdout[-1000:]}, {stderr[-1000:]}"
                )
            try:
                with build_opener().open(f"http://127.0.0.1:{port}/api/session/",
                                         timeout=1) as response:
                    if response.status == 200:
                        ready = True
                        break
            except (URLError, TimeoutError, ConnectionError):
                time.sleep(0.2)
        if not ready:
            raise AssertionError("migrated station service did not answer HTTP")
        if process.poll() is not None:
            raise AssertionError("station service did not remain running")
        yield
    finally:
        if process.poll() is None:
            process.terminate()
        try:
            process.communicate(timeout=15)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate(timeout=5)


class MigratedLoginHTTPTests(unittest.TestCase):
    def test_migrated_sqlite_secret_and_existing_admin_survive_real_http(self):
        with tempfile.TemporaryDirectory(prefix="station-migrated-login-") as temp:
            root = Path(temp)
            old_state, archive = root / "legacy-station", root / "legacy-archive"
            station, archive_data = root / "station-data", root / "archive-data"
            frontend = root / "frontend"
            archive.mkdir(mode=0o700)
            (archive / "objects").mkdir(mode=0o700)
            station.mkdir(mode=0o700)
            archive_data.mkdir(mode=0o700)
            frontend.mkdir()
            (frontend / "index.html").write_text("<!doctype html><title>Station fixture</title>")

            initialization = subprocess.run(
                _command(old_state, port=_port(), initialize_only=True),
                env=_environment(old_state), text=True, capture_output=True,
                timeout=90,
            )
            self.assertEqual(initialization.returncode, 0, initialization.stderr)
            database = old_state / "station-access.sqlite3"
            self.assertTrue(database.is_file())
            original_secret = (old_state / "deployment-secrets.json").read_bytes()
            self.assertTrue(original_secret)

            # The original password hash is created by Django, not by a
            # hand-made, incompatible auth_user schema.
            create_user = subprocess.run(
                [sys.executable, "-c", (
                    "import django; django.setup();"
                    "from django.contrib.auth import get_user_model;"
                    "get_user_model().objects.create_superuser("
                    f"username={USERNAME!r}, email='fixture@example.invalid',"
                    f"password={PASSWORD!r})"
                )],
                env=_environment(old_state), text=True, capture_output=True,
                timeout=60,
            )
            self.assertEqual(create_user.returncode, 0, create_user.stderr)

            object_bytes = b"frozen archive store fixture for retained station"
            import hashlib
            digest = hashlib.sha256(object_bytes).hexdigest()
            (archive / "objects" / digest).write_bytes(object_bytes)
            make_catalogue(archive / "catalogue.sqlite3", digest, len(object_bytes))

            report = migrate(
                station_source=str(old_state), archive_source=str(archive),
                station_destination=str(station), archive_destination=str(archive_data),
                station_storage_id="a" * 32, archive_storage_id="b" * 32,
                checkpoint_confirmed=True,
            )
            self.assertEqual(report["state"], "complete")
            self.assertEqual(report["station_sqlite_integrity"], "ok")
            self.assertEqual((station / "deployment-secrets.json").read_bytes(),
                             original_secret)
            self.assertEqual((station / "station-access.sqlite3").stat().st_mode & 0o777,
                             0o600)
            self.assertEqual((archive_data / "store/objects" / digest).read_bytes(),
                             object_bytes)

            cookies = CookieJar()
            opener = build_opener(HTTPCookieProcessor(cookies))
            first_port = _port()
            with _server(station, frontend, first_port):
                base = f"http://127.0.0.1:{first_port}"
                with opener.open(base + "/api/session/", timeout=5) as response:
                    self.assertFalse(json.load(response)["authenticated"])
                csrf = next(cookie.value for cookie in cookies if cookie.name == "csrftoken")

                def authenticate(password):
                    return Request(
                        base + "/api/login/",
                        data=json.dumps({"username": USERNAME,
                                         "password": password}).encode(),
                        headers={"Content-Type": "application/json",
                                 "X-CSRFToken": csrf},
                        method="POST",
                    )

                with self.assertRaises(HTTPError) as denied:
                    opener.open(authenticate("invalid-password"), timeout=5)
                self.assertEqual(denied.exception.code, 401)
                with opener.open(authenticate(PASSWORD), timeout=5) as response:
                    data = json.load(response)
                    self.assertTrue(data["authenticated"])
                    self.assertEqual(data["user"]["username"], USERNAME)
                    self.assertTrue(data["user"]["is_superuser"])
                with opener.open(base + "/api/session/", timeout=5) as response:
                    self.assertTrue(json.load(response)["authenticated"])
            self.assertEqual((station / "deployment-secrets.json").read_bytes(),
                             original_secret)

            # Restart the real server using the *same* migrated state and
            # secret. The existing authenticated browser session must persist.
            second_port = _port()
            with _server(station, frontend, second_port):
                with opener.open(f"http://127.0.0.1:{second_port}/api/session/",
                                 timeout=5) as response:
                    self.assertTrue(json.load(response)["authenticated"])
            self.assertEqual((station / "deployment-secrets.json").read_bytes(),
                             original_secret)
