"""Exercise the actual production module launch route as an OS subprocess.

This deliberately does not import cli.main: specification parsing alone failed
to detect a missing `python -m zog.station_access.cli` module entry.
"""
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
from urllib.request import urlopen

SOURCE = Path(__file__).resolve().parents[2] / "src"
MODULE = ("-m", "zog.station_access.cli")


class ProductionModuleLaunchTests(unittest.TestCase):
    def environment(self, state, frontend=None):
        env = os.environ.copy()
        env["PYTHONPATH"] = str(SOURCE) + os.pathsep + env.get("PYTHONPATH", "")
        env["STATION_ACCESS_STATE_DIRECTORY"] = str(state)
        env["DJANGO_SETTINGS_MODULE"] = "zog.station_access.project.settings"
        env["STATION_ACCESS_DEBUG"] = "0"
        env["STATION_ACCESS_ALLOWED_HOSTS"] = "localhost,127.0.0.1"
        if frontend is not None:
            env["STATION_ACCESS_FRONTEND_DIRECTORY"] = str(frontend)
            env.pop("STATION_ACCESS_FRONTEND_INSTALLATION", None)
        return env

    def command(self, *args):
        return [sys.executable, *MODULE, *args]

    def test_help_runs_main_without_initializing_state(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "not-created"
            result = subprocess.run(self.command("--help"), env=self.environment(state),
                                    text=True, capture_output=True, timeout=15)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("usage:", result.stdout.lower())
            self.assertIn("--initialize-only", result.stdout)
            self.assertFalse(state.exists())

    def test_initialize_only_creates_disposable_state(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "station-state"
            result = subprocess.run(
                self.command("--host", "127.0.0.1", "--port", "8000",
                             "--state-directory", str(state), "--initialize-only"),
                env=self.environment(state), text=True, capture_output=True, timeout=90)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue((state / "station-access.sqlite3").is_file())
            secrets = json.loads((state / "deployment-secrets.json").read_text())
            self.assertTrue(secrets["django_secret_key"])
            self.assertTrue(secrets["websockify_secret"])

    def test_serving_route_stays_running_and_answers_http(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state, frontend = root / "state", root / "frontend"
            frontend.mkdir()
            (frontend / "index.html").write_text("<!doctype html><title>Station test</title>")
            # A disposable ephemeral port is never an authorization to bind a
            # production listener. This test runs on local loopback only.
            with socket.socket() as reserve:
                reserve.bind(("127.0.0.1", 0))
                port = reserve.getsockname()[1]
            process = subprocess.Popen(
                self.command("--host", "127.0.0.1", "--port", str(port),
                             "--state-directory", str(state)),
                env=self.environment(state, frontend), stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, text=True)
            try:
                deadline = time.monotonic() + 90
                observed = False
                while time.monotonic() < deadline:
                    if process.poll() is not None:
                        stdout, stderr = process.communicate(timeout=5)
                        self.fail(f"station exited before serving: {process.returncode}: {stdout} {stderr}")
                    try:
                        with urlopen(f"http://127.0.0.1:{port}/api/login/", timeout=1) as response:
                            self.assertIn(response.status, (200, 405))
                            observed = True
                            break
                    except HTTPError as response:
                        # Method denial is still a live Django HTTP response.
                        self.assertIn(response.code, (400, 403, 405))
                        observed = True
                        break
                    except (URLError, TimeoutError, ConnectionError):
                        time.sleep(0.2)
                self.assertTrue(observed, "station did not answer HTTP before deadline")
                self.assertIsNone(process.poll(), "station did not remain serving")
            finally:
                process.terminate()
                try:
                    process.communicate(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.communicate(timeout=5)
