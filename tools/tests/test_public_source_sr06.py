"""SR-06 source publication: legacy identity and systemd timers never install."""
import importlib.util
import shutil
import sys
import tempfile
from pathlib import Path
import subprocess
import unittest


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "station_publication_boundary", ROOT / "tools/check-public-source.py")
boundary = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(boundary)


class SR06PublicationTests(unittest.TestCase):
    def test_current_checkout_quarantines_legacy_and_preserves_singleton_grant(self):
        tracked = set(subprocess.check_output(
            ["git", "-C", str(ROOT), "ls-files", "-z"]).decode().strip("\0").split("\0"))
        self.assertFalse(boundary.inspect_sr06(tracked))
        self.assertFalse(boundary.inspect(tracked))

    def test_legacy_paths_fail_closed_if_reintroduced(self):
        tracked = set(boundary.QUARANTINED_SR06) | {boundary.WEB_COMPOSITION, boundary.LEGACY_INSTALL_GUIDE,
                 "docs/station-access/legacy/noninstallable/README.md"}
        for original in (
            "integration/application.py",
            "deployment/deployment-jobs/station-deployment-jobs.service",
            "deployment/deployment-jobs/station-deployment-jobs.timer",
            "deployment/host-dns/host-dns-reconcile.service",
            "deployment/host-dns/host-dns-reconcile.timer",
        ):
            with self.subTest(original=original):
                problems = boundary.inspect_sr06(tracked | {original})
                self.assertIn((original, "sr06-unsafe-deployable-legacy-identity"), problems)

    def test_symbolic_singleton_grant_cannot_apply_to_nonpersistent_desktop(self):
        legacy = (ROOT / "docs/station-access/legacy/noninstallable/vnc-application.py.txt").read_text()
        self.assertTrue(boundary._check_legacy_vnc(legacy))
        # Merely dropping the named user and adding a singleton application
        # grant to a multi-instance desktop must fail the guard.
        unbound = legacy.replace('        user="regular",\n', "")
        attempted = unbound.replace('    multiple_instances=True,\n',
                                    '    multiple_instances=True,\n    execution_identity="application",\n')
        self.assertFalse(boundary._check_legacy_vnc(attempted))
        self.assertFalse(boundary._check_production_template(attempted))
        self.assertFalse(boundary._check_production_template(legacy))
        self.assertTrue(boundary._check_production_template(
            (ROOT / boundary.WEB_COMPOSITION).read_text()))

    def test_wheel_metadata_cannot_install_legacy_deployment_data(self):
        pyproject = (ROOT / "pyproject.toml").read_text()
        self.assertTrue(boundary._check_wheel_source_scope(pyproject))
        malicious = pyproject + """
[tool.setuptools.data-files]
"systemd/system" = ["docs/station-access/legacy/noninstallable/host-dns-reconcile.timer.txt"]
"""
        self.assertFalse(boundary._check_wheel_source_scope(malicious))


    def _namespace_fixture(self, root):
        """Run the real namespace checker against a minimal, safe source layout."""
        (root / "tools").mkdir(parents=True)
        shutil.copyfile(ROOT / "tools/check-python-namespace.py",
                        root / "tools/check-python-namespace.py")
        pkg = root / "src/zog/station_access"
        (pkg / "host_registry/fixtures").mkdir(parents=True)
        (pkg / "__init__.py").write_text("")
        (pkg / "cli.py").write_text("")
        (pkg / "host_registry/fixtures/managed-state.json").write_text("{}")
        (root / "frontend").mkdir()
        (root / "frontend/toolchain.json").write_text("{}")
        production = root / boundary.WEB_COMPOSITION
        production.parent.mkdir(parents=True)
        production.write_bytes((ROOT / boundary.WEB_COMPOSITION).read_bytes())
        (root / "pyproject.toml").write_text(chr(10).join((
            '[project.scripts]',
            'station-access = "zog.station_access.cli:main"',
            '[tool.setuptools.packages.find]',
            'where = ["src"]',
            'include = ["zog.station_access*"]',
        )) + chr(10))
        return production

    def _run_namespace(self, root):
        return subprocess.run(
            [sys.executable, str(root / "tools/check-python-namespace.py")],
            cwd=root, text=True, capture_output=True, check=False)

    def test_namespace_checker_accepts_quarantine_and_rejects_legacy_reintroduction(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            production = self._namespace_fixture(root)
            result = self._run_namespace(root)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("namespace/layout contract: OK", result.stdout)
            self.assertFalse((root / "integration/application.py").exists())
            legacy = root / "integration/application.py"
            legacy.write_text('application(name="legacy")' + chr(10))
            result = self._run_namespace(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("quarantined VNC declaration", result.stderr)
            legacy.unlink()
            production.unlink()
            result = self._run_namespace(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("maintained station production declaration is missing", result.stderr)

    def test_namespace_checker_rejects_invalid_production_grants(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            production = self._namespace_fixture(root)
            valid = production.read_text()
            self.assertIn('execution_identity="application"', valid)
            for changed in (
                valid.replace('execution_identity="application"', 'execution_identity="legacy"'),
                valid.replace('multiple_instances=False', 'multiple_instances=True'),
                valid.replace('persistent=True', 'persistent=False'),
                valid.replace('name="web",', 'name="web", user="regular",'),
            ):
                with self.subTest(changed=changed[-100:]):
                    production.write_text(changed)
                    result = self._run_namespace(root)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("production identity declaration is invalid", result.stderr)
            production.write_text(valid)
            result = self._run_namespace(root)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_quarantine_bytes_remain_exact_historical_blobs(self):
        for path, sha in boundary.QUARANTINED_SR06.items():
            with self.subTest(path=path):
                self.assertTrue(path.endswith(".txt"))
                self.assertEqual(boundary._blob_sha((ROOT / path).read_bytes()), sha)


if __name__ == "__main__":
    unittest.main()
