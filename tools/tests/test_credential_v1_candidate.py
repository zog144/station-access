"""Negative regression for reviewed credential-v1 source provenance."""
import copy
import importlib.util
import json
import tomllib
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "tools/check-credential-v1-candidate.py"
spec = importlib.util.spec_from_file_location("credential_v1_candidate_check", MODULE_PATH)
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)


class CredentialV1CandidateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.accepted = json.loads((ROOT / "public-companion-pins.json").read_text())
        cls.candidate = json.loads((ROOT / "credential-v1-companion-candidate.json").read_text())
        cls.pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text())

    def validate(self, **changes):
        candidate = copy.deepcopy(self.candidate)
        project = copy.deepcopy(self.pyproject)
        accepted = copy.deepcopy(self.accepted)
        candidate.update(changes.pop("candidate", {}))
        project.update(changes.pop("pyproject", {}))
        accepted.update(changes.pop("accepted", {}))
        self.assertFalse(changes)
        return checker.inspect(ROOT, accepted=accepted, candidate=candidate,
                               pyproject=project)

    def component(self, repository, candidate=None):
        value = self.candidate if candidate is None else candidate
        return next(x for x in value["additional_candidates"]
                    if x["repository"] == repository)

    def test_exact_reviewed_source_set_and_unchanged_accepted_baseline(self):
        self.assertEqual(self.validate(), checker.SOURCE)
        self.assertNotEqual(checker.BASE, checker.SOURCE)
        self.assertEqual(self.candidate["rights_acceptance"], "pending-independent-owner-attestation")
        self.assertEqual(self.candidate["consumer_acceptance"], "accepted")
        self.assertEqual(
            self.component("zog144/host-discover")["candidate_commit"],
            checker.DISCOVERY_SOURCE)
        self.assertEqual(
            self.component("zog144/host-install")["candidate_commit"],
            checker.INSTALL_SOURCE)

    def test_native_publication_or_delivery_approval_is_still_rejected(self):
        for change in (
            {"status": "accepted"},
            {"rights_acceptance": "accepted"},
            {"consumer_acceptance": "pending-independent-review"},
            {"native_installation_approval": "approved"},
            {"publication_approval": "approved"},
            {"credential_delivery_approval": "approved"},
            {"candidate_commit": checker.BASE},
            {"candidate_commit": "0" * 40},
            {"accepted_baseline_commit": checker.SOURCE},
            {"accepted_baseline_manifest_blob": "0" * 40},
            {"candidate_component_version": "0.3.4"},
        ):
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.validate(candidate=change)

    def test_reviewed_component_versions_rights_and_provenance_are_exact(self):
        for repository, bad_version in (
            ("zog144/host-discover", "0.4.13"),
            ("zog144/host-install", "0.14.3"),
        ):
            amended = copy.deepcopy(self.candidate)
            self.component(repository, amended)["candidate_component_version"] = bad_version
            with self.subTest(repository=repository), self.assertRaises(ValueError):
                self.validate(candidate=amended)

        for repository in ("zog144/host-discover", "zog144/host-install"):
            for field, value in (
                ("rights_acceptance", "accepted"),
                ("consumer_acceptance", "pending-independent-review"),
            ):
                amended = copy.deepcopy(self.candidate)
                self.component(repository, amended)[field] = value
                with self.subTest(repository=repository, field=field), self.assertRaises(ValueError):
                    self.validate(candidate=amended)

            amended = copy.deepcopy(self.candidate)
            self.component(repository, amended)["source_provenance"]["license_blob_sha1"] = "0" * 40
            with self.subTest(repository=repository, field="license_blob_sha1"), self.assertRaises(ValueError):
                self.validate(candidate=amended)

    def test_host_discover_dependency_parent_and_host_install_pr_base_are_required(self):
        discover = self.component("zog144/host-discover")
        install = self.component("zog144/host-install")
        self.assertEqual(discover["dependency_candidate_commit"], checker.DISCOVERY_DEPENDENCY)
        self.assertEqual(install["pr_base_commit"], checker.INSTALL_PR_BASE)

        for repository, patch in (
            ("zog144/host-discover", {"candidate_commit": checker.DISCOVERY_DEPENDENCY}),
            ("zog144/host-discover", {"dependency_candidate_commit": "0" * 40}),
            ("zog144/host-install", {"candidate_commit": "6e8b3792c6bc43e6b55dd254892105f7abea5a29"}),
            ("zog144/host-install", {"pr_base_commit": "0" * 40}),
        ):
            modified = copy.deepcopy(self.candidate)
            self.component(repository, modified).update(patch)
            with self.subTest(repository=repository, patch=patch), self.assertRaises(ValueError):
                self.validate(candidate=modified)

    def test_runtime_pin_rollback_and_accepted_manifest_rewrite_rejected(self):
        invalid = copy.deepcopy(self.pyproject)
        invalid["project"]["dependencies"] = [
            "host-identify==0.3.4" if x == "host-identify==0.3.5" else x
            for x in invalid["project"]["dependencies"]]
        with self.assertRaises(ValueError):
            self.validate(pyproject=invalid)
        modified = copy.deepcopy(self.accepted)
        next(x for x in modified["dependencies"]
             if x["repository"] == "zog144/host-identify")["commit"] = checker.SOURCE
        with self.assertRaises(ValueError):
            self.validate(accepted=modified)

    def test_full_ci_verifies_exact_reviewed_source_and_pip_metadata(self):
        text = (ROOT / ".github/workflows/test.yml").read_text()
        for required in (
            'credential-v1-companion-candidate.json',
            checker.SOURCE,
            checker.DISCOVERY_SOURCE,
            checker.INSTALL_SOURCE,
            'host-identify==0.3.5',
            'host-install==0.14.9',
            'importlib.metadata.version("host-identify") == "0.3.5"',
            'importlib.metadata.version("host-discover") == "0.4.14"',
            'importlib.metadata.version("host-install") == "0.14.9"',
            'zog-credential-delivery-envelope-v1',
        ):
            self.assertIn(required, text)


if __name__ == "__main__":
    unittest.main()
