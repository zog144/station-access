"""Negative regression for accepted-baseline versus candidate host-identify pin."""
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

    def test_exact_035_candidate_and_unchanged_034_baseline(self):
        self.assertEqual(self.validate(), checker.SOURCE)
        self.assertNotEqual(checker.BASE, checker.SOURCE)

    def test_forged_acceptance_and_old_source_rejected(self):
        for change in (
            {"status":"accepted"}, {"rights_acceptance":"accepted"},
            {"consumer_acceptance":"accepted"}, {"native_installation_approval":"approved"},
            {"publication_approval":"approved"}, {"credential_delivery_approval":"approved"},
            {"candidate_commit":checker.BASE},
            {"candidate_commit":"0"*40},
            {"accepted_baseline_commit":checker.SOURCE},
            {"accepted_baseline_manifest_blob":"0"*40},
            {"candidate_component_version":"0.3.4"}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.validate(candidate=change)

    def test_incompatible_host_discover_and_host_install_candidate_rejected(self):
        for repository, bad_version in (
            ("zog144/host-discover", "0.4.9"),
            ("zog144/host-install", "0.10.0")):
            amended = copy.deepcopy(self.candidate)
            next(x for x in amended["additional_candidates"]
                 if x["repository"] == repository)["candidate_component_version"] = bad_version
            with self.subTest(repository=repository), self.assertRaises(ValueError):
                self.validate(candidate=amended)
        for repository in ("zog144/host-discover", "zog144/host-install"):
            amended = copy.deepcopy(self.candidate)
            next(x for x in amended["additional_candidates"]
                 if x["repository"] == repository)["rights_acceptance"] = "accepted"
            with self.subTest(repository=repository), self.assertRaises(ValueError):
                self.validate(candidate=amended)

    def test_host_install_corrected_immutable_commit_and_parent_are_required(self):
        host_install = next(entry for entry in self.candidate["additional_candidates"]
                            if entry["repository"] == "zog144/host-install")
        self.assertEqual(host_install["candidate_commit"],
                         "6e8b3792c6bc43e6b55dd254892105f7abea5a29")
        self.assertEqual(host_install["correction_parent"],
                         "79ad2b6f72c89acfca998d393664151010db7134")
        for patch in (
            {"candidate_commit": host_install["correction_parent"]},
            {"candidate_commit": "0" * 40},
            {"correction_parent": "0" * 40},
        ):
            with self.subTest(patch=patch), self.assertRaises(ValueError):
                modified = copy.deepcopy(self.candidate)
                next(x for x in modified["additional_candidates"]
                     if x["repository"] == "zog144/host-install").update(patch)
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

    def test_full_ci_verifies_exact_source_and_pip_metadata(self):
        text = (ROOT / ".github/workflows/test.yml").read_text()
        for required in (
            'credential-v1-companion-candidate.json',
            checker.SOURCE,
            "6e8b3792c6bc43e6b55dd254892105f7abea5a29",
            'host-identify==0.3.5',
            'importlib.metadata.version("host-identify") == "0.3.5"',
            'zog-credential-delivery-envelope-v1'):
            self.assertIn(required, text)


if __name__ == "__main__":
    unittest.main()
