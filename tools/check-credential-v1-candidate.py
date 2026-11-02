"""Source-only gate for the independently reviewed canonical credential v1 set.

This never upgrades the separately accepted October 22 publication manifest.
Exact source/consumer compatibility does not establish owner rights or authorize native installation,
publication, credential delivery, protected pins, or Host receipt signing.
"""
import hashlib
import json
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASE = "1a5eac0b255c995022db6a3a4c0051efffa748cc"
SOURCE = "4a176373ff4cb47a66a8ab1b5fd3d6ff01ff2a3b"
DISCOVERY_BASE = "0f2c6fd5cb33528ed2fe9fd1c855d2f691db6f80"
DISCOVERY_DEPENDENCY = "ed63d8df3cb733192c82b60dd95d13389b9922b5"
DISCOVERY_SOURCE = "4653cbffcef627dd8945dcb0d14deac5947e97fa"
INSTALL_BASE = "e6e474c63749a614fcf934d547d70b2bd12d7ce0"
INSTALL_PR_BASE = "17e3e0e6b9405a3a81dc25575ba2dadcf6bfa588"
INSTALL_SOURCE = "5c03d935be85622789b18559448e1560066d0a37"
SCHEMA = "zog-station-credential-v1-companion-candidate-v1"


def blob_hash(raw):
    return hashlib.sha1(b"blob " + str(len(raw)).encode("ascii")
                        + bytes([0]) + raw).hexdigest()


def inspect(root=ROOT, *, accepted=None, candidate=None, pyproject=None):
    root = Path(root)
    accepted_bytes = (root / "public-companion-pins.json").read_bytes()
    accepted = json.loads(accepted_bytes) if accepted is None else accepted
    candidate = (json.loads((root / "credential-v1-companion-candidate.json").read_text())
                 if candidate is None else candidate)
    pyproject = (tomllib.loads((root / "pyproject.toml").read_text())
                 if pyproject is None else pyproject)

    dependencies = accepted["dependencies"]
    matches = [entry for entry in dependencies
               if entry.get("repository") == "zog144/host-identify"]
    expected_top_provenance = {
        "license_blob_sha1": "e9ff0303fc483b30cee48e503f2c86e5b5b140e7",
        "bsd_license_blob_sha1": "7e1ffb223693647c1750e550d9fd7ee94ce4ee0b",
        "gpl_license_blob_sha1": "f6cdd22a6c1fbc887e08a215cb4beb3c47048041",
        "notices_blob_sha1": "c365eb11014ac8abeed28f67778b51c9588992c1",
        "pyproject_blob_sha1": "8c66720f40fa3c6796215f96a494d0edf30dbeae",
        "ancestry": "strict-descendant-of-accepted-baseline",
        "ahead_by": 5,
    }
    if (accepted.get("status") != "accepted" or len(matches) != 1
            or matches[0].get("commit") != BASE
            or candidate.get("schema") != SCHEMA
            or candidate.get("status") != "source-candidate-not-accepted"
            or candidate.get("repository") != "zog144/host-identify"
            or candidate.get("accepted_baseline_commit") != BASE
            or candidate.get("accepted_baseline_manifest") != "public-companion-pins.json"
            or candidate.get("accepted_baseline_manifest_blob") != blob_hash(accepted_bytes)
            or candidate.get("candidate_commit") != SOURCE
            or candidate.get("candidate_component_version") != "0.3.5"
            or candidate.get("canonical_module") != "zog.host_identify.credential_delivery"
            or candidate.get("rights_acceptance") != "pending-independent-owner-attestation"
            or candidate.get("consumer_acceptance") != "accepted"
            or candidate.get("source_reviewed_at") != "2026-11-01"
            or candidate.get("source_provenance") != expected_top_provenance
            or candidate.get("native_installation_approval") != "not-authorized"
            or candidate.get("publication_approval") != "not-authorized"
            or candidate.get("credential_delivery_approval") != "not-authorized"
            or "host-identify==0.3.5" not in pyproject["project"]["dependencies"]
            or "host-identify==0.3.4" in pyproject["project"]["dependencies"]):
        raise ValueError("HTTPS source candidate, rights review, or accepted provenance mismatch")

    needed = {
        "zog144/host-discover": {
            "old": DISCOVERY_BASE,
            "dependency": DISCOVERY_DEPENDENCY,
            "new": DISCOVERY_SOURCE,
            "version": "0.4.14",
            "provenance": {
                "license_blob_sha1": "ca56aaf8d8fe938ed915ce2fdb58650ce2721a97",
                "bsd_license_blob_sha1": "7e1ffb223693647c1750e550d9fd7ee94ce4ee0b",
                "gpl_license_blob_sha1": "f6cdd22a6c1fbc887e08a215cb4beb3c47048041",
                "notices_blob_sha1": "60264a9c522c3808ba687346ee816202862c6b5b",
                "pyproject_blob_sha1": "d1db218c669f3fdb30f81993635dbb52d4f10e00",
                "ancestry": "strict-descendant-of-accepted-baseline-and-dependency-candidate",
                "accepted_baseline_ahead_by": 18,
            },
        },
        "zog144/host-install": {
            "old": INSTALL_BASE,
            "pr_base": INSTALL_PR_BASE,
            "new": INSTALL_SOURCE,
            "version": "0.14.9",
            "provenance": {
                "license_blob_sha1": "1b04ccfebcecd431a15e03bd9ff376826c0856f6",
                "bsd_license_blob_sha1": "7e1ffb223693647c1750e550d9fd7ee94ce4ee0b",
                "gpl_license_blob_sha1": "f6cdd22a6c1fbc887e08a215cb4beb3c47048041",
                "notices_blob_sha1": "ac7c663f78201cba0f26c0f931e8f6c23e3714bf",
                "pyproject_blob_sha1": "660fab378d3341b16a7d81d51f685f48c02bf489",
                "ancestry": "strict-descendant-of-accepted-baseline-and-pr-base",
                "accepted_baseline_ahead_by": 183,
                "pr_base_ahead_by": 21,
            },
        },
    }
    other = candidate.get("additional_candidates")
    accepted_pins = {x["repository"]: x["commit"] for x in dependencies}
    if (type(other) is not list or len(other) != len(needed)
            or not all(type(entry) is dict for entry in other)
            or {x.get("repository") for x in other} != set(needed)):
        raise ValueError("Missing explicit compatible companion candidates")

    for entry in other:
        expected = needed[entry["repository"]]
        if (accepted_pins.get(entry["repository"]) != expected["old"]
                or entry.get("accepted_baseline_commit") != expected["old"]
                or entry.get("candidate_commit") != expected["new"]
                or entry.get("candidate_component_version") != expected["version"]
                or entry.get("rights_acceptance") != "pending-independent-owner-attestation"
                or entry.get("consumer_acceptance") != "accepted"
                or entry.get("native_installation_approval") != "not-authorized"
                or entry.get("source_provenance") != expected["provenance"]):
            raise ValueError("Dependent source candidate does not match exact reviewed chain")
        if entry["repository"] == "zog144/host-discover":
            if entry.get("dependency_candidate_commit") != expected["dependency"]:
                raise ValueError("host-discover dependency/profile ancestry is not exact")
        elif entry.get("pr_base_commit") != expected["pr_base"]:
            raise ValueError("host-install PR ancestry is not exact")
    return SOURCE


if __name__ == "__main__":
    inspect()
    print("Credential v1 consumer/source compatibility PASS; independent rights and native/publication/delivery PENDING")
