"""Source-only gate for proposed host-identify 0.3.5 companion adoption.

This never upgrades the separately accepted October 22 companion manifest.
Neither source test nor a successful candidate run authorizes installation.
"""
import hashlib
import json
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASE = "1a5eac0b255c995022db6a3a4c0051efffa748cc"
SOURCE = "4a176373ff4cb47a66a8ab1b5fd3d6ff01ff2a3b"
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
            or candidate.get("rights_acceptance") != "pending-independent-review"
            or candidate.get("consumer_acceptance") != "pending-independent-review"
            or candidate.get("native_installation_approval") != "not-authorized"
            or candidate.get("publication_approval") != "not-authorized"
            or candidate.get("credential_delivery_approval") != "not-authorized"
            or "host-identify==0.3.5" not in pyproject["project"]["dependencies"]
            or "host-identify==0.3.4" in pyproject["project"]["dependencies"]):
        raise ValueError("HTTPS dependency candidate or accepted provenance mismatch")
    other = candidate.get("additional_candidates")
    needed = {
        "zog144/host-discover": {
            "old": "0f2c6fd5cb33528ed2fe9fd1c855d2f691db6f80",
            "new": "ebe83775e9099fd406f6ad9213a42b25bade5b13",
            "version": "0.4.13",
        },
        "zog144/host-install": {
            "old": "e6e474c63749a614fcf934d547d70b2bd12d7ce0",
            "new": "79ad2b6f72c89acfca998d393664151010db7134",
            "version": "0.14.3",
        },
    }
    accepted_pins = {x["repository"]: x["commit"]
                     for x in dependencies}
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
                or entry.get("rights_acceptance") != "pending-independent-review"
                or entry.get("consumer_acceptance") != "pending-independent-review"
                or entry.get("native_installation_approval") != "not-authorized"):
            raise ValueError("Dependent source candidate does not match exact version chain")
    return SOURCE


if __name__ == "__main__":
    inspect()
    print("Source-only HTTPS companion candidate consistent; native and publication NO-GO")
