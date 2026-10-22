"""Validate published tool-serve HTTP fixtures against JSON Schema 2020-12."""
from pathlib import Path
import json
import unittest

from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = ROOT / "docs" / "station-access" / "contracts" / "workspace-agent-v1.schema.json"
FIXTURES = ROOT / "docs" / "station-access" / "contracts" / "examples"

class WorkspaceAgentContractTests(unittest.TestCase):
    def test_schema_itself_is_valid(self):
        schema = json.loads(SCHEMA.read_text())
        Draft202012Validator.check_schema(schema)
        self.assertEqual(schema["$schema"], "https://json-schema.org/draft/2020-12/schema")
        self.assertEqual(len(schema["x-zog-endpoints"]), 6)

    def test_every_public_fixture_matches_strict_v1_response_shape(self):
        schema = json.loads(SCHEMA.read_text())
        validator = Draft202012Validator(schema, format_checker=FormatChecker())
        examples = sorted(FIXTURES.glob("*.json"))
        self.assertEqual(len(examples), 7)
        for path in examples:
            with self.subTest(path=path.name):
                doc = json.loads(path.read_text())
                validator.validate(doc)
                self.assertNotIn("password", str(doc).lower())
                self.assertNotIn("/proc/", str(doc))
                self.assertNotIn("private", str(doc))

    def test_examples_reject_unlisted_sensitive_fields(self):
        schema = json.loads(SCHEMA.read_text())
        validator = Draft202012Validator(schema, format_checker=FormatChecker())
        doc = json.loads((FIXTURES / "runtime.json").read_text())
        doc["runtime"]["raw_host_path"] = "/private/root"
        self.assertFalse(validator.is_valid(doc))
        doc = json.loads((FIXTURES / "logs.json").read_text())
        doc["logs"]["entries"][0]["host_pid"] = 123
        self.assertFalse(validator.is_valid(doc))
