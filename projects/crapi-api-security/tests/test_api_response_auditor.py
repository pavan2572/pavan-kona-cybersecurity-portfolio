import importlib.util
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).parents[1] / "scripts" / "api_response_auditor.py"
SPEC = importlib.util.spec_from_file_location("api_response_auditor", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(MODULE)


class ApiResponseAuditorTests(unittest.TestCase):
    def test_exact_allowlist_passes(self):
        payload = {"id": "demo-1", "profile": {"display_name": "Sample"}}
        result = MODULE.audit(payload, ["id", "profile.display_name"])
        self.assertTrue(result["passed"])
        self.assertEqual(result["unexpected_fields"], [])

    def test_unexpected_fields_are_reported(self):
        payload = {"id": "demo-1", "profile": {"email": "sample@example.com"}}
        result = MODULE.audit(payload, ["id"])
        self.assertEqual(result["unexpected_fields"], ["profile.email"])
        self.assertFalse(result["passed"])

    def test_sensitive_fields_are_flagged_even_if_allowlisted(self):
        payload = {"access_token": "NOT-A-REAL-TOKEN"}
        result = MODULE.audit(payload, ["access_token"])
        self.assertEqual(result["sensitive_name_matches"], ["access_token"])
        self.assertFalse(result["passed"])

    def test_array_paths_use_wildcard_notation(self):
        payload = {"orders": [{"id": 1}, {"id": 2}]}
        result = MODULE.audit(payload, ["orders[].id"])
        self.assertTrue(result["passed"])

    def test_json_allowlist_must_be_string_array(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "allowlist.json"
            path.write_text('{"id": true}', encoding="utf-8")
            with self.assertRaises(ValueError):
                MODULE.load_allowlist(path)


if __name__ == "__main__":
    unittest.main()
