import importlib.util
import unittest
from pathlib import Path

BASE = Path(__file__).parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


IOC = load("ioc_triage", BASE / "scripts" / "ioc_triage.py")
KEV = load("kev_watch", BASE / "scripts" / "kev_watch.py")


class IocTriageTests(unittest.TestCase):
    def test_documentation_ip_is_not_public_threat_intel(self):
        result = IOC.classify_indicator("192.0.2.10", "ip")
        self.assertEqual(result[0], "non_public_or_reserved")

    def test_global_ip_is_only_a_candidate(self):
        result = IOC.classify_indicator("8.8.8.8", "ip")
        self.assertEqual(result[0], "public_candidate")
        self.assertIn("not established", result[1])

    def test_example_domain_is_reserved_for_documentation(self):
        result = IOC.classify_indicator("demo.example.com", "domain")
        self.assertEqual(result[0], "documentation_or_test")

    def test_invalid_domain_is_rejected(self):
        result = IOC.classify_indicator("not a domain", "domain")
        self.assertEqual(result[0], "invalid")

    def test_confidence_bands(self):
        self.assertEqual(IOC.confidence_band(90), "High")
        self.assertEqual(IOC.confidence_band(65), "Medium")
        self.assertEqual(IOC.confidence_band(20), "Low")


class KevFilterTests(unittest.TestCase):
    def test_filter_and_catalog_metadata(self):
        catalog = {
            "catalogVersion": "demo-version",
            "dateReleased": "2026-01-10",
            "vulnerabilities": [
                {"cveID":"DEMO-CVE-1","vendorProject":"Acme","product":"Widget",
                 "dateAdded":"2026-01-09","dueDate":"2026-01-20"},
                {"cveID":"DEMO-CVE-2","vendorProject":"Other","product":"Service",
                 "dateAdded":"2026-01-11","dueDate":"2026-01-30"},
            ],
        }
        rows = KEV.filter_records(catalog, since="2026-01-10", vendor="other")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["cveID"], "DEMO-CVE-2")
        self.assertEqual(rows[0]["catalogVersion"], "demo-version")

    def test_invalid_since_date_is_rejected(self):
        with self.assertRaises(ValueError):
            KEV.filter_records({"vulnerabilities":[]}, since="not-a-date")


if __name__ == "__main__":
    unittest.main()
