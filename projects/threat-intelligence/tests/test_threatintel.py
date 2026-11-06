import csv
import sys
import tempfile
import unittest
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
import threatintel


class ThreatIntelTests(unittest.TestCase):
    def load_rows(self):
        with (ROOT / "data/sample_iocs.csv").open(newline="", encoding="utf-8") as handle:
            return list(csv.DictReader(handle))

    def test_indicator_types_are_normalized(self):
        self.assertEqual(threatintel.classify_indicator("203.0.113.44", "ipv4"), ("ipv4", "203.0.113.44"))
        self.assertEqual(threatintel.classify_indicator("CDN-UPDATE.EXAMPLE.TEST", "domain"), ("domain", "cdn-update.example.test"))
        self.assertEqual(threatintel.classify_indicator("A" * 64, "sha256")[0], "sha256")

    def test_invalid_indicators_are_rejected(self):
        with self.assertRaises(ValueError):
            threatintel.classify_indicator("not-an-ip", "ipv4")
        with self.assertRaises(ValueError):
            threatintel.classify_indicator("javascript:alert(1)", "url")

    def test_duplicate_iocs_are_collapsed(self):
        enriched = threatintel.enrich_rows(self.load_rows(), date(2026, 11, 6))
        ip_rows = [row for row in enriched if row["indicator"] == "203.0.113.44"]
        self.assertEqual(len(ip_rows), 1)
        self.assertEqual(ip_rows[0]["observations"], 2)
        self.assertIn("Analyst-Lab-Note", ip_rows[0]["sources"])

    def test_freshness_bands(self):
        as_of = date(2026, 11, 6)
        self.assertEqual(threatintel.freshness_points(date(2026, 11, 5), as_of), 30)
        self.assertEqual(threatintel.freshness_points(date(2026, 10, 1), as_of), 10)

    def test_synthetic_events_match_normalized_iocs(self):
        indicators = threatintel.enrich_rows(self.load_rows(), date(2026, 11, 6))
        events = threatintel.load_events(ROOT / "data/sample_events.jsonl")
        matches = threatintel.match_events(events, indicators)
        self.assertEqual(len(matches), 4)
        self.assertIn("cdn-update.example.test", [row["matched_indicator"] for row in matches])
        self.assertTrue(any(row["indicator_type"] == "sha256" for row in matches))

    def test_outputs_are_created(self):
        indicators = threatintel.enrich_rows(self.load_rows(), date(2026, 11, 6))
        events = threatintel.load_events(ROOT / "data/sample_events.jsonl")
        matches = threatintel.match_events(events, indicators)
        with tempfile.TemporaryDirectory() as tmp:
            threatintel.write_outputs(indicators, matches, Path(tmp))
            self.assertTrue((Path(tmp) / "threat_iocs.csv").is_file())
            self.assertTrue((Path(tmp) / "event_matches.csv").is_file())
            self.assertIn("Synthetic", (Path(tmp) / "analyst_summary.md").read_text())


if __name__ == "__main__":
    unittest.main()
