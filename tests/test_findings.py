"""Tests for the unified findings model, scoring, and exporters."""

import csv
import io
import json
import unittest

from netscope import findings as F


def _sample():
    return [
        F.make_finding("cve", "critical", "RCE", host="10.0.0.1", port=22, refs=["CVE-1"]),
        F.make_finding("tls", "medium", "Self-signed", host="10.0.0.1", port=443),
        F.make_finding("weak-auth", "high", "Open Redis", host="10.0.0.2", port=6379),
    ]


class ModelTests(unittest.TestCase):
    def test_stable_id(self):
        a = F.make_finding("cve", "high", "X", host="h", port=1, detail="d")
        b = F.make_finding("cve", "high", "X", host="h", port=1, detail="d")
        self.assertEqual(a["id"], b["id"])

    def test_dedupe(self):
        a = F.make_finding("cve", "high", "X", host="h", port=1, detail="d")
        b = F.make_finding("cve", "high", "X", host="h", port=1, detail="d")
        self.assertEqual(len(F.dedupe([a, b])), 1)

    def test_sort_order(self):
        s = F.sort_findings(_sample())
        self.assertEqual(s[0]["severity"], "critical")
        self.assertEqual(s[-1]["severity"], "medium")

    def test_severity_counts(self):
        c = F.severity_counts(_sample())
        self.assertEqual(c["critical"], 1)
        self.assertEqual(c["high"], 1)
        self.assertEqual(c["medium"], 1)
        self.assertEqual(c["low"], 0)

    def test_risk_score_bounds_and_monotonic(self):
        self.assertEqual(F.risk_score([]), 0)
        one_low = [F.make_finding("x", "low", "t")]
        one_crit = [F.make_finding("x", "critical", "t")]
        self.assertGreater(F.risk_score(one_crit), F.risk_score(one_low))
        self.assertLessEqual(F.risk_score(_sample() * 5), 100)

    def test_host_scores(self):
        scores = F.host_risk_scores(_sample())
        self.assertIn("10.0.0.1", scores)
        self.assertIn("10.0.0.2", scores)


class ExportTests(unittest.TestCase):
    def test_json_roundtrip(self):
        doc = json.loads(F.export(_sample(), "json"))
        self.assertEqual(len(doc["findings"]), 3)
        self.assertIn("meta", doc)

    def test_ndjson_one_per_line(self):
        out = F.export(_sample(), "ndjson")
        self.assertTrue(out.endswith("\n"))  # each record is newline-terminated
        lines = out.splitlines()
        self.assertEqual(len(lines), 3)
        for ln in lines:
            json.loads(ln)  # each line is valid JSON

    def test_ndjson_empty(self):
        self.assertEqual(F.export([], "ndjson"), "")

    def test_csv_header_and_rows(self):
        rows = list(csv.reader(io.StringIO(F.export(_sample(), "csv"))))
        self.assertEqual(rows[0][0], "severity")
        self.assertEqual(len(rows), 4)  # header + 3

    def test_sarif_shape(self):
        doc = json.loads(F.export(_sample(), "sarif"))
        self.assertEqual(doc["version"], "2.1.0")
        run = doc["runs"][0]
        self.assertEqual(run["tool"]["driver"]["name"], "netscope")
        self.assertEqual(len(run["results"]), 3)
        levels = {r["level"] for r in run["results"]}
        self.assertTrue(levels <= {"error", "warning", "note", "none"})

    def test_unknown_format(self):
        with self.assertRaises(ValueError):
            F.export(_sample(), "xml")


class AdapterTests(unittest.TestCase):
    def test_from_risky_ports(self):
        risky = {23: "Telnet cleartext"}
        out = F.from_risky_ports("h", [{"port": 23, "service": "telnet"}, {"port": 80, "service": "http"}], risky)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["port"], 23)

    def test_from_cve_matches_severity_from_cvss(self):
        out = F.from_cve_matches("h", 22, "openssh 7.2", [{"cve": "CVE-X", "cvss": 9.8, "title": "t"}])
        self.assertEqual(out[0]["severity"], "critical")

    def test_from_capture_alerts_category(self):
        out = F.from_capture_alerts([("high", "BEACON: host beaconing")])
        self.assertTrue(out[0]["category"].startswith("traffic-"))


if __name__ == "__main__":
    unittest.main()
