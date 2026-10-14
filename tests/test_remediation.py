"""Remediation guidance + Markdown export."""

import csv
import io
import json
import unittest

from netscope import findings as F, remediation as R
from netscope.utils import RISKY_PORTS


class RemediationLookupTests(unittest.TestCase):
    def test_every_risky_port_has_specific_advice(self):
        for port in RISKY_PORTS:
            self.assertIn(port, R._PORT_FIX, f"no specific remediation for risky port {port}")
            self.assertEqual(R.for_finding("exposed-port", "x", port), R._PORT_FIX[port])

    def test_unknown_port_falls_back_to_generic(self):
        self.assertEqual(R.for_finding("exposed-port", "x", 4444), R._PORT_FALLBACK)

    def test_every_tls_title_the_auditor_emits_is_covered(self):
        titles = ["Expired TLS certificate", "TLS certificate expiring soon", "Self-signed TLS certificate",
                  "TLS certificate hostname mismatch", "Weak certificate signature algorithm",
                  "Obsolete TLS protocol (TLSv1)", "Weak TLS cipher negotiated"]
        for t in titles:
            self.assertTrue(R.for_finding("tls", t, 443), t)

    def test_every_probe_title_is_covered(self):
        titles = ["Anonymous FTP login allowed", "Unauthenticated Redis exposed",
                  "Unauthenticated MongoDB exposed", "Unauthenticated Elasticsearch exposed",
                  "SNMP readable with default community 'public'"]
        for t in titles:
            self.assertTrue(R.for_finding("weak-auth", t, 1), t)

    def test_every_capture_alert_category_is_covered(self):
        for prefix in ("ARP", "DHCP", "SCAN", "BEACON", "DNS-TUNNEL", "PLAINTEXT"):
            out = F.from_capture_alerts([("high", f"{prefix}: something")])
            self.assertTrue(out[0]["remediation"], prefix)

    def test_unknown_category_has_no_advice(self):
        self.assertEqual(R.for_finding("mystery", "t", 1), "")


class FindingRemediationTests(unittest.TestCase):
    def test_default_remediation_is_attached(self):
        f = F.make_finding("tls", "high", "Expired TLS certificate", host="h", port=443)
        self.assertIn("Renew", f["remediation"])

    def test_explicit_remediation_wins_and_empty_string_is_respected(self):
        self.assertEqual(F.make_finding("tls", "high", "Expired TLS certificate", remediation="mine")["remediation"], "mine")
        self.assertEqual(F.make_finding("tls", "high", "Expired TLS certificate", remediation="")["remediation"], "")

    def test_remediation_never_affects_the_id(self):
        a = F.make_finding("cve", "high", "t", host="h", port=22, detail="d")
        b = F.make_finding("cve", "high", "t", host="h", port=22, detail="d", remediation="something else")
        self.assertEqual(a["id"], b["id"])

    def test_adapters_populate_it(self):
        cve = F.from_cve_matches("h", 22, "openssh 7.2", [{"cve": "CVE-X", "cvss": 9.8, "title": "t"}])[0]
        port = F.from_risky_ports("h", [{"port": 23, "service": "telnet"}], RISKY_PORTS)[0]
        ns = F.from_nameservices("h", ["ssdp", "netbios"])
        self.assertIn("backport", cve["remediation"])
        self.assertIn("SSH", port["remediation"])
        self.assertTrue(all(f["remediation"] for f in ns))

    def test_csv_and_sarif_and_json_carry_it(self):
        fs = [F.make_finding("tls", "high", "Expired TLS certificate", host="h", port=443, detail="d")]
        rows = list(csv.DictReader(io.StringIO(F.export(fs, "csv"))))
        self.assertIn("Renew", rows[0]["remediation"])
        sarif = json.loads(F.export(fs, "sarif"))
        self.assertIn("Renew", sarif["runs"][0]["results"][0]["properties"]["remediation"])
        self.assertIn("Renew", json.loads(F.export(fs, "json"))["findings"][0]["remediation"])


class MarkdownTests(unittest.TestCase):
    def md(self, findings, **meta):
        return F.export(findings, "markdown", meta=meta or None)

    def test_structure_grouping_and_order(self):
        fs = [F.make_finding("tls", "medium", "Self-signed TLS certificate", host="10.0.0.9", port=443, detail="d1"),
              F.make_finding("cve", "critical", "Bad CVE", host="10.0.0.2", port=22, detail="d2",
                             refs=["CVE-1"], cvss=9.8, evidence="OpenSSH 7.2")]
        out = self.md(fs, subnet="10.0.0.0/24", risk_score=70)
        self.assertTrue(out.startswith("# netscope findings"))
        self.assertIn("| critical | 1 |", out)
        self.assertLess(out.index("## 10.0.0.2"), out.index("## 10.0.0.9"))
        self.assertIn("### [CRITICAL] Bad CVE:22", out)
        self.assertIn("**CVSS:** 9.8", out)
        self.assertIn("**Remediation:**", out)
        self.assertTrue(out.endswith("\n") and not out.endswith("\n\n"))
        self.assertNotIn("\n\n\n", out)

    def test_empty_is_a_valid_document(self):
        out = self.md([])
        self.assertIn("No findings.", out)
        self.assertIn("| info | 0 |", out)

    def test_hostile_text_cannot_inject_markdown(self):
        evil = "x](http://evil)\n# FAKE HEADING\n| a | b |"
        out = self.md([F.make_finding("tls", "high", evil, host="h", port=1, detail=evil, evidence=evil)])
        self.assertNotIn("\n# FAKE HEADING", out)
        self.assertNotIn("](http://evil)", out.replace("\\]\\(http://evil\\)", ""))
        self.assertEqual([l for l in out.splitlines() if l.startswith("# ")], ["# netscope findings"])

    def test_cli_accepts_markdown_export(self):
        from tests.test_cli import run_main, canned_result
        from unittest import mock
        from netscope import security
        f = F.make_finding("tls", "high", "Expired TLS certificate", host="10.0.0.5", port=443, detail="d")
        with mock.patch.object(security, "deep_check_hosts", return_value=[canned_result("10.0.0.5", [f])]):
            code, out, _ = run_main("audit", "--host", "10.0.0.5", "--export", "markdown")
        self.assertEqual(code, 0)
        self.assertTrue(out.startswith("# netscope findings"))


if __name__ == "__main__":
    unittest.main()
