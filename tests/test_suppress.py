"""Accepted-risk suppressions and the --fail-on severity gate."""

import datetime
import json
import os
import tempfile
import unittest
from unittest import mock

from netscope import findings as F, security, storage, suppress as S
from tests.test_cli import run_main, canned_result

TODAY = datetime.date(2026, 6, 15)


def write(text, name="rules"):
    path = os.path.join(tempfile.mkdtemp(), name)
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)
    return path


def fnd(cat="cve", sev="high", title="t", host="10.0.0.5", port=22, detail="d"):
    return F.make_finding(cat, sev, title, host=host, port=port, detail=detail)


class LoadRulesTests(unittest.TestCase):
    def test_json_list_and_wrapped_object(self):
        rule = {"id": "a1b2c3d4e5f6", "reason": "lab", "expires": "2026-12-31"}
        for doc in (json.dumps([rule]), json.dumps({"suppressions": [rule]})):
            rules = S.load_rules(write(doc))
            self.assertEqual((rules[0]["id"], rules[0]["reason"], rules[0]["expires"]),
                             ("a1b2c3d4e5f6", "lab", datetime.date(2026, 12, 31)))

    def test_line_format(self):
        rules = S.load_rules(write(
            "# comment\n\na1b2c3d4e5f6  expires=2026-12-31  # lab router\n"
            "tls:10.0.0.*:443   # internal CA\ncve:*:*\n"))
        self.assertEqual(rules[0]["id"], "a1b2c3d4e5f6")
        self.assertEqual(rules[0]["reason"], "lab router")
        self.assertEqual((rules[1]["category"], rules[1]["host"], rules[1]["port"]), ("tls", "10.0.0.*", 443))
        self.assertEqual((rules[2]["category"], rules[2]["host"], rules[2]["port"]), ("cve", None, None))

    def test_malformed_files_are_rejected_with_a_location(self):
        bad = {
            "empty-json-rule": "[{}]",
            "wildcard-only": "[{\"category\": \"*\", \"host\": \"*\"}]",
            "unknown-key": "[{\"id\": \"a1b2c3d4e5f6\", \"sevrity\": \"x\"}]",
            "bad-id": "[{\"id\": \"nothex\"}]",
            "bad-date": "[{\"id\": \"a1b2c3d4e5f6\", \"expires\": \"soon\"}]",
            "bad-port": "[{\"host\": \"h\", \"port\": \"http\"}]",
            "not-a-list": "{\"foo\": 1}",
            "broken-json": "[{",
            "line-all-wild": "*:*:*",
            "line-two-selectors": "a1b2c3d4e5f6 tls:h:1",
            "line-short-selector": "tls:10.0.0.1",
            "line-bad-id": "zzz",
        }
        for name, text in bad.items():
            with self.assertRaises(S.SuppressionError, msg=name):
                S.load_rules(write(text))

    def test_error_names_the_line(self):
        with self.assertRaises(S.SuppressionError) as cm:
            S.load_rules(write("a1b2c3d4e5f6\nbogus\n", "ignore.txt"))
        self.assertIn("ignore.txt:2", str(cm.exception))

    def test_missing_file(self):
        with self.assertRaises(S.SuppressionError):
            S.load_rules("/no/such/file")


class ApplyTests(unittest.TestCase):
    def setUp(self):
        self.a = fnd(title="A", host="10.0.0.5", port=22)
        self.b = fnd("tls", "medium", "B", host="10.0.0.6", port=443)
        self.c = fnd("weak-auth", "critical", "C", host="192.168.1.9", port=6379)
        self.fs = [self.a, self.b, self.c]

    def apply(self, text, today=TODAY):
        return S.apply_suppressions(self.fs, S.load_rules(write(text)), today=today)

    def test_match_by_id(self):
        active, supp, _ = self.apply(f"{self.a['id']}  # known")
        self.assertEqual([f["title"] for f in active], ["B", "C"])
        self.assertEqual(supp[0]["suppression"]["reason"], "known")
        self.assertNotIn("suppression", self.a)                    # original not mutated

    def test_selectors_are_anded_and_globbed(self):
        active, supp, _ = self.apply("tls:10.0.0.*:443")
        self.assertEqual([f["title"] for f in supp], ["B"])
        active, supp, _ = self.apply("tls:10.0.0.*:8443")           # wrong port
        self.assertEqual(supp, [])
        active, supp, _ = self.apply("*:192.168.*:*")
        self.assertEqual([f["title"] for f in supp], ["C"])

    def test_expired_rule_does_not_apply_and_is_reported(self):
        active, supp, expired = self.apply(f"{self.a['id']} expires=2026-01-01 # old")
        self.assertEqual(len(active), 3)
        self.assertEqual(supp, [])
        self.assertEqual(len(expired), 1)

    def test_rule_valid_through_its_expiry_day(self):
        _, supp, expired = self.apply(f"{self.a['id']} expires=2026-06-15")
        self.assertEqual((len(supp), len(expired)), (1, 0))

    def test_nothing_is_lost(self):
        active, supp, _ = self.apply("cve:*:*")
        self.assertEqual(len(active) + len(supp), len(self.fs))

    def test_apply_to_results_rescoring(self):
        r = canned_result("10.0.0.5", [self.a, self.c])
        before = r["risk_score"]
        S.apply_to_results([r], {self.a["id"]})
        self.assertEqual([f["title"] for f in r["findings"]], ["A"])
        self.assertEqual(r["suppressed_count"], 1)
        self.assertLess(r["risk_score"], before)

    def test_exceeds(self):
        self.assertTrue(S.exceeds(self.fs, "critical"))
        self.assertTrue(S.exceeds([self.b], "medium"))
        self.assertFalse(S.exceeds([self.b], "high"))
        self.assertFalse(S.exceeds([], "low"))
        self.assertFalse(S.exceeds(self.fs, None))


class IdDiscoverabilityTests(unittest.TestCase):
    def test_ids_appear_in_every_human_export_so_rules_can_be_written(self):
        f = fnd()
        self.assertIn(f["id"], F.export([f], "csv"))
        self.assertIn(f["id"], F.export([f], "markdown"))
        self.assertIn(f["id"], F.export([f], "json"))
        self.assertIn(f["id"], F.export([f], "ndjson"))


class SarifSuppressionTests(unittest.TestCase):
    def test_suppressed_results_are_marked_not_dropped(self):
        a, b = fnd(title="A"), fnd(title="B", port=80)
        _, supp, _ = S.apply_suppressions([a], S.load_rules(write(f"{a['id']} # why")), today=TODAY)
        doc = json.loads(F.export([b] + supp, "sarif"))
        marked = [r for r in doc["runs"][0]["results"] if "suppressions" in r]
        self.assertEqual(len(doc["runs"][0]["results"]), 2)
        self.assertEqual(marked[0]["suppressions"][0]["justification"], "why")
        self.assertEqual(marked[0]["suppressions"][0]["status"], "accepted")
        self.assertEqual(len(marked), 1)


class CliGateTests(unittest.TestCase):
    def setUp(self):
        self.hi = fnd(sev="high", title="Old CVE", port=22)
        self.lo = fnd("tls", "low", "Minor TLS", port=443, detail="x")
        self.res = lambda: [canned_result("10.0.0.5", [self.hi, self.lo])]

    def audit(self, *extra, results=None):
        with mock.patch.object(security, "deep_check_hosts", return_value=results or self.res()) as m:
            out = run_main("audit", "--host", "10.0.0.5", *extra)
        return out + (m,)

    def test_fail_on_exit_code(self):
        self.assertEqual(self.audit()[0], 0)                                       # no gate -> never fails
        code, _, err, _ = self.audit("--fail-on", "high")
        self.assertEqual(code, 3)
        self.assertIn("FAIL", err)
        self.assertEqual(self.audit("--fail-on", "critical")[0], 0)
        self.assertEqual(self.audit("--fail-on", "low")[0], 3)

    def test_ignore_file_suppresses_reports_and_unblocks_the_gate(self):
        path = write(f"{self.hi['id']}  # accepted until patch window")
        code, out, _, _ = self.audit("--ignore-file", path, "--fail-on", "high")
        self.assertEqual(code, 0)
        self.assertIn("Suppressed 1 finding(s)", out)
        self.assertIn("accepted until patch window", out)                          # visible, not silent

    def test_suppressed_findings_leave_exports_but_ride_along_in_sarif(self):
        path = write(f"{self.hi['id']}  # ok")
        _, out, _, _ = self.audit("--ignore-file", path, "--export", "csv")
        self.assertNotIn("Old CVE", out)
        self.assertIn("Minor TLS", out)
        _, out, _, _ = self.audit("--ignore-file", path, "--export", "sarif")
        results = json.loads(out)["runs"][0]["results"]
        self.assertEqual(len(results), 2)
        self.assertEqual(sum("suppressions" in r for r in results), 1)

    def test_json_output_uses_active_set(self):
        path = write(f"{self.hi['id']}")
        _, out, _, _ = self.audit("--ignore-file", path, "--json")
        doc = json.loads(out)
        self.assertEqual(doc["suppressed"], 1)
        self.assertEqual([f["title"] for f in doc["results"][0]["findings"]], ["Minor TLS"])

    def test_bad_ignore_file_fails_fast_with_exit_2(self):
        code, _, err, m = self.audit("--ignore-file", write("bogus line here"))
        self.assertEqual(code, 2)
        self.assertIn("Error:", err)
        m.assert_not_called()                                                      # before any scanning
        code, _, _, m = self.audit("--ignore-file", "/no/such/file")
        self.assertEqual(code, 2)
        m.assert_not_called()

    def test_expired_rule_warns_on_stderr_and_gate_still_fires(self):
        path = write(f"{self.hi['id']} expires=2020-01-01 # stale")
        code, _, err, _ = self.audit("--ignore-file", path, "--fail-on", "high")
        self.assertEqual(code, 3)
        self.assertIn("expired", err)

    def test_saved_snapshot_holds_active_findings_only(self):
        db = os.path.join(tempfile.mkdtemp(), "s.db")
        path = write(f"{self.hi['id']}")
        self.audit("--ignore-file", path, "--save", "--db", db)
        conn = storage.connect(db)
        self.assertEqual([r["title"] for r in storage.get_scan_findings(conn, 1)], ["Minor TLS"])

    def test_security_deep_and_quick_support_the_gate(self):
        with mock.patch.object(security, "deep_check_hosts", return_value=self.res()):
            self.assertEqual(run_main("security", "--host", "10.0.0.5", "--deep", "--fail-on", "high")[0], 3)
        quick = [{"host": "10.0.0.5", "open_ports": [{"port": 23, "service": "telnet"}], "risky_findings": []}]
        with mock.patch.object(security, "check_hosts", return_value=quick):
            self.assertEqual(run_main("security", "--host", "10.0.0.5", "--fail-on", "medium")[0], 3)
            self.assertEqual(run_main("security", "--host", "10.0.0.5", "--fail-on", "high")[0], 0)

    def test_diff_gates_on_new_findings_only(self):
        db = os.path.join(tempfile.mkdtemp(), "d.db")
        with mock.patch.object(security, "deep_check_hosts",
                               side_effect=[[canned_result("10.0.0.5", [self.lo])],
                                            [canned_result("10.0.0.5", [self.lo, self.hi])]]):
            run_main("audit", "--host", "10.0.0.5", "--save", "--db", db)
            run_main("audit", "--host", "10.0.0.5", "--save", "--db", db)
        self.assertEqual(run_main("diff", "--db", db, "--fail-on", "high")[0], 3)       # new high
        self.assertEqual(run_main("diff", "--db", db, "--fail-on", "critical")[0], 0)
        path = write(f"{self.hi['id']}  # accepted")
        self.assertEqual(run_main("diff", "--db", db, "--fail-on", "high", "--ignore-file", path)[0], 0)

    def test_invalid_fail_on_value_is_an_argument_error(self):
        self.assertEqual(run_main("audit", "--host", "10.0.0.5", "--fail-on", "urgent")[0], 2)


if __name__ == "__main__":
    unittest.main()
