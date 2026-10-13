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


class StableIdTests(unittest.TestCase):
    def test_key_overrides_detail_in_id(self):
        a = F.make_finding("tls", "medium", "T", host="h", port=1, detail="expires in 12 days", key="expiring")
        b = F.make_finding("tls", "medium", "T", host="h", port=1, detail="expires in 11 days", key="expiring")
        self.assertEqual(a["id"], b["id"])
        self.assertNotEqual(a["detail"], b["detail"])           # the human text still differs

    def test_without_key_detail_still_distinguishes(self):
        a = F.make_finding("cve", "high", "Same title", host="h", port=22, detail="CVE-A text")
        b = F.make_finding("cve", "high", "Same title", host="h", port=22, detail="CVE-B text")
        self.assertNotEqual(a["id"], b["id"])

    def test_id_depends_on_host_port_category_title(self):
        base = dict(severity="low", title="T", host="h", port=1, detail="d")
        ids = {
            F.make_finding("c", **base)["id"],
            F.make_finding("c2", **base)["id"],
            F.make_finding("c", **{**base, "host": "h2"})["id"],
            F.make_finding("c", **{**base, "port": 2})["id"],
            F.make_finding("c", **{**base, "title": "T2"})["id"],
        }
        self.assertEqual(len(ids), 5)

    def test_severity_change_does_not_change_id(self):
        a = F.make_finding("c", "low", "T", host="h")
        b = F.make_finding("c", "high", "T", host="h")
        self.assertEqual(a["id"], b["id"])          # re-scored issue is the same issue

    def test_from_tls_threads_key_through(self):
        tls = [{"severity": "medium", "title": "X", "key": "k", "detail": "d1"}]
        tls2 = [{"severity": "medium", "title": "X", "key": "k", "detail": "d2"}]
        self.assertEqual(F.from_tls("h", 443, tls)[0]["id"], F.from_tls("h", 443, tls2)[0]["id"])

    def test_unknown_severity_normalised(self):
        self.assertEqual(F.make_finding("c", "catastrophic", "T")["severity"], "info")
        self.assertEqual(F.make_finding("c", None, "T")["severity"], "info")


class SarifTests(unittest.TestCase):
    def _doc(self, findings):
        return json.loads(F.to_sarif(findings))

    def test_every_result_has_a_physical_location(self):
        # GitHub code scanning only displays results with a physicalLocation.
        doc = self._doc(_sample() + [F.make_finding("traffic-arp", "high", "ARP: x")])
        for r in doc["runs"][0]["results"]:
            loc = r["locations"][0]
            uri = loc["physicalLocation"]["artifactLocation"]["uri"]
            self.assertTrue(uri.startswith("netscope/"), uri)
            self.assertEqual(loc["physicalLocation"]["region"]["startLine"], 1)
            self.assertTrue(loc["logicalLocations"][0]["fullyQualifiedName"])

    def test_uri_is_relative_and_cannot_traverse_for_odd_hosts(self):
        for host in ("fe80::1", "a b/c", "../../etc/passwd", "..", "....//", "h\u00f6st", "", "x\x00y", "a\\b"):
            f = F.make_finding("c", "low", "T", host=host, port=22)
            uri = self._doc([f])["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
            segments = uri.split("/")
            self.assertEqual(segments[0], "netscope", uri)
            self.assertEqual(len(segments), 3, uri)                 # netscope/<host>/<port>: no extra structure
            self.assertNotIn("..", uri)
            self.assertRegex(uri, r"^[A-Za-z0-9._/-]+$")
        plain = F.make_finding("c", "low", "T", host="10.0.0.1", port=22)
        uri = self._doc([plain])["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        self.assertEqual(uri, "netscope/10.0.0.1/22")                # normal hosts stay readable

    def test_partial_fingerprints_carry_finding_id(self):
        f = F.make_finding("cve", "high", "T", host="h", port=22)
        r = self._doc([f])["runs"][0]["results"][0]
        self.assertEqual(r["partialFingerprints"]["netscopeFindingId/v1"], f["id"])

    def test_version_comes_from_package(self):
        from netscope import __version__
        self.assertEqual(self._doc([])["runs"][0]["tool"]["driver"]["version"], __version__)

    def test_rules_cover_every_result(self):
        doc = self._doc(_sample())
        rules = {r["id"] for r in doc["runs"][0]["tool"]["driver"]["rules"]}
        self.assertTrue({r["ruleId"] for r in doc["runs"][0]["results"]} <= rules)

    def test_empty_findings_is_valid_document(self):
        doc = self._doc([])
        self.assertEqual((doc["version"], doc["runs"][0]["results"]), ("2.1.0", []))

    def test_level_mapping(self):
        levels = {f["severity"]: self._doc([f])["runs"][0]["results"][0]["level"]
                  for f in (F.make_finding("c", s, "T") for s in F.SEVERITIES)}
        self.assertEqual(levels, {"critical": "error", "high": "error", "medium": "warning",
                                  "low": "note", "info": "none"})


class ExportEdgeTests(unittest.TestCase):
    def test_csv_quotes_commas_quotes_and_newlines(self):
        f = F.make_finding("c", "low", 'Title, with "quotes"', host="h", port=None,
                           detail="line1\nline2, more", refs=["a", "b"], cvss=5.5)
        rows = list(csv.reader(io.StringIO(F.export([f], "csv"))))
        self.assertEqual(rows[1][4], 'Title, with "quotes"')
        self.assertEqual(rows[1][5], "line1\nline2, more")
        self.assertEqual((rows[1][3], rows[1][6], rows[1][7]), ("", "a;b", "5.5"))

    def test_json_meta_and_unicode(self):
        f = F.make_finding("c", "low", "caf\u00e9 \u2603")
        doc = json.loads(F.export([f], "json", meta={"subnet": "10.0.0.0/24"}))
        self.assertEqual(doc["meta"], {"subnet": "10.0.0.0/24"})
        self.assertEqual(doc["findings"][0]["title"], "caf\u00e9 \u2603")

    def test_format_name_is_case_insensitive_and_defaults_to_json(self):
        self.assertEqual(F.export([], "CSV").splitlines()[0].split(",")[0], "severity")
        self.assertIn("findings", json.loads(F.export([], None)))

    def test_ndjson_lines_each_valid_with_unicode_and_newlines_in_text(self):
        f = F.make_finding("c", "low", "t", detail="a\nb")
        (line,) = F.export([f], "ndjson").splitlines()
        self.assertEqual(json.loads(line)["detail"], "a\nb")

    def test_sorting_is_stable_for_equal_severity(self):
        fs = [F.make_finding("c", "low", "T", host=h, port=p) for h, p in
              (("b", 2), ("a", 9), ("a", 1), ("b", None))]
        self.assertEqual([(f["host"], f["port"]) for f in F.sort_findings(fs)],
                         [("a", 1), ("a", 9), ("b", None), ("b", 2)])


class ScoreEdgeTests(unittest.TestCase):
    def test_score_never_exceeds_100_and_is_int(self):
        huge = [F.make_finding("c", "critical", f"t{i}") for i in range(500)]
        self.assertEqual(F.risk_score(huge), 100)
        self.assertIsInstance(F.risk_score(huge), int)

    def test_info_only_scores_zero(self):
        self.assertEqual(F.risk_score([F.make_finding("c", "info", "t")] * 10), 0)

    def test_missing_or_bad_severity_does_not_crash(self):
        self.assertEqual(F.risk_score([{"severity": "bogus"}, {}]), 0)
        self.assertEqual(F.severity_counts([{"severity": "bogus"}])["info"], 0)

    def test_by_host_groups_networkwide_findings(self):
        groups = F.by_host([F.make_finding("traffic", "high", "t"), F.make_finding("c", "low", "t", host="h")])
        self.assertEqual(set(groups), {"network", "h"})

    def test_from_capture_alerts_variants(self):
        out = F.from_capture_alerts([("high", "DNS-TUNNEL: x"), ("bogus", "no prefix here"), ("low", ":leading colon")])
        self.assertEqual([f["category"] for f in out], ["traffic-dns-tunnel", "traffic-traffic", "traffic-traffic"])
        self.assertEqual(out[1]["severity"], "medium")             # unknown severity -> medium
        self.assertLessEqual(len(out[0]["title"]), 80)

    def test_cve_severity_derivation_boundaries(self):
        for cvss, sev in ((10, "critical"), (9.0, "critical"), (8.9, "high"), (7.0, "high"),
                          (6.9, "medium"), (4.0, "medium"), (3.9, "low"), (0.1, "low"), (0, "info"),
                          (None, "medium"), ("x", "medium")):
            out = F.from_cve_matches("h", 1, "p", [{"cve": "CVE-X", "cvss": cvss, "title": "t"}])
            self.assertEqual(out[0]["severity"], sev, cvss)


if __name__ == "__main__":
    unittest.main()
