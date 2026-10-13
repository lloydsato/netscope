"""Tests for the deep-audit pipeline orchestration (scan/probe layers mocked)."""

import socket
import unittest
from unittest import mock

from netscope import security, findings as F


def fp(port, product="", version="", banner=""):
    return {"port": port, "service": "x", "banner": banner or f"{product} {version}".strip(),
            "os_hint": "", "product": product, "version": version}


OPEN = [{"port": 22, "service": "ssh"}, {"port": 443, "service": "https"}, {"port": 6379, "service": "redis"}]


class DeepCheckTests(unittest.TestCase):
    def run_deep(self, fingerprints, tls=None, probes_out=None, snmp_out=None, open_ports=None, **kw):
        ports = [dict(p) for p in (OPEN if open_ports is None else open_ports)]
        with mock.patch.object(security.portscan, "scan", return_value=ports), \
                mock.patch.object(security.fingerprint, "fingerprint_port",
                                  side_effect=lambda h, p: fingerprints[p]), \
                mock.patch.object(security.tlsaudit, "inspect", return_value=tls or {"ok": False}), \
                mock.patch.object(security.probes, "run_all", return_value=probes_out or []), \
                mock.patch.object(security.probes, "check_snmp_default_community", return_value=snmp_out or []):
            return security.deep_check_host("10.0.0.5", **kw)

    def titles(self, res):
        return [f["title"] for f in res["findings"]]

    def test_old_openssh_gets_cves_with_refs_and_evidence(self):
        res = self.run_deep({22: fp(22, "openssh", "7.2p2"), 443: fp(443), 6379: fp(6379)})
        cves = {r for f in res["findings"] for r in f["refs"] if r.startswith("CVE-")}
        self.assertIn("CVE-2018-15473", cves)
        self.assertIn("CVE-2023-38408", cves)
        self.assertNotIn("CVE-2024-6387", cves)
        f = [f for f in res["findings"] if "CVE-2018-15473" in f["refs"]][0]
        self.assertEqual((f["host"], f["port"], f["evidence"], f["category"]), ("10.0.0.5", 22, "openssh 7.2p2", "cve"))

    def test_patched_versions_produce_no_cves(self):
        res = self.run_deep({22: fp(22, "openssh", "9.8p1"), 443: fp(443, "nginx", "1.25.3"), 6379: fp(6379)})
        self.assertEqual([f for f in res["findings"] if f["category"] == "cve"], [])

    def test_unauthenticated_service_banner_triggers_weak_default(self):
        res = self.run_deep({22: fp(22), 443: fp(443), 6379: fp(6379, "redis", "5.0.7")})
        wd = [f for f in res["findings"] if f["category"] == "weak-default"]
        self.assertEqual(len(wd), 1)
        self.assertEqual((wd[0]["severity"], wd[0]["port"]), ("high", 6379))
        self.assertFalse([f for f in res["findings"] if "CVE-2023-28425" in f["refs"]])   # 5.0.7 unaffected

    def test_risky_port_heuristic_still_reported(self):
        res = self.run_deep({22: fp(22), 443: fp(443), 6379: fp(6379)})
        self.assertTrue(any(f["category"] == "exposed-port" and f["port"] == 6379 for f in res["findings"]))

    def test_tls_findings_only_on_tls_ports_and_when_ok(self):
        tls = {"ok": True, "findings": [{"severity": "high", "title": "Obsolete TLS protocol (TLSv1)",
                                         "detail": "d", "evidence": "e", "key": "proto-TLSv1"}]}
        res = self.run_deep({22: fp(22), 443: fp(443), 6379: fp(6379)}, tls=tls)
        t = [f for f in res["findings"] if f["category"] == "tls"]
        self.assertEqual([(f["port"], f["title"]) for f in t], [(443, "Obsolete TLS protocol (TLSv1)")])
        res = self.run_deep({22: fp(22), 443: fp(443), 6379: fp(6379)}, tls={"ok": False, "error": "x"})
        self.assertFalse([f for f in res["findings"] if f["category"] == "tls"])

    def test_do_tls_and_do_probes_flags(self):
        tls = {"ok": True, "findings": [{"severity": "low", "title": "T", "detail": "", "evidence": ""}]}
        probe = [{"category": "weak-auth", "severity": "critical", "title": "P", "host": "10.0.0.5",
                  "port": 6379, "detail": "", "evidence": ""}]
        fps = {22: fp(22), 443: fp(443), 6379: fp(6379)}
        res = self.run_deep(fps, tls=tls, probes_out=probe, do_tls=False, do_probes=False)
        self.assertFalse([f for f in res["findings"] if f["category"] in ("tls", "weak-auth")])
        res = self.run_deep(fps, tls=tls, probes_out=probe)
        self.assertTrue([f for f in res["findings"] if f["category"] == "weak-auth"])

    def test_probe_and_tls_crashes_do_not_abort_the_audit(self):
        ports = [dict(p) for p in OPEN]
        with mock.patch.object(security.portscan, "scan", return_value=ports), \
                mock.patch.object(security.fingerprint, "fingerprint_port",
                                  side_effect=lambda h, p: fp(p, "openssh", "7.2p2") if p == 22 else fp(p)), \
                mock.patch.object(security.tlsaudit, "inspect", side_effect=RuntimeError("tls boom")), \
                mock.patch.object(security.probes, "run_all", side_effect=OSError("probe boom")), \
                mock.patch.object(security.probes, "check_snmp_default_community", side_effect=ValueError("snmp boom")):
            res = security.deep_check_host("10.0.0.5")
        self.assertTrue([f for f in res["findings"] if f["category"] == "cve"])      # rest of audit survived

    def test_findings_sorted_scored_and_deduped(self):
        probe = [{"category": "weak-auth", "severity": "critical", "title": "Unauthenticated Redis exposed",
                  "host": "10.0.0.5", "port": 6379, "detail": "d", "evidence": ""}] * 2     # duplicate
        res = self.run_deep({22: fp(22, "openssh", "7.2p2"), 443: fp(443), 6379: fp(6379)}, probes_out=probe)
        sev = [F.severity_rank(f) for f in res["findings"]]
        self.assertEqual(sev, sorted(sev))
        self.assertEqual(len({f["id"] for f in res["findings"]}), len(res["findings"]))
        self.assertEqual(res["risk_score"], F.risk_score(res["findings"]))
        self.assertGreater(res["risk_score"], 0)

    def test_services_and_open_ports_annotated(self):
        res = self.run_deep({22: fp(22, "openssh", "7.2p2", banner="SSH-2.0-OpenSSH_7.2p2"), 443: fp(443), 6379: fp(6379)})
        svc = {s["port"]: s for s in res["services"]}
        self.assertEqual((svc[22]["product"], svc[22]["version"]), ("openssh", "7.2p2"))
        self.assertEqual([p["port"] for p in res["open_ports"]], [22, 443, 6379])
        self.assertEqual(res["open_ports"][0]["banner"], "SSH-2.0-OpenSSH_7.2p2")

    def test_no_open_ports_is_a_clean_zero(self):
        res = self.run_deep({}, open_ports=[])
        self.assertEqual((res["findings"], res["risk_score"], res["services"]), ([], 0, []))

    def test_product_without_version_matches_only_wildcards(self):
        res = self.run_deep({22: fp(22, "openssh", ""), 443: fp(443), 6379: fp(6379)})
        self.assertEqual([f for f in res["findings"] if f["category"] == "cve"], [])


class HostsAndSummaryTests(unittest.TestCase):
    def test_hosts_accept_dicts_and_strings_and_timing_is_forwarded(self):
        seen = []
        with mock.patch.object(security, "deep_check_host",
                               side_effect=lambda ip, ports=None, timing=None: seen.append((ip, timing)) or
                               {"host": ip, "findings": [], "risk_score": 0}):
            security.deep_check_hosts([{"ip": "10.0.0.1"}, "10.0.0.2"], timing=1)
        self.assertEqual(seen, [("10.0.0.1", 1), ("10.0.0.2", 1)])

    def test_quick_check_forwards_timing_and_flags_risky(self):
        with mock.patch.object(security.portscan, "scan", return_value=[{"port": 23, "service": "telnet"},
                                                                       {"port": 80, "service": "http"}]) as scan:
            res = security.check_hosts([{"ip": "10.0.0.1"}], timing=0)
        self.assertEqual(scan.call_args.kwargs["timing"], 0)
        self.assertEqual([f["port"] for f in res[0]["risky_findings"]], [23])
        self.assertIn("port 23", security.summarize(res))

    def test_summarize_deep_orders_hosts_by_risk_and_handles_empty(self):
        hi = F.make_finding("cve", "critical", "Bad", host="b", port=22)
        lo = F.make_finding("tls", "low", "Meh", host="a", port=443)
        text = security.summarize_deep([
            {"host": "a", "findings": [lo], "risk_score": F.risk_score([lo])},
            {"host": "b", "findings": [hi], "risk_score": F.risk_score([hi])},
            {"host": "c", "findings": [], "risk_score": 0}])
        self.assertLess(text.index("b  (risk"), text.index("a  (risk"))
        self.assertNotIn("c  (risk", text)
        self.assertIn("critical 1", text)
        self.assertIn("No findings", security.summarize_deep([{"host": "c", "findings": [], "risk_score": 0}]))
        self.assertIn("No findings", security.summarize_deep([]))

    def test_unresolvable_host_raises_runtime_error(self):
        with self.assertRaises(RuntimeError):
            security.deep_check_host("no-such-host.invalid")

    def test_check_host_on_real_loopback_listener(self):
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        s.listen(1)
        self.addCleanup(s.close)
        port = s.getsockname()[1]
        with mock.patch.dict(security.RISKY_PORTS, {port: "test-risky"}):
            res = security.check_host("127.0.0.1", ports=[port], timing=5)
        self.assertEqual(res["risky_findings"][0]["risk"], "test-risky")


if __name__ == "__main__":
    unittest.main()
