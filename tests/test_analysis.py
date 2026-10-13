"""Tests for the advanced passive detectors (beaconing, DNS tunnelling)."""

import unittest

from netscope import analysis
from netscope.utils import shannon_entropy


class BeaconingTests(unittest.TestCase):
    def test_regular_interval_flagged(self):
        base = 1_700_000_000
        conn = {("10.0.0.5", "203.0.113.9", 443): [base + i * 60 for i in range(10)]}
        out = analysis.detect_beaconing(conn)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["dst"], "203.0.113.9")
        self.assertAlmostEqual(out[0]["interval"], 60.0, delta=0.1)

    def test_irregular_not_flagged(self):
        base = 1_700_000_000
        gaps = [1, 40, 3, 200, 5, 9, 120, 2]
        times, t = [], base
        for g in gaps:
            t += g
            times.append(t)
        conn = {("10.0.0.5", "93.184.216.34", 443): times}
        self.assertEqual(analysis.detect_beaconing(conn), [])

    def test_too_few_events(self):
        conn = {("a", "b", 1): [1, 2, 3]}
        self.assertEqual(analysis.detect_beaconing(conn), [])


class DnsTunnelingTests(unittest.TestCase):
    def test_high_entropy_long_labels_flagged(self):
        stats = {"evil-tunnel.com": {
            "count": 40, "unique": 40,
            "labels": ["a" * 50],  # long label
            "max_entropy": 4.5, "txt": 40,
        }}
        out = analysis.detect_dns_tunneling(stats)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["domain"], "evil-tunnel.com")

    def test_normal_domain_not_flagged(self):
        stats = {"example.com": {
            "count": 5, "unique": 2, "labels": ["www"], "max_entropy": 1.8, "txt": 0,
        }}
        self.assertEqual(analysis.detect_dns_tunneling(stats), [])

    def test_single_signal_not_enough(self):
        # Many unique subdomains but short/low-entropy labels (like a CDN) ->
        # only one signal, should not flag.
        stats = {"cdn.example.net": {
            "count": 100, "unique": 100, "labels": ["img1"], "max_entropy": 2.0, "txt": 0,
        }}
        self.assertEqual(analysis.detect_dns_tunneling(stats), [])


class EntropyTests(unittest.TestCase):
    def test_entropy_ordering(self):
        self.assertEqual(shannon_entropy(""), 0.0)
        self.assertEqual(shannon_entropy("aaaa"), 0.0)
        self.assertGreater(shannon_entropy("ab7d9f2kx"), shannon_entropy("aaaaab"))


class SummarizeTests(unittest.TestCase):
    def test_alerts_include_new_categories(self):
        summary = {
            "beaconing": [{"severity": "high", "note": "beacon note"}],
            "dns_tunneling": [{"severity": "high", "note": "tunnel note"}],
        }
        alerts = analysis.summarize_findings(summary)
        msgs = " ".join(m for _, m in alerts)
        self.assertIn("BEACON", msgs)
        self.assertIn("DNS-TUNNEL", msgs)


class PortScanTests(unittest.TestCase):
    def test_vertical_scan_flagged(self):
        t = {"10.0.0.66": {"10.0.0.1": set(range(1000, 1040))}}
        out = analysis.detect_port_scans(t)
        self.assertEqual(len(out), 1)
        self.assertEqual((out[0]["kind"], out[0]["target"], out[0]["ports"]), ("vertical", "10.0.0.1", 40))

    def test_horizontal_sweep_flagged(self):
        t = {"10.0.0.66": {f"10.0.0.{i}": {445} for i in range(1, 41)}}
        out = analysis.detect_port_scans(t)
        self.assertEqual((out[0]["kind"], out[0]["hosts"]), ("horizontal", 40))
        self.assertIn("445", out[0]["note"])

    def test_many_connections_to_one_service_is_not_a_scan(self):
        # 200 SYNs, but all to one host:port -- an ordinary busy client.
        self.assertEqual(analysis.detect_port_scans({"10.0.0.5": {"151.101.1.1": {443}}}), [])

    def test_web_fanout_is_not_a_scan(self):
        t = {"10.0.0.5": {f"34.1.{i}.1": {443} for i in range(100)}}
        self.assertEqual(analysis.detect_port_scans(t), [])

    def test_thresholds_are_boundaries(self):
        just_under = {"a": {"b": set(range(1, 15))}}
        just_over = {"a": {"b": set(range(1, 16))}}
        self.assertEqual(analysis.detect_port_scans(just_under), [])
        self.assertEqual(len(analysis.detect_port_scans(just_over)), 1)

    def test_empty_inputs(self):
        self.assertEqual(analysis.detect_port_scans({}), [])
        self.assertEqual(analysis.detect_port_scans({"a": {}}), [])

    def test_ordering_and_alert_rendering(self):
        t = {"small": {"x": set(range(1, 20))}, "big": {"x": set(range(1, 100))}}
        out = analysis.detect_port_scans(t)
        self.assertEqual([f["ip"] for f in out], ["big", "small"])
        alerts = analysis.summarize_findings({"possible_scanners": out})
        self.assertTrue(all(a[1].startswith("SCAN:") for a in alerts))


class SummarizeAlertOrderTests(unittest.TestCase):
    def test_alerts_sorted_by_severity(self):
        alerts = analysis.summarize_findings({
            "insecure_protocols": [{"proto": "Telnet", "src": "a", "dst": "b"}],
            "arp_anomalies": [{"ip": "1.1.1.1", "macs": ["m1", "m2"], "severity": "critical", "note": "n"}],
        })
        self.assertEqual([a[0] for a in alerts], ["critical", "medium"])

    def test_empty(self):
        self.assertEqual(analysis.summarize_findings({}), [])


class ArpAndDhcpTests(unittest.TestCase):
    def test_gateway_spoof_is_critical_other_is_high(self):
        out = analysis.detect_arp_spoofing({"10.0.0.1": {"aa", "bb"}, "10.0.0.9": {"cc", "dd"}, "10.0.0.5": {"ee"}},
                                           gateway_ip="10.0.0.1")
        self.assertEqual([(f["ip"], f["severity"]) for f in out],
                         [("10.0.0.1", "critical"), ("10.0.0.9", "high")])

    def test_single_mac_not_flagged(self):
        self.assertEqual(analysis.detect_arp_spoofing({"10.0.0.5": {"aa"}}), [])

    def test_rogue_dhcp(self):
        self.assertEqual(analysis.detect_rogue_dhcp({"10.0.0.1": "aa"}), [])
        self.assertEqual(analysis.detect_rogue_dhcp({"10.0.0.1": "aa"}, expected_gateway="10.0.0.1"), [])
        multi = analysis.detect_rogue_dhcp({"10.0.0.1": "aa", "10.0.0.99": "bb"}, expected_gateway="10.0.0.1")
        self.assertEqual(sorted(f["severity"] for f in multi), ["high", "medium"])


class BeaconEdgeTests(unittest.TestCase):
    def test_identical_timestamps_do_not_divide_by_zero(self):
        self.assertEqual(analysis.detect_beaconing({("a", "b", 1): [5.0] * 20}), [])

    def test_unsorted_input_is_sorted(self):
        times = [60 * i for i in range(10)]
        times.reverse()
        self.assertEqual(len(analysis.detect_beaconing({("a", "b", 1): times})), 1)

    def test_dns_tunnel_needs_two_signals(self):
        one_signal = {"cdn.example": {"count": 100, "unique": 100, "labels": ["abc"], "max_entropy": 1.0, "txt": 0}}
        self.assertEqual(analysis.detect_dns_tunneling(one_signal), [])


if __name__ == "__main__":
    unittest.main()
