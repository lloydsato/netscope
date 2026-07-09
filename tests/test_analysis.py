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


if __name__ == "__main__":
    unittest.main()
