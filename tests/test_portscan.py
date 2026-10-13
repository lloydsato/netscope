"""Tests for TCP/UDP scanning against loopback listeners."""

import socket
import threading
import unittest

from netscope import portscan
from netscope.utils import timing_profile, TIMING_PROFILES


def _listen():
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", 0))
    s.listen(16)
    return s, s.getsockname()[1]


def _free_port():
    s, port = _listen()
    s.close()
    return port


class TcpScanTests(unittest.TestCase):
    def setUp(self):
        self.srv, self.port = _listen()
        self.addCleanup(self.srv.close)

    def test_finds_open_port_and_skips_closed(self):
        closed = _free_port()
        res = portscan.scan("127.0.0.1", ports=[self.port, closed], timeout=0.5)
        self.assertEqual([r["port"] for r in res], [self.port])

    def test_results_sorted_and_labelled(self):
        s2, p2 = _listen()
        self.addCleanup(s2.close)
        res = portscan.scan("127.0.0.1", ports=[max(self.port, p2), min(self.port, p2)], timeout=0.5)
        self.assertEqual([r["port"] for r in res], sorted([self.port, p2]))
        self.assertTrue(all(r["service"] for r in res))

    def test_duplicates_collapsed(self):
        res = portscan.scan("127.0.0.1", ports=[self.port, self.port, self.port], timeout=0.5)
        self.assertEqual(len(res), 1)

    def test_empty_port_list(self):
        self.assertEqual(portscan.scan("127.0.0.1", ports=[]), [])

    def test_accepts_any_iterable(self):
        self.assertEqual(len(portscan.scan("127.0.0.1", ports=iter([self.port]), timeout=0.5)), 1)
        self.assertEqual(len(portscan.scan("127.0.0.1", ports=(p for p in [self.port]), timeout=0.5)), 1)

    def test_invalid_ports_raise_value_error_not_crash(self):
        # Regression: 70000 raised OverflowError inside a worker thread.
        for bad in ([0], [-1], [65536], [70000], ["80"], [80.0], [None], [True]):
            with self.assertRaises(ValueError, msg=bad):
                portscan.scan("127.0.0.1", ports=bad)

    def test_boundary_ports_accepted(self):
        portscan.scan("127.0.0.1", ports=[1, 65535], timeout=0.2)

    def test_unresolvable_host(self):
        with self.assertRaises(RuntimeError) as cm:
            portscan.scan("no-such-host.invalid", ports=[80])
        self.assertIn("Could not resolve", str(cm.exception))

    def test_caller_list_not_mutated(self):
        ports = [self.port, _free_port(), _free_port()]
        before = list(ports)
        portscan.scan("127.0.0.1", ports=ports, timeout=0.3)
        self.assertEqual(ports, before)         # shuffling must happen on a copy

    def test_default_ports_come_from_common_list(self):
        self.assertIn(22, portscan.COMMON_SCAN_PORTS)
        self.assertEqual(portscan.COMMON_SCAN_PORTS, sorted(set(portscan.COMMON_SCAN_PORTS)))

    def test_timing_levels_all_work(self):
        for level in range(0, 6):
            res = portscan.scan("127.0.0.1", ports=[self.port], timing=level, timeout=0.5, max_workers=4)
            self.assertEqual(len(res), 1, level)

    def test_scan_port_swallows_connection_errors(self):
        self.assertIsNone(portscan.scan_port("127.0.0.1", _free_port(), 0.2))
        self.assertIsNone(portscan.scan_port("127.0.0.1", 70000, 0.2))

    def test_many_ports_concurrently(self):
        res = portscan.scan("127.0.0.1", ports=range(1, 1025), timeout=0.2, max_workers=200)
        self.assertIsInstance(res, list)         # completes, and every entry is well-formed
        self.assertTrue(all(set(r) == {"port", "service"} for r in res))


class TimingProfileTests(unittest.TestCase):
    def test_levels_clamped(self):
        self.assertEqual(timing_profile(-5)["level"], 0)
        self.assertEqual(timing_profile(99)["level"], 5)
        self.assertEqual(timing_profile(None)["level"], 3)
        self.assertEqual(timing_profile("4")["level"], 4)

    def test_monotonic_speed(self):
        timeouts = [TIMING_PROFILES[i]["timeout"] for i in range(6)]
        workers = [TIMING_PROFILES[i]["workers"] for i in range(6)]
        self.assertEqual(timeouts, sorted(timeouts, reverse=True))   # faster = shorter timeout
        self.assertEqual(workers, sorted(workers))                   # faster = more workers


class UdpScanTests(unittest.TestCase):
    def test_closed_udp_port_reports_closed(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        self.assertEqual(portscan.scan_udp_port("127.0.0.1", port, timeout=1.0), "closed")

    def test_responding_udp_port_reports_open(self):
        u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        u.bind(("127.0.0.1", 0))
        self.addCleanup(u.close)

        def echo():
            data, addr = u.recvfrom(1024)
            u.sendto(b"pong", addr)

        threading.Thread(target=echo, daemon=True).start()
        self.assertEqual(portscan.scan_udp_port("127.0.0.1", u.getsockname()[1], timeout=2.0), "open")

    def test_silent_udp_port_reports_open_or_filtered(self):
        u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        u.bind(("127.0.0.1", 0))
        self.addCleanup(u.close)
        self.assertEqual(portscan.scan_udp_port("127.0.0.1", u.getsockname()[1], timeout=0.3),
                         "open|filtered")

    def test_scan_udp_omits_closed_and_sorts(self):
        quiet = []
        for _ in range(2):
            u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            u.bind(("127.0.0.1", 0))
            self.addCleanup(u.close)
            quiet.append(u.getsockname()[1])
        c = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        c.bind(("127.0.0.1", 0))
        closed = c.getsockname()[1]
        c.close()
        res = portscan.scan_udp("127.0.0.1", ports=quiet + [closed], timeout=0.3)
        self.assertEqual([r["port"] for r in res], sorted(quiet))
        self.assertTrue(all(r["state"] == "open|filtered" for r in res))

    def test_scan_udp_validates_ports_and_host(self):
        with self.assertRaises(ValueError):
            portscan.scan_udp("127.0.0.1", ports=[99999])
        with self.assertRaises(RuntimeError):
            portscan.scan_udp("no-such-host.invalid", ports=[53])
        self.assertEqual(portscan.scan_udp("127.0.0.1", ports=[]), [])

    def test_known_probes_are_well_formed(self):
        self.assertEqual(portscan._UDP_PROBES[123][0], 0x1B)          # NTP client mode
        self.assertEqual(len(portscan._UDP_PROBES[123]), 48)
        self.assertEqual(portscan._UDP_PROBES[161][0], 0x30)          # SNMP SEQUENCE


if __name__ == "__main__":
    unittest.main()
