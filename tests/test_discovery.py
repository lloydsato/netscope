"""Tests for host discovery helpers (no root or real LAN required)."""

import socket
import sys
import types
import unittest
from unittest import mock

from netscope import discovery


class ParseSubnetTests(unittest.TestCase):
    def test_valid_forms(self):
        self.assertEqual(str(discovery.parse_subnet("192.168.1.77/24")), "192.168.1.0/24")   # host bits ok
        self.assertEqual(str(discovery.parse_subnet(" 10.1.2.3/32 ")), "10.1.2.3/32")
        self.assertEqual(str(discovery.parse_subnet("10.0.0.0/16")), "10.0.0.0/16")           # exactly the cap

    def test_rejects_garbage_ipv6_and_oversize(self):
        for bad in ("foo", "", "300.1.1.0/24", "10.0.0.0/33", "fe80::/64", "10.0.0.0/8", "0.0.0.0/0"):
            with self.assertRaises(RuntimeError, msg=bad):
                discovery.parse_subnet(bad)

    def test_error_message_is_actionable(self):
        with self.assertRaises(RuntimeError) as cm:
            discovery.parse_subnet("10.0.0.0/8")
        self.assertIn("/16", str(cm.exception))


class PingSweepTests(unittest.TestCase):
    def test_hosts_that_refuse_probes_are_still_found(self):
        # Regression: only completed connects counted, so a live host with all
        # probe ports closed (answers RST) was reported as down. Linux loopback
        # answers for all of 127.0.0.0/8 with RST on closed ports.
        hosts = discovery.ping_sweep("127.0.0.0/30", timeout=0.5)
        self.assertEqual([h["ip"] for h in hosts], ["127.0.0.1", "127.0.0.2"])
        self.assertTrue(all(h["mac"] is None for h in hosts))

    def test_silent_hosts_are_not_reported(self):
        with mock.patch.object(socket.socket, "connect_ex", return_value=110):   # ETIMEDOUT
            self.assertEqual(discovery.ping_sweep("127.0.0.0/30", timeout=0.1), [])

    def test_single_host_slash32(self):
        self.assertEqual([h["ip"] for h in discovery.ping_sweep("127.0.0.1/32", timeout=0.5)], ["127.0.0.1"])

    def test_sorted_numerically(self):
        with mock.patch.object(socket.socket, "connect_ex", return_value=0):
            ips = [h["ip"] for h in discovery.ping_sweep("10.0.0.0/28", timeout=0.1)]
        self.assertEqual(ips, sorted(ips, key=lambda x: tuple(map(int, x.split(".")))))
        self.assertEqual(len(ips), 14)             # /28 has 14 usable hosts

    def test_refuses_oversized_sweep_before_doing_any_work(self):
        with mock.patch.object(socket.socket, "connect_ex") as ce:
            with self.assertRaises(RuntimeError):
                discovery.ping_sweep("10.0.0.0/8")
            ce.assert_not_called()


class DiscoverTests(unittest.TestCase):
    def test_unknown_method(self):
        with self.assertRaises(ValueError):
            discovery.discover("127.0.0.0/30", "bogus")

    def test_sweep_method_returns_normalised_subnet(self):
        subnet, hosts, method = discovery.discover("127.0.0.5/30", "sweep")
        self.assertEqual((subnet, method), ("127.0.0.4/30", "sweep"))

    def test_no_subnet_and_no_autodetect(self):
        with mock.patch.object(discovery, "get_default_subnet", return_value=None):
            with self.assertRaises(RuntimeError):
                discovery.discover(None, "sweep")

    def test_auto_falls_back_to_sweep_without_privileges(self):
        with mock.patch.object(discovery, "is_root", return_value=False):
            subnet, hosts, method = discovery.discover("127.0.0.0/30", "auto")
        self.assertEqual(method, "sweep")
        self.assertEqual(len(hosts), 2)

    def test_explicit_arp_without_privileges_is_an_error_not_a_fallback(self):
        # Fake scapy so the privilege check is reached whether or not scapy is installed.
        fake = types.ModuleType("scapy.all")
        fake.ARP = fake.Ether = fake.srp = None
        with mock.patch.dict(sys.modules, {"scapy.all": fake}), \
                mock.patch.object(discovery, "is_root", return_value=False):
            with self.assertRaises(RuntimeError) as cm:
                discovery.discover("127.0.0.0/30", "arp")
        self.assertIn("raw socket", str(cm.exception))


class ArpScanTests(unittest.TestCase):
    def _fake_scapy(self, answers):
        mod = types.ModuleType("scapy.all")
        mod.ARP = lambda **kw: ("arp", kw)
        mod.Ether = lambda **kw: _Chain()
        mod.srp = lambda pkt, timeout, verbose: (answers, [])
        return mod

    def test_duplicates_collapsed_and_sorted(self):
        rx = lambda ip, mac: types.SimpleNamespace(psrc=ip, hwsrc=mac)
        answers = [(None, rx("192.168.1.10", "aa:aa:aa:aa:aa:10")),
                   (None, rx("192.168.1.2", "aa:aa:aa:aa:aa:02")),
                   (None, rx("192.168.1.10", "aa:aa:aa:aa:aa:10")),        # duplicate reply
                   (None, rx("192.168.1.10", "bb:bb:bb:bb:bb:10"))]        # same IP, different MAC: keep both
        with mock.patch.dict(sys.modules, {"scapy.all": self._fake_scapy(answers)}), \
                mock.patch.object(discovery, "is_root", return_value=True):
            hosts = discovery.arp_scan("192.168.1.0/24")
        self.assertEqual([(h["ip"], h["mac"]) for h in hosts],
                         [("192.168.1.2", "aa:aa:aa:aa:aa:02"), ("192.168.1.10", "aa:aa:aa:aa:aa:10"),
                          ("192.168.1.10", "bb:bb:bb:bb:bb:10")])

    def test_requires_root(self):
        with mock.patch.dict(sys.modules, {"scapy.all": self._fake_scapy([])}), \
                mock.patch.object(discovery, "is_root", return_value=False):
            with self.assertRaises(RuntimeError):
                discovery.arp_scan("192.168.1.0/24")

    def test_invalid_subnet_rejected_before_sending(self):
        with mock.patch.dict(sys.modules, {"scapy.all": self._fake_scapy([])}), \
                mock.patch.object(discovery, "is_root", return_value=True):
            with self.assertRaises(RuntimeError):
                discovery.arp_scan("not-a-subnet")


class _Chain:
    def __truediv__(self, other):
        return self


if __name__ == "__main__":
    unittest.main()
