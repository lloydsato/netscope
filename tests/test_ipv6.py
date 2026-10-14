"""IPv6 support: address-family handling, resolution, NDP discovery.

The IPv6 socket paths are exercised with recording fakes (so the tests don't need
an IPv6-capable host); one real loopback test runs only where ::1 works.
"""

import json
import socket
import sys
import types
import unittest
from unittest import mock

from netscope import discovery, fingerprint, portscan, probes, utils
from tests.test_cli import run_main

V6 = "2001:db8::10"
LL = "fe80::1ff:fe23:4567:890a"


class UtilsTests(unittest.TestCase):
    def test_is_ipv6(self):
        for h in ("::1", V6, LL, LL + "%eth0", "::ffff:10.0.0.1"):
            self.assertTrue(utils.is_ipv6(h), h)
        for h in ("10.0.0.1", "example.com", "", "1:2", "999.1.1.1", None):
            self.assertFalse(utils.is_ipv6(h), h)

    def test_family_for(self):
        self.assertEqual(utils.family_for("::1"), socket.AF_INET6)
        self.assertEqual(utils.family_for("10.0.0.1"), socket.AF_INET)

    def test_host_header_brackets_v6_only(self):
        self.assertEqual(utils.host_header("::1"), "[::1]")
        self.assertEqual(utils.host_header("[::1]"), "[::1]")
        self.assertEqual(utils.host_header("10.0.0.1"), "10.0.0.1")
        self.assertEqual(utils.host_header("router.lan"), "router.lan")


def gai(*addrs):
    """getaddrinfo result for the given addresses (family inferred)."""
    out = []
    for a in addrs:
        fam = socket.AF_INET6 if ":" in a else socket.AF_INET
        sa = (a, 0, 0, 0) if fam == socket.AF_INET6 else (a, 0)
        out.append((fam, socket.SOCK_STREAM, 6, "", sa))
    return out


class ResolveTests(unittest.TestCase):
    def test_literals_pass_through(self):
        self.assertEqual(portscan._resolve("::1"), "::1")
        self.assertEqual(portscan._resolve("127.0.0.1"), "127.0.0.1")

    def test_dual_stack_name_prefers_ipv4(self):
        with mock.patch.object(socket, "getaddrinfo", return_value=gai(V6, "10.0.0.7")):
            self.assertEqual(portscan._resolve("host.lan"), "10.0.0.7")

    def test_v6_only_name_resolves_to_v6(self):
        with mock.patch.object(socket, "getaddrinfo", return_value=gai(V6)):
            self.assertEqual(portscan._resolve("host.lan"), V6)

    def test_failures_keep_the_friendly_error(self):
        with mock.patch.object(socket, "getaddrinfo", side_effect=socket.gaierror("nope")):
            with self.assertRaises(RuntimeError) as cm:
                portscan._resolve("x.invalid")
        self.assertIn("Could not resolve", str(cm.exception))
        with mock.patch.object(socket, "getaddrinfo", return_value=[]):
            with self.assertRaises(RuntimeError):
                portscan._resolve("x.invalid")


class FakeSock:
    """Records the family it was created with; behaves like a connected socket."""
    made = []

    def __init__(self, family=socket.AF_INET, kind=socket.SOCK_STREAM, *a):
        self.family, self.kind, self.sent = family, kind, []
        FakeSock.made.append(self)

    def __enter__(self): return self
    def __exit__(self, *a): return False
    def settimeout(self, t): pass
    def connect(self, addr): self.addr = addr
    def connect_ex(self, addr): self.addr = addr; return 0
    def send(self, d): self.sent.append(d)
    def sendall(self, d): self.sent.append(d)
    def recv(self, n): raise socket.timeout()


class FamilySelectionTests(unittest.TestCase):
    def setUp(self):
        FakeSock.made = []

    def families(self, fn, *args):
        FakeSock.made = []
        with mock.patch.object(socket, "socket", FakeSock):
            fn(*args)
        return [s.family for s in FakeSock.made]

    def test_tcp_connect_scan(self):
        self.assertEqual(self.families(portscan.scan_port, V6, 80), [socket.AF_INET6])
        self.assertEqual(self.families(portscan.scan_port, "10.0.0.1", 80), [socket.AF_INET])

    def test_udp_probe(self):
        self.assertEqual(self.families(portscan.scan_udp_port, V6, 53), [socket.AF_INET6])
        self.assertEqual(self.families(portscan.scan_udp_port, "10.0.0.1", 53), [socket.AF_INET])

    def test_banner_grab(self):
        self.assertEqual(self.families(fingerprint._grab_generic, V6, 22, 0.1), [socket.AF_INET6])

    def test_snmp_probe(self):
        self.assertEqual(self.families(probes.check_snmp_default_community, V6), [socket.AF_INET6])
        self.assertEqual(self.families(probes.check_snmp_default_community, "10.0.0.1"), [socket.AF_INET])

    def test_full_scan_end_to_end_on_a_v6_literal(self):
        with mock.patch.object(socket, "socket", FakeSock):
            res = portscan.scan("::1", ports=[22, 80], timing=5)
        self.assertEqual([r["port"] for r in res], [22, 80])
        self.assertTrue(all(s.family == socket.AF_INET6 for s in FakeSock.made))


class HostHeaderTests(unittest.TestCase):
    def sent_by(self, fn, host):
        sent = []

        class Rec(FakeSock):
            def sendall(self, d): sent.append(d)
            def recv(self, n): return b""

        with mock.patch.object(socket, "create_connection", lambda *a, **k: Rec()):
            fn(host)
        return b"".join(sent)

    def test_elasticsearch_probe_brackets_v6_host(self):
        req = self.sent_by(probes.check_elasticsearch, V6)
        self.assertIn(b"Host: [" + V6.encode() + b"]\r\n", req)

    def test_v4_host_header_unchanged(self):
        req = self.sent_by(probes.check_elasticsearch, "10.0.0.7")
        self.assertIn(b"Host: 10.0.0.7\r\n", req)


class FakeScapy:
    """Minimal scapy.all stand-in for ndp_scan."""

    class _Layer:
        def __init__(self, **kw): self.kw = kw
        def __truediv__(self, other): return self

    class Ether(_Layer): pass
    class IPv6(_Layer): pass
    class ICMPv6EchoRequest(_Layer): pass

    def __init__(self, replies, iface="eth0"):
        self.calls = []
        mod = types.ModuleType("scapy.all")
        mod.Ether, mod.IPv6, mod.ICMPv6EchoRequest = self.Ether, self.IPv6, self.ICMPv6EchoRequest
        mod.conf = types.SimpleNamespace(iface=iface)
        replies = [({}, _Indexable({self.IPv6: types.SimpleNamespace(src=ip),
                                    self.Ether: types.SimpleNamespace(src=mac)})) for ip, mac in replies]

        def srp(pkt, **kw):
            self.calls.append(kw)
            return replies, []
        mod.srp = srp
        self.module = mod


class _Indexable:
    def __init__(self, layers): self._l = layers
    def __getitem__(self, key): return self._l[key]


class NdpScanTests(unittest.TestCase):
    def scan(self, replies, root=True, **kw):
        fake = FakeScapy(replies)
        with mock.patch.dict(sys.modules, {"scapy.all": fake.module}), \
                mock.patch.object(discovery, "is_root", return_value=root):
            return discovery.ndp_scan(**kw), fake

    def test_dedupes_sorts_skips_unspecified_and_zones_link_local(self):
        hosts, fake = self.scan([(LL, "aa:aa:aa:aa:aa:02"), (V6, "aa:aa:aa:aa:aa:01"),
                                 (LL, "aa:aa:aa:aa:aa:02"), ("::", "aa:aa:aa:aa:aa:03")], iface="eth0")
        # numeric address order: 2001:db8:: < fe80::
        self.assertEqual([(h["ip"], h["mac"]) for h in hosts],
                         [(V6, "aa:aa:aa:aa:aa:01"), (LL + "%eth0", "aa:aa:aa:aa:aa:02")])
        self.assertTrue(fake.calls[0]["multi"])
        self.assertEqual(fake.calls[0]["iface"], "eth0")

    def test_default_interface_comes_from_scapy(self):
        hosts, fake = self.scan([(LL, "aa:aa:aa:aa:aa:02")])
        self.assertEqual(hosts[0]["ip"], LL + "%eth0")

    def test_requires_root(self):
        with self.assertRaises(RuntimeError) as cm:
            self.scan([], root=False)
        self.assertIn("raw socket", str(cm.exception))

    def test_requires_scapy(self):
        with mock.patch.dict(sys.modules, {"scapy.all": None, "scapy": None}):
            with self.assertRaises(RuntimeError) as cm:
                discovery.ndp_scan()
        self.assertIn("scapy is required", str(cm.exception))

    def test_no_replies(self):
        self.assertEqual(self.scan([])[0], [])


class DiscoverIpv6CliTests(unittest.TestCase):
    def test_discover_ipv6_outputs_hosts(self):
        found = [{"ip": V6, "mac": "00:50:56:00:00:01"}]
        with mock.patch.object(discovery, "ndp_scan", return_value=found) as nd:
            code, out, _ = run_main("discover", "--ipv6", "--iface", "eth1", "--json")
        self.assertEqual(code, 0)
        nd.assert_called_once_with(iface="eth1")
        doc = json.loads(out)
        self.assertEqual(doc["hosts"][0]["ip"], V6)
        self.assertEqual(doc["method"], "ndp")
        self.assertIn("VMware", doc["hosts"][0]["vendor"])

    def test_ipv6_rejects_subnet(self):
        with mock.patch.object(discovery, "ndp_scan") as nd:
            code, _, err = run_main("discover", "--ipv6", "--subnet", "10.0.0.0/24")
        self.assertEqual(code, 2)
        self.assertIn("--subnet", err)
        nd.assert_not_called()

    def test_ndp_errors_are_reported(self):
        with mock.patch.object(discovery, "ndp_scan", side_effect=RuntimeError("needs root")):
            code, _, err = run_main("discover", "--ipv6")
        self.assertEqual((code, "needs root" in err), (1, True))

    def test_ipv4_discovery_unchanged(self):
        with mock.patch.object(discovery, "discover", return_value=("10.0.0.0/24", [], "sweep")) as d, \
                mock.patch.object(discovery, "ndp_scan") as nd:
            run_main("discover")
        d.assert_called_once()
        nd.assert_not_called()


def _v6_loopback_works():
    try:
        s = socket.socket(socket.AF_INET6)
        s.bind(("::1", 0))
        s.close()
        return True
    except OSError:
        return False


@unittest.skipUnless(_v6_loopback_works(), "no IPv6 loopback on this host")
class RealLoopbackTests(unittest.TestCase):
    def test_scan_and_fingerprint_a_real_v6_listener(self):
        srv = socket.socket(socket.AF_INET6)
        srv.bind(("::1", 0))
        srv.listen(5)
        port = srv.getsockname()[1]
        import threading

        def serve():
            try:
                while True:
                    c, _ = srv.accept()
                    c.sendall(b"SSH-2.0-OpenSSH_7.2p2 Ubuntu\r\n")
                    c.close()
            except OSError:
                pass
        threading.Thread(target=serve, daemon=True).start()
        try:
            self.assertEqual([r["port"] for r in portscan.scan("::1", ports=[port])], [port])
            fp = fingerprint.fingerprint_port("::1", port)
            self.assertEqual(fp["product"], "openssh")
        finally:
            srv.close()


if __name__ == "__main__":
    unittest.main()
