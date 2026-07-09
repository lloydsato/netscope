"""Tests for SNI extraction and offline pcap analysis.

The pcap-replay tests need scapy; they skip cleanly if it isn't installed.
"""

import os
import random
import string
import tempfile
import unittest

from netscope.capture import _extract_sni, _parent_domain

try:
    from scapy.all import Ether, IP, TCP, UDP, DNS, DNSQR, wrpcap  # noqa: F401
    _HAVE_SCAPY = True
except Exception:
    _HAVE_SCAPY = False


def _client_hello(host):
    hb = host.encode()
    sni = b"\x00" + len(hb).to_bytes(2, "big") + hb
    sni_list = len(sni).to_bytes(2, "big") + sni
    ext = b"\x00\x00" + len(sni_list).to_bytes(2, "big") + sni_list
    exts = len(ext).to_bytes(2, "big") + ext
    body = b"\x03\x03" + b"\x00" * 32 + b"\x00" + b"\x00\x02\x00\x2f" + b"\x01\x00" + exts
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + len(hs).to_bytes(2, "big") + hs


class SniTests(unittest.TestCase):
    def test_extract(self):
        self.assertEqual(_extract_sni(_client_hello("secure.example.org")), "secure.example.org")

    def test_non_tls_returns_empty(self):
        self.assertEqual(_extract_sni(b"GET / HTTP/1.1\r\n"), "")

    def test_parent_domain(self):
        self.assertEqual(_parent_domain("a.b.evil.com"), "evil.com")
        self.assertEqual(_parent_domain("example.com"), "example.com")


@unittest.skipUnless(_HAVE_SCAPY, "scapy not available")
class OfflinePcapTests(unittest.TestCase):
    def setUp(self):
        from scapy.all import Ether, IP, TCP, UDP, DNS, DNSQR, wrpcap
        pkts = []
        base = 1_700_000_000
        for i in range(10):  # regular beacon
            p = Ether() / IP(src="192.168.1.10", dst="203.0.113.5") / TCP(sport=40000 + i, dport=443, flags="S")
            p.time = base + i * 60
            pkts.append(p)
        random.seed(1)
        for i in range(30):  # DNS tunnel
            label = "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(50))
            p = Ether() / IP(src="192.168.1.10", dst="8.8.8.8") / UDP(sport=55000 + i, dport=53) / \
                DNS(rd=1, qd=DNSQR(qname=f"{label}.evil-tunnel.com", qtype="TXT"))
            p.time = base + i
            pkts.append(p)
        self.pcap = tempfile.mktemp(suffix=".pcap")
        wrpcap(self.pcap, pkts)

    def tearDown(self):
        if os.path.exists(self.pcap):
            os.unlink(self.pcap)

    def test_offline_replay_detects_threats(self):
        from netscope import capture
        s = capture.capture(read_pcap=self.pcap)
        self.assertTrue(s["offline"])
        self.assertEqual(len(s["beaconing"]), 1)
        self.assertEqual(s["beaconing"][0]["dst"], "203.0.113.5")
        self.assertTrue(any(d["domain"] == "evil-tunnel.com" for d in s["dns_tunneling"]))
        cats = " ".join(m for _, m in s["alerts"])
        self.assertIn("BEACON", cats)
        self.assertIn("DNS-TUNNEL", cats)


if __name__ == "__main__":
    unittest.main()
