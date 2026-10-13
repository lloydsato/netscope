"""Tests for SNI extraction and offline pcap analysis.

The pcap-replay tests need scapy; they skip cleanly if it isn't installed.
"""

import importlib.util
import os
import random
import string
import tempfile
import unittest

from netscope.capture import _extract_sni, _parent_domain

_HAVE_SCAPY = importlib.util.find_spec("scapy") is not None


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


class SniTolerance(unittest.TestCase):
    def test_truncated_and_hostile_hello_never_raises(self):
        good = _client_hello("secure.example.org")
        for cut in range(0, len(good)):
            self.assertIsInstance(_extract_sni(good[:cut]), str)       # every truncation point
        self.assertEqual(_extract_sni(b"\x16\x03\x01" + b"\xff" * 80), "")
        self.assertEqual(_extract_sni(b""), "")

    def test_parent_domain_public_suffixes(self):
        # Regression: *.co.uk all collapsed into one "co.uk" bucket.
        self.assertEqual(_parent_domain("www.bbc.co.uk"), "bbc.co.uk")
        self.assertEqual(_parent_domain("a.b.example.com.au"), "example.com.au")
        self.assertEqual(_parent_domain("shop.co.uk"), "shop.co.uk")
        self.assertEqual(_parent_domain("deep.sub.example.org"), "example.org")
        self.assertEqual(_parent_domain("example.com."), "example.com")       # trailing dot
        self.assertEqual(_parent_domain("localhost"), "localhost")
        self.assertEqual(_parent_domain(""), "")


@unittest.skipUnless(_HAVE_SCAPY, "scapy not available")
class DetectionAccuracyTests(unittest.TestCase):
    def setUp(self):
        self._files = []

    def tearDown(self):
        for f in self._files:
            if os.path.exists(f):
                os.unlink(f)

    def _run(self, pkts, **kw):
        from scapy.all import wrpcap
        from netscope import capture
        f = tempfile.mktemp(suffix=".pcap")
        self._files.append(f)
        wrpcap(f, pkts)
        return capture.capture(read_pcap=f, **kw)

    @staticmethod
    def _tcp(src, dst, sport, dport, flags="S", payload=None):
        from scapy.all import Ether, IP, TCP, Raw
        p = Ether() / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags=flags)
        return p / Raw(payload) if payload else p

    def _msgs(self, summary, prefix):
        return [m for _, m in summary["alerts"] if m.startswith(prefix)]

    # --- plaintext protocols ---
    def test_bare_syn_to_telnet_or_ftp_port_is_not_a_cleartext_session(self):
        # Regression: any packet touching port 23/21 (a port scan, or netscope's own
        # portscan) raised "credentials/data exposed in the clear".
        pk = [self._tcp("10.0.0.50", "10.0.0.9", 40000, 23), self._tcp("10.0.0.9", "10.0.0.50", 23, 40000, "RA"),
              self._tcp("10.0.0.50", "10.0.0.9", 40001, 21)]
        self.assertEqual(self._msgs(self._run(pk), "PLAINTEXT"), [])

    def test_real_telnet_and_ftp_sessions_flagged_once_client_to_server(self):
        pk = [self._tcp("10.0.0.5", "10.0.0.9", 40000, 23, "PA", b"login: "),
              self._tcp("10.0.0.9", "10.0.0.5", 23, 40000, "PA", b"Password:"),
              self._tcp("10.0.0.5", "10.0.0.9", 40001, 21, "PA", b"USER x\r\n"),
              self._tcp("10.0.0.9", "10.0.0.5", 21, 40001, "PA", b"331 pw\r\n")]
        msgs = self._msgs(self._run(pk), "PLAINTEXT")
        self.assertEqual(len(msgs), 2)
        self.assertTrue(any("Telnet between 10.0.0.5 -> 10.0.0.9" in m for m in msgs))
        self.assertTrue(any("FTP between 10.0.0.5 -> 10.0.0.9" in m for m in msgs))

    def test_http_basic_auth_flagged_case_insensitively_without_leaking_secret(self):
        for hdr in (b"Authorization: Basic c2VjcmV0OnBhc3M=", b"authorization: basic c2VjcmV0OnBhc3M="):
            pk = [self._tcp("10.0.0.5", "10.0.0.9", 40000, 80, "PA", b"GET / HTTP/1.1\r\n" + hdr + b"\r\n\r\n")]
            s = self._run(pk)
            msgs = self._msgs(s, "PLAINTEXT")
            self.assertEqual(len(msgs), 1, hdr)
            self.assertNotIn("c2VjcmV0", " ".join(m for _, m in s["alerts"]))     # never surfaces the credential
            self.assertNotIn("c2VjcmV0", repr(s))

    def test_http_without_basic_auth_not_flagged(self):
        pk = [self._tcp("10.0.0.5", "10.0.0.9", 40000, 80, "PA", b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")]
        self.assertEqual(self._msgs(self._run(pk), "PLAINTEXT"), [])

    # --- port scans ---
    def test_normal_browsing_is_not_a_port_scan(self):
        # Regression: 30 completed connections to one CDN were reported as
        # "30 half-open SYNs -- likely port scanning".
        pk = []
        for i in range(30):
            sp = 50000 + i
            pk += [self._tcp("10.0.0.20", "151.101.1.1", sp, 443), self._tcp("151.101.1.1", "10.0.0.20", 443, sp, "SA"),
                   self._tcp("10.0.0.20", "151.101.1.1", sp, 443, "A")]
        self.assertEqual(self._run(pk)["possible_scanners"], [])

    def test_vertical_scan_detected(self):
        pk = [self._tcp("10.0.0.66", "10.0.0.1", 41000 + i, 1000 + i) for i in range(40)]
        s = self._run(pk)
        self.assertEqual(s["possible_scanners"][0]["kind"], "vertical")
        self.assertEqual(len(self._msgs(s, "SCAN")), 1)

    def test_horizontal_sweep_detected_but_web_fanout_ignored(self):
        sweep = [self._tcp("10.0.0.66", f"10.0.0.{i}", 41000 + i, 445) for i in range(1, 41)]
        self.assertEqual(self._run(sweep)["possible_scanners"][0]["kind"], "horizontal")
        web = [self._tcp("10.0.0.20", f"34.1.{i}.1", 42000 + i, 443) for i in range(60)]
        self.assertEqual(self._run(web)["possible_scanners"], [])

    # --- hostile input ---
    def test_dns_names_are_sanitised_against_terminal_escapes(self):
        from scapy.all import Ether, IP, UDP, DNS, DNSQR
        pk = [Ether() / IP(src="10.0.0.20", dst="8.8.8.8") / UDP(sport=5555, dport=53) /
              DNS(rd=1, qd=DNSQR(qname="\x1b[2J\x1b]0;pwned\x07.evil.com"))]
        s = self._run(pk)
        self.assertTrue(s["top_dns"])
        self.assertNotIn("\x1b", str(s))             # nothing in the summary can drive a terminal
        self.assertNotIn("\x07", str(s))
        for name, _ in s["top_dns"]:
            self.assertTrue(all(" " <= ch <= "~" for ch in name), repr(name))
            self.assertIn("evil.com", name)           # still useful to the analyst

    def test_sni_is_sanitised(self):
        hello = _client_hello("evil\x1b[31m.example.org")
        s = self._run([self._tcp("10.0.0.5", "10.0.0.9", 40000, 443, "PA", hello)])
        self.assertTrue(s["top_sni"])
        self.assertNotIn("\x1b", str(s))
        for name, _ in s["top_sni"]:
            self.assertTrue(all(" " <= ch <= "~" for ch in name), repr(name))

    def test_ipv6_counted_as_ipv6_not_non_ip(self):
        from scapy.all import Ether, IPv6, UDP
        s = self._run([Ether() / IPv6(src="fe80::1", dst="fe80::2") / UDP(sport=1, dport=2)])
        self.assertEqual(s["protocol_counts"], {"IPv6": 1})

    def test_arp_spoof_and_rogue_dhcp_detected(self):
        from scapy.all import Ether, ARP, IP, UDP, BOOTP, DHCP
        arp = lambda mac: Ether(src=mac) / ARP(op=2, psrc="10.0.0.1", hwsrc=mac, pdst="10.0.0.9")
        dhcp = lambda srv, mac: (Ether(src=mac) / IP(src=srv, dst="255.255.255.255") /
                                 UDP(sport=67, dport=68) / BOOTP() / DHCP(options=[("message-type", 2), "end"]))
        s = self._run([arp("aa:aa:aa:aa:aa:01"), arp("bb:bb:bb:bb:bb:02"),
                       dhcp("10.0.0.1", "aa:aa:aa:aa:aa:01"), dhcp("10.0.0.66", "bb:bb:bb:bb:bb:02")],
                      gateway_ip="10.0.0.1")
        self.assertEqual(s["arp_anomalies"][0]["severity"], "critical")
        self.assertEqual(len(s["dhcp_servers"]), 2)
        self.assertTrue(self._msgs(s, "DHCP"))
        self.assertTrue(self._msgs(s, "ARP"))
        self.assertEqual(s["protocol_counts"].get("ARP"), 2)

    def test_arp_probe_from_0_0_0_0_ignored(self):
        from scapy.all import Ether, ARP
        pk = [Ether(src="aa:aa:aa:aa:aa:01") / ARP(op=1, psrc="0.0.0.0", hwsrc="aa:aa:aa:aa:aa:01", pdst="10.0.0.9"),
              Ether(src="bb:bb:bb:bb:bb:02") / ARP(op=1, psrc="0.0.0.0", hwsrc="bb:bb:bb:bb:bb:02", pdst="10.0.0.9")]
        self.assertEqual(self._run(pk)["arp_anomalies"], [])

    # --- robustness ---
    def test_missing_corrupt_and_empty_pcaps_give_clean_errors(self):
        from netscope import capture
        with self.assertRaises(RuntimeError):
            capture.capture(read_pcap="/definitely/not/here.pcap")
        bad = tempfile.mktemp(suffix=".pcap")
        self._files.append(bad)
        with open(bad, "w") as f:
            f.write("this is not a pcap")
        with self.assertRaises(RuntimeError):
            capture.capture(read_pcap=bad)
        empty = tempfile.mktemp(suffix=".pcap")
        self._files.append(empty)
        open(empty, "wb").close()
        with self.assertRaises(RuntimeError):
            capture.capture(read_pcap=empty)

    def test_truncated_pcap_reports_what_was_read(self):
        from scapy.all import wrpcap, Ether, IP, UDP
        from netscope import capture
        f = tempfile.mktemp(suffix=".pcap")
        self._files.append(f)
        wrpcap(f, [Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / UDP() for _ in range(20)])
        with open(f, "rb") as fh:
            data = fh.read()
        with open(f, "wb") as fh:
            fh.write(data[:-7])                       # chop the last record mid-packet
        try:
            s = capture.capture(read_pcap=f)
            self.assertGreaterEqual(s["total_packets"], 19)       # scapy tolerates the tail ...
        except RuntimeError as e:
            self.assertIn("pcap", str(e))                          # ... or we report it cleanly

    def test_empty_capture_has_zero_everything(self):
        from scapy.all import wrpcap
        f = tempfile.mktemp(suffix=".pcap")
        self._files.append(f)
        wrpcap(f, [])
        from netscope import capture
        s = capture.capture(read_pcap=f)
        self.assertEqual((s["total_packets"], s["alerts"], s["top_bandwidth"]), (0, [], []))

    def test_pcap_out_is_streamed_and_replayable(self):
        from scapy.all import Ether, IP, UDP, rdpcap
        out = tempfile.mktemp(suffix=".pcap")
        self._files.append(out)
        pk = [Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=1000 + i, dport=9) for i in range(15)]
        s = self._run(pk, pcap_out=out)
        self.assertEqual(s["pcap_out"], out)
        self.assertEqual(len(rdpcap(out)), 15)

    def test_unwritable_pcap_out_fails_before_capturing(self):
        from netscope import capture
        with self.assertRaises(RuntimeError):
            capture.capture(read_pcap=self._make_pcap(), pcap_out="/nonexistent_dir/x.pcap")

    def test_no_pcap_file_left_behind_when_nothing_captured(self):
        from scapy.all import wrpcap
        from netscope import capture
        src = tempfile.mktemp(suffix=".pcap")
        out = tempfile.mktemp(suffix=".pcap")
        self._files += [src, out]
        wrpcap(src, [])
        s = capture.capture(read_pcap=src, pcap_out=out)
        self.assertIsNone(s["pcap_out"])
        self.assertFalse(os.path.exists(out))

    def _make_pcap(self):
        from scapy.all import wrpcap, Ether, IP, UDP
        f = tempfile.mktemp(suffix=".pcap")
        self._files.append(f)
        wrpcap(f, [Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / UDP()])
        return f

    def test_state_is_bounded_under_hostile_volume(self):
        from scapy.all import Ether, IP, UDP, DNS, DNSQR
        from unittest import mock
        from netscope import capture
        pk = [Ether() / IP(src="10.0.0.20", dst="8.8.8.8") / UDP(sport=5000 + (i % 1000), dport=53) /
              DNS(rd=1, qd=DNSQR(qname=f"{i:06d}.t{i % 50}.example.com")) for i in range(400)]
        with mock.patch.object(capture, "_MAX_DNS_NAMES", 25), \
                mock.patch.object(capture, "_MAX_UNIQUE_PER_PARENT", 6), \
                mock.patch.object(capture, "_MAX_DNS_PARENTS", 10):
            s = self._run(pk)
        self.assertEqual(s["total_packets"], 400)
        self.assertLessEqual(len(s["top_dns"]), 15)


@unittest.skipUnless(_HAVE_SCAPY, "scapy not available")
class DnsTunnelFalsePositiveTests(unittest.TestCase):
    def test_busy_co_uk_domains_are_not_lumped_into_a_tunnel(self):
        # Regression: every *.co.uk query was bucketed under "co.uk"; enough
        # distinct sites plus one long label then looked like a tunnel.
        from scapy.all import Ether, IP, UDP, DNS, DNSQR, wrpcap
        from netscope import capture
        names = [f"www.site{i}.co.uk" for i in range(30)] + ["a" * 45 + ".other.co.uk"]
        pk = [Ether() / IP(src="10.0.0.20", dst="8.8.8.8") / UDP(sport=6000 + i, dport=53) /
              DNS(rd=1, qd=DNSQR(qname=n)) for i, n in enumerate(names)]
        f = tempfile.mktemp(suffix=".pcap")
        wrpcap(f, pk)
        try:
            s = capture.capture(read_pcap=f)
        finally:
            os.unlink(f)
        self.assertEqual(s["dns_tunneling"], [])


if __name__ == "__main__":
    unittest.main()
