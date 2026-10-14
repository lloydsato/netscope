"""Name & service discovery: mDNS / SSDP / NetBIOS parsers and orchestration.

No network is touched: packets are canned and the socket-level helpers are patched.
"""

import socket
import struct
import unittest
from unittest import mock

from netscope import nameservices as ns, findings as F


def dns_name(name):
    return b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"


def rr(owner, rtype, rdata, cls=1, ttl=120):
    return dns_name(owner) + struct.pack(">HHIH", rtype, cls, ttl, len(rdata)) + rdata


def mdns_response(*records):
    return struct.pack(">HHHHHH", 0, 0x8400, 0, len(records), 0, 0) + b"".join(records)


class MdnsTests(unittest.TestCase):
    def test_a_record_gives_hostname_for_matching_source(self):
        pkt = mdns_response(rr("Living-Room-TV.local", 1, socket.inet_aton("10.0.0.7")))
        info = ns.collect_mdns([("10.0.0.7", pkt)])
        self.assertEqual(info["10.0.0.7"]["hostname"], "Living-Room-TV")

    def test_a_record_for_a_different_ip_is_not_trusted(self):
        # A device may announce on behalf of others; we only believe self-announcements.
        pkt = mdns_response(rr("victim.local", 1, socket.inet_aton("10.0.0.99")))
        info = ns.collect_mdns([("10.0.0.7", pkt)])
        self.assertEqual(info["10.0.0.7"]["hostname"], "")

    def test_service_types_collected(self):
        pkt = mdns_response(rr("_services._dns-sd._udp.local", 12, dns_name("_airplay._tcp.local")))
        info = ns.collect_mdns([("10.0.0.7", pkt)])
        self.assertEqual(info["10.0.0.7"]["services"], ["_airplay._tcp.local"])

    def test_compressed_names(self):
        owner = dns_name("tv.local")
        body = struct.pack(">HHHHHH", 0, 0x8400, 0, 2, 0, 0)
        first = owner + struct.pack(">HHIH", 1, 1, 60, 4) + socket.inet_aton("10.0.0.7")
        ptr_off = 12                                           # points back at "tv.local"
        second = struct.pack(">H", 0xC000 | ptr_off) + struct.pack(">HHIH", 1, 1, 60, 4) + socket.inet_aton("10.0.0.7")
        parsed = ns.parse_mdns(body + first + second)
        self.assertEqual(parsed["a"], {"tv.local": "10.0.0.7"})

    def test_malformed_packets_never_raise(self):
        good = mdns_response(rr("a.local", 1, socket.inet_aton("10.0.0.7")))
        for bad in (b"", b"\x00" * 5, good[:20], good[:-2],
                    struct.pack(">HHHHHH", 0, 0x8400, 0, 1, 0, 0) + b"\xc0\x0c" + b"\x00" * 10,   # self-pointer
                    b"\xff" * 64):
            ns.parse_mdns(bad)

    def test_pointer_loop_rejected(self):
        loop = struct.pack(">HHHHHH", 0, 0x8400, 0, 1, 0, 0) + b"\xc0\x0c"
        self.assertEqual(ns.parse_mdns(loop), {"a": {}, "ptr": []})

    def test_queries_ignored(self):
        q = struct.pack(">HHHHHH", 0, 0x0000, 1, 0, 0, 0) + dns_name("x.local") + b"\x00\x0c\x00\x01"
        self.assertEqual(ns.parse_mdns(q), {"a": {}, "ptr": []})

    def test_hostile_hostname_sanitised(self):
        pkt = mdns_response(rr("evil\x1b[2Jname.local", 1, socket.inet_aton("10.0.0.7")))
        host = ns.collect_mdns([("10.0.0.7", pkt)])["10.0.0.7"]["hostname"]
        self.assertNotIn("\x1b", host)

    def test_query_is_wellformed(self):
        q = ns.build_mdns_query()
        self.assertEqual(struct.unpack(">HHHHHH", q[:12])[2], 1)
        self.assertTrue(q.endswith(b"\x00\x0c\x80\x01"))


SSDP_REPLY = (b"HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=1800\r\nLOCATION: http://10.0.0.7:49152/desc.xml\r\n"
              b"SERVER: Linux UPnP/1.0 Foo/1.2\r\nST: upnp:rootdevice\r\n\r\n")
DESC = ("<root><device><friendlyName>Den Speaker</friendlyName><manufacturer>Acme</manufacturer>"
        "<modelName>Boom 3</modelName></device></root>")


class SsdpTests(unittest.TestCase):
    def test_parse_headers(self):
        hdr = ns.parse_ssdp(SSDP_REPLY)
        self.assertEqual(hdr["location"], "http://10.0.0.7:49152/desc.xml")
        self.assertEqual(hdr["server"], "Linux UPnP/1.0 Foo/1.2")

    def test_non_200_and_garbage_ignored(self):
        self.assertEqual(ns.parse_ssdp(b"NOTIFY * HTTP/1.1\r\nHOST: x\r\n\r\n"), {})
        self.assertEqual(ns.parse_ssdp(b"\xff\xfe\x00garbage"), {})

    def test_description_fields_extracted(self):
        self.assertEqual(ns.parse_upnp_description(DESC),
                         {"hostname": "Den Speaker", "manufacturer": "Acme", "model": "Boom 3"})

    def test_description_is_sanitised_and_bounded(self):
        out = ns.parse_upnp_description("<friendlyName>a\x1b[31mb</friendlyName>")
        self.assertNotIn("\x1b", out["hostname"])
        self.assertEqual(ns.parse_upnp_description("<friendlyName>" + "x" * 500 + "</friendlyName>"), {})

    def test_entity_bomb_is_just_text(self):
        bomb = '<!DOCTYPE l [<!ENTITY a "aaaa"><!ENTITY b "&a;&a;&a;&a;">]><friendlyName>&b;</friendlyName>'
        self.assertEqual(ns.parse_upnp_description(bomb)["hostname"], "&b;")      # never expanded

    def test_collect_fetches_description_once_per_host(self):
        fetch = mock.Mock(return_value=DESC)
        info = ns.collect_ssdp([("10.0.0.7", SSDP_REPLY), ("10.0.0.7", SSDP_REPLY)], fetch=fetch)
        self.assertEqual(fetch.call_count, 1)
        self.assertEqual(info["10.0.0.7"]["model"], "Boom 3")

    def test_fetch_refuses_urls_pointing_elsewhere(self):
        # SSRF guard: a device may not steer us to another host, port-scan-by-proxy style.
        with mock.patch.object(ns.socket, "create_connection") as cc:
            self.assertEqual(ns._fetch_description("http://169.254.169.254/latest", "10.0.0.7", 1), "")
            self.assertEqual(ns._fetch_description("https://10.0.0.7/x", "10.0.0.7", 1), "")
            self.assertEqual(ns._fetch_description("file:///etc/passwd", "10.0.0.7", 1), "")
            cc.assert_not_called()

    def test_fetch_reads_from_announcing_host(self):
        sock = mock.MagicMock()
        sock.__enter__.return_value = sock
        sock.recv.side_effect = [b"HTTP/1.0 200 OK\r\n\r\n" + DESC.encode(), b""]
        with mock.patch.object(ns.socket, "create_connection", return_value=sock) as cc:
            text = ns._fetch_description("http://10.0.0.7:49152/desc.xml", "10.0.0.7", 1)
        cc.assert_called_once_with(("10.0.0.7", 49152), timeout=1)
        self.assertIn("Boom 3", text)


def nbstat_response(entries):
    """entries: [(name, suffix, flags)]"""
    rdata = bytes([len(entries)]) + b"".join(
        name.ljust(15).encode() + bytes([suffix]) + struct.pack(">H", flags) for name, suffix, flags in entries
    ) + b"\x00" * 6                                                 # statistics (MAC etc.)
    owner = b"\x20" + b"CK" + b"AA" * 15 + b"\x00"
    return (struct.pack(">HHHHHH", 0x4E53, 0x8400, 0, 1, 0, 0) + owner
            + struct.pack(">HHIH", 0x0021, 1, 0, len(rdata)) + rdata)


class NetbiosTests(unittest.TestCase):
    def test_hostname_and_workgroup(self):
        pkt = nbstat_response([("DESKTOP-ABC", 0x00, 0x0400), ("WORKGROUP", 0x00, 0x8400),
                               ("DESKTOP-ABC", 0x20, 0x0400)])
        self.assertEqual(ns.parse_netbios(pkt), {"hostname": "DESKTOP-ABC", "workgroup": "WORKGROUP"})

    def test_no_workstation_name(self):
        pkt = nbstat_response([("SOMETHING", 0x20, 0x0400)])
        self.assertEqual(ns.parse_netbios(pkt), {})

    def test_truncated_and_garbage(self):
        good = nbstat_response([("HOST", 0x00, 0x0400)])
        for bad in (b"", b"\x00" * 11, good[:30], good[:60], b"\xff" * 80):
            self.assertIsInstance(ns.parse_netbios(bad), dict)

    def test_query_shape(self):
        q = ns.build_netbios_query()
        self.assertEqual(len(q), 50)
        self.assertEqual(q[12], 0x20)

    def test_name_with_control_bytes_sanitised(self):
        pkt = nbstat_response([("EV\x1b[1mIL", 0x00, 0x0400)])
        self.assertNotIn("\x1b", ns.parse_netbios(pkt)["hostname"])


class DiscoverNamesTests(unittest.TestCase):
    def run_discover(self, mdns_pkts=None, ssdp_pkts=None, netbios=None, hosts=("10.0.0.7", "10.0.0.8"), **kw):
        def multicast(payload, group, timeout):
            return (mdns_pkts or []) if group == ns.MDNS_GROUP else (ssdp_pkts or [])
        with mock.patch.object(ns, "_multicast_collect", side_effect=multicast), \
                mock.patch.object(ns, "_fetch_description", return_value=DESC), \
                mock.patch.object(ns, "_netbios_probe", side_effect=lambda ip, t: (netbios or {}).get(ip, {})):
            return ns.discover_names([{"ip": h} for h in hosts], **kw)

    def test_merges_sources_and_flags_exposures(self):
        mdns = [("10.0.0.7", mdns_response(rr("den.local", 1, socket.inet_aton("10.0.0.7"))))]
        res = self.run_discover(mdns_pkts=mdns, ssdp_pkts=[("10.0.0.7", SSDP_REPLY)],
                                netbios={"10.0.0.8": {"hostname": "PC8", "workgroup": "WG"}})
        self.assertEqual(res["10.0.0.7"]["hostname"], "den")          # mDNS wins over UPnP friendlyName
        self.assertEqual(res["10.0.0.7"]["model"], "Boom 3")
        self.assertEqual(res["10.0.0.7"]["exposures"], ["ssdp"])
        self.assertEqual(res["10.0.0.8"]["hostname"], "PC8")
        self.assertEqual(res["10.0.0.8"]["exposures"], ["netbios"])

    def test_responders_outside_scope_are_dropped(self):
        res = self.run_discover(ssdp_pkts=[("192.168.77.1", SSDP_REPLY)])
        self.assertEqual(set(res), {"10.0.0.7", "10.0.0.8"})
        self.assertTrue(all(not v["exposures"] for v in res.values()))

    def test_protocols_can_be_disabled(self):
        res = self.run_discover(ssdp_pkts=[("10.0.0.7", SSDP_REPLY)], ssdp=False)
        self.assertEqual(res["10.0.0.7"]["exposures"], [])

    def test_enrich_hosts_updates_dicts_in_place(self):
        hosts = [{"ip": "10.0.0.7", "mac": "aa"}, {"ip": "10.0.0.8", "mac": "bb"}]
        with mock.patch.object(ns, "discover_names", return_value={
                "10.0.0.7": {"hostname": "den", "model": "Boom 3", "manufacturer": "Acme",
                             "workgroup": "", "services": ["_airplay._tcp.local"], "exposures": ["ssdp"]}}):
            ns.enrich_hosts(hosts)
        self.assertEqual(hosts[0]["hostname"], "den")
        self.assertEqual(hosts[0]["exposures"], ["ssdp"])
        self.assertNotIn("hostname", hosts[1])

    def test_multicast_collect_survives_socket_errors(self):
        with mock.patch.object(ns.socket, "socket", side_effect=OSError("no multicast")):
            self.assertEqual(ns._multicast_collect(b"x", ns.MDNS_GROUP, 0.1), [])


class FindingsAdapterTests(unittest.TestCase):
    def test_ssdp_and_netbios_findings(self):
        out = F.from_nameservices("10.0.0.7", ["ssdp", "netbios"], "den")
        by_port = {f["port"]: f for f in out}
        self.assertEqual(by_port[1900]["severity"], "medium")
        self.assertEqual(by_port[137]["severity"], "low")
        self.assertTrue(all(f["category"] == "name-service" for f in out))
        self.assertIn("den", by_port[1900]["detail"])

    def test_no_exposures_no_findings(self):
        self.assertEqual(F.from_nameservices("10.0.0.7", []), [])

    def test_ids_stable_across_runs(self):
        a = F.from_nameservices("10.0.0.7", ["ssdp"], "den")[0]["id"]
        b = F.from_nameservices("10.0.0.7", ["ssdp"], "den")[0]["id"]
        self.assertEqual(a, b)


if __name__ == "__main__":
    unittest.main()
