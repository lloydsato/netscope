"""Tests for read-only weak/default-auth probes.

Loopback mock servers stand in for the real services so the probes can be
exercised deterministically and offline.
"""

import socket
import struct
import threading
import time
import unittest

from netscope import probes


def _serve(handler, connections=1):
    """Start a loopback TCP server that handles ``connections`` clients in turn;
    return its port."""
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", 0))
    s.listen(5)
    port = s.getsockname()[1]

    def loop():
        try:
            for _ in range(connections):
                c, _ = s.accept()
                try:
                    handler(c)
                except OSError:
                    pass
                finally:
                    c.close()
        except OSError:
            pass
        finally:
            s.close()

    threading.Thread(target=loop, daemon=True).start()
    return port


class SnmpPacketTests(unittest.TestCase):
    def test_packet_is_well_formed(self):
        pkt = probes._snmp_get_sysdescr("public")
        self.assertEqual(pkt[0], 0x30)              # SEQUENCE
        self.assertIn(b"public", pkt)
        self.assertGreater(len(pkt), 30)

    def test_extract_printable(self):
        self.assertEqual(
            probes._extract_printable(b"\xa2\x05Linux router 5.4\x00\x01"),
            "Linux router 5.4",
        )

    def test_ber_length_multibyte(self):
        self.assertEqual(probes._ber_len(5), b"\x05")
        self.assertEqual(probes._ber_len(200)[0], 0x81)


class RedisProbeTests(unittest.TestCase):
    def test_unauth_redis_flagged(self):
        def handler(c):
            data = c.recv(64)
            if data.startswith(b"PING"):
                c.sendall(b"+PONG\r\n")
                c.recv(64)
                c.sendall(b"# Server\r\nredis_version:6.0.9\r\n")
        port = _serve(handler)
        out = probes.check_redis("127.0.0.1", port)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["severity"], "critical")
        self.assertIn("6.0.9", out[0]["evidence"])

    def test_authed_redis_not_flagged(self):
        def handler(c):
            c.recv(64)
            c.sendall(b"-NOAUTH Authentication required.\r\n")
        port = _serve(handler)
        self.assertEqual(probes.check_redis("127.0.0.1", port), [])


class FtpProbeTests(unittest.TestCase):
    def test_anonymous_login_flagged(self):
        def handler(c):
            c.sendall(b"220 ready\r\n")
            c.recv(64); c.sendall(b"331 need password\r\n")
            c.recv(64); c.sendall(b"230 Login successful.\r\n")
            c.recv(64)
        port = _serve(handler)
        out = probes.check_ftp_anonymous("127.0.0.1", port)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["severity"], "high")

    def test_denied_login_not_flagged(self):
        def handler(c):
            c.sendall(b"220 ready\r\n")
            c.recv(64); c.sendall(b"331 need password\r\n")
            c.recv(64); c.sendall(b"530 Login incorrect.\r\n")
            c.recv(64)
        port = _serve(handler)
        self.assertEqual(probes.check_ftp_anonymous("127.0.0.1", port), [])



class FtpEdgeCaseTests(unittest.TestCase):
    def test_multiline_greeting_delivered_in_pieces(self):
        # RFC 959 multi-line replies: the probe must wait for the final "220 " line.
        def handler(c):
            c.sendall(b"220-Welcome to the archive\r\n")
            time.sleep(0.15)
            c.sendall(b"220-Second line\r\n")
            time.sleep(0.15)
            c.sendall(b"220 ready\r\n")
            c.recv(64); c.sendall(b"331 need password\r\n")
            c.recv(64); c.sendall(b"230 Login successful.\r\n")
            c.recv(64)
        port = _serve(handler)
        out = probes.check_ftp_anonymous("127.0.0.1", port, timeout=3)
        self.assertEqual([f["title"] for f in out], ["Anonymous FTP login allowed"])

    def test_230_straight_after_user_is_anonymous_access(self):
        def handler(c):
            c.sendall(b"220 ready\r\n")
            c.recv(64); c.sendall(b"230 Anonymous access granted\r\n")
            c.recv(64); c.sendall(b"503 Login with USER first\r\n")
        port = _serve(handler)
        self.assertEqual(len(probes.check_ftp_anonymous("127.0.0.1", port, timeout=3)), 1)

    def test_multiline_login_reply(self):
        def handler(c):
            c.sendall(b"220 ready\r\n")
            c.recv(64); c.sendall(b"331 need password\r\n")
            c.recv(64); c.sendall(b"230-Welcome\r\n230 Guest login ok\r\n")
            c.recv(64)
        port = _serve(handler)
        self.assertEqual(len(probes.check_ftp_anonymous("127.0.0.1", port, timeout=3)), 1)

    def test_non_ftp_service_not_flagged(self):
        def handler(c):
            c.sendall(b"SSH-2.0-OpenSSH_9.6\r\n")
        port = _serve(handler)
        self.assertEqual(probes.check_ftp_anonymous("127.0.0.1", port, timeout=2), [])

    def test_too_many_users_greeting_not_flagged(self):
        def handler(c):
            c.sendall(b"421 Too many users\r\n")
        port = _serve(handler)
        self.assertEqual(probes.check_ftp_anonymous("127.0.0.1", port, timeout=2), [])

    def test_hanging_server_times_out_cleanly(self):
        def handler(c):
            time.sleep(1.5)       # never greets
        port = _serve(handler)
        t0 = time.monotonic()
        self.assertEqual(probes.check_ftp_anonymous("127.0.0.1", port, timeout=0.4), [])
        self.assertLess(time.monotonic() - t0, 1.2)

    def test_connection_refused(self):
        self.assertEqual(probes.check_ftp_anonymous("127.0.0.1", _closed_port(), timeout=1), [])


def _closed_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class RedisEdgeCaseTests(unittest.TestCase):
    def test_unauth_redis_still_reported_when_info_hangs(self):
        # A confirmed unauthenticated PING must survive INFO timing out.
        def handler(c):
            c.recv(64); c.sendall(b"+PONG\r\n"); c.recv(64)
            time.sleep(1.0)
        port = _serve(handler)
        out = probes.check_redis("127.0.0.1", port, timeout=0.3)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["evidence"], "+PONG")

    def test_protected_mode_not_flagged(self):
        def handler(c):
            c.recv(64)
            c.sendall(b"-DENIED Redis is running in protected mode\r\n")
        port = _serve(handler)
        self.assertEqual(probes.check_redis("127.0.0.1", port), [])

    def test_non_redis_echo_not_flagged(self):
        def handler(c):
            c.sendall(c.recv(64))           # plain echo service
        port = _serve(handler)
        self.assertEqual(probes.check_redis("127.0.0.1", port, timeout=1), [])

    def test_connection_refused(self):
        self.assertEqual(probes.check_redis("127.0.0.1", _closed_port(), timeout=1), [])


class ElasticsearchProbeTests(unittest.TestCase):
    BODY = (b'{"name":"n1","cluster_name":"prod","version":{"number":"7.10.2",'
            b'"lucene_version":"8.7.0"},"tagline":"You Know, for Search"}')

    def test_unauth_es_flagged_with_version(self):
        def handler(c):
            c.recv(1024)
            c.sendall(b"HTTP/1.0 200 OK\r\nContent-Type: application/json\r\n\r\n" + self.BODY)
        port = _serve(handler)
        out = probes.check_elasticsearch("127.0.0.1", port)
        self.assertEqual(len(out), 1)
        self.assertIn("7.10.2", out[0]["evidence"])

    def test_headers_and_body_in_separate_segments(self):
        def handler(c):
            c.recv(1024)
            c.sendall(b"HTTP/1.0 200 OK\r\nContent-Type: application/json\r\n\r\n")
            time.sleep(0.3)
            c.sendall(self.BODY)
        port = _serve(handler)
        self.assertEqual(len(probes.check_elasticsearch("127.0.0.1", port, timeout=3)), 1)

    def test_security_enabled_401_not_flagged(self):
        def handler(c):
            c.recv(1024)
            c.sendall(b'HTTP/1.0 401 Unauthorized\r\nWWW-Authenticate: Basic realm="security"\r\n\r\n'
                      b'{"error":{"type":"security_exception"},"status":401}')
        port = _serve(handler)
        self.assertEqual(probes.check_elasticsearch("127.0.0.1", port), [])

    def test_other_json_service_not_flagged(self):
        def handler(c):
            c.recv(1024)
            c.sendall(b'HTTP/1.0 200 OK\r\n\r\n{"status":"ok"}')
        port = _serve(handler)
        self.assertEqual(probes.check_elasticsearch("127.0.0.1", port), [])


# ---------- MongoDB: wire-format mocks ----------

def _bson_double(name, v):
    return b"\x01" + name.encode() + b"\x00" + struct.pack("<d", v)


def _bson_str(name, v):
    raw = v.encode() + b"\x00"
    return b"\x02" + name.encode() + b"\x00" + struct.pack("<i", len(raw)) + raw


def _bson_i32(name, v):
    return b"\x10" + name.encode() + b"\x00" + struct.pack("<i", v)


def _bson_sub(name, doc):
    return b"\x03" + name.encode() + b"\x00" + doc


def _doc(*els):
    body = b"".join(els) + b"\x00"
    return struct.pack("<i", len(body) + 4) + body


def _op_msg_reply(doc):
    body = struct.pack("<I", 0) + b"\x00" + doc
    return struct.pack("<iiii", 16 + len(body), 99, 1, 2013) + body


def _op_reply(doc):
    body = struct.pack("<iqii", 8, 0, 0, 1) + doc
    return struct.pack("<iiii", 16 + len(body), 99, 1, 1) + body


_HOSTINFO_OK = _doc(
    _bson_sub("system", _doc(_bson_str("hostname", "db1"), _bson_i32("memSizeMB", 2048))),
    _bson_sub("os", _doc(_bson_str("type", "Linux"))),
    _bson_double("ok", 1.0),
)
_UNAUTHORIZED = _doc(
    _bson_double("ok", 0.0),
    _bson_str("errmsg", "command hostInfo requires authentication"),
    _bson_i32("code", 13),
    _bson_str("codeName", "Unauthorized"),
)
_ISMASTER = _doc(
    b"\x08ismaster\x00\x01", _bson_i32("maxWireVersion", 17), _bson_double("ok", 1.0),
)


def _read_wire(c):
    head = c.recv(4)
    if len(head) < 4:
        return None
    n = struct.unpack("<i", head)[0]
    rest = b""
    while len(rest) < n - 4:
        chunk = c.recv(n - 4 - len(rest))
        if not chunk:
            break
        rest += chunk
    return head + rest


def _mongod(auth, legacy=False):
    """Mock mongod. ``auth``: secured server. ``legacy``: pre-3.6 (no OP_MSG)."""
    def handler(c):
        msg = _read_wire(c)
        if not msg:
            return
        opcode = struct.unpack_from("<i", msg, 12)[0]
        if opcode == 2013 and not legacy:
            payload = msg[21:]
            if b"isMaster" in payload or b"hello" in payload:
                c.sendall(_op_msg_reply(_ISMASTER))
            else:
                c.sendall(_op_msg_reply(_UNAUTHORIZED if auth else _HOSTINFO_OK))
        elif opcode == 2004:
            if b"isMaster" in msg[16:]:
                c.sendall(_op_reply(_ISMASTER))
            else:
                c.sendall(_op_reply(_UNAUTHORIZED if auth else _HOSTINFO_OK))
        # legacy + OP_MSG, or anything unknown: just drop the connection
    return handler


class MongoProbeTests(unittest.TestCase):
    def test_unauthenticated_mongod_flagged(self):
        port = _serve(_mongod(auth=False), connections=2)
        out = probes.check_mongodb("127.0.0.1", port)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["severity"], "critical")

    def test_auth_enabled_mongod_not_flagged(self):
        # Regression: every mongod answers isMaster pre-auth, so that alone
        # must NOT be reported as "unauthenticated" (it used to be, as critical).
        port = _serve(_mongod(auth=True), connections=2)
        self.assertEqual(probes.check_mongodb("127.0.0.1", port), [])

    def test_legacy_server_falls_back_to_op_query(self):
        port = _serve(_mongod(auth=False, legacy=True), connections=2)
        self.assertEqual(len(probes.check_mongodb("127.0.0.1", port)), 1)

    def test_legacy_server_with_auth_not_flagged(self):
        port = _serve(_mongod(auth=True, legacy=True), connections=2)
        self.assertEqual(probes.check_mongodb("127.0.0.1", port), [])

    def test_non_mongo_service_not_flagged(self):
        def handler(c):
            c.recv(1024)
            c.sendall(b"HTTP/1.0 400 Bad Request\r\n\r\n")
        port = _serve(handler, connections=2)
        self.assertEqual(probes.check_mongodb("127.0.0.1", port, timeout=1), [])

    def test_truncated_and_garbage_replies_do_not_crash(self):
        for payload in (b"\x10\x00\x00\x00", b"\xff\xff\xff\x7f" + b"x" * 12, b"", b"\x00" * 40):
            port = _serve(lambda c, p=payload: (c.recv(1024), c.sendall(p)), connections=2)
            self.assertEqual(probes.check_mongodb("127.0.0.1", port, timeout=1), [], payload)

    def test_bson_parser_tolerates_malformed_input(self):
        self.assertEqual(probes._bson_parse(b""), {})
        self.assertEqual(probes._bson_parse(b"\x05\x00\x00\x00\x00"), {})
        self.assertEqual(probes._bson_parse(b"\x20\x00\x00\x00\x01ok"), {})   # truncated
        self.assertEqual(probes._bson_parse(_UNAUTHORIZED)["code"], 13)

    def test_op_msg_and_op_query_are_well_formed(self):
        for pkt, opcode in ((probes._mongo_op_msg("hostInfo"), 2013),
                            (probes._mongo_op_query("hostInfo"), 2004)):
            length, _, _, op = struct.unpack_from("<iiii", pkt, 0)
            self.assertEqual(length, len(pkt))
            self.assertEqual(op, opcode)
        # embedded BSON document length must be self-consistent
        msg = probes._mongo_op_msg("hostInfo")
        doc = msg[21:]
        self.assertEqual(struct.unpack_from("<i", doc, 0)[0], len(doc))
        self.assertEqual(probes._bson_parse(doc), {"hostInfo": 1, "$db": "admin"})


# ---------- SNMP: BER + UDP mocks ----------

def _snmp_response(community, request_id, sysdescr=b"Linux router 5.4", version=0, error=0):
    t = probes._tlv
    vb = t(0x30, t(0x30, t(0x06, bytes([0x2b, 6, 1, 2, 1, 1, 1, 0])) + t(0x04, sysdescr)))
    pdu = t(0xA2, t(0x02, probes._ber_int(request_id)) + t(0x02, bytes([error])) +
            t(0x02, b"\x00") + vb)
    return t(0x30, t(0x02, bytes([version])) + t(0x04, community.encode()) + pdu)


def _udp_server(responder):
    """UDP mock; ``responder(data, send)`` is called per datagram."""
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    u.bind(("127.0.0.1", 0))
    port = u.getsockname()[1]

    def loop():
        u.settimeout(5)
        while True:
            try:
                data, addr = u.recvfrom(4096)
            except OSError:
                break
            responder(data, lambda b, a=addr: u.sendto(b, a))

    threading.Thread(target=loop, daemon=True).start()
    return port, u


class SnmpProbeTests(unittest.TestCase):
    def _agent(self, accept=("public",), versions=(0, 1)):
        def responder(data, send):
            req = _parse_req(data)
            if req and req["community"] in accept and req["version"] in versions:
                send(_snmp_response(req["community"], req["request_id"],
                                    version=req["version"]))
        return _udp_server(responder)

    def test_default_community_detected_and_evidence_is_sysdescr(self):
        port, u = self._agent(accept=("public",))
        self.addCleanup(u.close)
        out = probes.check_snmp_default_community("127.0.0.1", port=port, timeout=1.0)
        self.assertEqual([f["title"] for f in out],
                         ["SNMP readable with default community 'public'"])
        self.assertEqual(out[0]["evidence"], "Linux router 5.4")   # not the community string!

    def test_both_default_communities(self):
        port, u = self._agent(accept=("public", "private"))
        self.addCleanup(u.close)
        out = probes.check_snmp_default_community("127.0.0.1", port=port, timeout=1.0)
        self.assertEqual(len(out), 2)

    def test_v2c_only_agent_detected(self):
        port, u = self._agent(accept=("public",), versions=(1,))
        self.addCleanup(u.close)
        self.assertEqual(len(probes.check_snmp_default_community("127.0.0.1", port=port, timeout=1.0)), 1)

    def test_custom_community_list_and_empty_entries_ignored(self):
        port, u = self._agent(accept=("s3cret",))
        self.addCleanup(u.close)
        out = probes.check_snmp_default_community("127.0.0.1", port=port,
                                                  communities=("", "nope", "s3cret", "s3cret"), timeout=1.0)
        self.assertEqual([f["title"] for f in out], ["SNMP readable with default community 's3cret'"])
        self.assertEqual(probes.check_snmp_default_community("127.0.0.1", port=port, communities=("",)), [])
        self.assertEqual(probes.check_snmp_default_community("127.0.0.1", port=port, communities=()), [])

    def test_agent_with_other_community_not_flagged(self):
        port, u = self._agent(accept=("hunter2",))
        self.addCleanup(u.close)
        self.assertEqual(probes.check_snmp_default_community("127.0.0.1", port=port, timeout=0.6), [])

    def test_non_snmp_udp_responder_with_0xa2_byte_not_flagged(self):
        # Regression: the old check was `b"\xa2" in data`, which any binary reply satisfies.
        port, u = _udp_server(lambda d, send: send(b"\x00\x01garbage\xa2\xffnot-snmp"))
        self.addCleanup(u.close)
        self.assertEqual(probes.check_snmp_default_community("127.0.0.1", port=port, timeout=0.6), [])

    def test_reply_with_wrong_community_or_request_id_ignored(self):
        def responder(data, send):
            req = _parse_req(data)
            send(_snmp_response("other", req["request_id"]))            # wrong community
            send(_snmp_response(req["community"], req["request_id"] + 50))   # unsolicited id
        port, u = _udp_server(responder)
        self.addCleanup(u.close)
        self.assertEqual(probes.check_snmp_default_community("127.0.0.1", port=port, timeout=0.6), [])

    def test_get_response_with_error_status_still_proves_community(self):
        def responder(data, send):
            req = _parse_req(data)
            send(_snmp_response(req["community"], req["request_id"], error=2, sysdescr=b""))
        port, u = _udp_server(responder)
        self.addCleanup(u.close)
        out = probes.check_snmp_default_community("127.0.0.1", port=port, communities=("public",), timeout=1.0)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["evidence"], "community=public")

    def test_closed_port_returns_fast(self):
        # ICMP port-unreachable on a connected UDP socket => no 3s wait.
        t0 = time.monotonic()
        self.assertEqual(probes.check_snmp_default_community("127.0.0.1", port=_closed_udp_port(), timeout=3.0), [])
        self.assertLess(time.monotonic() - t0, 1.5)

    def test_silent_host_waits_at_most_one_timeout(self):
        port, u = _udp_server(lambda d, send: None)
        self.addCleanup(u.close)
        t0 = time.monotonic()
        self.assertEqual(probes.check_snmp_default_community("127.0.0.1", port=port, timeout=0.5), [])
        self.assertLess(time.monotonic() - t0, 1.2)     # old code: 0.5s x communities

    def test_unresolvable_host_does_not_raise(self):
        self.assertEqual(probes.check_snmp_default_community("no-such-host.invalid", timeout=0.5), [])


def _closed_udp_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _parse_req(data):
    """Parse an SNMP GetRequest (test-side, independent of the probe's parser)."""
    try:
        tag, msg, _ = probes._ber_read(data, 0)
        _, ver, i = probes._ber_read(msg, 0)
        _, comm, i = probes._ber_read(msg, i)
        _, pdu, _ = probes._ber_read(msg, i)
        _, rid, _ = probes._ber_read(pdu, 0)
        return {"version": int.from_bytes(ver, "big"), "community": comm.decode(),
                "request_id": int.from_bytes(rid, "big")}
    except Exception:
        return None


class BerTests(unittest.TestCase):
    def test_request_roundtrips_through_parser_helpers(self):
        for community in ("public", "a" * 200):          # 200 chars forces a long-form length
            for version in (0, 1):
                pkt = probes._snmp_get_sysdescr(community, version=version, request_id=7)
                req = _parse_req(pkt)
                self.assertEqual(req, {"version": version, "community": community, "request_id": 7})

    def test_ber_int_is_minimal_positive(self):
        self.assertEqual(probes._ber_int(1), b"\x01")
        self.assertEqual(probes._ber_int(127), b"\x7f")
        self.assertEqual(probes._ber_int(128), b"\x00\x80")    # must not read as negative
        self.assertEqual(probes._ber_int(256), b"\x01\x00")

    def test_parse_response_valid(self):
        r = probes._snmp_parse_response(_snmp_response("public", 3))
        self.assertEqual((r["community"], r["request_id"], r["sysdescr"], r["error_status"]),
                         ("public", 3, "Linux router 5.4", 0))

    def test_parse_response_rejects_junk(self):
        good = _snmp_response("public", 3)
        junk = [b"", b"\x30", b"\x30\x84\xff\xff\xff\xff", b"\xa2\x01\x00", good[:-3],
                good.replace(b"\xa2", b"\xa0", 1),        # GetRequest, not a response
                b"\x30\x03\x02\x01\x00", bytes(range(256))]
        for j in junk:
            self.assertIsNone(probes._snmp_parse_response(j), j[:8])


if __name__ == "__main__":
    unittest.main()
