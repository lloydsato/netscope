"""Tests for read-only weak/default-auth probes.

Loopback mock servers stand in for the real services so the probes can be
exercised deterministically and offline.
"""

import socket
import threading
import unittest

from netscope import probes


def _serve(handler):
    """Start a one-shot loopback TCP server; return its port."""
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", 0))
    s.listen(1)
    port = s.getsockname()[1]

    def loop():
        try:
            c, _ = s.accept()
            handler(c)
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


if __name__ == "__main__":
    unittest.main()
