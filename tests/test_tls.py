"""Tests for TLS/certificate auditing against a loopback self-signed server."""

import os
import socket
import ssl
import subprocess
import tempfile
import threading
import unittest

from netscope import tlsaudit


def _have_openssl():
    try:
        subprocess.run(["openssl", "version"], capture_output=True, check=True)
        return True
    except Exception:
        return False


@unittest.skipUnless(_have_openssl(), "openssl not available")
class TlsInspectTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.mkdtemp()
        cls.cert = os.path.join(cls.dir, "c.pem")
        cls.key = os.path.join(cls.dir, "k.pem")
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-keyout", cls.key,
             "-out", cls.cert, "-days", "400", "-nodes", "-subj", "/CN=router.lan"],
            check=True, capture_output=True,
        )
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cls.cert, cls.key)
        cls.srv = socket.socket()
        cls.srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        cls.srv.bind(("127.0.0.1", 0))
        cls.srv.listen(5)
        cls.port = cls.srv.getsockname()[1]

        def loop():
            while True:
                try:
                    c, _ = cls.srv.accept()
                except OSError:
                    break
                try:
                    ctx.wrap_socket(c, server_side=True).close()
                except Exception:
                    try:
                        c.close()
                    except OSError:
                        pass

        cls.thread = threading.Thread(target=loop, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.close()

    def test_self_signed_detected(self):
        res = tlsaudit.inspect("127.0.0.1", self.port)
        self.assertTrue(res["ok"])
        titles = [f["title"] for f in res["findings"]]
        self.assertIn("Self-signed TLS certificate", titles)

    def test_protocol_and_cipher_reported(self):
        res = tlsaudit.inspect("127.0.0.1", self.port)
        self.assertTrue(res["protocol"].startswith("TLS"))
        self.assertTrue(res["cipher"])

    def test_subject_parsed(self):
        res = tlsaudit.inspect("127.0.0.1", self.port)
        self.assertEqual(res["subject"], "router.lan")


class HostMatchTests(unittest.TestCase):
    def test_wildcard_match(self):
        self.assertTrue(tlsaudit._host_matches("a.example.com", "*.example.com"))
        self.assertFalse(tlsaudit._host_matches("a.b.example.com", "*.example.com"))

    def test_exact_match(self):
        self.assertTrue(tlsaudit._host_matches("Example.com", "example.com"))


if __name__ == "__main__":
    unittest.main()
