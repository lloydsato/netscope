"""Tests for TLS/certificate auditing against a loopback self-signed server."""

import os
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import unittest
import warnings
from unittest import mock

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



def _openssl(*args):
    subprocess.run(["openssl", *args], check=True, capture_output=True)


def _make_cert(dirpath, name, subj, days=400, digest="sha256", extra=()):
    key, crt = os.path.join(dirpath, name + ".key"), os.path.join(dirpath, name + ".pem")
    _openssl("req", "-x509", "-newkey", "rsa:2048", "-keyout", key, "-out", crt,
             "-days", str(days), "-nodes", "-subj", subj, f"-{digest}", *extra)
    return crt, key


def _tls_server(cert, key, min_version, max_version):
    """Loopback TLS server pinned to a protocol range; returns (port, close)."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        ctx.minimum_version = getattr(ssl.TLSVersion, min_version)
        ctx.maximum_version = getattr(ssl.TLSVersion, max_version)
    ctx.set_ciphers("ALL:@SECLEVEL=0")
    ctx.load_cert_chain(cert, key)
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(8)

    def loop():
        while True:
            try:
                c, _ = srv.accept()
            except OSError:
                break
            try:
                ctx.wrap_socket(c, server_side=True).close()
            except Exception:
                c.close()

    threading.Thread(target=loop, daemon=True).start()
    return srv.getsockname()[1], srv.close


def _titles(res):
    return [f["title"] for f in res["findings"]]


@unittest.skipUnless(_have_openssl(), "openssl not available")
class ProtocolAuditTests(unittest.TestCase):
    """Regression: Python's default client refuses TLS < 1.2, so a TLS 1.0-only
    server used to be reported as 'no TLS service' and the obsolete-protocol check
    could never fire."""

    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.mkdtemp()
        cls.cert, cls.key = _make_cert(cls.dir, "srv", "/CN=router.lan")

    def _inspect(self, lo, hi):
        port, close = _tls_server(self.cert, self.key, lo, hi)
        self.addCleanup(close)
        return tlsaudit.inspect("127.0.0.1", port, timeout=3)

    def _skip_if_client_cannot(self, name):
        try:
            tlsaudit._client_context(name)
        except (AttributeError, ValueError, ssl.SSLError):
            self.skipTest(f"this OpenSSL build cannot speak {name}")

    def test_tls10_only_server_is_audited_and_flagged(self):
        self._skip_if_client_cannot("TLSv1")
        res = self._inspect("TLSv1", "TLSv1")
        self.assertTrue(res["ok"], res.get("error"))
        self.assertEqual(res["protocol"], "TLSv1")
        self.assertIn("Obsolete TLS protocol (TLSv1)", _titles(res))
        self.assertEqual(res["subject"], "router.lan")

    def test_server_accepting_tls10_alongside_tls13_is_flagged(self):
        # Negotiation picks the best protocol (1.3), so only per-version probing
        # can see that 1.0 is still accepted.
        self._skip_if_client_cannot("TLSv1")
        res = self._inspect("TLSv1", "TLSv1_3")
        self.assertTrue(res["ok"])
        self.assertEqual(res["protocol"], "TLSv1.3")
        self.assertIn("TLSv1", res["obsolete_protocols"])
        self.assertIn("Obsolete TLS protocol (TLSv1)", _titles(res))

    def test_tls11_detected_separately(self):
        self._skip_if_client_cannot("TLSv1_1")
        res = self._inspect("TLSv1_1", "TLSv1_1")
        self.assertEqual(res["obsolete_protocols"], ["TLSv1.1"])
        self.assertNotIn("Obsolete TLS protocol (TLSv1)", _titles(res))

    def test_modern_only_server_has_no_protocol_finding(self):
        res = self._inspect("TLSv1_2", "TLSv1_3")
        self.assertTrue(res["ok"])
        self.assertEqual(res["obsolete_protocols"], [])
        self.assertFalse([t for t in _titles(res) if t.startswith("Obsolete")])


@unittest.skipUnless(_have_openssl(), "openssl not available")
class CertificateAuditTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.mkdtemp()

    def _inspect_cert(self, cert, key, host="127.0.0.1", **kw):
        port, close = _tls_server(cert, key, "TLSv1_2", "TLSv1_3")
        self.addCleanup(close)
        return tlsaudit.inspect(host, port, timeout=3, **kw)

    def test_expiring_soon_and_expired_via_clock(self):
        cert, key = _make_cert(self.dir, "t1", "/CN=a.lan", days=30)
        now = time.time()
        res = self._inspect_cert(cert, key)
        self.assertNotIn("TLS certificate expiring soon", _titles(res))     # 30d left: fine
        with mock.patch("netscope.tlsaudit.time.time", return_value=now + 20 * 86400):
            res = self._inspect_cert(cert, key)
        soon = [f for f in res["findings"] if f["title"] == "TLS certificate expiring soon"]
        self.assertEqual(len(soon), 1)
        self.assertIn("day(s)", soon[0]["detail"])
        with mock.patch("netscope.tlsaudit.time.time", return_value=now + 45 * 86400):
            res = self._inspect_cert(cert, key)
        expired = [f for f in res["findings"] if f["title"] == "Expired TLS certificate"]
        self.assertEqual(len(expired), 1)
        self.assertEqual(expired[0]["severity"], "high")
        self.assertNotIn("TLS certificate expiring soon", _titles(res))

    def test_expiry_finding_ids_are_stable_across_days(self):
        # Regression: the day count lives in `detail`; ids must not depend on it
        # or `netscope diff` reports the same issue as new + resolved daily.
        from netscope import findings as F
        cert, key = _make_cert(self.dir, "t2", "/CN=b.lan", days=30)
        now = time.time()
        ids = set()
        for offset in (15, 16, 17):
            with mock.patch("netscope.tlsaudit.time.time", return_value=now + offset * 86400):
                res = self._inspect_cert(cert, key)
            (f,) = [f for f in F.from_tls("10.0.0.1", 443, res["findings"])
                    if f["title"] == "TLS certificate expiring soon"]
            ids.add(f["id"])
        self.assertEqual(len(ids), 1)

    def test_self_signed_without_common_name_is_detected(self):
        cert, key = _make_cert(self.dir, "t3", "/O=Acme Corp")
        res = self._inspect_cert(cert, key)
        self.assertIn("Self-signed TLS certificate", _titles(res))
        self.assertIsNone(res["subject"])

    def test_ca_issued_cert_sharing_a_common_name_is_not_self_signed(self):
        # Regression: comparing only the CN flagged this as self-signed.
        ca_crt, ca_key = _make_cert(self.dir, "ca", "/O=Real CA/CN=shared.lan",
                                    extra=("-addext", "basicConstraints=critical,CA:TRUE"))
        leaf_key, csr, leaf_crt = (os.path.join(self.dir, n) for n in ("leaf.key", "leaf.csr", "leaf.pem"))
        _openssl("req", "-new", "-newkey", "rsa:2048", "-nodes", "-keyout", leaf_key,
                 "-out", csr, "-subj", "/O=Leaf Org/CN=shared.lan")
        _openssl("x509", "-req", "-in", csr, "-CA", ca_crt, "-CAkey", ca_key,
                 "-CAcreateserial", "-out", leaf_crt, "-days", "100")
        res = self._inspect_cert(leaf_crt, leaf_key)
        self.assertEqual(res["subject"], "shared.lan")
        self.assertEqual(res["issuer"], "shared.lan")
        self.assertNotIn("Self-signed TLS certificate", _titles(res))

    def test_sha1_signature_flagged_and_sha256_not(self):
        sha1_crt, sha1_key = _make_cert(self.dir, "t5", "/CN=old.lan", digest="sha1")
        res = self._inspect_cert(sha1_crt, sha1_key)
        weak = [f for f in res["findings"] if f["title"] == "Weak certificate signature algorithm"]
        self.assertEqual(len(weak), 1)
        self.assertIn("sha1", weak[0]["evidence"].lower())
        ok_crt, ok_key = _make_cert(self.dir, "t6", "/CN=new.lan")
        self.assertNotIn("Weak certificate signature algorithm",
                         _titles(self._inspect_cert(ok_crt, ok_key)))

    def test_hostname_mismatch_uses_sans_over_cn(self):
        crt, key = _make_cert(self.dir, "t7", "/CN=localhost",
                              extra=("-addext", "subjectAltName=DNS:somewhere-else.lan"))
        # CN says localhost, but with a SAN present the CN must be ignored (RFC 6125).
        res = self._inspect_cert(crt, key, host="localhost")
        self.assertIn("TLS certificate hostname mismatch", _titles(res))
        crt2, key2 = _make_cert(self.dir, "t8", "/CN=other.lan",
                                extra=("-addext", "subjectAltName=DNS:localhost"))
        self.assertNotIn("TLS certificate hostname mismatch",
                         _titles(self._inspect_cert(crt2, key2, host="localhost")))

    def test_ip_literal_never_gets_hostname_finding(self):
        crt, key = _make_cert(self.dir, "t9", "/CN=router.lan")
        self.assertNotIn("TLS certificate hostname mismatch", _titles(self._inspect_cert(crt, key)))


class NotTlsTests(unittest.TestCase):
    def test_closed_port(self):
        s = socket.socket(); s.bind(("127.0.0.1", 0)); port = s.getsockname()[1]; s.close()
        res = tlsaudit.inspect("127.0.0.1", port, timeout=1)
        self.assertFalse(res["ok"])
        self.assertTrue(res["error"])
        self.assertEqual(res["findings"], [])

    def test_plain_text_service_is_not_tls(self):
        srv = socket.socket(); srv.bind(("127.0.0.1", 0)); srv.listen(1)
        self.addCleanup(srv.close)

        def serve():
            try:
                c, _ = srv.accept()
                c.sendall(b"220 hello, I am an SMTP server\r\n")
                time.sleep(0.3)
                c.close()
            except OSError:
                pass

        threading.Thread(target=serve, daemon=True).start()
        res = tlsaudit.inspect("127.0.0.1", srv.getsockname()[1], timeout=2)
        self.assertFalse(res["ok"])

    def test_silent_service_times_out_quickly(self):
        srv = socket.socket(); srv.bind(("127.0.0.1", 0)); srv.listen(1)
        self.addCleanup(srv.close)
        held = []
        threading.Thread(target=lambda: held.append(srv.accept()), daemon=True).start()
        t0 = time.monotonic()
        res = tlsaudit.inspect("127.0.0.1", srv.getsockname()[1], timeout=0.5)
        self.assertFalse(res["ok"])
        self.assertLess(time.monotonic() - t0, 3)

    def test_unresolvable_host(self):
        res = tlsaudit.inspect("no-such-host.invalid", 443, timeout=1)
        self.assertFalse(res["ok"])


class HelperTests(unittest.TestCase):
    def test_parse_notafter(self):
        self.assertEqual(tlsaudit._parse_notafter("Jun  1 12:00:00 2025 GMT"),
                         ssl.cert_time_to_seconds("Jun  1 12:00:00 2025 GMT"))
        self.assertEqual(tlsaudit._parse_notafter("Jan  1 00:00:00 1970 GMT"), 0)
        for bad in ("", "garbage", None, "Foo 99 99:99:99 2025 GMT"):
            self.assertIsNone(tlsaudit._parse_notafter(bad), bad)

    def test_oid_decoding(self):
        self.assertEqual(tlsaudit._oid_to_str(bytes.fromhex("2a864886f70d010105")),
                         "1.2.840.113549.1.1.5")                       # sha1WithRSA
        self.assertEqual(tlsaudit._oid_to_str(b""), "")

    def test_signature_oid_of_garbage_is_empty(self):
        for junk in (b"", b"\x30", b"\x30\x03\x01\x02\x03", bytes(range(200))):
            self.assertEqual(tlsaudit._signature_oid(junk), "")

    def test_weak_cipher_tokens(self):
        weak = ("DES-CBC3-SHA", "RC4-SHA", "EXP-RC4-MD5", "ADH-AES256-SHA", "AECDH-AES128-SHA", "NULL-SHA")
        strong = ("ECDHE-RSA-AES256-GCM-SHA384", "TLS_AES_256_GCM_SHA384", "ECDHE-ECDSA-CHACHA20-POLY1305")
        flagged = lambda c: any(t in c.upper() for t in tlsaudit._WEAK_CIPHER_TOKENS)
        for c in weak:
            self.assertTrue(flagged(c), c)
        for c in strong:
            self.assertFalse(flagged(c), c)

    def test_looks_like_hostname(self):
        self.assertTrue(tlsaudit._looks_like_hostname("router.lan"))
        self.assertTrue(tlsaudit._looks_like_hostname("localhost"))
        self.assertFalse(tlsaudit._looks_like_hostname("192.168.1.1"))
        self.assertFalse(tlsaudit._looks_like_hostname("::1"))


class HostMatchTests(unittest.TestCase):
    def test_wildcard_match(self):
        self.assertTrue(tlsaudit._host_matches("a.example.com", "*.example.com"))
        self.assertFalse(tlsaudit._host_matches("a.b.example.com", "*.example.com"))

    def test_exact_match(self):
        self.assertTrue(tlsaudit._host_matches("Example.com", "example.com"))

    def test_wildcard_does_not_match_bare_domain_or_tld(self):
        self.assertFalse(tlsaudit._host_matches("example.com", "*.example.com"))
        self.assertFalse(tlsaudit._host_matches("com", "*.com"))

    def test_trailing_dot_and_case(self):
        self.assertTrue(tlsaudit._host_matches("WWW.Example.COM.", "www.example.com"))


if __name__ == "__main__":
    unittest.main()
