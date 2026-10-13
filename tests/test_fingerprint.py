"""Tests for banner-based product/version extraction."""

import socket
import ssl
import threading
import time
import unittest
from unittest import mock

from netscope import fingerprint


class ParseServiceTests(unittest.TestCase):
    def test_openssh(self):
        r = fingerprint.parse_service("SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.10")
        self.assertEqual(r["product"], "openssh")
        self.assertEqual(r["version"], "7.2p2")

    def test_apache(self):
        r = fingerprint.parse_service("Server: Apache/2.4.49 (Unix)")
        self.assertEqual(r["product"], "apache_http_server")
        self.assertEqual(r["version"], "2.4.49")

    def test_nginx(self):
        r = fingerprint.parse_service("Server: nginx/1.10.3")
        self.assertEqual(r["product"], "nginx")
        self.assertEqual(r["version"], "1.10.3")

    def test_vsftpd(self):
        r = fingerprint.parse_service("220 (vsFTPd 2.3.4)")
        self.assertEqual(r["product"], "vsftpd")
        self.assertEqual(r["version"], "2.3.4")

    def test_redis_info(self):
        r = fingerprint.parse_service("redis_version:6.0.9")
        self.assertEqual(r["product"], "redis")
        self.assertEqual(r["version"], "6.0.9")

    def test_product_without_version(self):
        r = fingerprint.parse_service("220 mail.example.com ESMTP Postfix")
        self.assertEqual(r["product"], "postfix")
        self.assertEqual(r["version"], "")

    def test_unrecognised(self):
        r = fingerprint.parse_service("hello there")
        self.assertEqual(r["product"], "")
        self.assertEqual(r["version"], "")

    def test_empty(self):
        self.assertEqual(fingerprint.parse_service(""), {"product": "", "version": ""})


class MoreSignatureTests(unittest.TestCase):
    def test_mikrotik_banners_map_to_routeros(self):
        for banner in ("220 MikroTik FTP server (MikroTik 6.40.5) ready", "MikroTik v6.45.9 (stable)",
                       "RouterOS 6.42"):
            r = fingerprint.parse_service(banner)
            self.assertEqual(r["product"], "routeros", banner)
            self.assertRegex(r["version"], r"^6\.4")

    def test_openssh_variants(self):
        for banner, ver in (("SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.19", "9.6p1"),
                            ("SSH-2.0-OpenSSH_8.1", "8.1"),
                            ("SSH-2.0-OpenSSH_for_Windows_8.1", "8.1")):
            r = fingerprint.parse_service(banner)
            self.assertEqual((r["product"], r["version"]), ("openssh", ver), banner)

    def test_dropbear_and_unrecognised_ssh_have_no_openssh_match(self):
        self.assertEqual(fingerprint.parse_service("SSH-2.0-dropbear_2019.78")["product"], "")

    def test_elasticsearch_requires_corroborating_markers(self):
        es = '{ "name" : "n", "version" : { "number" : "7.10.2", "lucene_version" : "8.7.0" } }'
        self.assertEqual(fingerprint.parse_service(es), {"product": "elasticsearch", "version": "7.10.2"})
        legacy = '{"status":200,"version":{"number":"1.4.2"},"tagline":"You Know, for Search"}'
        self.assertEqual(fingerprint.parse_service(legacy)["version"], "1.4.2")
        # a random JSON API on :9200 that merely has a "number" field is not Elasticsearch
        self.assertEqual(fingerprint.parse_service('{"number": "42", "ok": true}')["product"], "")

    def test_version_is_delimited_not_glued_to_next_field(self):
        info = fingerprint._clean(b"$100\r\n# Server\r\nredis_version:6.0.9\r\nredis_git_sha1:00000000\r\n")
        self.assertEqual(fingerprint.parse_service(info), {"product": "redis", "version": "6.0.9"})

    def test_apache_server_header_without_version(self):
        self.assertEqual(fingerprint.parse_service("Server: Apache"), {"product": "apache_http_server", "version": ""})

    def test_case_insensitive(self):
        self.assertEqual(fingerprint.parse_service("server: NGINX/1.18.0")["product"], "nginx")

    def test_exim_mysql_proftpd(self):
        self.assertEqual(fingerprint.parse_service("220 mx ESMTP Exim 4.91 Mon")["version"], "4.91")
        self.assertEqual(fingerprint.parse_service("220 ProFTPD 1.3.5 Server (Debian)")["version"], "1.3.5")
        self.assertEqual(fingerprint.parse_service("5.5.5-10.3.22-MariaDB")["product"], "")  # not claimed

    def test_hostile_banner_is_handled(self):
        for banner in ("A" * 100000, "\x00" * 50, "OpenSSH_" * 5000, "\u2603" * 100):
            fingerprint.parse_service(banner)                    # must not raise or hang


class CleanTests(unittest.TestCase):
    def test_newlines_become_spaces_controls_dropped(self):
        self.assertEqual(fingerprint._clean(b"220-Hi\r\n220 ready\x00\x1b[31m\tok"), "220-Hi 220 ready[31m ok")
        self.assertEqual(fingerprint._clean(b""), "")
        self.assertEqual(len(fingerprint._clean(b"x" * 1000, limit=50)), 50)

    def test_non_utf8_bytes(self):
        self.assertIsInstance(fingerprint._clean(bytes(range(256))), str)


def _serve(handler, n=1):
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", 0))
    s.listen(8)
    port = s.getsockname()[1]

    def loop():
        for _ in range(n):
            try:
                c, _ = s.accept()
            except OSError:
                break
            try:
                handler(c)
            except (OSError, ssl.SSLError):
                pass
            finally:
                c.close()
        s.close()

    threading.Thread(target=loop, daemon=True).start()
    return port


class LiveGrabTests(unittest.TestCase):
    def test_http_server_header_via_head(self):
        port = _serve(lambda c: (c.recv(1024), c.sendall(b"HTTP/1.1 200 OK\r\nServer: nginx/1.10.3\r\n\r\n")))
        with mock.patch.object(fingerprint, "_HTTP_PORTS", {port}):
            fp = fingerprint.fingerprint_port("127.0.0.1", port, timeout=2)
        self.assertEqual((fp["product"], fp["version"]), ("nginx", "1.10.3"))

    def test_headers_split_across_segments(self):
        def handler(c):
            c.recv(1024)
            c.sendall(b"HTTP/1.1 200 OK\r\nServ")
            time.sleep(0.2)
            c.sendall(b"er: Apache/2.4.49 (Unix)\r\n\r\n")
        port = _serve(handler)
        with mock.patch.object(fingerprint, "_HTTP_PORTS", {port}):
            fp = fingerprint.fingerprint_port("127.0.0.1", port, timeout=3)
        self.assertEqual((fp["product"], fp["version"]), ("apache_http_server", "2.4.49"))

    def test_no_server_header_falls_back_to_status_line(self):
        port = _serve(lambda c: (c.recv(1024), c.sendall(b"HTTP/1.0 403 Forbidden\r\nX-Other: 1\r\n\r\n")))
        with mock.patch.object(fingerprint, "_HTTP_PORTS", {port}):
            fp = fingerprint.fingerprint_port("127.0.0.1", port, timeout=2)
        self.assertEqual(fp["banner"], "HTTP/1.0 403 Forbidden")

    def test_elasticsearch_version_read_from_body(self):
        body = b'{ "name":"n", "version":{ "number":"7.10.2", "lucene_version":"8.7.0" } }'

        def handler(c):
            c.recv(1024)
            c.sendall(b"HTTP/1.0 200 OK\r\nContent-Type: application/json\r\n\r\n")
            time.sleep(0.2)
            c.sendall(body)
        port = _serve(handler)
        with mock.patch.object(fingerprint, "_HTTP_PORTS", {port}), mock.patch.object(fingerprint, "_BODY_PORTS", {port}):
            fp = fingerprint.fingerprint_port("127.0.0.1", port, timeout=3)
        self.assertEqual((fp["product"], fp["version"]), ("elasticsearch", "7.10.2"))

    def test_redis_version_from_info(self):
        def handler(c):
            c.recv(64)
            c.sendall(b"$40\r\n# Server\r\nredis_version:6.0.9\r\nos:Linux\r\n")
        port = _serve(handler)
        with mock.patch.object(fingerprint, "_REDIS_PORTS", {port}):
            fp = fingerprint.fingerprint_port("127.0.0.1", port, timeout=2)
        self.assertEqual((fp["product"], fp["version"]), ("redis", "6.0.9"))

    def test_redis_requiring_auth_reveals_nothing(self):
        port = _serve(lambda c: (c.recv(64), c.sendall(b"-NOAUTH Authentication required.\r\n")))
        with mock.patch.object(fingerprint, "_REDIS_PORTS", {port}):
            fp = fingerprint.fingerprint_port("127.0.0.1", port, timeout=2)
        self.assertEqual((fp["product"], fp["version"]), ("", ""))

    def test_ssh_banner_read_passively(self):
        port = _serve(lambda c: c.sendall(b"SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.10\r\n"))
        fp = fingerprint.fingerprint_port("127.0.0.1", port, timeout=2)
        self.assertEqual((fp["product"], fp["version"], fp["os_hint"]), ("openssh", "7.2p2", "Linux (Ubuntu)"))

    def test_http_on_nonstandard_port_found_by_fallback(self):
        # Regression: only well-known HTTP ports got an HTTP probe, so a web
        # server on 8081/9000/5000 (silent until spoken to) was never identified.
        port = _serve(lambda c: (c.recv(1024), c.sendall(b"HTTP/1.1 200 OK\r\nServer: lighttpd/1.4.55\r\n\r\n")), n=2)
        fp = fingerprint.fingerprint_port("127.0.0.1", port, timeout=0.5)
        self.assertEqual((fp["product"], fp["version"]), ("lighttpd", "1.4.55"))

    def test_tls_http_server_identified_on_https_port(self):
        import os
        import subprocess
        import tempfile
        try:
            d = tempfile.mkdtemp()
            crt, key = os.path.join(d, "c.pem"), os.path.join(d, "k.pem")
            subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-keyout", key, "-out", crt,
                            "-days", "2", "-nodes", "-subj", "/CN=x"], check=True, capture_output=True)
        except Exception:
            self.skipTest("openssl not available")
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(crt, key)

        def handler(c):
            t = ctx.wrap_socket(c, server_side=True)
            t.recv(1024)
            t.sendall(b"HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\n\r\n")
        port = _serve(handler)
        with mock.patch.object(fingerprint, "_HTTP_PORTS", {port}), \
                mock.patch.object(fingerprint, "_HTTPS_FIRST_PORTS", {port}):
            fp = fingerprint.fingerprint_port("127.0.0.1", port, timeout=3)
        self.assertEqual((fp["product"], fp["version"]), ("nginx", "1.24.0"))

    def test_silent_service_returns_empty_within_bounded_time(self):
        port = _serve(lambda c: time.sleep(1.5), n=3)
        t0 = time.monotonic()
        fp = fingerprint.fingerprint_port("127.0.0.1", port, timeout=0.3)
        self.assertEqual((fp["banner"], fp["product"]), ("", ""))
        self.assertLess(time.monotonic() - t0, 3.0)

    def test_closed_port_returns_empty(self):
        s = socket.socket(); s.bind(("127.0.0.1", 0)); port = s.getsockname()[1]; s.close()
        fp = fingerprint.fingerprint_port("127.0.0.1", port, timeout=0.3)
        self.assertEqual((fp["banner"], fp["product"], fp["os_hint"]), ("", "", ""))


class HostLevelTests(unittest.TestCase):
    def test_os_guess_majority_and_deterministic_tie(self):
        def fake(host, port, timeout=2.0):
            hint = {1: "Linux (Debian)", 2: "Linux (Debian)", 3: "Windows", 4: ""}[port]
            return {"port": port, "service": "x", "banner": "", "os_hint": hint, "product": "", "version": ""}
        with mock.patch.object(fingerprint, "fingerprint_port", side_effect=fake):
            self.assertEqual(fingerprint.fingerprint_host("h", [1, 2, 3, 4])["os_guess"], "Linux (Debian)")
            tie = {fingerprint.fingerprint_host("h", [2, 3])["os_guess"] for _ in range(20)}
        self.assertEqual(tie, {"Linux (Debian)"})              # alphabetical tie-break, not hash-order

    def test_accepts_ints_and_dicts_and_empty(self):
        with mock.patch.object(fingerprint, "fingerprint_port",
                               side_effect=lambda h, p, t=2.0: {"port": p, "os_hint": "", "banner": "",
                                                               "product": "", "version": "", "service": ""}):
            r = fingerprint.fingerprint_host("h", [22, {"port": 80}])
            self.assertEqual([x["port"] for x in r["ports"]], [22, 80])
            self.assertEqual(fingerprint.fingerprint_host("h", [])["ports"], [])


if __name__ == "__main__":
    unittest.main()
