"""Tests for banner-based product/version extraction."""

import unittest

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


if __name__ == "__main__":
    unittest.main()
