"""Tests for the offline vuln database and its version comparator."""

import unittest

from netscope import vulndb


class VersionCompareTests(unittest.TestCase):
    def test_tuple_parsing(self):
        self.assertEqual(vulndb._version_tuple("7.2p2"), (7, 2, 2))
        self.assertEqual(vulndb._version_tuple("1.4.10"), (1, 4, 10))
        self.assertEqual(vulndb._version_tuple("2.4.49"), (2, 4, 49))

    def test_cmp_padding(self):
        self.assertEqual(vulndb._cmp("1.2", "1.2.0"), 0)
        self.assertTrue(vulndb._cmp("1.10", "1.9") > 0)   # numeric, not lexical
        self.assertTrue(vulndb._cmp("2.4.49", "2.4.50") < 0)

    def test_predicates(self):
        self.assertTrue(vulndb._version_match("7.2", "<7.7"))
        self.assertFalse(vulndb._version_match("7.9", "<7.7"))
        self.assertTrue(vulndb._version_match("2.4.49", "==2.4.49"))
        self.assertTrue(vulndb._version_match("2.4.50", "<=2.4.50"))
        self.assertTrue(vulndb._version_match("4.90", ">=4.87,<4.91"))
        self.assertFalse(vulndb._version_match("4.91", ">=4.87,<4.91"))
        self.assertTrue(vulndb._version_match("anything", "*"))

    def test_no_version_only_wildcard(self):
        # Without a version we can't confirm a range -> only "*" matches.
        self.assertFalse(vulndb._version_match("", "<7.7"))
        self.assertTrue(vulndb._version_match("", "*"))


class MatchTests(unittest.TestCase):
    def test_openssh_old_matches_and_orders_by_cvss(self):
        m = vulndb.match("openssh", "7.2p2")
        cves = [r["cve"] for r in m]
        self.assertIn("CVE-2018-15473", cves)
        self.assertIn("CVE-2023-38408", cves)
        self.assertNotIn("CVE-2024-6387", cves)   # needs >=8.5p1
        # ordered by CVSS descending
        cvsses = [r["cvss"] for r in m]
        self.assertEqual(cvsses, sorted(cvsses, reverse=True))

    def test_apache_exact_version(self):
        m = vulndb.match("apache_http_server", "2.4.49")
        self.assertTrue(any(r["cve"] == "CVE-2021-41773" for r in m))

    def test_unknown_product(self):
        self.assertEqual(vulndb.match("totally-not-real", "1.0"), [])

    def test_weak_defaults(self):
        self.assertIsNotNone(vulndb.weak_default("redis"))
        self.assertIsNotNone(vulndb.weak_default("mongodb"))
        self.assertIsNone(vulndb.weak_default("openssh"))

    def test_severity_derived_when_absent(self):
        for r in vulndb.match("vsftpd", "2.3.4"):
            self.assertIn(r["severity"], ("critical", "high", "medium", "low", "info"))


if __name__ == "__main__":
    unittest.main()
