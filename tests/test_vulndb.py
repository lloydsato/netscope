"""Tests for the offline vuln database and its version comparator."""

import unittest

from netscope import vulndb


class VersionCompareTests(unittest.TestCase):
    def test_tuple_parsing(self):
        self.assertEqual(vulndb._version_tuple("1.4.10"), (1, 4, 10))
        self.assertEqual(vulndb._version_tuple("2.4.49"), (2, 4, 49))
        self.assertEqual(vulndb._version_tuple(""), (0,))
        self.assertEqual(vulndb._version_tuple("garbage-"), vulndb._version_tuple("garbage"))

    def test_patch_level_suffix_ordering(self):
        # OpenSSH 'p' levels: boundary comparisons must be exact.
        self.assertTrue(vulndb._cmp("9.3p1", "9.3p2") < 0)
        self.assertTrue(vulndb._cmp("7.2p2", "7.2") > 0)
        self.assertTrue(vulndb._cmp("7.7p1", "7.8") < 0)
        self.assertTrue(vulndb._cmp("8.5p1", "8.5p1") == 0)

    def test_letter_suffix_ordering(self):
        # ProFTPD/OpenSSL style: trailing letter is a post-release patch.
        self.assertTrue(vulndb._cmp("1.3.5", "1.3.5a") < 0)
        self.assertTrue(vulndb._cmp("1.3.5a", "1.3.5b") < 0)
        self.assertTrue(vulndb._cmp("1.0.2k", "1.0.2") > 0)

    def test_prerelease_sorts_before_release(self):
        self.assertTrue(vulndb._cmp("2.0rc1", "2.0") < 0)
        self.assertTrue(vulndb._cmp("2.0rc1", "2.0rc2") < 0)
        self.assertTrue(vulndb._cmp("2.0beta1", "2.0rc1") < 0)
        self.assertTrue(vulndb._cmp("2.0-alpha", "2.0-beta") < 0)

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

    def test_or_alternatives(self):
        pred = "<1.3.8 || >=1.4.0,<1.4.3"
        self.assertTrue(vulndb._version_match("1.3.7", pred))
        self.assertFalse(vulndb._version_match("1.3.8", pred))
        self.assertFalse(vulndb._version_match("1.3.9", pred))   # gap between branches
        self.assertTrue(vulndb._version_match("1.4.2", pred))
        self.assertFalse(vulndb._version_match("1.4.3", pred))
        self.assertFalse(vulndb._version_match("1.6.0", pred))

    def test_malformed_predicates_never_match_or_crash(self):
        for bad in ("", " ", "||", ",", "<", "<=", ">= ,", None):
            self.assertFalse(vulndb._version_match("1.0", bad), bad)

    def test_no_version_only_wildcard(self):
        # Without a version we can't confirm a range -> only "*" matches.
        self.assertFalse(vulndb._version_match("", "<7.7"))
        self.assertTrue(vulndb._version_match("", "*"))


def _cves(product, version):
    return {r["cve"] for r in vulndb.match(product, version)}


class CveBoundaryRegressionTests(unittest.TestCase):
    """Boundaries verified against NVD (and nginx's own advisory for CVE-2017-7529).

    Every record here once had a wrong range: either flagging unaffected
    versions (false positives) or skipping affected ones (false negatives).
    """

    def test_openssh_username_enum_includes_7_7(self):          # NVD: "through 7.7"
        self.assertIn("CVE-2018-15473", _cves("openssh", "7.7"))
        self.assertIn("CVE-2018-15473", _cves("openssh", "7.7p1"))
        self.assertNotIn("CVE-2018-15473", _cves("openssh", "7.8"))
        self.assertNotIn("CVE-2018-15473", _cves("openssh", "7.8p1"))

    def test_openssh_agent_pkcs11_boundary(self):               # before 9.3p2
        self.assertIn("CVE-2023-38408", _cves("openssh", "9.3p1"))
        self.assertNotIn("CVE-2023-38408", _cves("openssh", "9.3p2"))

    def test_openssh_regresshion_range(self):                   # 8.5p1 <= v < 9.8p1
        self.assertNotIn("CVE-2024-6387", _cves("openssh", "8.4p1"))
        self.assertIn("CVE-2024-6387", _cves("openssh", "8.5p1"))
        self.assertIn("CVE-2024-6387", _cves("openssh", "9.7p1"))
        self.assertNotIn("CVE-2024-6387", _cves("openssh", "9.8p1"))

    def test_apache_42013_only_2_4_49_and_2_4_50(self):
        for fixed_or_unaffected in ("2.2.34", "2.4.7", "2.4.48", "2.4.51", "2.4.58"):
            self.assertNotIn("CVE-2021-42013", _cves("apache_http_server", fixed_or_unaffected))
        for affected in ("2.4.49", "2.4.50"):
            self.assertIn("CVE-2021-42013", _cves("apache_http_server", affected))
        self.assertIn("CVE-2021-41773", _cves("apache_http_server", "2.4.49"))
        self.assertNotIn("CVE-2021-41773", _cves("apache_http_server", "2.4.50"))

    def test_nginx_range_filter_vendor_advisory(self):
        # Vulnerable 0.5.6-1.13.2; not vulnerable 1.13.3+ and 1.12.1+.
        for affected in ("0.5.6", "1.10.3", "1.12.0", "1.13.0", "1.13.2"):
            self.assertIn("CVE-2017-7529", _cves("nginx", affected), affected)
        for safe in ("0.5.5", "1.12.1", "1.12.2", "1.13.3", "1.13.6", "1.18.0", "1.25.3"):
            self.assertNotIn("CVE-2017-7529", _cves("nginx", safe), safe)

    def test_proftpd_mod_copy_only_1_3_5(self):
        self.assertIn("CVE-2015-3306", _cves("proftpd", "1.3.5"))
        self.assertNotIn("CVE-2015-3306", _cves("proftpd", "1.3.5a"))   # fixed
        self.assertNotIn("CVE-2015-3306", _cves("proftpd", "1.3.4"))
        self.assertNotIn("CVE-2015-3306", _cves("proftpd", "1.3.6"))

    def test_exim_return_of_the_wizard_includes_4_91(self):    # NVD: 4.87 to 4.91 inclusive
        self.assertNotIn("CVE-2019-10149", _cves("exim", "4.86"))
        for affected in ("4.87", "4.89", "4.91"):
            self.assertIn("CVE-2019-10149", _cves("exim", affected))
        self.assertNotIn("CVE-2019-10149", _cves("exim", "4.92"))

    def test_redis_msetnx_7_0_8_to_7_0_9(self):
        self.assertNotIn("CVE-2023-28425", _cves("redis", "5.0.7"))
        self.assertNotIn("CVE-2023-28425", _cves("redis", "7.0.7"))
        self.assertIn("CVE-2023-28425", _cves("redis", "7.0.8"))
        self.assertIn("CVE-2023-28425", _cves("redis", "7.0.9"))
        self.assertNotIn("CVE-2023-28425", _cves("redis", "7.0.10"))
        self.assertNotIn("CVE-2023-28425", _cves("redis", "7.2.4"))

    def test_elasticsearch_groovy_sandbox_branches(self):
        for affected in ("1.1.0", "1.3.7", "1.4.0", "1.4.2"):
            self.assertIn("CVE-2015-1427", _cves("elasticsearch", affected), affected)
        for safe in ("1.3.8", "1.3.9", "1.4.3", "1.6.0", "7.10.2"):
            self.assertNotIn("CVE-2015-1427", _cves("elasticsearch", safe), safe)

    def test_mongodb_nativehelper_branches_and_severity(self):
        for affected in ("2.0.8", "2.2.0", "2.2.3"):
            self.assertIn("CVE-2013-1892", _cves("mongodb", affected), affected)
        for safe in ("2.0.9", "2.2.4", "2.4.0", "2.6.0", "4.4.0"):
            self.assertNotIn("CVE-2013-1892", _cves("mongodb", safe), safe)
        rec = [r for r in vulndb.match("mongodb", "2.0.8") if r["cve"] == "CVE-2013-1892"][0]
        self.assertEqual(rec["severity"], "medium")                 # NVD v2 score 6.0

    def test_routeros_winbox_range(self):
        self.assertNotIn("CVE-2018-14847", _cves("routeros", "6.28"))
        self.assertIn("CVE-2018-14847", _cves("routeros", "6.42"))
        self.assertNotIn("CVE-2018-14847", _cves("routeros", "6.42.1"))
        self.assertNotIn("CVE-2018-14847", _cves("routeros", "7.1"))

    def test_vsftpd_backdoor_only_2_3_4(self):
        self.assertIn("CVE-2011-2523", _cves("vsftpd", "2.3.4"))
        self.assertNotIn("CVE-2011-2523", _cves("vsftpd", "2.3.5"))
        self.assertNotIn("CVE-2011-2523", _cves("vsftpd", "3.0.3"))

    def test_every_record_is_well_formed(self):
        """Guards the data file itself: required keys, parseable predicates."""
        records = vulndb._load_db()["records"]
        self.assertGreater(len(records), 0)
        for r in records:
            for key in ("product", "affected", "cve", "cvss", "title", "description", "ref"):
                self.assertTrue(r.get(key) not in (None, ""), (r.get("cve"), key))
            self.assertRegex(r["cve"], r"^CVE-\d{4}-\d{4,}$")
            self.assertTrue(0 <= float(r["cvss"]) <= 10)
            # A predicate must match *something* (not be a typo that never fires)
            # and must not match everything (that would be a blanket false positive).
            probes_ = ["0.1", "1.0", "1.4.2", "2.0.8", "2.4.49", "4.91", "6.42", "7.0.8",
                       "7.7p1", "8.5p1", "9.0", "99.0"]
            hits = [v for v in probes_ if vulndb._version_match(v, r["affected"])]
            self.assertNotEqual(len(hits), len(probes_), r["cve"])


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


class DataFileIntegrityTests(unittest.TestCase):
    """The shipped snapshot must be exactly what scripts/build_vulndb.py produces."""

    @staticmethod
    def _load_build_script():
        import importlib.util
        import os
        path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                            "scripts", "build_vulndb.py")
        if not os.path.exists(path):
            raise unittest.SkipTest("build script not present (installed package)")
        spec = importlib.util.spec_from_file_location("build_vulndb", path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod

    def test_shipped_db_matches_build_script(self):
        mod = self._load_build_script()
        shipped = vulndb._load_db()
        self.assertEqual(shipped["records"], mod.RECORDS)
        self.assertEqual(shipped["weak_defaults"], mod.WEAK_DEFAULTS)

    def test_build_is_reproducible(self):
        import contextlib
        import io
        import os
        mod = self._load_build_script()
        path = vulndb._DATA_PATH
        before = open(path, "rb").read()
        try:
            with contextlib.redirect_stdout(io.StringIO()):
                mod.build()
            after = open(path, "rb").read()
        finally:
            open(path, "wb").write(before)          # never leave the tree modified by a test
        self.assertEqual(before, after)
        self.assertTrue(os.path.getsize(path) > 0)

    def test_missing_database_warns_and_disables_matching(self):
        from unittest import mock
        vulndb._load_db.cache_clear()
        try:
            with mock.patch.object(vulndb, "_DATA_PATH", "/nonexistent/vulns.json.gz"):
                with self.assertWarns(RuntimeWarning) as cm:
                    self.assertEqual(vulndb.match("openssh", "1.0"), [])
            self.assertIn("DISABLED", str(cm.warning))
        finally:
            vulndb._load_db.cache_clear()

    def test_version_strings_agree(self):
        import os
        import re
        import netscope
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        setup_py = os.path.join(root, "setup.py")
        if not os.path.exists(setup_py):
            self.skipTest("setup.py not present")
        declared = re.search(r'version="([^"]+)"', open(setup_py).read()).group(1)
        self.assertEqual(declared, netscope.__version__)


if __name__ == "__main__":
    unittest.main()
