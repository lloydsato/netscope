"""Tests for scan-snapshot persistence and baseline diffing."""

import os
import tempfile
import unittest

from netscope import storage, findings as F


class SnapshotDiffTests(unittest.TestCase):
    def setUp(self):
        self.db = tempfile.mktemp(suffix=".db")
        self.conn = storage.connect(self.db)

    def tearDown(self):
        self.conn.close()
        if os.path.exists(self.db):
            os.unlink(self.db)

    def test_save_and_diff(self):
        a = F.make_finding("cve", "high", "Old CVE", host="10.0.0.1", port=22, detail="a")
        b = F.make_finding("tls", "medium", "Self-signed", host="10.0.0.1", port=443, detail="b")
        c = F.make_finding("weak-auth", "critical", "Open Redis", host="10.0.0.2", port=6379, detail="c")

        s1 = storage.save_scan(self.conn, [a, b], subnet="10.0.0.0/24", n_hosts=2)
        s2 = storage.save_scan(self.conn, [b, c], subnet="10.0.0.0/24", n_hosts=2)

        diff = storage.diff_scans(self.conn, s1, s2)
        self.assertEqual([f["title"] for f in diff["added"]], ["Open Redis"])
        self.assertEqual([f["title"] for f in diff["resolved"]], ["Old CVE"])
        self.assertEqual([f["title"] for f in diff["unchanged"]], ["Self-signed"])

    def test_get_scans_orders_newest_first(self):
        storage.save_scan(self.conn, [], label="first")
        storage.save_scan(self.conn, [], label="second")
        scans = storage.get_scans(self.conn, limit=5)
        self.assertEqual(scans[0]["label"], "second")

    def test_refs_roundtrip(self):
        f = F.make_finding("cve", "high", "X", host="h", port=1, refs=["CVE-1", "CVE-2"])
        sid = storage.save_scan(self.conn, [f])
        got = storage.get_scan_findings(self.conn, sid)
        self.assertEqual(got[0]["refs"], ["CVE-1", "CVE-2"])


if __name__ == "__main__":
    unittest.main()
