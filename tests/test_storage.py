"""Tests for scan-snapshot persistence and baseline diffing."""

import os
import tempfile
import unittest
from unittest import mock

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


class ConnectTests(unittest.TestCase):
    def test_bare_filename_works(self):
        # Regression: os.makedirs(os.path.dirname("audits.db")) -> makedirs("") raised.
        d = tempfile.mkdtemp()
        old = os.getcwd()
        os.chdir(d)
        try:
            conn = storage.connect("audits.db")
            conn.close()
            self.assertTrue(os.path.exists(os.path.join(d, "audits.db")))
        finally:
            os.chdir(old)

    def test_nested_missing_directories_created(self):
        d = tempfile.mkdtemp()
        path = os.path.join(d, "a", "b", "c", "x.db")
        storage.connect(path).close()
        self.assertTrue(os.path.exists(path))

    def test_tilde_expanded(self):
        d = tempfile.mkdtemp()
        with mock.patch.dict(os.environ, {"HOME": d, "USERPROFILE": d}):
            storage.connect("~/.nscope/t.db").close()
        self.assertTrue(os.path.exists(os.path.join(d, ".nscope", "t.db")))

    def test_reopen_is_idempotent_and_preserves_data(self):
        db = os.path.join(tempfile.mkdtemp(), "x.db")
        c = storage.connect(db)
        storage.upsert_devices(c, [{"ip": "10.0.0.1", "mac": "aa:aa:aa:aa:aa:01"}])
        c.close()
        c2 = storage.connect(db)
        self.assertEqual(storage.device_count(c2), 1)

    def test_unwritable_location_raises_oserror(self):
        with self.assertRaises(OSError):
            storage.connect("/proc/nope/x.db")


class DeviceAndPortTests(unittest.TestCase):
    def setUp(self):
        self.conn = storage.connect(os.path.join(tempfile.mkdtemp(), "d.db"))
        self.addCleanup(self.conn.close)

    def test_upsert_reports_only_new(self):
        h = [{"ip": "10.0.0.1", "mac": "aa:aa:aa:aa:aa:01", "vendor": "V"}]
        self.assertEqual(storage.upsert_devices(self.conn, h), ["aa:aa:aa:aa:aa:01"])
        self.assertEqual(storage.upsert_devices(self.conn, h), [])

    def test_ip_change_updates_same_device(self):
        storage.upsert_devices(self.conn, [{"ip": "10.0.0.1", "mac": "aa:aa:aa:aa:aa:01"}])
        storage.upsert_devices(self.conn, [{"ip": "10.0.0.77", "mac": "aa:aa:aa:aa:aa:01"}])
        devs = storage.get_devices(self.conn)
        self.assertEqual((len(devs), devs[0]["ip"]), (1, "10.0.0.77"))

    def test_none_fields_do_not_erase_known_values(self):
        storage.upsert_devices(self.conn, [{"ip": "10.0.0.1", "mac": "aa:aa:aa:aa:aa:01", "vendor": "Acme", "hostname": "nas"}])
        storage.upsert_devices(self.conn, [{"ip": "10.0.0.1", "mac": "aa:aa:aa:aa:aa:01"}])
        d = storage.get_devices(self.conn)[0]
        self.assertEqual((d["vendor"], d["hostname"]), ("Acme", "nas"))

    def test_hosts_without_identity_skipped(self):
        self.assertEqual(storage.upsert_devices(self.conn, [{}, {"ip": None, "mac": None}]), [])
        self.assertEqual(storage.device_count(self.conn), 0)

    def test_record_ports_returns_only_new_and_accepts_ints(self):
        self.assertEqual(storage.record_ports(self.conn, "dev", [{"port": 22, "service": "ssh"}, 80]), [22, 80])
        self.assertEqual(storage.record_ports(self.conn, "dev", [22, 80, 443]), [443])
        self.assertEqual(storage.get_known_ports(self.conn, "dev"), {22, 80, 443})

    def test_history_getters_have_human_timestamps(self):
        storage.upsert_devices(self.conn, [{"ip": "10.0.0.1", "mac": "aa:aa:aa:aa:aa:01"}])
        storage.record_event(self.conn, "new_device", "hello")
        self.assertRegex(storage.get_devices(self.conn)[0]["first_seen_h"], r"^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d$")
        self.assertEqual(storage.get_recent_events(self.conn)[0]["detail"], "hello")
        self.assertEqual(storage.get_recent_events(self.conn, limit=0), [])


class ScopedDiffTests(unittest.TestCase):
    def setUp(self):
        self.conn = storage.connect(os.path.join(tempfile.mkdtemp(), "s.db"))
        self.addCleanup(self.conn.close)

    def test_previous_scan_is_same_target_only(self):
        a1 = storage.save_scan(self.conn, [], subnet="10.0.0.1")
        b1 = storage.save_scan(self.conn, [], subnet="10.0.0.2")
        a2 = storage.save_scan(self.conn, [], subnet="10.0.0.1")
        self.assertEqual(storage.previous_scan(self.conn, a2)["id"], a1)    # skips b1
        self.assertIsNone(storage.previous_scan(self.conn, b1))
        self.assertIsNone(storage.previous_scan(self.conn, a1))
        self.assertIsNone(storage.previous_scan(self.conn, 999))

    def test_previous_scan_handles_null_subnet(self):
        s1 = storage.save_scan(self.conn, [])
        s2 = storage.save_scan(self.conn, [])
        self.assertEqual(storage.previous_scan(self.conn, s2)["id"], s1)

    def test_get_scan(self):
        sid = storage.save_scan(self.conn, [], subnet="x", label="L", n_hosts=3)
        row = storage.get_scan(self.conn, sid)
        self.assertEqual((row["subnet"], row["label"], row["n_hosts"]), ("x", "L", 3))
        self.assertIsNone(storage.get_scan(self.conn, sid + 1))

    def test_scan_findings_expose_id_like_live_findings(self):
        f = F.make_finding("tls", "low", "T", host="h", port=1)
        sid = storage.save_scan(self.conn, [f])
        self.assertEqual(storage.get_scan_findings(self.conn, sid)[0]["id"], f["id"])

    def test_diff_with_unknown_ids_is_empty_not_error(self):
        d = storage.diff_scans(self.conn, 998, 999)
        self.assertEqual((d["added"], d["resolved"], d["unchanged"]), ([], [], []))

    def test_volatile_detail_does_not_split_a_finding(self):
        # Regression: "expires in 12 days" vs "11 days" made one issue appear as
        # a resolved finding AND a new one in every daily diff.
        def tls(days):
            return F.from_tls("10.0.0.1", 443, [{
                "severity": "medium", "title": "TLS certificate expiring soon", "key": "expiring",
                "detail": f"Certificate expires in {days} day(s) (x).", "evidence": ""}])
        s1 = storage.save_scan(self.conn, tls(12), subnet="10.0.0.1")
        s2 = storage.save_scan(self.conn, tls(11), subnet="10.0.0.1")
        d = storage.diff_scans(self.conn, s1, s2)
        self.assertEqual((len(d["added"]), len(d["resolved"]), len(d["unchanged"])), (0, 0, 1))

    def test_weird_text_roundtrips(self):
        f = F.make_finding("x", "info", "t\u00e9st \"quoted\" ; semi", host="h", port=None,
                           detail="line1\nline2", refs=["a b", "c"])
        sid = storage.save_scan(self.conn, [f])
        got = storage.get_scan_findings(self.conn, sid)[0]
        self.assertEqual((got["title"], got["detail"], got["refs"]), (f["title"], f["detail"], ["a b", "c"]))


if __name__ == "__main__":
    unittest.main()
