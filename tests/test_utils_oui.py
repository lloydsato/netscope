"""Tests for shared helpers (utils) and the bundled OUI vendor database."""

import ipaddress
import unittest
from unittest import mock

from netscope import oui, utils


class SafeTextTests(unittest.TestCase):
    def test_control_and_escape_bytes_neutralised(self):
        out = utils.safe_text("\x1b[2J\x1b[Hevil\x07\r\n\x00.com")
        self.assertNotIn("\x1b", out)
        self.assertTrue(all(" " <= ch <= "~" for ch in out))
        self.assertIn("evil", out)

    def test_non_ascii_replaced(self):
        self.assertEqual(utils.safe_text("café"), "caf?")

    def test_limit_and_none(self):
        self.assertEqual(utils.safe_text("a" * 500, limit=10), "a" * 10)
        self.assertEqual(utils.safe_text(None), "")
        self.assertEqual(utils.safe_text(12345), "12345")

    def test_plain_text_untouched(self):
        self.assertEqual(utils.safe_text("www.example.com"), "www.example.com")


class EntropyTests(unittest.TestCase):
    def test_bounds(self):
        self.assertEqual(utils.shannon_entropy(""), 0.0)
        self.assertEqual(utils.shannon_entropy("aaaa"), 0.0)
        self.assertAlmostEqual(utils.shannon_entropy("ab"), 1.0)
        self.assertAlmostEqual(utils.shannon_entropy("abcd"), 2.0)

    def test_random_looking_beats_english(self):
        self.assertGreater(utils.shannon_entropy("x9f3kq0z8vj2m7wl4c1b"),
                           utils.shannon_entropy("aaaaabbbbbaaaaabbbbb"))


class FmtTableTests(unittest.TestCase):
    def test_alignment_and_none_cells(self):
        out = utils.fmt_table([["a", None], ["longer", 5]], ["COL1", "COL2"])
        lines = out.splitlines()
        self.assertEqual(len(lines), 4)
        self.assertTrue(lines[0].startswith("COL1"))
        self.assertIn("None", out)               # no crash on non-strings
        self.assertEqual(len({len(l.rstrip()) <= len(lines[1]) for l in lines}), 1)

    def test_empty_rows(self):
        self.assertEqual(len(utils.fmt_table([], ["A", "B"]).splitlines()), 2)


class SubnetTests(unittest.TestCase):
    def test_default_subnet_is_valid_cidr_or_none(self):
        s = utils.get_default_subnet()
        if s is not None:
            self.assertIsInstance(ipaddress.ip_network(s), ipaddress.IPv4Network)

    def test_no_network_returns_none_not_raise(self):
        with mock.patch("socket.socket", side_effect=OSError("network is unreachable")):
            self.assertIsNone(utils.get_default_subnet())


class DataTableTests(unittest.TestCase):
    def test_risky_ports_are_valid_and_explained(self):
        for port, why in utils.RISKY_PORTS.items():
            self.assertTrue(1 <= port <= 65535)
            self.assertTrue(why.strip())

    def test_port_name(self):
        self.assertEqual(utils.port_name(22), "ssh")
        self.assertEqual(utils.port_name(54321), "unknown")

    def test_udp_ports_valid_and_sorted(self):
        self.assertEqual(utils.COMMON_UDP_PORTS, sorted(set(utils.COMMON_UDP_PORTS)))
        self.assertTrue(all(1 <= p <= 65535 for p in utils.COMMON_UDP_PORTS))


class OuiTests(unittest.TestCase):
    def test_database_loaded(self):
        db = oui._load_db()
        self.assertGreater(len(db), 30000)
        for key in list(db)[:200]:
            self.assertRegex(key, r"^[0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2}$")

    def test_known_vendors_in_every_common_format(self):
        for mac in ("00:00:0c:12:34:56", "00:00:0C:12:34:56", "00-00-0C-12-34-56",
                    "0000.0c12.3456", "00000c123456", "00:00:0C"):
            self.assertIn("Cisco", oui.lookup(mac), mac)
        self.assertIn("VMware", oui.lookup("00:50:56:aa:bb:cc"))
        self.assertIn("Raspberry", oui.lookup("b8:27:eb:00:00:01"))

    def test_randomised_private_mac(self):
        # Locally-administered bit set (0x02) and not a registered OUI.
        self.assertEqual(oui.lookup("da:a1:19:12:34:56"), "randomized/private MAC")
        self.assertTrue(oui.is_locally_administered("da:a1:19:12:34:56"))
        self.assertTrue(oui.is_locally_administered("02:00:00:00:00:01"))
        self.assertFalse(oui.is_locally_administered("00:00:0c:00:00:01"))

    def test_unknown_but_globally_administered(self):
        self.assertEqual(oui.lookup("04:00:00:00:00:01"), "unknown")

    def test_garbage_input_never_raises(self):
        for bad in (None, "", " ", "zz", "12", "not a mac", "00:11", "::::::", 0):
            try:
                result = oui.lookup(bad)
            except Exception as e:           # noqa: BLE001
                self.fail(f"lookup({bad!r}) raised {e!r}")
            self.assertEqual(result, "unknown", bad)
        self.assertFalse(oui.is_locally_administered(None))
        self.assertFalse(oui.is_locally_administered("z"))

    def test_enrich_hosts_in_place(self):
        hosts = [{"ip": "10.0.0.1", "mac": "00:50:56:00:00:01"}, {"ip": "10.0.0.2", "mac": None},
                 {"ip": "10.0.0.3"}]
        out = oui.enrich_hosts(hosts)
        self.assertIs(out, hosts)
        self.assertIn("VMware", hosts[0]["vendor"])
        self.assertEqual(hosts[1]["vendor"], "unknown")
        self.assertEqual(hosts[2]["vendor"], "unknown")

    def test_missing_database_warns_instead_of_silently_failing(self):
        oui._load_db.cache_clear()
        try:
            with mock.patch.object(oui, "_DATA_PATH", "/nonexistent/oui.json.gz"):
                with self.assertWarns(RuntimeWarning):
                    self.assertEqual(oui._load_db(), {})
        finally:
            oui._load_db.cache_clear()


if __name__ == "__main__":
    unittest.main()
