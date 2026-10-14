"""Config file: validation, lookup rules, and precedence against CLI flags."""

import json
import os
import tempfile
import unittest
from unittest import mock

from netscope import cli, config as C, discovery, security, findings as F
from tests.test_cli import run_main, canned_result


def write(obj, name="config.json"):
    d = tempfile.mkdtemp()
    path = os.path.join(d, name)
    with open(path, "w", encoding="utf-8") as f:
        f.write(obj if isinstance(obj, str) else json.dumps(obj))
    return path


class ParseTests(unittest.TestCase):
    def test_valid_document(self):
        out = C.parse({"subnet": "192.168.1.0/24", "timing": 2, "method": "sweep", "fail_on": "high",
                       "webhook": "https://ntfy.sh/x", "gateway": "192.168.1.1", "iface": "eth0",
                       "db": "~/x.db", "ignore_file": "~/ign.txt"})
        self.assertEqual(out["timing"], 2)
        self.assertEqual(out["fail_on"], "high")
        self.assertFalse(out["db"].startswith("~"))                    # ~ expanded

    def test_dashed_and_cased_keys_accepted(self):
        self.assertEqual(C.parse({"Fail-On": "low"}), {"fail_on": "low"})

    def test_invalid_values_rejected(self):
        bad = [{"timing": 9}, {"timing": "2"}, {"timing": True}, {"subnet": "not-a-net"}, {"subnet": ""},
               {"method": "magic"}, {"fail_on": "urgent"}, {"fail_on": "info"},
               {"webhook": "ftp://x"}, {"webhook": "javascript:alert(1)"}, {"gateway": "gw"},
               {"db": 5}, {"iface": ""}]
        for doc in bad:
            with self.assertRaises(C.ConfigError, msg=str(doc)):
                C.parse(doc)

    def test_unknown_keys_rejected_so_typos_cannot_silently_drop_a_setting(self):
        with self.assertRaises(C.ConfigError) as cm:
            C.parse({"fial_on": "high"})
        self.assertIn("fial_on", str(cm.exception))

    def test_non_object_rejected(self):
        for doc in ([], "x", 3, None):
            with self.assertRaises(C.ConfigError):
                C.parse(doc)


class LoadTests(unittest.TestCase):
    def test_explicit_path_loads(self):
        self.assertEqual(C.load(write({"timing": 1}), environ={}), {"timing": 1})

    def test_explicit_missing_file_is_an_error(self):
        with self.assertRaises(C.ConfigError):
            C.load("/no/such/config.json", environ={})

    def test_env_var_is_used_and_is_required(self):
        self.assertEqual(C.load(None, environ={C.ENV_VAR: write({"timing": 4})}), {"timing": 4})
        with self.assertRaises(C.ConfigError):
            C.load(None, environ={C.ENV_VAR: "/no/such"})

    def test_explicit_beats_env(self):
        env = {C.ENV_VAR: write({"timing": 4})}
        self.assertEqual(C.load(write({"timing": 1}), environ=env), {"timing": 1})

    def test_user_file_optional(self):
        with mock.patch.object(C, "DEFAULT_PATH", os.path.join(tempfile.mkdtemp(), "none.json")):
            self.assertEqual(C.load(None, environ={}), {})
        with mock.patch.object(C, "DEFAULT_PATH", write({"timing": 5})):
            self.assertEqual(C.load(None, environ={}), {"timing": 5})

    def test_cwd_config_is_never_loaded_implicitly(self):
        cwd = tempfile.mkdtemp()
        with open(os.path.join(cwd, "netscope.json"), "w") as f:
            f.write('{"ignore_file": "/tmp/evil.txt", "webhook": "https://evil.example/x"}')
        old = os.getcwd()
        try:
            os.chdir(cwd)
            with mock.patch.object(C, "DEFAULT_PATH", None):
                self.assertEqual(C.load(None, environ={}), {})
        finally:
            os.chdir(old)

    def test_bad_json_and_unreadable(self):
        with self.assertRaises(C.ConfigError):
            C.load(write("{nope"), environ={})
        with self.assertRaises(C.ConfigError):
            C.load(tempfile.mkdtemp(), environ={})                   # a directory

    def test_error_mentions_the_file(self):
        path = write({"timing": 99})
        with self.assertRaises(C.ConfigError) as cm:
            C.load(path, environ={})
        self.assertIn(path, str(cm.exception))


class ParserDefaultsTests(unittest.TestCase):
    def test_config_supplies_defaults_only_where_the_flag_exists(self):
        p = cli.build_parser({"timing": 2, "fail_on": "high", "webhook": "https://x/y", "subnet": "10.0.0.0/24"})
        audit = p.parse_args(["audit", "--host", "h"])
        self.assertEqual((audit.timing, audit.fail_on, audit.subnet), (2, "high", "10.0.0.0/24"))
        watch = p.parse_args(["watch"])
        self.assertEqual(watch.webhook, "https://x/y")
        self.assertFalse(hasattr(p.parse_args(["history"]), "webhook"))   # not leaked onto commands without it

    def test_cli_flag_beats_config(self):
        p = cli.build_parser({"timing": 2, "method": "sweep", "fail_on": "high"})
        a = p.parse_args(["audit", "--host", "h", "-T", "5", "--method", "arp", "--fail-on", "low"])
        self.assertEqual((a.timing, a.method, a.fail_on), (5, "arp", "low"))

    def test_no_config_leaves_original_defaults(self):
        a = cli.build_parser().parse_args(["audit", "--host", "h"])
        self.assertEqual((a.timing, a.method, a.fail_on, a.subnet), (None, "auto", None, None))


class EndToEndTests(unittest.TestCase):
    def test_config_flag_applies_gate_and_subnet(self):
        cfg = write({"fail_on": "high", "subnet": "10.9.0.0/24"})
        hi = [canned_result("10.9.0.5", [F.make_finding(
            "cve", "high", "Bad", host="10.9.0.5", port=22, detail="d")])]
        with mock.patch.object(discovery, "discover", return_value=("10.9.0.0/24", [{"ip": "10.9.0.5"}], "arp")) as d, \
                mock.patch.object(security, "deep_check_hosts", return_value=hi):
            code, _, _ = run_main("--config", cfg, "audit", "--no-names")
        self.assertEqual(code, 3)
        self.assertEqual(d.call_args[0][0], "10.9.0.0/24")             # subnet came from the config
        with mock.patch.object(discovery, "discover", return_value=("10.9.0.0/24", [{"ip": "10.9.0.5"}], "arp")), \
                mock.patch.object(security, "deep_check_hosts", return_value=hi):
            code, _, _ = run_main("--config", cfg, "audit", "--no-names", "--fail-on", "critical")
        self.assertEqual(code, 0)                                      # flag overrode config

    def test_bad_config_exits_2_before_doing_anything(self):
        with mock.patch.object(discovery, "discover") as d:
            code, _, err = run_main("--config", write({"timing": 99}), "discover")
        self.assertEqual(code, 2)
        self.assertIn("Error:", err)
        d.assert_not_called()

    def test_missing_explicit_config_exits_2(self):
        self.assertEqual(run_main("--config", "/no/such.json", "history")[0], 2)

    def test_env_var_config(self):
        with mock.patch.dict(os.environ, {C.ENV_VAR: write({"timing": 99})}):
            self.assertEqual(run_main("history")[0], 2)

    def test_help_mentions_config(self):
        code, out, _ = run_main("--help")
        self.assertIn("--config", out)


if __name__ == "__main__":
    unittest.main()
