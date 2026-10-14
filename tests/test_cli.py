"""End-to-end CLI tests: argument validation, exit codes, and (crucially) that
machine-readable output on stdout is never polluted by human-readable text."""

import contextlib
import csv
import io
import json
import os
import socket
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from netscope import cli, storage, findings as F, security, discovery, nameservices, config as config_mod

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

_patches = []


def setUpModule():
    # Name discovery does real multicast/UDP I/O; keep in-process CLI tests off the network,
    # and off any real ~/.netscope/config.json / $NETSCOPE_CONFIG on the machine running them.
    for p in (mock.patch.object(nameservices, "discover_names", return_value={}),
              mock.patch.object(config_mod, "DEFAULT_PATH", None),
              mock.patch.dict(os.environ, {}, clear=False)):
        p.start()
        _patches.append(p)
    os.environ.pop(config_mod.ENV_VAR, None)


def tearDownModule():
    for p in reversed(_patches):
        p.stop()


def run_main(*argv):
    """In-process run -> (exit_code, stdout, stderr)."""
    out, err = io.StringIO(), io.StringIO()
    code = 0
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            code = cli.main(list(argv))
        except SystemExit as e:                      # argparse errors / --version
            code = e.code if isinstance(e.code, int) else 1
    return code, out.getvalue(), err.getvalue()


def run_proc(*argv, **kw):
    """Real subprocess -> CompletedProcess (true stdout/stderr separation)."""
    env = dict(os.environ, PYTHONPATH=REPO + os.pathsep + os.environ.get("PYTHONPATH", ""))
    return subprocess.run([sys.executable, "-W", "ignore", "-m", "netscope.cli", *argv],
                          capture_output=True, text=True, env=env, cwd=REPO, timeout=120, **kw)


def listener():
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", 0))
    s.listen(8)
    return s, s.getsockname()[1]


def closed_port():
    s, p = listener()
    s.close()
    return p


class ParsePortRangeTests(unittest.TestCase):
    def test_valid_specs(self):
        self.assertEqual(cli.parse_port_range("80"), [80])
        self.assertEqual(cli.parse_port_range("80,443"), [80, 443])
        self.assertEqual(cli.parse_port_range("8000-8003"), [8000, 8001, 8002, 8003])
        self.assertEqual(cli.parse_port_range(" 22 , 80-81 ,"), [22, 80, 81])         # whitespace, trailing comma
        self.assertEqual(cli.parse_port_range("80,80,79-81"), [80, 79, 81])           # de-duplicated
        self.assertEqual(cli.parse_port_range("1-3,65535"), [1, 2, 3, 65535])
        self.assertEqual(len(cli.parse_port_range("1-65535")), 65535)

    def test_invalid_specs_raise_value_error_with_message(self):
        for bad in ("abc", "0", "65536", "-5", "1-", "-80", "1-2-3", "100-50", ",", "", "  ", "80;443",
                    "0x50", "8e1", "80-abc", "1.5", "99999-100000"):
            with self.assertRaises(ValueError, msg=repr(bad)) as cm:
                cli.parse_port_range(bad)
            self.assertTrue(str(cm.exception), repr(bad))

    def test_huge_range_does_not_explode_memory_before_validating(self):
        with self.assertRaises(ValueError):
            cli.parse_port_range("1-99999999999")


class SplitHostPortTests(unittest.TestCase):
    def test_forms(self):
        sp = cli._split_host_port
        self.assertEqual(sp("example.com", 443), ("example.com", 443))
        self.assertEqual(sp("example.com:8443", 443), ("example.com", 8443))
        self.assertEqual(sp("10.0.0.1:993", 443), ("10.0.0.1", 993))
        self.assertEqual(sp("::1", 443), ("::1", 443))                              # bare IPv6
        self.assertEqual(sp("fe80::1%eth0", 443), ("fe80::1%eth0", 443))
        self.assertEqual(sp("[::1]", 443), ("::1", 443))
        self.assertEqual(sp("[2001:db8::1]:8443", 443), ("2001:db8::1", 8443))
        self.assertEqual(sp("  host  ", 443), ("host", 443))

    def test_invalid(self):
        for bad in ("host:abc", "host:", "host:0", "host:99999", ":443", "", "  ", "[::1", "[]", "[::1]x",
                    "[::1]:", "[::1]:abc", "host:-1"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                cli._split_host_port(bad, 443)


class ArgumentValidationTests(unittest.TestCase):
    def test_version(self):
        from netscope import __version__
        code, out, err = run_main("--version")
        self.assertEqual(code, 0)
        self.assertIn(__version__, out + err)

    def test_no_command_is_an_error(self):
        self.assertEqual(run_main()[0], 2)

    def test_bad_numeric_options_exit_2_with_message(self):
        cases = [("portscan", "h", "--ports", "abc"), ("portscan", "h", "--ports", "70000"),
                 ("portscan", "h", "--ports", "80", "--full"), ("portscan", "h", "-T", "9"),
                 ("capture", "--duration", "0"), ("capture", "--duration", "-5"), ("capture", "--max-packets", "-1"),
                 ("watch", "--interval", "0"), ("watch", "--rounds", "-1"), ("history", "--limit", "0"),
                 ("diff", "--old", "0"), ("audit", "--capture-seconds", "-1"), ("audit", "--export", "xml")]
        for argv in cases:
            code, out, err = run_main(*argv)
            self.assertEqual(code, 2, argv)
            self.assertTrue(err.strip(), argv)

    def test_json_and_stdout_export_conflict(self):
        code, out, err = run_main("audit", "--host", "127.0.0.1", "--json", "--export", "csv")
        self.assertEqual(code, 2)
        self.assertIn("--export-out", err)
        self.assertEqual(out, "")                                    # nothing was scanned or printed

    def test_json_with_export_to_file_is_allowed(self):
        out_file = os.path.join(tempfile.mkdtemp(), "e.json")
        with mock.patch.object(security, "deep_check_hosts", return_value=[]):
            code, out, err = run_main("audit", "--host", "127.0.0.1", "--json", "--export", "json",
                                      "--export-out", out_file)
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["results"], [])
        self.assertIn("findings", json.load(open(out_file)))

    def test_tls_bad_target_exit_2(self):
        for bad in ("host:abc", "[::1", "host:70000"):
            code, _, err = run_main("tls", bad)
            self.assertEqual(code, 2, bad)
            self.assertIn("Error", err)

    def test_snmp_communities_validation(self):
        for bad in (",", " , ", ""):
            self.assertEqual(run_main("snmp", "127.0.0.1", "--communities", bad)[0], 2, repr(bad))

    def test_bad_subnet_is_a_clean_error_not_a_traceback(self):
        for sub in (("discover", "--method", "sweep"), ("security",), ("audit",), ("report",)):
            for subnet in ("not-a-subnet", "10.0.0.0/8", "fe80::/64"):
                code, out, err = run_main(*sub, "--subnet", subnet)
                self.assertEqual(code, 1, (sub, subnet))
                self.assertIn("Error:", err)
                self.assertNotIn("Traceback", err)


class MachineOutputPurityTests(unittest.TestCase):
    """The documented promise: `--json` output can be piped straight into jq."""

    def test_portscan_json_stdout_is_exactly_json_and_text_goes_to_stderr(self):
        srv, port = listener()
        self.addCleanup(srv.close)
        p = run_proc("portscan", "127.0.0.1", "--ports", str(port), "--json")
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual([r["port"] for r in json.loads(p.stdout)], [port])      # parses: nothing else on stdout
        self.assertIn("Open ports on 127.0.0.1", p.stderr)

    def test_portscan_json_with_zero_results_is_an_empty_array(self):
        p = run_proc("portscan", "127.0.0.1", "--ports", str(closed_port()), "--json")
        self.assertEqual(json.loads(p.stdout), [])
        self.assertEqual(p.returncode, 0)

    def test_portscan_fingerprint_json_includes_service_details(self):
        srv, port = listener()
        self.addCleanup(srv.close)

        def serve_forever():
            # The scanner connects once to detect the port and again to fingerprint it.
            while True:
                try:
                    c, _ = srv.accept()
                except OSError:
                    return
                c.sendall(b"SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.10\r\n")
                c.close()
        import threading
        threading.Thread(target=serve_forever, daemon=True).start()
        p = run_proc("portscan", "127.0.0.1", "--ports", str(port), "--fingerprint", "--json")
        (row,) = json.loads(p.stdout)
        self.assertEqual((row["product"], row["version"]), ("openssh", "7.2p2"))
        self.assertIn("OpenSSH_7.2p2", row["banner"])
        self.assertEqual(row["os_hint"], "Linux (Ubuntu)")

    def test_human_mode_unchanged_when_no_machine_flag(self):
        srv, port = listener()
        self.addCleanup(srv.close)
        p = run_proc("portscan", "127.0.0.1", "--ports", str(port))
        self.assertIn("Open ports on 127.0.0.1", p.stdout)
        self.assertEqual(p.stderr, "")

    def test_audit_csv_export_to_stdout_is_pure_csv(self):
        p = run_proc("audit", "--host", "127.0.0.1", "--export", "csv", "-T", "5")
        self.assertEqual(p.returncode, 0, p.stderr)
        rows = list(csv.reader(io.StringIO(p.stdout)))
        self.assertEqual(rows[0][:3], ["severity", "category", "host"])        # header is the very first line
        self.assertIn("Overall risk score", p.stderr)

    def test_audit_json_is_pure_json(self):
        p = run_proc("audit", "--host", "127.0.0.1", "--json", "-T", "5")
        doc = json.loads(p.stdout)
        self.assertEqual(doc["subnet"], "127.0.0.1")
        self.assertIn("risk_score", doc)

    def test_audit_sarif_stdout_validates_structurally(self):
        p = run_proc("audit", "--host", "127.0.0.1", "--export", "sarif", "-T", "5")
        doc = json.loads(p.stdout)
        self.assertEqual(doc["version"], "2.1.0")

    def test_tls_failure_with_json_still_emits_json_and_exit_1(self):
        p = run_proc("tls", f"127.0.0.1:{closed_port()}", "--json")
        self.assertEqual(p.returncode, 1)
        self.assertFalse(json.loads(p.stdout)["ok"])

    def test_snmp_no_response_json_is_empty_array(self):
        p = run_proc("snmp", "127.0.0.1", "--json")
        self.assertEqual(json.loads(p.stdout), [])

    def test_history_json_empty_db(self):
        db = os.path.join(tempfile.mkdtemp(), "h.db")
        for extra in ((), ("--events",)):
            p = run_proc("history", "--db", db, "--json", *extra)
            self.assertEqual(json.loads(p.stdout), [])

    def test_broken_pipe_exits_quietly(self):
        # `netscope history | head -1`: the reader hangs up while we still have output.
        db = os.path.join(tempfile.mkdtemp(), "big.db")
        conn = storage.connect(db)
        storage.upsert_devices(conn, [{"ip": f"10.1.{i // 250}.{i % 250}", "mac": f"aa:00:{i >> 8:02x}:{i & 255:02x}:00:01",
                                       "vendor": "V" * 20} for i in range(3000)])
        conn.close()
        env = dict(os.environ, PYTHONPATH=REPO)
        proc = subprocess.Popen([sys.executable, "-W", "ignore", "-m", "netscope.cli", "history", "--db", db],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, cwd=REPO)
        proc.stdout.readline()                # consume one line, then hang up like `| head -1`
        proc.stdout.close()
        try:
            _, err = proc.communicate(timeout=60)
        except subprocess.TimeoutExpired:
            proc.kill()
            self.fail("process did not exit after its stdout pipe was closed")
        self.assertNotIn(b"Traceback", err)
        self.assertNotIn(b"BrokenPipeError", err)
        self.assertEqual(proc.returncode, 0)


class DiscoverCommandTests(unittest.TestCase):
    def test_no_hosts_json_is_valid(self):
        with mock.patch.object(discovery, "discover", return_value=("10.0.0.0/24", [], "sweep")):
            code, out, err = run_main("discover", "--json")
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out), {"subnet": "10.0.0.0/24", "method": "sweep", "hosts": []})

    def test_save_records_devices(self):
        db = os.path.join(tempfile.mkdtemp(), "d.db")
        hosts = [{"ip": "10.0.0.1", "mac": "00:50:56:00:00:01"}]
        with mock.patch.object(discovery, "discover", return_value=("10.0.0.0/24", hosts, "arp")):
            code, out, _ = run_main("discover", "--save", "--db", db)
        self.assertEqual(code, 0)
        self.assertIn("VMware", out)
        self.assertEqual(storage.device_count(storage.connect(db)), 1)

    def test_discovery_error_reported(self):
        with mock.patch.object(discovery, "discover", side_effect=RuntimeError("needs root")):
            code, _, err = run_main("discover")
        self.assertEqual((code, "needs root" in err), (1, True))


class NameDiscoveryCommandTests(unittest.TestCase):
    HOSTS = [{"ip": "10.0.0.7", "mac": "00:50:56:00:00:07"}, {"ip": "10.0.0.8", "mac": "00:50:56:00:00:08"}]
    NAMES = {"10.0.0.7": {"hostname": "den", "model": "Boom 3", "manufacturer": "Acme", "workgroup": "",
                          "services": [], "exposures": ["ssdp"]},
             "10.0.0.8": {"hostname": "", "model": "", "manufacturer": "", "workgroup": "WG",
                          "services": [], "exposures": ["netbios"]}}

    def hosts(self):
        return [dict(h) for h in self.HOSTS]

    def test_discover_names_adds_columns_and_json_fields(self):
        with mock.patch.object(discovery, "discover", return_value=("10.0.0.0/24", self.hosts(), "arp")), \
                mock.patch.object(nameservices, "discover_names", return_value=self.NAMES):
            code, out, _ = run_main("discover", "--names")
            self.assertEqual(code, 0)
            self.assertIn("NAME", out)
            self.assertIn("Boom 3", out)
            code, out, _ = run_main("discover", "--names", "--json")
        hosts = json.loads(out)["hosts"]
        self.assertEqual(hosts[0]["hostname"], "den")
        self.assertEqual(hosts[0]["exposures"], ["ssdp"])

    def test_discover_without_names_does_not_touch_the_network(self):
        with mock.patch.object(discovery, "discover", return_value=("10.0.0.0/24", self.hosts(), "arp")), \
                mock.patch.object(nameservices, "discover_names") as dn:
            run_main("discover")
        dn.assert_not_called()

    def test_discover_save_stores_the_hostname(self):
        db = os.path.join(tempfile.mkdtemp(), "n.db")
        with mock.patch.object(discovery, "discover", return_value=("10.0.0.0/24", self.hosts(), "arp")), \
                mock.patch.object(nameservices, "discover_names", return_value=self.NAMES):
            run_main("discover", "--names", "--save", "--db", db)
        code, out, _ = run_main("history", "--db", db)
        self.assertIn("den", out)

    def test_audit_turns_exposures_into_findings(self):
        with mock.patch.object(discovery, "discover", return_value=("10.0.0.0/24", self.hosts(), "arp")), \
                mock.patch.object(nameservices, "discover_names", return_value=self.NAMES), \
                mock.patch.object(security, "deep_check_hosts",
                                  return_value=[canned_result("10.0.0.7", []), canned_result("10.0.0.8", [])]):
            code, out, _ = run_main("audit", "--export", "csv")
        self.assertEqual(code, 0)
        self.assertIn("UPnP/SSDP service advertised", out)
        self.assertIn("NetBIOS name service responding", out)

    def test_audit_no_names_and_host_mode_skip_lan_queries(self):
        with mock.patch.object(discovery, "discover", return_value=("10.0.0.0/24", self.hosts(), "arp")), \
                mock.patch.object(nameservices, "discover_names") as dn, \
                mock.patch.object(security, "deep_check_hosts", return_value=[canned_result("10.0.0.7", [])]):
            run_main("audit", "--no-names")
            run_main("audit", "--host", "10.0.0.7")
        dn.assert_not_called()


class ErrorHandlingTests(unittest.TestCase):
    def test_keyboard_interrupt_is_130_without_traceback(self):
        with mock.patch.object(cli, "cmd_history", side_effect=KeyboardInterrupt):
            code, _, err = run_main("history")
        self.assertEqual(code, 130)
        self.assertNotIn("Traceback", err)

    def test_runtime_and_os_errors_become_exit_1(self):
        for exc in (RuntimeError("boom"), PermissionError("denied"), sqlite_error()):
            with mock.patch.object(cli, "cmd_history", side_effect=exc):
                code, _, err = run_main("history")
            self.assertEqual(code, 1, exc)
            self.assertIn("Error:", err)

    def test_stdout_is_always_restored(self):
        before = sys.stdout
        with mock.patch.object(cli, "cmd_history", side_effect=RuntimeError("x")):
            run_main("history", "--json")
        self.assertIs(sys.stdout, before)
        self.assertIsNone(cli._machine_stream)

    def test_unwritable_db_path_is_a_clean_error(self):
        code, _, err = run_main("history", "--db", "/proc/nope/x.db")
        self.assertEqual(code, 1)
        self.assertNotIn("Traceback", err)

    def test_unresolvable_host_in_each_scanning_command(self):
        for argv in (("portscan", "no-such-host.invalid"), ("portscan", "no-such-host.invalid", "--udp"),
                     ("security", "--host", "no-such-host.invalid"),
                     ("security", "--host", "no-such-host.invalid", "--deep"),
                     ("audit", "--host", "no-such-host.invalid")):
            code, _, err = run_main(*argv)
            self.assertEqual(code, 1, argv)
            self.assertIn("Could not resolve", err)

    def test_export_to_unwritable_file_is_a_clean_error(self):
        with mock.patch.object(security, "deep_check_hosts", return_value=[]):
            code, _, err = run_main("audit", "--host", "127.0.0.1", "--export", "json",
                                    "--export-out", "/proc/nope/out.json")
        self.assertEqual(code, 1)
        self.assertIn("Error:", err)

    def test_watch_rejects_bad_webhook(self):
        code, _, err = run_main("watch", "--rounds", "1", "--webhook", "file:///etc/passwd",
                                "--db", os.path.join(tempfile.mkdtemp(), "w.db"))
        self.assertEqual(code, 1)
        self.assertIn("http", err)

    def test_capture_read_errors(self):
        self.assertEqual(run_main("capture", "--read", "/definitely/missing.pcap")[0], 1)
        bad = os.path.join(tempfile.mkdtemp(), "bad.pcap")
        open(bad, "w").write("nope")
        code, _, err = run_main("capture", "--read", bad)
        self.assertEqual(code, 1)
        self.assertNotIn("Traceback", err)

    def test_udp_ignored_flags_are_called_out(self):
        code, out, err = run_main("portscan", "127.0.0.1", "--udp", "--fingerprint", "-T", "2", "--ports", "9")
        self.assertEqual(code, 0)
        self.assertIn("--fingerprint has no effect with --udp", err)
        self.assertIn("--timing has no effect with --udp", err)


def sqlite_error():
    import sqlite3
    return sqlite3.OperationalError("database is locked")


def canned_result(host, findings):
    return {"host": host, "open_ports": [{"port": 22, "service": "ssh"}], "services": [],
            "findings": findings, "risk_score": F.risk_score(findings)}


class DiffAndSnapshotTests(unittest.TestCase):
    def setUp(self):
        self.db = os.path.join(tempfile.mkdtemp(), "snap.db")
        self.a = F.make_finding("cve", "high", "Old CVE", host="10.0.0.5", port=22, detail="a")
        self.b = F.make_finding("tls", "medium", "Self-signed", host="10.0.0.5", port=443, detail="b")
        self.c = F.make_finding("weak-auth", "critical", "Open Redis", host="10.0.0.5", port=6379, detail="c")

    def audit(self, host, findings, *extra):
        with mock.patch.object(security, "deep_check_hosts", return_value=[canned_result(host, findings)]):
            return run_main("audit", "--host", host, "--save", "--db", self.db, *extra)

    def test_audit_diff_compares_with_previous_snapshot_of_same_target(self):
        self.audit("10.0.0.5", [self.a, self.b])
        code, out, _ = self.audit("10.0.0.5", [self.b, self.c], "--diff")
        self.assertEqual(code, 0)
        self.assertIn("1 NEW finding", out)
        self.assertIn("Open Redis", out)
        self.assertIn("1 RESOLVED finding", out)
        self.assertIn("Old CVE", out)

    def test_audit_diff_ignores_snapshots_of_other_targets(self):
        # Regression: --diff compared against whatever snapshot was saved last, even
        # for a different host, reporting all of the other host's findings as resolved.
        self.audit("10.0.0.5", [self.a, self.b])
        code, out, _ = self.audit("10.0.0.6", [self.c], "--diff")
        self.assertIn("no previous snapshot of 10.0.0.6", out)
        self.assertNotIn("RESOLVED", out)

    def test_diff_default_picks_previous_snapshot_of_same_target(self):
        self.audit("10.0.0.5", [self.a])
        self.audit("10.0.0.9", [self.c])             # interleaved snapshot of another target
        self.audit("10.0.0.5", [self.b])
        code, out, _ = run_main("diff", "--db", self.db)
        self.assertEqual(code, 0)
        self.assertIn("Diffing snapshot #1 -> #3", out)
        self.assertIn("Self-signed", out)

    def test_diff_with_no_comparable_snapshot_says_so(self):
        self.audit("10.0.0.5", [self.a])
        self.audit("10.0.0.9", [self.c])
        code, out, _ = run_main("diff", "--db", self.db)
        self.assertEqual(code, 1)
        self.assertIn("--old/--new", out)

    def test_diff_empty_db(self):
        code, out, _ = run_main("diff", "--db", self.db)
        self.assertEqual(code, 1)
        self.assertIn("No saved audit snapshots", out)

    def test_diff_explicit_ids_validated(self):
        # Regression: nonexistent ids printed "No change in findings".
        self.audit("10.0.0.5", [self.a])
        self.audit("10.0.0.5", [self.b])
        code, out, err = run_main("diff", "--db", self.db, "--old", "98", "--new", "99")
        self.assertEqual(code, 1)
        self.assertIn("no saved snapshot #98", err)
        self.assertIn("[2, 1]", err)                 # tells the user what does exist
        self.assertNotIn("No change", out)
        code, _, err = run_main("diff", "--db", self.db, "--old", "1", "--new", "99")
        self.assertEqual(code, 1)

    def test_diff_requires_old_and_new_together(self):
        # Regression: --old alone was silently ignored.
        self.audit("10.0.0.5", [self.a])
        self.audit("10.0.0.5", [self.b])
        for only in (("--old", "1"), ("--new", "2")):
            code, _, err = run_main("diff", "--db", self.db, *only)
            self.assertEqual(code, 2, only)
            self.assertIn("together", err)

    def test_diff_explicit_across_targets_warns(self):
        self.audit("10.0.0.5", [self.a])
        self.audit("10.0.0.9", [self.c])
        code, out, _ = run_main("diff", "--db", self.db, "--old", "1", "--new", "2")
        self.assertEqual(code, 0)
        self.assertIn("different targets", out)

    def test_diff_export_and_json_of_new_findings(self):
        self.audit("10.0.0.5", [self.a])
        self.audit("10.0.0.5", [self.b, self.c])
        code, out, _ = run_main("diff", "--db", self.db, "--export", "ndjson")
        rows = [json.loads(l) for l in out.splitlines() if l.startswith("{")]
        self.assertEqual({r["title"] for r in rows}, {"Self-signed", "Open Redis"})
        self.assertTrue(all(r["id"] for r in rows))                  # same "id" key as live findings
        code, out, _ = run_main("diff", "--db", self.db, "--json")
        self.assertEqual({f["title"] for f in json.loads(out)["added"]}, {"Self-signed", "Open Redis"})

    def test_audit_diff_without_save_still_saves_and_diffs(self):
        with mock.patch.object(security, "deep_check_hosts", return_value=[canned_result("10.0.0.5", [self.a])]):
            run_main("audit", "--host", "10.0.0.5", "--diff", "--db", self.db)
            code, out, _ = run_main("audit", "--host", "10.0.0.5", "--diff", "--db", self.db)
        self.assertIn("No change in findings", out)

    def test_saved_ports_attach_to_the_mac_identity_not_a_phantom_ip_device(self):
        # Regression: `security --deep --save` / `audit --save` recorded ports under
        # the IP while the device row is keyed by MAC, so `watch` never saw them.
        hosts = [{"ip": "10.0.0.5", "mac": "aa:bb:cc:00:00:05", "vendor": "V"}]
        with mock.patch.object(discovery, "discover", return_value=("10.0.0.0/24", hosts, "arp")), \
                mock.patch.object(security, "deep_check_hosts", return_value=[canned_result("10.0.0.5", [])]):
            code, _, _ = run_main("audit", "--save", "--db", self.db)
        self.assertEqual(code, 0)
        conn = storage.connect(self.db)
        self.assertEqual(storage.get_known_ports(conn, "aa:bb:cc:00:00:05"), {22})
        self.assertEqual(storage.get_known_ports(conn, "10.0.0.5"), set())
        quick = [{"host": "10.0.0.5", "open_ports": [{"port": 80, "service": "http"}], "risky_findings": []}]
        with mock.patch.object(discovery, "discover", return_value=("10.0.0.0/24", hosts, "arp")), \
                mock.patch.object(security, "check_hosts", return_value=quick):
            run_main("security", "--save", "--db", self.db)
        self.assertEqual(storage.get_known_ports(conn, "aa:bb:cc:00:00:05"), {22, 80})

    def test_identity_for_falls_back_to_ip(self):
        hosts = [{"ip": "10.0.0.5", "mac": None}, {"ip": "10.0.0.6", "mac": "aa:aa:aa:aa:aa:06"}, "10.0.0.7"]
        self.assertEqual(cli._identity_for("10.0.0.5", hosts), "10.0.0.5")
        self.assertEqual(cli._identity_for("10.0.0.6", hosts), "aa:aa:aa:aa:aa:06")
        self.assertEqual(cli._identity_for("10.0.0.7", hosts), "10.0.0.7")
        self.assertEqual(cli._identity_for("10.9.9.9", hosts), "10.9.9.9")

    def test_no_hosts_gives_valid_empty_documents(self):
        with mock.patch.object(discovery, "discover", return_value=("10.0.0.0/24", [], "sweep")):
            code, out, _ = run_main("audit", "--json")
            self.assertEqual(json.loads(out), {"subnet": "10.0.0.0/24", "results": [], "risk_score": 0})
            code, out, _ = run_main("audit", "--export", "csv")
            self.assertTrue(out.startswith("severity,"))
            code, out, _ = run_main("security", "--json")
            self.assertEqual(json.loads(out), [])


class HistoryCommandTests(unittest.TestCase):
    def test_devices_and_events_listing(self):
        db = os.path.join(tempfile.mkdtemp(), "h.db")
        conn = storage.connect(db)
        storage.upsert_devices(conn, [{"ip": "10.0.0.1", "mac": "00:50:56:00:00:01", "vendor": "VMware, Inc."}])
        storage.record_event(conn, "new_device", "hello world")
        conn.close()
        code, out, _ = run_main("history", "--db", db)
        self.assertIn("10.0.0.1", out)
        code, out, _ = run_main("history", "--db", db, "--events", "--limit", "5")
        self.assertIn("hello world", out)
        code, out, _ = run_main("history", "--db", db, "--events", "--json")
        self.assertEqual(json.loads(out)[0]["detail"], "hello world")


class ReportCommandTests(unittest.TestCase):
    def test_report_written_and_escapes_hostile_values(self):
        out_file = os.path.join(tempfile.mkdtemp(), "r.html")
        hosts = [{"ip": "10.0.0.1", "mac": "aa:bb:cc:00:00:01", "vendor": "<script>alert(1)</script>"}]
        evil = F.make_finding("cve", "high", "<img src=x onerror=alert(1)>", host="10.0.0.1", port=22,
                              detail="</td><script>alert(2)</script>", refs=["<b>x</b>"])
        deep = [{"host": "10.0.0.1", "open_ports": [], "services": [], "findings": [evil], "risk_score": 20}]
        with mock.patch.object(discovery, "discover", return_value=("10.0.0.0/24", hosts, "arp")), \
                mock.patch.object(cli, "enrich_devices", return_value=[{"ip": "10.0.0.1", "mac": hosts[0]["mac"],
                                                                         "vendor": hosts[0]["vendor"],
                                                                         "open_ports": [], "os_guess": "<i>x</i>"}]), \
                mock.patch.object(security, "deep_check_hosts", return_value=deep):
            code, out, err = run_main("report", "-o", out_file, "--db", os.path.join(tempfile.mkdtemp(), "r.db"))
        self.assertEqual(code, 0, err)
        html_text = open(out_file, encoding="utf-8").read()
        self.assertNotIn("<script>", html_text)
        self.assertNotIn("<img src=x", html_text)
        self.assertIn("&lt;script&gt;", html_text)
        self.assertTrue(html_text.startswith("<!doctype html>"))


if __name__ == "__main__":
    unittest.main()
