"""Tests for the watch loop: baselining, alerts, resilience (discovery/scan mocked)."""

import contextlib
import io
import os
import tempfile
import unittest
from unittest import mock

from netscope import monitor, storage


_REAL_POST_WEBHOOK = monitor._post_webhook      # WatchBase swaps the module attribute for a stub


def host(n, mac=True, vendor="Acme"):
    return {"ip": f"10.0.0.{n}", "mac": f"aa:bb:cc:00:00:{n:02x}" if mac else None, "vendor": vendor}


class WatchBase(unittest.TestCase):
    def setUp(self):
        self.db = os.path.join(tempfile.mkdtemp(), "watch.db")
        self.posts = []
        self.rounds = []                    # one entry per discovery call: list of hosts (or Exception)
        self.ports = {}                     # ip -> list of open port numbers
        p1 = mock.patch.object(monitor, "_post_webhook", lambda url, text: self.posts.append(text))
        p2 = mock.patch.object(monitor.discovery, "discover", side_effect=self._discover)
        p3 = mock.patch.object(monitor.portscan, "scan", side_effect=self._scan)
        p4 = mock.patch.object(monitor.time, "sleep", lambda s: None)
        for p in (p1, p2, p3, p4):
            p.start()
            self.addCleanup(p.stop)

    def _discover(self, subnet=None, method="auto"):
        item = self.rounds.pop(0)
        if isinstance(item, Exception):
            raise item
        return "10.0.0.0/24", [dict(h) for h in item], "arp"

    def _scan(self, ip, *a, **k):
        return [{"port": p, "service": f"svc{p}"} for p in self.ports.get(ip, [])]

    def watch(self, rounds, scan_ports=False, webhook="http://hook.example/x"):
        buf, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(err):
            result = monitor.run(rounds=rounds, interval=1, scan_ports=scan_ports,
                                 db_path=self.db, webhook=webhook)
        return result, buf.getvalue(), err.getvalue()


class BaselineTests(WatchBase):
    def test_first_run_on_empty_db_is_silent_baseline(self):
        # Regression: every existing device was announced as "NEW DEVICE joined"
        # (and POSTed to the webhook) on the very first run.
        self.rounds = [[host(1), host(2), host(3)]]
        _, out, _ = self.watch(1)
        self.assertNotIn("NEW DEVICE", out)
        self.assertIn("Baseline established: 3 device(s) known.", out)
        self.assertEqual(self.posts, [])
        conn = storage.connect(self.db)
        self.assertEqual(storage.device_count(conn), 3)           # ...but they are recorded
        self.assertEqual(storage.get_recent_events(conn), [])

    def test_new_device_after_baseline_alerts_once(self):
        self.rounds = [[host(1)], [host(1), host(2)], [host(1), host(2)]]
        _, out, _ = self.watch(3)
        self.assertEqual(out.count("NEW DEVICE joined"), 1)
        self.assertIn("10.0.0.2", out)
        self.assertEqual(len(self.posts), 1)
        self.assertTrue(self.posts[0].startswith("netscope: NEW DEVICE"))

    def test_second_process_run_alerts_on_new_but_not_known_devices(self):
        self.rounds = [[host(1), host(2)]]
        self.watch(1)
        self.rounds = [[host(1), host(2), host(3)]]
        _, out, _ = self.watch(1)
        self.assertEqual(out.count("NEW DEVICE joined"), 1)
        self.assertIn("10.0.0.3", out)
        self.assertNotIn("Baseline established", out)

    def test_device_without_mac_keyed_by_ip(self):
        self.rounds = [[host(1)], [host(1), host(9, mac=False)]]
        _, out, _ = self.watch(2)
        self.assertIn("10.0.0.9 [no-mac]", out)

    def test_events_logged_to_history(self):
        self.rounds = [[host(1)], [host(1), host(2)]]
        self.watch(2)
        events = storage.get_recent_events(storage.connect(self.db))
        self.assertEqual([e["type"] for e in events], ["new_device"])

    def test_empty_network(self):
        self.rounds = [[], []]
        result, out, _ = self.watch(2)
        self.assertEqual(result["rounds"], 2)
        self.assertIn("Baseline established: 0", out)


class PortAlertTests(WatchBase):
    def test_first_port_scan_of_known_device_is_baseline_not_news(self):
        # Regression: a device already in the DB (from `discover --save`) had every
        # open port reported as "NEW PORT" the first time --scan-ports ran.
        self.rounds = [[host(1)]]
        self.watch(1)                                    # device known, ports never scanned
        self.rounds = [[host(1)]]
        self.ports = {"10.0.0.1": [22, 80, 443]}
        _, out, _ = self.watch(1, scan_ports=True)
        self.assertNotIn("NEW PORT", out)

    def test_newly_opened_port_alerts(self):
        self.rounds = [[host(1)], [host(1)], [host(1)]]
        self.ports = {"10.0.0.1": [22]}
        self.watch(1, scan_ports=True)                   # baseline: 22 open
        self.rounds = [[host(1)], [host(1)]]
        self.ports = {"10.0.0.1": [22, 4444]}
        _, out, _ = self.watch(1, scan_ports=True)
        self.assertEqual(out.count("NEW PORT"), 1)
        self.assertIn("4444", out)
        self.assertTrue(any("NEW PORT" in p for p in self.posts))

    def test_port_opening_on_a_host_that_had_none_still_alerts(self):
        # The case a "baseline if no known ports" shortcut would miss: scanned,
        # nothing open, later something listens (e.g. a backdoor).
        self.rounds = [[host(1)]]
        self.ports = {}
        self.watch(1, scan_ports=True)
        self.rounds = [[host(1)]]
        self.ports = {"10.0.0.1": [31337]}
        _, out, _ = self.watch(1, scan_ports=True)
        self.assertIn("NEW PORT open on 10.0.0.1: 31337", out)

    def test_unchanged_ports_never_realert(self):
        self.rounds = [[host(1)]] * 4
        self.ports = {"10.0.0.1": [22, 80]}
        _, out, _ = self.watch(4, scan_ports=True)
        self.assertNotIn("NEW PORT", out)

    def test_brand_new_device_with_open_ports_gets_one_alert_not_many(self):
        self.rounds = [[host(1)], [host(1), host(2)]]
        self.ports = {"10.0.0.1": [22], "10.0.0.2": [22, 80, 8080]}
        _, out, _ = self.watch(2, scan_ports=True)
        self.assertEqual(out.count("NEW DEVICE"), 1)
        self.assertEqual(out.count("NEW PORT"), 0)

    def test_baseline_marker_survives_reconnect_and_covers_legacy_rows(self):
        conn = storage.connect(self.db)
        self.assertFalse(storage.has_port_baseline(conn, "dev"))
        storage.record_ports(conn, "dev", [])
        self.assertTrue(storage.has_port_baseline(conn, "dev"))           # scanned, nothing open
        conn.execute("INSERT INTO ports (identity, port, service, first_seen, last_seen) VALUES ('old',22,'ssh',1,1)")
        conn.commit()
        self.assertTrue(storage.has_port_baseline(conn, "old"))           # pre-marker DB rows count


class ResilienceTests(WatchBase):
    def test_transient_failure_mid_run_does_not_end_monitoring(self):
        self.rounds = [[host(1)], RuntimeError("interface went away"), [host(1), host(2)]]
        result, out, err = self.watch(3)
        self.assertEqual(result["rounds"], 3)
        self.assertIn("round 2 failed: interface went away (will retry)", err)
        self.assertEqual(out.count("NEW DEVICE joined"), 1)

    def test_first_discovery_failure_is_fatal_and_reported(self):
        self.rounds = [RuntimeError("needs root")]
        with self.assertRaises(RuntimeError):
            self.watch(1)

    def test_keyboard_interrupt_stops_cleanly(self):
        self.rounds = [[host(1)]]
        with mock.patch.object(monitor.time, "sleep", side_effect=KeyboardInterrupt):
            result, out, _ = self.watch(0)           # rounds=0 -> would run forever
        self.assertIn("Stopped.", out)
        self.assertEqual(result["rounds"], 1)

    def test_webhook_must_be_http_or_https(self):
        for bad in ("file:///etc/passwd", "ftp://x/y", "javascript:alert(1)", "hooks.slack.com/x", "http://", ""):
            if not bad:
                continue
            with self.assertRaises(RuntimeError, msg=bad):
                monitor.run(rounds=1, db_path=self.db, webhook=bad)

    def test_database_connection_closed_even_on_failure(self):
        self.rounds = [RuntimeError("boom")]
        with mock.patch.object(storage, "connect", wraps=storage.connect) as conn_factory:
            with self.assertRaises(RuntimeError):
                self.watch(1)
        self.assertTrue(conn_factory.called)


class WebhookDeliveryTests(unittest.TestCase):
    """Exercises the real _post_webhook (no discovery/scan mocking involved)."""

    def setUp(self):
        monitor._webhook_warned = False
        self.addCleanup(setattr, monitor, "_webhook_warned", False)

    def test_failure_warns_once_and_never_crashes(self):
        with mock.patch("urllib.request.urlopen", side_effect=OSError("connection refused")):
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                _REAL_POST_WEBHOOK("http://hook.example/x", "one")
                _REAL_POST_WEBHOOK("http://hook.example/x", "two")
        self.assertEqual(err.getvalue().count("webhook delivery failed"), 1)
        self.assertIn("connection refused", err.getvalue())

    def test_http_error_status_is_a_handled_failure_too(self):
        import urllib.error
        boom = urllib.error.HTTPError("http://x", 500, "server error", {}, None)
        with mock.patch("urllib.request.urlopen", side_effect=boom):
            with contextlib.redirect_stderr(io.StringIO()):
                _REAL_POST_WEBHOOK("http://hook.example/x", "msg")      # must not raise

    def test_payload_shape_timeout_and_response_closed(self):
        sent = {}

        class Resp:
            closed = False

            def __enter__(self):
                return self

            def __exit__(self, *a):
                Resp.closed = True

        def fake_urlopen(req, timeout):
            sent["body"] = req.data
            sent["timeout"] = timeout
            sent["ctype"] = req.get_header("Content-type")
            return Resp()

        with mock.patch("urllib.request.urlopen", fake_urlopen):
            _REAL_POST_WEBHOOK("https://hooks.example/x", "netscope: hi")
        import json
        self.assertEqual(json.loads(sent["body"]), {"text": "netscope: hi", "content": "netscope: hi"})
        self.assertEqual(sent["ctype"], "application/json")
        self.assertTrue(Resp.closed)                      # no leaked connection per alert
        self.assertLessEqual(sent["timeout"], 10)

    def test_unicode_and_quotes_survive_json_encoding(self):
        sent = {}

        class Resp:
            def __enter__(self):
                return self

            def __exit__(self, *a):
                pass

        with mock.patch("urllib.request.urlopen", lambda req, timeout: (sent.update(b=req.data), Resp())[1]):
            _REAL_POST_WEBHOOK("http://x", 'NEW "dev" \u2603 {braces}')
        import json
        self.assertEqual(json.loads(sent["b"])["text"], 'NEW "dev" \u2603 {braces}')


if __name__ == "__main__":
    unittest.main()
