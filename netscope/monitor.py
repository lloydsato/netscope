"""Continuous network monitoring with change detection.

Repeatedly discovers devices (and optionally scans their ports), diffs the
result against the SQLite history, and raises alerts when something changes:
a new device joins, or (with port scanning) a new port opens on a known host.
Alerts print to the console, get logged to the events table, and can optionally
be POSTed to a webhook (e.g. a Slack/Discord/ntfy endpoint) so you get notified
while away.

The first run against an empty database only establishes a baseline -- it does
not announce every existing device (or webhook-spam you with them) as "new".
"""

import json
import sys
import time
import urllib.parse
import urllib.request

from . import discovery, portscan, oui, storage

_webhook_warned = False


def _validate_webhook(url: str):
    parts = urllib.parse.urlparse(url)
    if parts.scheme not in ("http", "https") or not parts.netloc:
        raise RuntimeError(f"--webhook must be an http:// or https:// URL (got {url!r})")


def _post_webhook(url: str, text: str):
    global _webhook_warned
    try:
        data = json.dumps({"text": text, "content": text}).encode()  # covers Slack & Discord shapes
        req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=5):
            pass
    except Exception as e:  # noqa: BLE001
        # Notification is best-effort and must never crash monitoring -- but a
        # dead webhook means alerts silently stop arriving, so say so (once).
        if not _webhook_warned:
            _webhook_warned = True
            print(f"(warning: webhook delivery failed: {e}; further failures not shown)",
                  file=sys.stderr)


def _emit(conn, etype, msg, webhook=None):
    ts = time.strftime("%H:%M:%S")
    print(f"[{ts}] {msg}", flush=True)
    storage.record_event(conn, etype, msg)
    if webhook:
        _post_webhook(webhook, f"netscope: {msg}")


def run(
    subnet: str = None,
    method: str = "auto",
    interval: int = 60,
    rounds: int = 0,
    scan_ports: bool = False,
    db_path: str = None,
    webhook: str = None,
):
    """Monitor loop.

    interval: seconds between rounds.
    rounds:   number of rounds to run (0 = run until interrupted).
    scan_ports: also port-scan each discovered host and alert on new open ports.
    """
    if webhook:
        _validate_webhook(webhook)
    conn = storage.connect(db_path)
    try:
        return _run(conn, subnet, method, interval, rounds, scan_ports, webhook)
    finally:
        conn.close()


def _run(conn, subnet, method, interval, rounds, scan_ports, webhook):
    # Establish the subnet once so the log is clear.
    subnet_resolved, first_hosts, method_used = discovery.discover(subnet, method)
    oui.enrich_hosts(first_hosts)
    print(f"Monitoring {subnet_resolved} (method: {method_used}, interval: {interval}s). Ctrl-C to stop.\n")

    # An empty history means this run is the baseline: record, don't alert.
    baseline_run = storage.device_count(conn) == 0

    round_num = 0
    try:
        while True:
            round_num += 1
            try:
                if round_num == 1:
                    hosts = first_hosts
                else:
                    _, hosts, _ = discovery.discover(subnet_resolved, method)
                    oui.enrich_hosts(hosts)
                _check_round(conn, hosts, scan_ports, webhook, quiet=(baseline_run and round_num == 1))
            except RuntimeError as e:
                if round_num == 1:
                    raise
                # A transient failure (interface flap, DNS hiccup) shouldn't end
                # a long-running monitor; report it and try again next round.
                print(f"[{time.strftime('%H:%M:%S')}] round {round_num} failed: {e} (will retry)",
                      file=sys.stderr, flush=True)
            else:
                if round_num == 1:
                    print(f"Baseline established: {len(hosts)} device(s) known." if baseline_run
                          else f"{len(hosts)} device(s) seen; watching for changes.", flush=True)

            if rounds and round_num >= rounds:
                break
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\nStopped.")

    return {"rounds": round_num, "subnet": subnet_resolved}


def _check_round(conn, hosts, scan_ports, webhook, quiet=False):
    new_ids = storage.upsert_devices(conn, hosts)
    for h in hosts:
        ident = h.get("mac") or h.get("ip")
        if not ident:
            continue
        if ident in new_ids and not quiet:
            label = f"{h.get('ip')} [{h.get('mac') or 'no-mac'}] ({h.get('vendor', 'unknown')})"
            _emit(conn, "new_device", f"NEW DEVICE joined: {label}", webhook)

        if scan_ports:
            # Ask *before* recording: a device whose ports were never scanned has
            # nothing to compare against, so its open ports are baseline, not news.
            baselined = storage.has_port_baseline(conn, ident)
            open_ports = portscan.scan(h["ip"])
            new_ports = storage.record_ports(conn, ident, open_ports)
            if baselined and ident not in new_ids:
                for p in new_ports:
                    services = [e["service"] for e in open_ports if e["port"] == p]
                    _emit(conn, "new_port", f"NEW PORT open on {h['ip']}: {p} ({services})", webhook)
