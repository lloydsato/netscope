"""Continuous network monitoring with change detection.

Repeatedly discovers devices (and optionally scans their ports), diffs the
result against the SQLite history, and raises alerts when something changes:
a new device joins, a known device comes back, or a new port opens on a host.
Alerts print to the console, get logged to the events table, and can optionally
be POSTed to a webhook (e.g. a Slack/Discord/ntfy endpoint) so you get notified
while away.
"""

import json
import time
import urllib.request

from . import discovery, portscan, oui, storage


def _post_webhook(url: str, text: str):
    try:
        data = json.dumps({"text": text, "content": text}).encode()  # covers Slack & Discord shapes
        req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
        urllib.request.urlopen(req, timeout=5)
    except Exception:
        pass  # notification is best-effort; never let it crash monitoring


def _emit(conn, etype, msg, webhook=None):
    ts = time.strftime("%H:%M:%S")
    print(f"[{ts}] {msg}")
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
    conn = storage.connect(db_path)

    # Establish the subnet once so the log is clear.
    subnet_resolved, first_hosts, method_used = discovery.discover(subnet, method)
    oui.enrich_hosts(first_hosts)
    print(f"Monitoring {subnet_resolved} (method: {method_used}, interval: {interval}s). Ctrl-C to stop.\n")

    round_num = 0
    try:
        while True:
            round_num += 1
            if round_num == 1:
                hosts = first_hosts
            else:
                _, hosts, _ = discovery.discover(subnet_resolved, method)
                oui.enrich_hosts(hosts)

            new_ids = storage.upsert_devices(conn, hosts)
            for h in hosts:
                ident = h.get("mac") or h.get("ip")
                if ident in new_ids:
                    label = f"{h.get('ip')} [{h.get('mac') or 'no-mac'}] ({h.get('vendor','unknown')})"
                    _emit(conn, "new_device", f"NEW DEVICE joined: {label}", webhook)

                if scan_ports:
                    known = storage.get_known_ports(conn, ident)
                    open_ports = portscan.scan(h["ip"])
                    new_ports = storage.record_ports(conn, ident, open_ports)
                    # Only alert for ports that are genuinely new to a device we've seen before.
                    for p in new_ports:
                        if ident not in new_ids:
                            _emit(conn, "new_port",
                                  f"NEW PORT open on {h['ip']}: {p} ({[e['service'] for e in open_ports if e['port']==p]})",
                                  webhook)

            if round_num == 1 and not new_ids:
                print(f"Baseline established: {len(hosts)} device(s) known.")

            if rounds and round_num >= rounds:
                break
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\nStopped.")

    return {"rounds": round_num, "subnet": subnet_resolved}
