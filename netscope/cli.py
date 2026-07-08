#!/usr/bin/env python3
"""netscope: local network discovery, fingerprinting, traffic analysis,
continuous monitoring, and security reporting.

Commands:
    discover   Find devices on the LAN (with vendor + optional fingerprinting)
    portscan   Scan a host for open TCP ports (with optional banner grabbing)
    capture    Capture live traffic and run passive threat detection (root)
    watch      Continuously monitor the LAN and alert on changes
    security   Scan discovered/given hosts for risky exposed ports
    report     Generate a standalone HTML network report
    history    Show devices and events recorded in the local database
"""

import argparse
import json
import sys

from . import discovery, portscan, fingerprint, oui, security, storage, report
from . import capture as capture_mod
from . import monitor as monitor_mod
from .utils import fmt_table, get_default_subnet, RISKY_PORTS


# ---------- shared helpers ----------

def parse_port_range(spec: str):
    ports = []
    for part in spec.split(","):
        part = part.strip()
        if "-" in part:
            lo, hi = part.split("-")
            ports.extend(range(int(lo), int(hi) + 1))
        elif part:
            ports.append(int(part))
    return ports


def enrich_devices(hosts, do_fingerprint=False):
    """For each discovered host, scan ports, annotate risky ones, and (optionally)
    fingerprint services for an OS guess. Returns device dicts ready for reporting.
    """
    devices = []
    for h in hosts:
        ip = h["ip"]
        scan_res = portscan.scan(ip)
        for e in scan_res:
            e["risk"] = RISKY_PORTS.get(e["port"])
        os_guess = ""
        if do_fingerprint and scan_res:
            fp = fingerprint.fingerprint_host(ip, scan_res)
            os_guess = fp["os_guess"]
        devices.append({
            "ip": ip, "mac": h.get("mac"), "vendor": h.get("vendor", "unknown"),
            "open_ports": scan_res, "os_guess": os_guess,
        })
    return devices


# ---------- commands ----------

def cmd_discover(args):
    try:
        subnet, hosts, method_used = discovery.discover(args.subnet, args.method)
    except RuntimeError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    oui.enrich_hosts(hosts)
    print(f"Subnet: {subnet}  (method: {method_used})")
    if not hosts:
        print("No hosts found.")
        return 0

    fp_map = {}
    if args.fingerprint:
        print("Fingerprinting services...")
        for h in hosts:
            open_ports = portscan.scan(h["ip"])
            fp = fingerprint.fingerprint_host(h["ip"], open_ports)
            fp_map[h["ip"]] = fp["os_guess"]

    headers = ["IP", "MAC", "VENDOR"] + (["OS GUESS"] if args.fingerprint else [])
    rows = []
    for h in hosts:
        row = [h["ip"], h.get("mac") or "-", h.get("vendor", "unknown")]
        if args.fingerprint:
            row.append(fp_map.get(h["ip"]) or "-")
        rows.append(row)
    print(fmt_table(rows, headers))

    if args.save:
        conn = storage.connect(args.db)
        new_ids = storage.upsert_devices(conn, hosts)
        print(f"\nSaved to history ({len(new_ids)} new device(s)).")

    if args.json:
        for h in hosts:
            if args.fingerprint:
                h["os_guess"] = fp_map.get(h["ip"], "")
        print(json.dumps({"subnet": subnet, "method": method_used, "hosts": hosts}, indent=2))
    return 0


def cmd_portscan(args):
    ports = range(1, 1025) if args.full else (parse_port_range(args.ports) if args.ports else None)
    try:
        results = portscan.scan(args.host, ports=ports)
    except RuntimeError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    print(f"Open ports on {args.host}:")
    if not results:
        print("  (none found in scanned range)")
        return 0

    if args.fingerprint:
        fp = fingerprint.fingerprint_host(args.host, results)
        by_port = {r["port"]: r for r in fp["ports"]}
        rows = [[r["port"], r["service"], (by_port.get(r["port"], {}).get("banner") or "-")[:48]] for r in results]
        print(fmt_table(rows, ["PORT", "SERVICE", "BANNER"]))
        if fp["os_guess"]:
            print(f"\nOS guess: {fp['os_guess']}")
    else:
        rows = [[r["port"], r["service"], "risky" if RISKY_PORTS.get(r["port"]) else ""] for r in results]
        print(fmt_table(rows, ["PORT", "SERVICE", "NOTE"]))

    if args.json:
        print(json.dumps(results, indent=2))
    return 0


def cmd_capture(args):
    try:
        s = capture_mod.capture(
            iface=args.iface, duration=args.duration, bpf_filter=args.filter,
            pcap_out=args.pcap, max_packets=args.max_packets, gateway_ip=args.gateway,
        )
    except RuntimeError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    print(f"Captured {s['total_packets']} packets over {s['duration']}s")
    print(f"Protocols: {s['protocol_counts']}")

    if s["top_bandwidth"]:
        print("\nTop bandwidth:")
        print(fmt_table([[b["host"], b["human"]] for b in s["top_bandwidth"]], ["HOST", "TRAFFIC"]))
    if s["top_dns"]:
        print("\nTop DNS lookups:")
        print(fmt_table([[d, n] for d, n in s["top_dns"][:10]], ["DOMAIN", "COUNT"]))

    if s["alerts"]:
        print("\n=== THREAT FEED ===")
        for sev, msg in s["alerts"]:
            print(f"  [{sev.upper()}] {msg}")
    else:
        print("\nNo threats detected in this capture.")

    if s["pcap_out"]:
        print(f"\nSaved capture to {s['pcap_out']}")
    if args.json:
        print(json.dumps(s, indent=2, default=str))
    return 0


def cmd_watch(args):
    try:
        monitor_mod.run(
            subnet=args.subnet, method=args.method, interval=args.interval,
            rounds=args.rounds, scan_ports=args.scan_ports, db_path=args.db,
            webhook=args.webhook,
        )
    except RuntimeError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    return 0


def cmd_security(args):
    if args.host:
        results = [security.check_host(args.host)]
        hosts_for_save = [{"ip": args.host}]
    else:
        try:
            subnet, hosts, _ = discovery.discover(args.subnet)
        except RuntimeError as e:
            print(f"Error: {e}", file=sys.stderr)
            return 1
        if not hosts:
            print("No hosts discovered to scan.")
            return 0
        oui.enrich_hosts(hosts)
        print(f"Discovered {len(hosts)} host(s) on {subnet}, scanning each...\n")
        results = security.check_hosts(hosts)
        hosts_for_save = hosts

    print(security.summarize(results))

    if args.save:
        conn = storage.connect(args.db)
        storage.upsert_devices(conn, hosts_for_save)
        for r in results:
            ident = r["host"]
            storage.record_ports(conn, ident, r["open_ports"])
        print("\nSaved scan results to history.")

    if args.json:
        print(json.dumps(results, indent=2))
    return 0


def cmd_report(args):
    try:
        subnet, hosts, method_used = discovery.discover(args.subnet, args.method)
    except RuntimeError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    oui.enrich_hosts(hosts)
    print(f"Discovered {len(hosts)} device(s) on {subnet}. Scanning + fingerprinting...")
    devices = enrich_devices(hosts, do_fingerprint=True)

    cap = None
    if args.capture_seconds > 0:
        print(f"Capturing traffic for {args.capture_seconds}s for the threat feed...")
        try:
            cap = capture_mod.capture(iface=args.iface, duration=args.capture_seconds, gateway_ip=args.gateway)
        except RuntimeError as e:
            print(f"(skipping capture: {e})", file=sys.stderr)

    events = None
    try:
        conn = storage.connect(args.db)
        storage.upsert_devices(conn, hosts)
        for d in devices:
            storage.record_ports(conn, d.get("mac") or d["ip"], d["open_ports"])
        events = storage.get_recent_events(conn, limit=20)
    except Exception:
        pass

    out = args.output or "netscope-report.html"
    report.write_report(out, devices, cap, events, subnet=subnet)
    print(f"\nReport written to {out}")
    return 0


def cmd_history(args):
    conn = storage.connect(args.db)
    if args.events:
        events = storage.get_recent_events(conn, limit=args.limit)
        if not events:
            print("No events recorded yet.")
            return 0
        print(fmt_table([[e["ts_h"], e["type"], e["detail"]] for e in events], ["TIME", "TYPE", "DETAIL"]))
    else:
        devices = storage.get_devices(conn)
        if not devices:
            print("No devices recorded yet. Run 'netscope discover --save' first.")
            return 0
        rows = [[d["ip"], d["mac"] or "-", (d["vendor"] or "unknown")[:28], d["first_seen_h"], d["last_seen_h"]] for d in devices]
        print(fmt_table(rows, ["IP", "MAC", "VENDOR", "FIRST SEEN", "LAST SEEN"]))
    if args.json:
        payload = storage.get_recent_events(conn, args.limit) if args.events else storage.get_devices(conn)
        print(json.dumps(payload, indent=2))
    return 0


# ---------- parser ----------

def _add_db(p):
    p.add_argument("--db", default=None, help="Path to history DB (default: ~/.netscope/netscope.db)")


def build_parser():
    p = argparse.ArgumentParser(prog="netscope", description=__doc__.split("\n\n")[0])
    sub = p.add_subparsers(dest="command", required=True)

    d = sub.add_parser("discover", help="Find devices on the local network")
    d.add_argument("--subnet", default=None, help=f"CIDR, e.g. 192.168.1.0/24 (default: auto, now {get_default_subnet() or 'unknown'})")
    d.add_argument("--method", choices=["auto", "arp", "sweep"], default="auto")
    d.add_argument("--fingerprint", action="store_true", help="Also grab banners and guess each device's OS")
    d.add_argument("--save", action="store_true", help="Save discovered devices to history")
    d.add_argument("--json", action="store_true")
    _add_db(d)
    d.set_defaults(func=cmd_discover)

    ps = sub.add_parser("portscan", help="Scan a host for open TCP ports")
    ps.add_argument("host")
    ps.add_argument("--ports", help="e.g. 80,443,8000-8100 (default: common ports)")
    ps.add_argument("--full", action="store_true", help="Scan all well-known ports 1-1024")
    ps.add_argument("--fingerprint", action="store_true", help="Grab service banners + OS guess")
    ps.add_argument("--json", action="store_true")
    ps.set_defaults(func=cmd_portscan)

    c = sub.add_parser("capture", help="Capture traffic + passive threat detection (needs root)")
    c.add_argument("--iface", default=None)
    c.add_argument("--duration", type=int, default=15)
    c.add_argument("--filter", default=None, help="BPF filter, e.g. 'tcp port 80'")
    c.add_argument("--pcap", default=None, help="Save a .pcap for Wireshark")
    c.add_argument("--gateway", default=None, help="Your gateway IP (sharpens ARP/DHCP checks)")
    c.add_argument("--max-packets", type=int, default=0, dest="max_packets")
    c.add_argument("--json", action="store_true")
    c.set_defaults(func=cmd_capture)
    # backwards-compatible alias of `capture`
    m = sub.add_parser("monitor", help="Alias of 'capture'")
    for a in ("--iface", "--filter", "--pcap", "--gateway"):
        m.add_argument(a, default=None)
    m.add_argument("--duration", type=int, default=30)
    m.add_argument("--max-packets", type=int, default=0, dest="max_packets")
    m.add_argument("--json", action="store_true")
    m.set_defaults(func=cmd_capture)

    w = sub.add_parser("watch", help="Continuously monitor the LAN and alert on changes")
    w.add_argument("--subnet", default=None)
    w.add_argument("--method", choices=["auto", "arp", "sweep"], default="auto")
    w.add_argument("--interval", type=int, default=60, help="Seconds between rounds")
    w.add_argument("--rounds", type=int, default=0, help="Number of rounds (0 = until Ctrl-C)")
    w.add_argument("--scan-ports", action="store_true", dest="scan_ports", help="Also alert on newly-opened ports")
    w.add_argument("--webhook", default=None, help="POST alerts to this URL (Slack/Discord/ntfy)")
    _add_db(w)
    w.set_defaults(func=cmd_watch)

    s = sub.add_parser("security", help="Scan for commonly-risky open ports")
    s.add_argument("--subnet", default=None)
    s.add_argument("--host", default=None)
    s.add_argument("--save", action="store_true", help="Save results to history")
    s.add_argument("--json", action="store_true")
    _add_db(s)
    s.set_defaults(func=cmd_security)

    r = sub.add_parser("report", help="Generate a standalone HTML network report")
    r.add_argument("--subnet", default=None)
    r.add_argument("--method", choices=["auto", "arp", "sweep"], default="auto")
    r.add_argument("--capture-seconds", type=int, default=0, dest="capture_seconds", help="Capture N seconds of traffic for the threat feed (needs root)")
    r.add_argument("--gateway", default=None)
    r.add_argument("--iface", default=None)
    r.add_argument("--output", "-o", default=None, help="Output HTML path")
    _add_db(r)
    r.set_defaults(func=cmd_report)

    h = sub.add_parser("history", help="Show recorded devices / events")
    h.add_argument("--events", action="store_true", help="Show the event log instead of devices")
    h.add_argument("--limit", type=int, default=50)
    h.add_argument("--json", action="store_true")
    _add_db(h)
    h.set_defaults(func=cmd_history)

    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
