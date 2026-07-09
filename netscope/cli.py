#!/usr/bin/env python3
"""netscope: local network discovery, fingerprinting, traffic analysis,
continuous monitoring, and security reporting.

Commands:
    discover   Find devices on the LAN (with vendor + optional fingerprinting)
    portscan   Scan a host for open TCP/UDP ports (with optional banner grabbing)
    capture    Capture (or replay a .pcap of) traffic and run passive detection
    watch      Continuously monitor the LAN and alert on changes
    security   Scan for risky ports; --deep adds CVE/TLS/weak-auth correlation
    audit      Full deep audit: discover + CVE/TLS/weak-auth, scored + exportable
    diff       Compare two saved audit snapshots (what changed)
    tls        Inspect a TLS service's certificate and negotiated protocol
    snmp       Check a host for SNMP default community strings
    report     Generate a standalone HTML network report
    history    Show devices and events recorded in the local database
"""

import argparse
import json
import sys

from . import discovery, portscan, fingerprint, oui, security, storage, report
from . import capture as capture_mod
from . import monitor as monitor_mod
from . import tlsaudit, probes, findings as fmod
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


def _split_host_port(spec, default_port):
    """Parse 'host' or 'host:port' -> (host, port)."""
    if ":" in spec and spec.count(":") == 1:
        host, _, port = spec.partition(":")
        return host, int(port)
    return spec, default_port


def emit_findings_export(findings, fmt, out_path, meta=None):
    """Render findings in `fmt` and write to `out_path` (or stdout if None)."""
    if not fmt:
        return
    text = fmod.export(findings, fmt, meta=meta)
    if out_path:
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(text)
        print(f"\nExported {len(findings)} finding(s) as {fmt} to {out_path}")
    else:
        print(text)


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

    if args.udp:
        try:
            results = portscan.scan_udp(args.host, ports=ports)
        except RuntimeError as e:
            print(f"Error: {e}", file=sys.stderr)
            return 1
        print(f"UDP ports on {args.host}:")
        if not results:
            print("  (none open/responding in scanned range)")
        else:
            rows = [[r["port"], r["service"], r["state"]] for r in results]
            print(fmt_table(rows, ["PORT", "SERVICE", "STATE"]))
        if args.json:
            print(json.dumps(results, indent=2))
        return 0

    try:
        results = portscan.scan(args.host, ports=ports, timing=args.timing)
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
        rows = []
        for r in results:
            info = by_port.get(r["port"], {})
            prod = info.get("product") or ""
            ver = info.get("version") or ""
            pv = f"{prod} {ver}".strip() or (info.get("banner") or "-")[:48]
            rows.append([r["port"], r["service"], pv])
        print(fmt_table(rows, ["PORT", "SERVICE", "PRODUCT/BANNER"]))
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
            read_pcap=getattr(args, "read", None),
        )
    except RuntimeError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    if s.get("offline"):
        print(f"Analysed {s['total_packets']} packets from {s['source']}")
    else:
        print(f"Captured {s['total_packets']} packets over {s['duration']}s")
    print(f"Protocols: {s['protocol_counts']}")

    if s["top_bandwidth"]:
        print("\nTop bandwidth:")
        print(fmt_table([[b["host"], b["human"]] for b in s["top_bandwidth"]], ["HOST", "TRAFFIC"]))
    if s["top_dns"]:
        print("\nTop DNS lookups:")
        print(fmt_table([[d, n] for d, n in s["top_dns"][:10]], ["DOMAIN", "COUNT"]))
    if s.get("top_sni"):
        print("\nTop TLS destinations (SNI):")
        print(fmt_table([[d, n] for d, n in s["top_sni"][:10]], ["SNI HOST", "COUNT"]))

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
    subnet = None
    if args.host:
        hosts = [{"ip": args.host}]
        print(f"Scanning {args.host}{' (deep audit)' if args.deep else ''}...\n")
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
        print(f"Discovered {len(hosts)} host(s) on {subnet}, "
              f"{'deep-auditing' if args.deep else 'scanning'} each...\n")

    if args.deep:
        results = security.deep_check_hosts(hosts, timing=args.timing)
        print(security.summarize_deep(results))
        all_findings = security.collect_findings(results)
        if args.save:
            conn = storage.connect(args.db)
            storage.upsert_devices(conn, hosts)
            for r in results:
                storage.record_ports(conn, r["host"], r["open_ports"])
            sid = storage.save_scan(
                conn, all_findings, subnet=subnet, label=args.label,
                n_hosts=len(results),
                summary={"counts": fmod.severity_counts(all_findings)},
            )
            print(f"\nSaved audit snapshot #{sid} ({len(all_findings)} findings) to history.")
        emit_findings_export(all_findings, args.export, args.export_out,
                             meta={"subnet": subnet, "hosts": len(results)})
        if args.json:
            print(json.dumps(results, indent=2, default=str))
        return 0

    # quick (port-heuristic) mode
    results = security.check_hosts(hosts)
    print(security.summarize(results))
    if args.save:
        conn = storage.connect(args.db)
        storage.upsert_devices(conn, hosts)
        for r in results:
            storage.record_ports(conn, r["host"], r["open_ports"])
        print("\nSaved scan results to history.")
    if args.export:
        quick_findings = []
        for r in results:
            quick_findings += fmod.from_risky_ports(r["host"], r["open_ports"], RISKY_PORTS)
        emit_findings_export(quick_findings, args.export, args.export_out,
                             meta={"subnet": subnet, "hosts": len(results), "mode": "quick"})
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

    # Deep findings for the report's vulnerability panel.
    findings = []
    try:
        deep = security.deep_check_hosts(hosts)
        findings = security.collect_findings(deep)
    except Exception as e:
        print(f"(skipping deep findings: {e})", file=sys.stderr)

    out = args.output or "netscope-report.html"
    report.write_report(out, devices, cap, events, subnet=subnet, findings=findings)
    print(f"\nReport written to {out} ({len(findings)} finding(s))")
    return 0


def cmd_audit(args):
    """Flagship: discover -> deep audit -> scored findings -> report/export."""
    if args.host:
        hosts = [{"ip": args.host}]
        subnet = args.host
    else:
        try:
            subnet, hosts, method_used = discovery.discover(args.subnet, args.method)
        except RuntimeError as e:
            print(f"Error: {e}", file=sys.stderr)
            return 1
        oui.enrich_hosts(hosts)
        print(f"Discovered {len(hosts)} host(s) on {subnet}. Running deep audit...\n")

    if not hosts:
        print("No hosts to audit.")
        return 0

    results = security.deep_check_hosts(hosts, timing=args.timing)
    all_findings = security.collect_findings(results)

    cap = None
    if args.capture_seconds > 0:
        print(f"\nCapturing traffic for {args.capture_seconds}s for the threat feed...")
        try:
            cap = capture_mod.capture(iface=args.iface, duration=args.capture_seconds,
                                      gateway_ip=args.gateway)
            all_findings += fmod.from_capture_alerts(cap.get("alerts", []))
            all_findings = fmod.dedupe(all_findings)
        except RuntimeError as e:
            print(f"(skipping capture: {e})", file=sys.stderr)

    print(security.summarize_deep(results))
    counts = fmod.severity_counts(all_findings)
    print(f"\nOverall risk score: {fmod.risk_score(all_findings)}/100  "
          f"(critical {counts['critical']}, high {counts['high']}, "
          f"medium {counts['medium']}, low {counts['low']})")

    conn = None
    if args.save or args.diff:
        conn = storage.connect(args.db)
        storage.upsert_devices(conn, hosts)
        for r in results:
            storage.record_ports(conn, r["host"], r["open_ports"])
        sid = storage.save_scan(conn, all_findings, subnet=subnet, label=args.label,
                                n_hosts=len(results),
                                summary={"counts": counts, "risk": fmod.risk_score(all_findings)})
        print(f"\nSaved audit snapshot #{sid} to history.")
        if args.diff:
            scans = storage.get_scans(conn, limit=2)
            if len(scans) >= 2:
                _print_diff(storage.diff_scans(conn, scans[1]["id"], scans[0]["id"]))
            else:
                print("(no previous snapshot to diff against yet)")

    if args.report:
        devices = enrich_devices(hosts, do_fingerprint=True)
        events = storage.get_recent_events(conn, limit=20) if conn else None
        report.write_report(args.report, devices, cap, events, subnet=subnet,
                            findings=all_findings)
        print(f"\nHTML report written to {args.report}")

    emit_findings_export(all_findings, args.export, args.export_out,
                         meta={"subnet": subnet, "hosts": len(results),
                               "risk_score": fmod.risk_score(all_findings)})
    if args.json:
        print(json.dumps({"subnet": subnet, "results": results,
                          "risk_score": fmod.risk_score(all_findings)}, indent=2, default=str))
    return 0


def _print_diff(diff):
    added, resolved = diff["added"], diff["resolved"]
    print("\n=== DIFF vs previous snapshot ===")
    if not added and not resolved:
        print("  No change in findings since the last snapshot.")
        return
    if added:
        print(f"  + {len(added)} NEW finding(s):")
        for f in fmod.sort_findings(added):
            port = f":{f['port']}" if f.get("port") else ""
            print(f"      [{(f.get('severity') or '').upper():8}] {f.get('host')}{port}  {f.get('title')}")
    if resolved:
        print(f"  - {len(resolved)} RESOLVED finding(s):")
        for f in fmod.sort_findings(resolved):
            port = f":{f['port']}" if f.get("port") else ""
            print(f"      [{(f.get('severity') or '').upper():8}] {f.get('host')}{port}  {f.get('title')}")


def cmd_diff(args):
    conn = storage.connect(args.db)
    scans = storage.get_scans(conn, limit=50)
    if len(scans) < 2:
        print("Need at least two saved audit snapshots to diff. "
              "Run 'netscope audit --save' at least twice.")
        return 1
    if args.old is not None and args.new is not None:
        old_id, new_id = args.old, args.new
    else:
        new_id, old_id = scans[0]["id"], scans[1]["id"]
    print(f"Diffing snapshot #{old_id} -> #{new_id}")
    diff = storage.diff_scans(conn, old_id, new_id)
    _print_diff(diff)
    if args.export:
        emit_findings_export(diff["added"], args.export, args.export_out,
                             meta={"diff": f"{old_id}->{new_id}", "kind": "added"})
    if args.json:
        print(json.dumps(diff, indent=2, default=str))
    return 0


def cmd_tls(args):
    host, port = _split_host_port(args.target, 443)
    res = tlsaudit.inspect(host, port)
    if not res.get("ok"):
        print(f"No TLS service at {host}:{port} ({res.get('error', 'unknown error')})")
        return 1
    print(f"TLS on {host}:{port}")
    print(f"  protocol: {res.get('protocol')}   cipher: {res.get('cipher')}")
    print(f"  subject:  {res.get('subject')}")
    print(f"  issuer:   {res.get('issuer')}")
    if res.get("san"):
        print(f"  SAN:      {', '.join(res['san'])}")
    print(f"  expires:  {res.get('not_after')}")
    if res["findings"]:
        print("\n  Findings:")
        for f in res["findings"]:
            print(f"    [{f['severity'].upper():8}] {f['title']} -- {f['detail']}")
    else:
        print("\n  No TLS findings.")
    if args.json:
        print(json.dumps(res, indent=2, default=str))
    return 0


def cmd_snmp(args):
    communities = tuple(c.strip() for c in args.communities.split(",")) if args.communities \
        else ("public", "private")
    res = probes.check_snmp_default_community(args.host, communities=communities)
    if not res:
        print(f"No SNMP response from {args.host} with communit(ies) {', '.join(communities)}.")
        return 0
    for f in res:
        print(f"[{f['severity'].upper()}] {f['title']}")
        print(f"    {f['detail']}")
        if f.get("evidence"):
            print(f"    sysDescr: {f['evidence']}")
    if args.json:
        print(json.dumps(res, indent=2, default=str))
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


def _add_export(p):
    p.add_argument("--export", choices=["json", "ndjson", "csv", "sarif"], default=None,
                   help="Export findings in a machine-readable format")
    p.add_argument("--export-out", default=None, dest="export_out",
                   help="Write the export to this file (default: stdout)")


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

    ps = sub.add_parser("portscan", help="Scan a host for open TCP/UDP ports")
    ps.add_argument("host")
    ps.add_argument("--ports", help="e.g. 80,443,8000-8100 (default: common ports)")
    ps.add_argument("--full", action="store_true", help="Scan all well-known ports 1-1024")
    ps.add_argument("--udp", action="store_true", help="UDP sweep instead of TCP (best-effort)")
    ps.add_argument("--fingerprint", action="store_true", help="Grab banners + product/version + OS guess")
    ps.add_argument("--timing", "-T", type=int, choices=range(0, 6), default=None,
                    metavar="0-5", help="Timing template: 0=stealthy .. 5=fastest (default 3)")
    ps.add_argument("--json", action="store_true")
    ps.set_defaults(func=cmd_portscan)

    c = sub.add_parser("capture", help="Capture traffic + passive threat detection (needs root)")
    c.add_argument("--iface", default=None)
    c.add_argument("--duration", type=int, default=15)
    c.add_argument("--filter", default=None, help="BPF filter, e.g. 'tcp port 80'")
    c.add_argument("--pcap", default=None, help="Save a .pcap for Wireshark")
    c.add_argument("--read", default=None, help="Analyse an existing .pcap offline (no root needed)")
    c.add_argument("--gateway", default=None, help="Your gateway IP (sharpens ARP/DHCP checks)")
    c.add_argument("--max-packets", type=int, default=0, dest="max_packets")
    c.add_argument("--json", action="store_true")
    c.set_defaults(func=cmd_capture)
    # backwards-compatible alias of `capture`
    m = sub.add_parser("monitor", help="Alias of 'capture'")
    for a in ("--iface", "--filter", "--pcap", "--gateway"):
        m.add_argument(a, default=None)
    m.add_argument("--duration", type=int, default=15)  # match `capture` -- it's an alias
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

    s = sub.add_parser("security", help="Scan for risky ports; --deep adds CVE/TLS/weak-auth audit")
    s.add_argument("--subnet", default=None)
    s.add_argument("--host", default=None)
    s.add_argument("--deep", action="store_true",
                   help="Deep audit: version fingerprint + CVE correlation + TLS + weak-auth probes")
    s.add_argument("--timing", "-T", type=int, choices=range(0, 6), default=None, metavar="0-5")
    s.add_argument("--label", default=None, help="Label this saved snapshot (with --save --deep)")
    s.add_argument("--save", action="store_true", help="Save results to history")
    s.add_argument("--json", action="store_true")
    _add_export(s)
    _add_db(s)
    s.set_defaults(func=cmd_security)

    a = sub.add_parser("audit", help="Full deep audit: discover + CVE/TLS/weak-auth + score + export")
    a.add_argument("--subnet", default=None)
    a.add_argument("--host", default=None, help="Audit a single host instead of discovering")
    a.add_argument("--method", choices=["auto", "arp", "sweep"], default="auto")
    a.add_argument("--timing", "-T", type=int, choices=range(0, 6), default=None, metavar="0-5")
    a.add_argument("--capture-seconds", type=int, default=0, dest="capture_seconds",
                   help="Also capture N seconds of traffic for the threat feed (needs root)")
    a.add_argument("--gateway", default=None)
    a.add_argument("--iface", default=None)
    a.add_argument("--report", default=None, metavar="FILE.html",
                   help="Also write a standalone HTML report")
    a.add_argument("--label", default=None, help="Label for the saved snapshot")
    a.add_argument("--save", action="store_true", help="Save this audit as a snapshot")
    a.add_argument("--diff", action="store_true",
                   help="After saving, show what changed vs the previous snapshot")
    a.add_argument("--json", action="store_true")
    _add_export(a)
    _add_db(a)
    a.set_defaults(func=cmd_audit)

    df = sub.add_parser("diff", help="Compare the two most recent audit snapshots")
    df.add_argument("--old", type=int, default=None, help="Old snapshot id (default: 2nd newest)")
    df.add_argument("--new", type=int, default=None, help="New snapshot id (default: newest)")
    df.add_argument("--json", action="store_true")
    _add_export(df)
    _add_db(df)
    df.set_defaults(func=cmd_diff)

    t = sub.add_parser("tls", help="Inspect a TLS service's certificate + protocol")
    t.add_argument("target", help="host or host:port (default port 443)")
    t.add_argument("--json", action="store_true")
    t.set_defaults(func=cmd_tls)

    sn = sub.add_parser("snmp", help="Check a host for SNMP default community strings")
    sn.add_argument("host")
    sn.add_argument("--communities", default=None, help="Comma-separated (default: public,private)")
    sn.add_argument("--json", action="store_true")
    sn.set_defaults(func=cmd_snmp)

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
