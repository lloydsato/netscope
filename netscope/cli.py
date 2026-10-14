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
import os
import sqlite3
import sys

from . import __version__
from . import discovery, portscan, fingerprint, oui, security, storage, report, nameservices, suppress
from . import config as config_mod
from . import capture as capture_mod
from . import monitor as monitor_mod
from . import tlsaudit, probes, findings as fmod
from .utils import fmt_table, get_default_subnet, RISKY_PORTS


# ---------- shared helpers ----------

# When --json (or --export without --export-out) is used, stdout is reserved for
# the machine-readable payload so it can be piped (`... --json | jq`). main()
# points sys.stdout at stderr for the duration of the command, so every ordinary
# progress/summary print() goes to the terminal instead, and the payload is
# written to the *real* stdout through machine_out().
_machine_stream = None


def machine_out(text):
    """Write machine-readable output (JSON / findings export) to real stdout."""
    stream = _machine_stream or sys.stdout
    stream.write(text if text.endswith("\n") else text + "\n")
    stream.flush()


def _port(value, what="port"):
    try:
        n = int(str(value).strip())
    except ValueError:
        raise ValueError(f"invalid {what} {str(value).strip()!r}: not a number") from None
    if not 1 <= n <= 65535:
        raise ValueError(f"invalid {what} {n}: must be between 1 and 65535")
    return n


def parse_port_range(spec: str):
    """Parse '80,443,8000-8100' -> sorted-as-given, de-duplicated port list.

    Raises ValueError (with a user-facing message) for non-numeric input, ports
    outside 1-65535, reversed ranges, or a spec that names no ports at all.
    """
    ports, seen = [], set()
    for part in str(spec).split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo_s, sep, hi_s = part.partition("-")
            if "-" in hi_s or not lo_s.strip() or not hi_s.strip():
                raise ValueError(f"invalid port range {part!r}: expected LOW-HIGH")
            lo, hi = _port(lo_s), _port(hi_s)
            if lo > hi:
                raise ValueError(f"invalid port range {part!r}: {lo} is greater than {hi}")
            batch = range(lo, hi + 1)
        else:
            batch = [_port(part)]
        for p in batch:
            if p not in seen:
                seen.add(p)
                ports.append(p)
    if not ports:
        raise ValueError(f"no ports in {spec!r}")
    return ports


def _split_host_port(spec, default_port):
    """Parse 'host', 'host:port', '[v6]' or '[v6]:port' -> (host, port).

    A bare IPv6 literal (several colons, no brackets) is a host with the default
    port. Raises ValueError on an empty host or an invalid port.
    """
    spec = (spec or "").strip()
    if spec.startswith("["):
        host, bracket, rest = spec[1:].partition("]")
        if not bracket or not host:
            raise ValueError(f"invalid target {spec!r}: unmatched '['")
        if not rest:
            return host, default_port
        if not rest.startswith(":"):
            raise ValueError(f"invalid target {spec!r}: expected ':port' after ']'")
        return host, _port(rest[1:])
    if spec.count(":") == 1:
        host, _, port = spec.partition(":")
        if not host:
            raise ValueError(f"invalid target {spec!r}: missing host")
        return host, _port(port)
    if not spec:
        raise ValueError("missing host")
    return spec, default_port


def _int_at_least(minimum):
    def check(value):
        try:
            n = int(value)
        except ValueError:
            raise argparse.ArgumentTypeError(f"invalid integer: {value!r}") from None
        if n < minimum:
            raise argparse.ArgumentTypeError(f"must be >= {minimum} (got {n})")
        return n
    return check


def _port_spec_arg(value):
    try:
        return parse_port_range(value)
    except ValueError as e:
        raise argparse.ArgumentTypeError(str(e)) from None


def emit_findings_export(findings, fmt, out_path, meta=None, suppressed=None):
    """Render findings in `fmt` and write to `out_path` (or stdout if None).

    SARIF additionally carries ``suppressed`` findings (marked as accepted) so
    code-scanning shows them as dismissed instead of losing them; the other
    formats list only the active findings.
    """
    if not fmt:
        return
    text = fmod.export(findings + (suppressed or []) if fmt == "sarif" else findings, fmt, meta=meta)
    if out_path:
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(text)
        print(f"\nExported {len(findings)} finding(s) as {fmt} to {out_path}")
    else:
        machine_out(text)


def _identity_for(ip, hosts):
    """Storage identity of a scanned host: its MAC when discovery found one, else
    its IP -- the same rule storage.upsert_devices uses, so recorded ports attach
    to the device row (and `watch` sees them) instead of a phantom IP-keyed one."""
    for h in hosts:
        if isinstance(h, dict) and h.get("ip") == ip and h.get("mac"):
            return h["mac"]
    return ip


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
            "hostname": h.get("hostname"), "model": h.get("model"),
            "open_ports": scan_res, "os_guess": os_guess,
        })
    return devices


# ---------- accepted-risk suppression + severity gate ----------

EXIT_GATE = 3      # --fail-on threshold met by an active finding


def _load_rules(args):
    """Load --ignore-file up front, so a typo fails before a long audit runs."""
    path = getattr(args, "ignore_file", None)
    return suppress.load_rules(path) if path else []


def _apply_rules(args, rules, findings):
    """Split findings into (active, suppressed), reporting -- never hiding -- what was suppressed."""
    if not rules:
        return findings, []
    active, suppressed, expired = suppress.apply_suppressions(findings, rules)
    for r in expired:
        print(f"Warning: suppression {r['where']} expired on {r['expires']}; it no longer applies.",
              file=sys.stderr)
    if suppressed:
        print(f"\nSuppressed {len(suppressed)} finding(s) as accepted risk ({args.ignore_file}):")
        for f in fmod.sort_findings(suppressed):
            port = f":{f['port']}" if f.get("port") else ""
            why = f["suppression"]["reason"] or "no reason given"
            print(f"  [{(f.get('severity') or '').upper():8}] {f.get('host')}{port}  {f.get('title')}  -- {why}")
    return active, suppressed


def _gate_code(args, active):
    """0, or EXIT_GATE when an active finding meets --fail-on."""
    level = getattr(args, "fail_on", None)
    if suppress.exceeds(active, level):
        n = sum(1 for f in active if fmod.severity_rank(f) <= fmod.SEVERITIES.index(level))
        print(f"\nFAIL: {n} active finding(s) at or above '{level}' (--fail-on {level}).", file=sys.stderr)
        return EXIT_GATE
    return 0


# ---------- commands ----------

def cmd_discover(args):
    try:
        subnet, hosts, method_used = discovery.discover(args.subnet, args.method)
    except RuntimeError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    oui.enrich_hosts(hosts)
    if args.names and hosts:
        nameservices.enrich_hosts(hosts)
    print(f"Subnet: {subnet}  (method: {method_used})")
    if not hosts:
        print("No hosts found.")
        if args.json:
            machine_out(json.dumps({"subnet": subnet, "method": method_used, "hosts": []}, indent=2))
        return 0

    fp_map = {}
    if args.fingerprint:
        print("Fingerprinting services...")
        for h in hosts:
            open_ports = portscan.scan(h["ip"])
            fp = fingerprint.fingerprint_host(h["ip"], open_ports)
            fp_map[h["ip"]] = fp["os_guess"]

    headers = (["IP", "MAC", "VENDOR"] + (["NAME", "MODEL"] if args.names else [])
               + (["OS GUESS"] if args.fingerprint else []))
    rows = []
    for h in hosts:
        row = [h["ip"], h.get("mac") or "-", h.get("vendor", "unknown")]
        if args.names:
            row += [h.get("hostname") or "-", h.get("model") or "-"]
        if args.fingerprint:
            row.append(fp_map.get(h["ip"]) or "-")
        rows.append(row)
    print(fmt_table(rows, headers))

    if args.save:
        conn = storage.connect(args.db)
        new_ids = storage.upsert_devices(conn, hosts)
        conn.close()
        print(f"\nSaved to history ({len(new_ids)} new device(s)).")

    if args.json:
        for h in hosts:
            if args.fingerprint:
                h["os_guess"] = fp_map.get(h["ip"], "")
        machine_out(json.dumps({"subnet": subnet, "method": method_used, "hosts": hosts}, indent=2))
    return 0


def cmd_portscan(args):
    ports = range(1, 1025) if args.full else (args.ports if args.ports else None)

    if args.udp:
        for flag, used in (("--fingerprint", args.fingerprint), ("--timing", args.timing is not None)):
            if used:
                print(f"(note: {flag} has no effect with --udp)", file=sys.stderr)
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
            machine_out(json.dumps(results, indent=2))
        return 0

    try:
        results = portscan.scan(args.host, ports=ports, timing=args.timing)
    except RuntimeError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    print(f"Open ports on {args.host}:")
    if not results:
        print("  (none found in scanned range)")
        if args.json:
            machine_out("[]")
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
            r.update(product=prod, version=ver, banner=info.get("banner", ""),
                     os_hint=info.get("os_hint", ""))
        print(fmt_table(rows, ["PORT", "SERVICE", "PRODUCT/BANNER"]))
        if fp["os_guess"]:
            print(f"\nOS guess: {fp['os_guess']}")
    else:
        rows = [[r["port"], r["service"], "risky" if RISKY_PORTS.get(r["port"]) else ""] for r in results]
        print(fmt_table(rows, ["PORT", "SERVICE", "NOTE"]))

    if args.json:
        machine_out(json.dumps(results, indent=2))
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
        machine_out(json.dumps(s, indent=2, default=str))
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


def _no_hosts_output(args, subnet, deep):
    """`--json` / `--export` must still yield a valid (empty) document when
    nothing was found, so scripts don't choke on an empty stdout."""
    if getattr(args, "export", None):
        emit_findings_export([], args.export, args.export_out,
                             meta={"subnet": subnet, "hosts": 0})
    if args.json:
        machine_out(json.dumps({"subnet": subnet, "results": [], "risk_score": 0} if deep else [], indent=2))


def cmd_security(args):
    rules = _load_rules(args)
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
            _no_hosts_output(args, subnet, args.deep)
            return 0
        oui.enrich_hosts(hosts)
        print(f"Discovered {len(hosts)} host(s) on {subnet}, "
              f"{'deep-auditing' if args.deep else 'scanning'} each...\n")

    try:
        if args.deep:
            results = security.deep_check_hosts(hosts, timing=args.timing)
        else:
            results = security.check_hosts(hosts, timing=args.timing)
    except RuntimeError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    if args.deep:
        all_findings = security.collect_findings(results)
        all_findings, suppressed = _apply_rules(args, rules, all_findings)
        suppress.apply_to_results(results, {f["id"] for f in all_findings})
        print(security.summarize_deep(results))
        if args.save:
            conn = storage.connect(args.db)
            storage.upsert_devices(conn, hosts)
            for r in results:
                storage.record_ports(conn, _identity_for(r["host"], hosts), r["open_ports"])
            sid = storage.save_scan(
                conn, all_findings, subnet=subnet or args.host, label=args.label,
                n_hosts=len(results),
                summary={"counts": fmod.severity_counts(all_findings)},
            )
            conn.close()
            print(f"\nSaved audit snapshot #{sid} ({len(all_findings)} findings) to history.")
        emit_findings_export(all_findings, args.export, args.export_out,
                             meta={"subnet": subnet, "hosts": len(results)}, suppressed=suppressed)
        if args.json:
            machine_out(json.dumps(results, indent=2, default=str))
        return _gate_code(args, all_findings)

    # quick (port-heuristic) mode
    print(security.summarize(results))
    if args.save:
        conn = storage.connect(args.db)
        storage.upsert_devices(conn, hosts)
        for r in results:
            storage.record_ports(conn, _identity_for(r["host"], hosts), r["open_ports"])
        conn.close()
        print("\nSaved scan results to history.")
    quick_findings, quick_suppressed = [], []
    if args.export or rules or args.fail_on:
        for r in results:
            quick_findings += fmod.from_risky_ports(r["host"], r["open_ports"], RISKY_PORTS)
        quick_findings, quick_suppressed = _apply_rules(args, rules, quick_findings)
    if args.export:
        emit_findings_export(quick_findings, args.export, args.export_out,
                             meta={"subnet": subnet, "hosts": len(results), "mode": "quick"},
                             suppressed=quick_suppressed)
    if args.json:
        machine_out(json.dumps(results, indent=2))
    return _gate_code(args, quick_findings)


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
        try:
            storage.upsert_devices(conn, hosts)
            for d in devices:
                storage.record_ports(conn, d.get("mac") or d["ip"], d["open_ports"])
            events = storage.get_recent_events(conn, limit=20)
        finally:
            conn.close()
    except (OSError, sqlite3.Error) as e:
        print(f"(history unavailable: {e})", file=sys.stderr)

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
    rules = _load_rules(args)
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
        _no_hosts_output(args, subnet, True)
        return 0

    name_findings = []
    if not args.no_names and not args.host:      # --host is a targeted, quick audit: no LAN-wide queries
        nameservices.enrich_hosts(hosts)
        for h in hosts:
            name_findings += fmod.from_nameservices(h["ip"], h.get("exposures", []), h.get("hostname", ""))

    try:
        results = security.deep_check_hosts(hosts, timing=args.timing)
    except RuntimeError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    all_findings = fmod.sort_findings(fmod.dedupe(security.collect_findings(results) + name_findings))

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

    all_findings, suppressed = _apply_rules(args, rules, all_findings)
    suppress.apply_to_results(results, {f["id"] for f in all_findings})
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
            storage.record_ports(conn, _identity_for(r["host"], hosts), r["open_ports"])
        sid = storage.save_scan(conn, all_findings, subnet=subnet, label=args.label,
                                n_hosts=len(results),
                                summary={"counts": counts, "risk": fmod.risk_score(all_findings)})
        print(f"\nSaved audit snapshot #{sid} to history.")
        if args.diff:
            prev = storage.previous_scan(conn, sid)
            if prev:
                _print_diff(storage.diff_scans(conn, prev["id"], sid))
            else:
                print(f"(no previous snapshot of {subnet} to diff against yet)")

    if args.report:
        devices = enrich_devices(hosts, do_fingerprint=True)
        events = storage.get_recent_events(conn, limit=20) if conn else None
        report.write_report(args.report, devices, cap, events, subnet=subnet,
                            findings=all_findings)
        print(f"\nHTML report written to {args.report}")

    emit_findings_export(all_findings, args.export, args.export_out,
                         meta={"subnet": subnet, "hosts": len(results),
                               "risk_score": fmod.risk_score(all_findings)},
                         suppressed=suppressed)
    if args.json:
        machine_out(json.dumps({"subnet": subnet, "results": results,
                                "risk_score": fmod.risk_score(all_findings),
                                "suppressed": len(suppressed)}, indent=2, default=str))
    if conn:
        conn.close()
    return _gate_code(args, all_findings)


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
    rules = _load_rules(args)
    if (args.old is None) != (args.new is None):
        print("Error: --old and --new must be given together (or neither, to compare "
              "the newest snapshot with the one before it).", file=sys.stderr)
        return 2
    conn = storage.connect(args.db)
    try:
        if args.old is not None:
            old_id, new_id = args.old, args.new
            for sid in (old_id, new_id):
                if storage.get_scan(conn, sid) is None:
                    print(f"Error: no saved snapshot #{sid}. "
                          f"Saved: {[x['id'] for x in storage.get_scans(conn, limit=20)] or 'none'}",
                          file=sys.stderr)
                    return 1
        else:
            scans = storage.get_scans(conn, limit=1)
            if not scans:
                print("No saved audit snapshots. Run 'netscope audit --save' at least twice.")
                return 1
            new_id = scans[0]["id"]
            prev = storage.previous_scan(conn, new_id)
            if not prev:
                print(f"No earlier snapshot of {scans[0]['subnet'] or 'this target'} to compare "
                      f"snapshot #{new_id} with. Run 'netscope audit --save' again, or pick "
                      f"snapshots explicitly with --old/--new.")
                return 1
            old_id = prev["id"]
        old_row, new_row = storage.get_scan(conn, old_id), storage.get_scan(conn, new_id)
        print(f"Diffing snapshot #{old_id} -> #{new_id}")
        if old_row["subnet"] != new_row["subnet"]:
            print(f"(note: these snapshots are for different targets: "
                  f"{old_row['subnet']} vs {new_row['subnet']})")
        diff = storage.diff_scans(conn, old_id, new_id)
        diff["added"], suppressed = _apply_rules(args, rules, diff["added"])
        _print_diff(diff)
        if args.export:
            emit_findings_export(diff["added"], args.export, args.export_out,
                                 meta={"diff": f"{old_id}->{new_id}", "kind": "added"},
                                 suppressed=suppressed)
        if args.json:
            machine_out(json.dumps(diff, indent=2, default=str))
        return _gate_code(args, diff["added"])      # gate on *new* findings: the regression signal
    finally:
        conn.close()


def cmd_tls(args):
    try:
        host, port = _split_host_port(args.target, 443)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 2
    res = tlsaudit.inspect(host, port)
    if not res.get("ok"):
        print(f"No TLS service at {host}:{port} ({res.get('error', 'unknown error')})")
        if args.json:
            machine_out(json.dumps(res, indent=2, default=str))
        return 1
    print(f"TLS on {host}:{port}")
    print(f"  protocol: {res.get('protocol')}   cipher: {res.get('cipher')}")
    print(f"  subject:  {res.get('subject')}")
    print(f"  issuer:   {res.get('issuer')}")
    if res.get("san"):
        print(f"  SAN:      {', '.join(res['san'])}")
    print(f"  expires:  {res.get('not_after')}")
    if res.get("cert_error"):
        print(f"  (certificate details unavailable: {res['cert_error']})")
    if res["findings"]:
        print("\n  Findings:")
        for f in res["findings"]:
            print(f"    [{f['severity'].upper():8}] {f['title']} -- {f['detail']}")
    else:
        print("\n  No TLS findings.")
    if args.json:
        machine_out(json.dumps(res, indent=2, default=str))
    return 0


def cmd_snmp(args):
    if args.communities is None:
        communities = ("public", "private")
    else:
        communities = tuple(c.strip() for c in args.communities.split(",") if c.strip())
        if not communities:
            print("Error: --communities needs at least one non-empty community string.",
                  file=sys.stderr)
            return 2
    res = probes.check_snmp_default_community(args.host, communities=communities)
    if not res:
        print(f"No SNMP response from {args.host} with communit(ies) {', '.join(communities)}.")
        if args.json:
            machine_out("[]")
        return 0
    for f in res:
        print(f"[{f['severity'].upper()}] {f['title']}")
        print(f"    {f['detail']}")
        if f.get("evidence"):
            print(f"    sysDescr: {f['evidence']}")
    if args.json:
        machine_out(json.dumps(res, indent=2, default=str))
    return 0


def cmd_history(args):
    conn = storage.connect(args.db)
    try:
        if args.events:
            events = storage.get_recent_events(conn, limit=args.limit)
            if not events:
                print("No events recorded yet.")
            else:
                print(fmt_table([[e["ts_h"], e["type"], e["detail"]] for e in events],
                                ["TIME", "TYPE", "DETAIL"]))
            payload = events
        else:
            devices = storage.get_devices(conn)
            if not devices:
                print("No devices recorded yet. Run 'netscope discover --save' first.")
            else:
                rows = [[d["ip"], d["mac"] or "-", (d["vendor"] or "unknown")[:28],
                         (d.get("hostname") or "-")[:28],
                         d["first_seen_h"], d["last_seen_h"]] for d in devices]
                print(fmt_table(rows, ["IP", "MAC", "VENDOR", "NAME", "FIRST SEEN", "LAST SEEN"]))
            payload = devices
        if args.json:
            machine_out(json.dumps(payload, indent=2))
        return 0
    finally:
        conn.close()


# ---------- parser ----------

def _add_db(p):
    p.add_argument("--db", default=None, help="Path to history DB (default: ~/.netscope/netscope.db)")


def _add_export(p):
    p.add_argument("--export", choices=["json", "ndjson", "csv", "sarif", "markdown"], default=None,
                   help="Export findings in a machine-readable format")
    p.add_argument("--export-out", default=None, dest="export_out",
                   help="Write the export to this file (default: stdout)")


def _add_gate(p):
    p.add_argument("--ignore-file", default=None, dest="ignore_file", metavar="FILE",
                   help="Accepted-risk file: findings it matches are reported as suppressed, not active")
    p.add_argument("--fail-on", choices=["critical", "high", "medium", "low"], default=None,
                   dest="fail_on", help=f"Exit {EXIT_GATE} if any active finding is at/above this severity")


def build_parser(config=None):
    """Build the argument parser. ``config`` ({dest: value}, see netscope.config)
    supplies per-user defaults; explicit command-line flags still win."""
    p = argparse.ArgumentParser(prog="netscope", description=__doc__.split("\n\n")[0])
    p.add_argument("--version", action="version", version=f"netscope {__version__}")
    p.add_argument("--config", default=None, metavar="FILE",
                   help="Settings file supplying default flag values (default: ~/.netscope/config.json; "
                        f"or set ${config_mod.ENV_VAR}). Must come before the command.")
    sub = p.add_subparsers(dest="command", required=True)

    d = sub.add_parser("discover", help="Find devices on the local network")
    d.add_argument("--subnet", default=None, help=f"CIDR, e.g. 192.168.1.0/24 (default: auto, now {get_default_subnet() or 'unknown'})")
    d.add_argument("--method", choices=["auto", "arp", "sweep"], default="auto")
    d.add_argument("--fingerprint", action="store_true", help="Also grab banners and guess each device's OS")
    d.add_argument("--names", action="store_true",
                   help="Also resolve hostnames/models via mDNS, SSDP/UPnP and NetBIOS")
    d.add_argument("--save", action="store_true", help="Save discovered devices to history")
    d.add_argument("--json", action="store_true")
    _add_db(d)
    d.set_defaults(func=cmd_discover)

    ps = sub.add_parser("portscan", help="Scan a host for open TCP/UDP ports")
    ps.add_argument("host")
    scope = ps.add_mutually_exclusive_group()
    scope.add_argument("--ports", type=_port_spec_arg,
                       help="e.g. 80,443,8000-8100 (default: common ports)")
    scope.add_argument("--full", action="store_true", help="Scan all well-known ports 1-1024")
    ps.add_argument("--udp", action="store_true", help="UDP sweep instead of TCP (best-effort)")
    ps.add_argument("--fingerprint", action="store_true", help="Grab banners + product/version + OS guess")
    ps.add_argument("--timing", "-T", type=int, choices=range(0, 6), default=None,
                    metavar="0-5", help="Timing template: 0=stealthy .. 5=fastest (default 3)")
    ps.add_argument("--json", action="store_true")
    ps.set_defaults(func=cmd_portscan)

    c = sub.add_parser("capture", help="Capture traffic + passive threat detection (needs root)")
    c.add_argument("--iface", default=None)
    c.add_argument("--duration", type=_int_at_least(1), default=15, help="Seconds to capture")
    c.add_argument("--filter", default=None, help="BPF filter, e.g. 'tcp port 80'")
    c.add_argument("--pcap", default=None, help="Save a .pcap for Wireshark")
    c.add_argument("--read", default=None, help="Analyse an existing .pcap offline (no root needed)")
    c.add_argument("--gateway", default=None, help="Your gateway IP (sharpens ARP/DHCP checks)")
    c.add_argument("--max-packets", type=_int_at_least(0), default=0, dest="max_packets",
                   help="Stop after this many packets (0 = no limit)")
    c.add_argument("--json", action="store_true")
    c.set_defaults(func=cmd_capture)
    # backwards-compatible alias of `capture`
    m = sub.add_parser("monitor", help="Alias of 'capture'")
    for a in ("--iface", "--filter", "--pcap", "--gateway"):
        m.add_argument(a, default=None)
    m.add_argument("--duration", type=_int_at_least(1), default=15)  # match `capture` -- it's an alias
    m.add_argument("--max-packets", type=_int_at_least(0), default=0, dest="max_packets")
    m.add_argument("--json", action="store_true")
    m.set_defaults(func=cmd_capture)

    w = sub.add_parser("watch", help="Continuously monitor the LAN and alert on changes")
    w.add_argument("--subnet", default=None)
    w.add_argument("--method", choices=["auto", "arp", "sweep"], default="auto")
    w.add_argument("--interval", type=_int_at_least(1), default=60, help="Seconds between rounds")
    w.add_argument("--rounds", type=_int_at_least(0), default=0, help="Number of rounds (0 = until Ctrl-C)")
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
    _add_gate(s)
    _add_db(s)
    s.set_defaults(func=cmd_security)

    a = sub.add_parser("audit", help="Full deep audit: discover + CVE/TLS/weak-auth + score + export")
    a.add_argument("--subnet", default=None)
    a.add_argument("--host", default=None, help="Audit a single host instead of discovering")
    a.add_argument("--method", choices=["auto", "arp", "sweep"], default="auto")
    a.add_argument("--timing", "-T", type=int, choices=range(0, 6), default=None, metavar="0-5")
    a.add_argument("--capture-seconds", type=_int_at_least(0), default=0, dest="capture_seconds",
                   help="Also capture N seconds of traffic for the threat feed (needs root)")
    a.add_argument("--gateway", default=None)
    a.add_argument("--iface", default=None)
    a.add_argument("--no-names", action="store_true", dest="no_names",
                   help="Skip mDNS/SSDP/NetBIOS name discovery (on by default for subnet audits)")
    a.add_argument("--report", default=None, metavar="FILE.html",
                   help="Also write a standalone HTML report")
    a.add_argument("--label", default=None, help="Label for the saved snapshot")
    a.add_argument("--save", action="store_true", help="Save this audit as a snapshot")
    a.add_argument("--diff", action="store_true",
                   help="After saving, show what changed vs the previous snapshot")
    a.add_argument("--json", action="store_true")
    _add_export(a)
    _add_gate(a)
    _add_db(a)
    a.set_defaults(func=cmd_audit)

    df = sub.add_parser("diff", help="Compare the two most recent audit snapshots")
    df.add_argument("--old", type=_int_at_least(1), default=None,
                    help="Old snapshot id (use with --new; default: the snapshot before the newest)")
    df.add_argument("--new", type=_int_at_least(1), default=None,
                    help="New snapshot id (use with --old; default: newest)")
    df.add_argument("--json", action="store_true")
    _add_export(df)
    _add_gate(df)
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
    r.add_argument("--capture-seconds", type=_int_at_least(0), default=0, dest="capture_seconds", help="Capture N seconds of traffic for the threat feed (needs root)")
    r.add_argument("--gateway", default=None)
    r.add_argument("--iface", default=None)
    r.add_argument("--output", "-o", default=None, help="Output HTML path")
    _add_db(r)
    r.set_defaults(func=cmd_report)

    h = sub.add_parser("history", help="Show recorded devices / events")
    h.add_argument("--events", action="store_true", help="Show the event log instead of devices")
    h.add_argument("--limit", type=_int_at_least(1), default=50, help="Max events to show")
    h.add_argument("--json", action="store_true")
    _add_db(h)
    h.set_defaults(func=cmd_history)

    for sp in sub.choices.values():
        applicable = {a.dest for a in sp._actions}
        sp.set_defaults(**{k: v for k, v in (config or {}).items() if k in applicable})
    return p


def _wants_machine_stdout(args):
    return bool(getattr(args, "json", False)) or bool(
        getattr(args, "export", None) and not getattr(args, "export_out", None))


def main(argv=None):
    global _machine_stream
    # --config must be known before the real parser is built, since it supplies defaults.
    pre = argparse.ArgumentParser(add_help=False, allow_abbrev=False)
    pre.add_argument("--config", default=None)
    try:
        cfg = config_mod.load(pre.parse_known_args(argv)[0].config)
    except config_mod.ConfigError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 2
    parser = build_parser(cfg)
    args = parser.parse_args(argv)
    if getattr(args, "json", False) and getattr(args, "export", None) and not getattr(args, "export_out", None):
        parser.error("--json and --export both write to stdout; add --export-out FILE "
                     "to send the export to a file")

    real_stdout = sys.stdout
    if _wants_machine_stdout(args):
        # Keep stdout clean for the payload; human-readable output goes to stderr.
        _machine_stream = real_stdout
        sys.stdout = sys.stderr
    try:
        return args.func(args)
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        return 130
    except BrokenPipeError:
        # Downstream closed the pipe (e.g. `| head`); exit quietly, not with a traceback.
        try:
            os.dup2(os.open(os.devnull, os.O_WRONLY), real_stdout.fileno())
        except (OSError, ValueError):
            pass
        return 0
    except suppress.SuppressionError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 2
    except RuntimeError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    except (OSError, sqlite3.Error) as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    finally:
        sys.stdout = real_stdout
        _machine_stream = None


if __name__ == "__main__":
    sys.exit(main())
