"""Passive threat-detection heuristics applied to captured traffic.

These are *detection* routines for spotting attacks against your own network
(the defensive side): ARP-spoofing / man-in-the-middle attempts, rogue DHCP
servers, port-scan activity, and use of insecure plaintext protocols. Nothing
here performs an attack -- it only interprets what was already seen on the wire.

Design note on plaintext detection: netscope flags *that* an insecure protocol
or cleartext credential exchange is happening and between which hosts, so you
can go fix the exposure. It deliberately does not decode or print the actual
credential values -- the goal is to surface risk, not to harvest secrets.
"""


def detect_arp_spoofing(ip_to_macs, gateway_ip=None):
    """ip_to_macs: {ip: set(mac,...)}. An IP claimed by 2+ MACs during the
    window is the classic ARP-spoofing / MITM signature.
    """
    findings = []
    for ip, macs in ip_to_macs.items():
        if len(macs) >= 2:
            sev = "critical" if (gateway_ip and ip == gateway_ip) else "high"
            findings.append({
                "ip": ip,
                "macs": sorted(macs),
                "severity": sev,
                "note": (
                    "Gateway IP is claimed by multiple MACs -- strong sign of an "
                    "active MITM/ARP-spoofing attack."
                    if sev == "critical"
                    else "IP is claimed by multiple MACs -- possible ARP spoofing "
                         "or an IP conflict."
                ),
            })
    findings.sort(key=lambda f: 0 if f["severity"] == "critical" else 1)
    return findings


def detect_rogue_dhcp(dhcp_servers, expected_gateway=None):
    """dhcp_servers: {server_ip: mac}. More than one DHCP server, or a server
    that isn't your gateway, may indicate a rogue DHCP server (used to redirect
    traffic). Reports when there's ambiguity worth a human look.
    """
    findings = []
    servers = list(dhcp_servers.keys())
    if len(servers) > 1:
        findings.append({
            "servers": servers,
            "severity": "high",
            "note": "Multiple DHCP servers seen on the LAN -- one may be rogue.",
        })
    if expected_gateway:
        for s in servers:
            if s != expected_gateway:
                findings.append({
                    "servers": [s],
                    "severity": "medium",
                    "note": f"DHCP offers seen from {s}, which is not the expected gateway {expected_gateway}.",
                })
    return findings


def detect_beaconing(conn_times, min_events=6, max_cv=0.25):
    """Spot regular, machine-like beaconing (a hallmark of C2 / malware check-ins).

    conn_times: {(src, dst, dport): [epoch_seconds, ...]}. For each pair with at
    least ``min_events`` connections, we look at the gaps between successive
    connections. Human/browser traffic is bursty and irregular; an automated
    beacon fires on a near-constant interval, so a low coefficient of variation
    (stddev/mean) of the gaps is the signal.
    """
    findings = []
    for (src, dst, dport), times in conn_times.items():
        times = sorted(times)
        if len(times) < min_events:
            continue
        gaps = [t2 - t1 for t1, t2 in zip(times, times[1:]) if t2 > t1]
        if len(gaps) < min_events - 1:
            continue
        mean = sum(gaps) / len(gaps)
        if mean <= 0:
            continue
        var = sum((g - mean) ** 2 for g in gaps) / len(gaps)
        cv = (var ** 0.5) / mean
        if cv <= max_cv:
            findings.append({
                "src": src, "dst": dst, "dport": dport,
                "count": len(times), "interval": round(mean, 1),
                "cv": round(cv, 3), "severity": "high",
                "note": (f"{src} contacted {dst}:{dport} {len(times)} times at a "
                         f"near-constant ~{mean:.0f}s interval -- possible C2 beaconing."),
            })
    findings.sort(key=lambda f: f["cv"])
    return findings


def detect_dns_tunneling(dns_stats, min_queries=20, entropy_threshold=3.6,
                         long_label=40):
    """Flag DNS traffic patterns consistent with tunnelling / exfiltration.

    dns_stats: {parent_domain: {"count": int, "labels": [longest-subdomain-label,
    ...], "max_entropy": float, "unique": int, "txt": int}}. Tunnels encode data
    in long, high-entropy subdomain labels and generate an unusual volume of
    unique subdomains (often TXT/NULL) under one parent.
    """
    findings = []
    for parent, st in dns_stats.items():
        count = st.get("count", 0)
        unique = st.get("unique", 0)
        max_len = max((len(l) for l in st.get("labels", [])), default=0)
        max_ent = st.get("max_entropy", 0.0)
        reasons = []
        if count >= min_queries and unique >= min_queries:
            reasons.append(f"{unique} unique subdomains")
        if max_len >= long_label:
            reasons.append(f"{max_len}-char label")
        if max_ent >= entropy_threshold:
            reasons.append(f"entropy {max_ent:.1f}")
        if st.get("txt", 0) >= min_queries:
            reasons.append(f"{st['txt']} TXT queries")
        # Require at least two independent signals to cut false positives from
        # legitimately busy domains (CDNs, telemetry).
        if len(reasons) >= 2:
            findings.append({
                "domain": parent, "count": count, "unique": unique,
                "max_label": max_len, "max_entropy": round(max_ent, 2),
                "severity": "high",
                "note": (f"DNS to *.{parent} looks like tunnelling/exfiltration "
                         f"({', '.join(reasons)})."),
            })
    findings.sort(key=lambda f: -f["unique"])
    return findings


def summarize_findings(analysis):
    """Roll the various detection outputs into a single ordered alert list."""
    alerts = []
    for f in analysis.get("arp_anomalies", []):
        alerts.append((f["severity"], f"ARP: {f['ip']} claimed by {', '.join(f['macs'])} -- {f['note']}"))
    for f in analysis.get("dhcp_findings", []):
        alerts.append((f["severity"], f"DHCP: {f['note']} ({', '.join(f['servers'])})"))
    for s in analysis.get("possible_scanners", []):
        alerts.append(("high", f"SCAN: {s['ip']} sent {s['syn_count']} half-open SYNs -- likely port scanning"))
    for b in analysis.get("beaconing", []):
        alerts.append((b["severity"], f"BEACON: {b['note']}"))
    for d in analysis.get("dns_tunneling", []):
        alerts.append((d["severity"], f"DNS-TUNNEL: {d['note']}"))
    for p in analysis.get("insecure_protocols", []):
        alerts.append(("medium", f"PLAINTEXT: {p['proto']} between {p['src']} -> {p['dst']} -- credentials/data exposed in the clear"))

    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    alerts.sort(key=lambda a: order.get(a[0], 9))
    return alerts
