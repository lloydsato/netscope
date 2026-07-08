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


def summarize_findings(analysis):
    """Roll the various detection outputs into a single ordered alert list."""
    alerts = []
    for f in analysis.get("arp_anomalies", []):
        alerts.append((f["severity"], f"ARP: {f['ip']} claimed by {', '.join(f['macs'])} -- {f['note']}"))
    for f in analysis.get("dhcp_findings", []):
        alerts.append((f["severity"], f"DHCP: {f['note']} ({', '.join(f['servers'])})"))
    for s in analysis.get("possible_scanners", []):
        alerts.append(("high", f"SCAN: {s['ip']} sent {s['syn_count']} half-open SYNs -- likely port scanning"))
    for p in analysis.get("insecure_protocols", []):
        alerts.append(("medium", f"PLAINTEXT: {p['proto']} between {p['src']} -> {p['dst']} -- credentials/data exposed in the clear"))

    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    alerts.sort(key=lambda a: order.get(a[0], 9))
    return alerts
