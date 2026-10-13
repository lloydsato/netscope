"""Security checks: sweep hosts for risky ports and, in --deep mode, correlate
what's actually running against known vulnerabilities.

Two levels:

- **Quick** (``check_host`` / ``check_hosts``): the original port-number
  heuristics -- fast, no service interaction beyond a connect scan.
- **Deep** (``deep_check_host`` / ``deep_check_hosts``): fingerprints each open
  port for product+version, correlates against the offline vuln DB, audits TLS
  services, and runs read-only weak/default-auth probes. Everything is emitted
  as unified ``findings`` records so it can be scored, reported, and exported.
"""

from . import portscan, fingerprint, vulndb, tlsaudit, probes, findings as fmod
from .utils import RISKY_PORTS

# Ports we attempt a TLS audit on when found open.
_TLS_PORTS = {443, 8443, 993, 995, 465, 5061, 989, 990, 636}


def check_host(host: str, ports=None, timing=None):
    """Scan one host and annotate any open ports that are considered risky."""
    open_ports = portscan.scan(host, ports=ports, timing=timing)
    for entry in open_ports:
        entry["risk"] = RISKY_PORTS.get(entry["port"])
    findings = [e for e in open_ports if e["risk"]]
    return {
        "host": host,
        "open_ports": open_ports,
        "risky_findings": findings,
    }


def check_hosts(hosts, ports=None, timing=None):
    """Scan multiple hosts (e.g. everything discovery.discover() found)."""
    results = []
    for h in hosts:
        ip = h["ip"] if isinstance(h, dict) else h
        results.append(check_host(ip, ports=ports, timing=timing))
    return results


def deep_check_host(host: str, ports=None, timing=None, do_tls=True, do_probes=True):
    """Full audit of one host -> {host, open_ports, services, findings[]}.

    findings are unified ``findings`` dicts (see netscope.findings).
    """
    open_ports = portscan.scan(host, ports=ports, timing=timing)
    all_findings = []
    services = []

    # 1) Port-number heuristics (kept -- cheap and still useful).
    all_findings += fmod.from_risky_ports(host, open_ports, RISKY_PORTS)

    for entry in open_ports:
        port = entry["port"]
        fp = fingerprint.fingerprint_port(host, port)
        product, version = fp.get("product", ""), fp.get("version", "")
        entry["product"], entry["version"] = product, version
        entry["banner"] = fp.get("banner", "")
        services.append({"port": port, "service": entry["service"],
                         "product": product, "version": version,
                         "banner": fp.get("banner", "")})

        # 2) CVE correlation.
        if product:
            matches = vulndb.match(product, version)
            all_findings += fmod.from_cve_matches(host, port, f"{product} {version}".strip(), matches)
            wd = vulndb.weak_default(product)
            if wd:
                all_findings.append(fmod.make_finding(
                    "weak-default", "high", f"{product} exposed with weak defaults",
                    host=host, port=port, detail=wd, evidence=f"{product} {version}".strip(),
                ))

        # 3) TLS audit on TLS-speaking ports.
        if do_tls and port in _TLS_PORTS:
            try:
                tls = tlsaudit.inspect(host, port)
                if tls.get("ok"):
                    all_findings += fmod.from_tls(host, port, tls.get("findings", []))
            except Exception:
                pass

    # 4) Read-only weak/default-auth probes (SNMP handled separately since it's UDP).
    if do_probes:
        try:
            all_findings += fmod.from_probes(probes.run_all(host, open_ports))
        except Exception:
            pass
        try:
            snmp = probes.check_snmp_default_community(host)
            all_findings += fmod.from_probes(snmp)
        except Exception:
            pass

    all_findings = fmod.dedupe(all_findings)
    return {
        "host": host,
        "open_ports": open_ports,
        "services": services,
        "findings": fmod.sort_findings(all_findings),
        "risk_score": fmod.risk_score(all_findings),
    }


def deep_check_hosts(hosts, ports=None, timing=None):
    results = []
    for h in hosts:
        ip = h["ip"] if isinstance(h, dict) else h
        results.append(deep_check_host(ip, ports=ports, timing=timing))
    return results


def collect_findings(deep_results):
    """Flatten the findings from a list of deep_check results into one list."""
    out = []
    for r in deep_results:
        out.extend(r.get("findings", []))
    return fmod.sort_findings(out)


def summarize(results):
    """Turn check_hosts() output into a short human-readable summary string."""
    lines = []
    total_risky = sum(len(r["risky_findings"]) for r in results)
    lines.append(f"Scanned {len(results)} host(s), found {total_risky} risky finding(s).")
    for r in results:
        if r["risky_findings"]:
            lines.append(f"\n{r['host']}:")
            for f in r["risky_findings"]:
                lines.append(f"  [!] port {f['port']} ({f['service']}) -- {f['risk']}")
    return "\n".join(lines)


def summarize_deep(deep_results):
    """Human-readable summary of a deep audit, grouped by host with risk scores."""
    findings = collect_findings(deep_results)
    counts = fmod.severity_counts(findings)
    lines = [
        f"Audited {len(deep_results)} host(s): {len(findings)} finding(s) "
        f"[critical {counts['critical']}, high {counts['high']}, "
        f"medium {counts['medium']}, low {counts['low']}].",
    ]
    for r in sorted(deep_results, key=lambda r: -r.get("risk_score", 0)):
        if not r.get("findings"):
            continue
        lines.append(f"\n{r['host']}  (risk {r.get('risk_score', 0)}/100):")
        for f in r["findings"]:
            port = f":{f['port']}" if f.get("port") else ""
            refs = f"  {', '.join(f['refs'])}" if f.get("refs") else ""
            lines.append(f"  [{f['severity'].upper():8}] {f['title']}{port}{refs}")
    if len(lines) == 1:
        lines.append("\nNo findings -- nothing risky surfaced in this audit.")
    return "\n".join(lines)
