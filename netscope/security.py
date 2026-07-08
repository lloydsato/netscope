"""Security checks: sweep discovered/given hosts for risky open ports."""

from . import portscan
from .utils import RISKY_PORTS


def check_host(host: str, ports=None):
    """Scan one host and annotate any open ports that are considered risky."""
    open_ports = portscan.scan(host, ports=ports)
    for entry in open_ports:
        entry["risk"] = RISKY_PORTS.get(entry["port"])
    findings = [e for e in open_ports if e["risk"]]
    return {
        "host": host,
        "open_ports": open_ports,
        "risky_findings": findings,
    }


def check_hosts(hosts, ports=None, max_workers_hint=None):
    """Scan multiple hosts (e.g. everything discovery.discover() found)."""
    results = []
    for h in hosts:
        ip = h["ip"] if isinstance(h, dict) else h
        results.append(check_host(ip, ports=ports))
    return results


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
