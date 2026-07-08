"""Service fingerprinting: grab banners from open ports and make a light-touch
guess at the software/OS behind them.

This is standard defensive inventory (what `nmap -sV` does, kept lightweight):
we connect to a port and read whatever the service volunteers, or send a
minimal HTTP request and read the Server header. No exploitation, just reading
what a service already announces about itself.
"""

import socket
import re

from .utils import port_name

# Ports where the server sends a banner immediately on connect.
_SERVER_SPEAKS_FIRST = {21, 22, 23, 25, 110, 143, 587, 3306, 5432, 6379}
# Ports we should send a small HTTP request to.
_HTTP_PORTS = {80, 8000, 8080, 8443, 443, 3000, 9200}


def _clean(data: bytes, limit: int = 200) -> str:
    text = data.decode("latin-1", "replace")
    text = "".join(ch for ch in text if ch.isprintable() or ch in " \t")
    return text.strip()[:limit]


def _grab_generic(host: str, port: int, timeout: float) -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((host, port))
            data = s.recv(256)
            return _clean(data)
    except OSError:
        return ""


def _grab_http(host: str, port: int, timeout: float) -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((host, port))
            req = f"HEAD / HTTP/1.0\r\nHost: {host}\r\nUser-Agent: netscope\r\n\r\n"
            s.sendall(req.encode())
            data = s.recv(1024)
        text = data.decode("latin-1", "replace")
        # Pull out the Server: header if present, else the status line.
        m = re.search(r"(?im)^server:\s*(.+)$", text)
        if m:
            return "Server: " + m.group(1).strip()[:120]
        first_line = text.splitlines()[0] if text.splitlines() else ""
        return first_line.strip()[:120]
    except (OSError, IndexError):
        return ""


# Rough OS / product inference from banner substrings. Purely heuristic hints.
_OS_HINTS = [
    (re.compile(r"ubuntu", re.I), "Linux (Ubuntu)"),
    (re.compile(r"debian", re.I), "Linux (Debian)"),
    (re.compile(r"raspbian", re.I), "Linux (Raspberry Pi OS)"),
    (re.compile(r"centos|red hat|rhel", re.I), "Linux (RHEL/CentOS)"),
    (re.compile(r"win(dows|32|64)|microsoft", re.I), "Windows"),
    (re.compile(r"freebsd", re.I), "FreeBSD"),
    (re.compile(r"mikrotik|routeros", re.I), "MikroTik RouterOS"),
    (re.compile(r"openwrt", re.I), "OpenWrt (router)"),
    (re.compile(r"dropbear", re.I), "embedded device (Dropbear SSH)"),
    (re.compile(r"cisco", re.I), "Cisco device"),
]


def _infer(banner: str) -> str:
    for pat, label in _OS_HINTS:
        if pat.search(banner):
            return label
    return ""


def fingerprint_port(host: str, port: int, timeout: float = 2.0) -> dict:
    if port in _HTTP_PORTS:
        banner = _grab_http(host, port, timeout)
    elif port in _SERVER_SPEAKS_FIRST:
        banner = _grab_generic(host, port, timeout)
    else:
        # Try a passive read anyway; many services still greet us.
        banner = _grab_generic(host, port, timeout)

    return {
        "port": port,
        "service": port_name(port),
        "banner": banner,
        "os_hint": _infer(banner),
    }


def fingerprint_host(host: str, open_ports, timeout: float = 2.0):
    """Fingerprint a list of open ports (ints or {'port':...} dicts) on a host.

    Returns {ports: [...], os_guess: str}. os_guess is the most common non-empty
    OS hint across banners, if any.
    """
    ports = [p["port"] if isinstance(p, dict) else p for p in open_ports]
    results = [fingerprint_port(host, p, timeout) for p in ports]

    hints = [r["os_hint"] for r in results if r["os_hint"]]
    os_guess = ""
    if hints:
        # pick the most frequent hint
        os_guess = max(set(hints), key=hints.count)

    return {"host": host, "ports": results, "os_guess": os_guess}
