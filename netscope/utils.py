"""Shared helpers for netscope: subnet detection, port name lookups, output formatting."""

import ipaddress
import math
import socket
import os


def get_default_subnet():
    """Best-effort guess of the local IPv4 subnet in CIDR form, e.g. '192.168.1.0/24'.

    Falls back to None if it can't be determined (e.g. non-Linux or no active interface),
    in which case the caller should ask the user to supply --subnet explicitly.
    """
    try:
        # Connect a UDP socket to a public IP (no packets actually sent) to find
        # which local interface/IP the OS would use for outbound traffic.
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        # Assume a /24 - the common case for home/office LANs.
        net = ipaddress.ip_network(f"{local_ip}/24", strict=False)
        return str(net)
    except Exception:
        return None


def is_ipv6(host) -> bool:
    """True for an IPv6 literal (a ``%zone`` suffix such as ``fe80::1%eth0`` is allowed)."""
    try:
        return ipaddress.ip_address(str(host).split("%", 1)[0]).version == 6
    except ValueError:
        return False


def family_for(host) -> int:
    """Socket address family for an already-resolved IP string."""
    return socket.AF_INET6 if is_ipv6(host) else socket.AF_INET


def host_header(host) -> str:
    """Value for an HTTP ``Host:`` header: IPv6 literals need brackets."""
    host = str(host)
    return f"[{host}]" if is_ipv6(host) and not host.startswith("[") else host


def is_root():
    try:
        return os.geteuid() == 0
    except AttributeError:
        # Windows has no geteuid; scapy there needs Npcap + admin shell instead.
        return None


# A small curated map of commonly-seen ports to service names, used for readable
# scan output. Not exhaustive -- unknown ports just show as "unknown".
COMMON_PORTS = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    67: "dhcp", 68: "dhcp", 80: "http", 110: "pop3", 111: "rpcbind",
    123: "ntp", 135: "msrpc", 139: "netbios-ssn", 143: "imap",
    161: "snmp", 389: "ldap", 443: "https", 445: "smb",
    465: "smtps", 514: "syslog", 587: "smtp-submission",
    631: "ipp", 993: "imaps", 995: "pop3s", 1433: "mssql",
    1521: "oracle", 1723: "pptp", 2049: "nfs", 3000: "dev-http",
    3306: "mysql", 3389: "rdp", 5060: "sip", 5432: "postgres",
    5900: "vnc", 6379: "redis", 8000: "dev-http", 8080: "http-alt",
    8443: "https-alt", 9200: "elasticsearch", 27017: "mongodb",
    # UDP-common services (port_name is used for both protocols)
    69: "tftp", 137: "netbios-ns", 138: "netbios-dgm", 162: "snmp-trap",
    500: "isakmp", 520: "rip", 1900: "ssdp", 5353: "mdns",
}

# Common UDP service ports worth probing in a UDP sweep. UDP scanning is far
# less reliable than TCP (no connection handshake), so we keep the default set
# small and probe each with a service-appropriate payload where we can.
COMMON_UDP_PORTS = sorted({
    53, 67, 68, 69, 123, 137, 138, 161, 162, 500, 514, 520, 1900, 5353,
})

# Scan timing profiles (loosely inspired by nmap's -T templates). Each maps a
# level 0..5 to concrete knobs: connect timeout, worker count, and per-probe
# jitter range (seconds). Lower = slower/stealthier, higher = faster/louder.
TIMING_PROFILES = {
    0: {"timeout": 4.0, "workers": 4, "jitter": (0.4, 1.2)},   # paranoid
    1: {"timeout": 3.0, "workers": 8, "jitter": (0.1, 0.5)},   # sneaky
    2: {"timeout": 2.0, "workers": 20, "jitter": (0.0, 0.15)}, # polite
    3: {"timeout": 0.75, "workers": 100, "jitter": (0.0, 0.0)},# normal (default)
    4: {"timeout": 0.5, "workers": 200, "jitter": (0.0, 0.0)}, # aggressive
    5: {"timeout": 0.3, "workers": 400, "jitter": (0.0, 0.0)}, # insane
}
DEFAULT_TIMING = 3


def timing_profile(level):
    """Return the knobs for a timing level, clamped to the valid range."""
    if level is None:
        level = DEFAULT_TIMING
    level = max(0, min(5, int(level)))
    return {"level": level, **TIMING_PROFILES[level]}


def shannon_entropy(s: str) -> float:
    """Shannon entropy (bits/char) of a string. Used to flag high-entropy DNS
    labels, a hallmark of DNS tunnelling / DGA domains.
    """
    if not s:
        return 0.0
    counts = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


# Ports that are worth flagging by default in security checks -- either because
# they're historically insecure (plaintext creds) or commonly targeted.
RISKY_PORTS = {
    21: "FTP transmits credentials in plaintext",
    23: "Telnet transmits everything in plaintext, including passwords",
    111: "rpcbind can leak info about running RPC services",
    139: "NetBIOS -- legacy SMB, associated with worms/lateral movement",
    445: "SMB -- frequent target (EternalBlue, ransomware propagation)",
    1433: "MSSQL exposed to the network -- should usually be firewalled",
    1723: "PPTP VPN -- protocol has known cryptographic weaknesses",
    3306: "MySQL exposed to the network -- should usually be firewalled",
    3389: "RDP -- frequent brute-force/ransomware entry point if internet-facing",
    5432: "Postgres exposed to the network -- should usually be firewalled",
    5900: "VNC -- often run with weak or no authentication",
    6379: "Redis -- historically shipped with no auth by default",
    27017: "MongoDB -- historically shipped with no auth by default",
}


def safe_text(value, limit: int = 253) -> str:
    """Make attacker-controlled text (DNS names, SNI, banners) safe to print.

    Anything outside printable ASCII -- notably ESC and other control bytes that
    a hostile host on the LAN could embed to rewrite an analyst's terminal -- is
    replaced with '?'. Truncated to ``limit`` characters.
    """
    text = str(value if value is not None else "")
    return "".join(ch if " " <= ch <= "~" else "?" for ch in text)[:limit]


def port_name(port: int) -> str:
    return COMMON_PORTS.get(port, "unknown")


def fmt_table(rows, headers):
    """Minimal dependency-free table formatter for terminal output."""
    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(str(cell)))
    def fmt_row(row):
        return "  ".join(str(c).ljust(widths[i]) for i, c in enumerate(row))
    lines = [fmt_row(headers), "  ".join("-" * w for w in widths)]
    lines += [fmt_row(r) for r in rows]
    return "\n".join(lines)
