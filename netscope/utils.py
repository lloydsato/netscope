"""Shared helpers for netscope: subnet detection, port name lookups, output formatting."""

import ipaddress
import socket
import struct
import fcntl
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
}

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
