"""Device discovery: find live hosts on the local subnet via ARP requests.

ARP scanning is the standard, fast way to enumerate devices on your own LAN
segment (it's what tools like arp-scan and the netdiscover do). It only works
for hosts on the same broadcast domain, and needs raw socket access, hence
root/administrator privileges.
"""

import errno
import socket
import ipaddress
import concurrent.futures

from .utils import get_default_subnet, is_root

# A TCP connect answered with RST proves the host is up just as much as a
# completed handshake does. (Windows reports it as WSAECONNREFUSED.)
_ALIVE_ERRNOS = {0, errno.ECONNREFUSED, getattr(errno, "WSAECONNREFUSED", errno.ECONNREFUSED)}

# Refuse absurd sweeps (a /8 is 16M hosts) instead of queueing them all.
MAX_SWEEP_ADDRESSES = 65536


def parse_subnet(subnet: str):
    """Validate a user-supplied CIDR -> ipaddress.IPv4Network.

    Raises RuntimeError (the CLI's user-facing error type) for malformed input,
    IPv6 (discovery is IPv4-only), or a network too large to sweep sensibly.
    """
    try:
        net = ipaddress.ip_network(str(subnet).strip(), strict=False)
    except ValueError as e:
        raise RuntimeError(f"Invalid subnet {subnet!r}: {e}. Use CIDR, e.g. 192.168.1.0/24") from None
    if net.version != 4:
        raise RuntimeError(f"Invalid subnet {subnet!r}: only IPv4 subnets are supported")
    if net.num_addresses > MAX_SWEEP_ADDRESSES:
        raise RuntimeError(
            f"Subnet {net} has {net.num_addresses:,} addresses; refusing to scan more than "
            f"{MAX_SWEEP_ADDRESSES:,} (a /16). Pass a smaller range."
        )
    return net


def arp_scan(subnet: str, timeout: float = 2.0):
    """ARP-scan `subnet` (CIDR string). Returns list of dicts: {ip, mac, vendor}.

    Requires scapy + root/admin. Raises RuntimeError with a clear message if
    permissions are insufficient rather than failing with a cryptic traceback.
    """
    try:
        from scapy.all import ARP, Ether, srp
    except ImportError as e:
        raise RuntimeError(
            "scapy is required for ARP scanning. Install with: pip install scapy"
        ) from e

    if is_root() is False:
        raise RuntimeError(
            "ARP scanning needs raw socket access. Re-run with sudo (Linux/macOS) "
            "or as Administrator (Windows, with Npcap installed)."
        )

    net = parse_subnet(subnet)
    arp = ARP(pdst=str(net))
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp

    result = srp(packet, timeout=timeout, verbose=False)[0]

    hosts, seen = [], set()
    for sent, received in result:
        key = (received.psrc, received.hwsrc)
        if key in seen:                      # a host (or proxy-ARP router) can answer twice
            continue
        seen.add(key)
        hosts.append({"ip": received.psrc, "mac": received.hwsrc})

    hosts.sort(key=lambda h: (ipaddress.ip_address(h["ip"]), h["mac"]))
    return hosts


def ping_sweep(subnet: str, max_workers: int = 64, timeout: float = 0.5):
    """Fallback host discovery using TCP connect probes instead of ICMP/ARP.

    Doesn't need root. Less reliable than ARP (misses hosts that silently drop
    every probe) but works everywhere, useful when scapy/root isn't available.
    Probes a handful of common ports per host; a host counts as up if any probe
    connects *or is actively refused* (RST) -- a live host with those ports
    closed answers immediately and would otherwise be missed.
    """
    net = parse_subnet(subnet)
    probe_ports = [80, 443, 22, 445, 139, 3389]

    def probe(ip):
        ip = str(ip)
        for port in probe_ports:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(timeout)
                    if s.connect_ex((ip, port)) in _ALIVE_ERRNOS:
                        return {"ip": ip, "mac": None}
            except OSError:
                continue
        return None

    hosts = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
        for result in ex.map(probe, net.hosts()):
            if result:
                hosts.append(result)

    hosts.sort(key=lambda h: ipaddress.ip_address(h["ip"]))
    return hosts


def discover(subnet: str = None, method: str = "auto"):
    """High-level entry point. Picks ARP if possible, falls back to ping sweep.

    method: "auto" | "arp" | "sweep"
    """
    if method not in ("auto", "arp", "sweep"):
        raise ValueError(f"unknown discovery method {method!r} (use auto, arp or sweep)")
    subnet = subnet or get_default_subnet()
    if not subnet:
        raise RuntimeError(
            "Could not auto-detect your subnet. Pass one explicitly, e.g. --subnet 192.168.1.0/24"
        )
    subnet = str(parse_subnet(subnet))

    if method == "sweep":
        return subnet, ping_sweep(subnet), "sweep"

    if method in ("auto", "arp"):
        try:
            return subnet, arp_scan(subnet), "arp"
        except RuntimeError:
            if method == "arp":
                raise
            # auto mode: fall back quietly
            return subnet, ping_sweep(subnet), "sweep"
