"""Device discovery: find live hosts on the local subnet via ARP requests.

ARP scanning is the standard, fast way to enumerate devices on your own LAN
segment (it's what tools like arp-scan and the netdiscover do). It only works
for hosts on the same broadcast domain, and needs raw socket access, hence
root/administrator privileges.
"""

import socket
import ipaddress
import concurrent.futures

from .utils import get_default_subnet, is_root


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

    arp = ARP(pdst=subnet)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp

    result = srp(packet, timeout=timeout, verbose=False)[0]

    hosts = []
    for sent, received in result:
        hosts.append({"ip": received.psrc, "mac": received.hwsrc})

    hosts.sort(key=lambda h: ipaddress.ip_address(h["ip"]))
    return hosts


def ping_sweep(subnet: str, max_workers: int = 64, timeout: float = 0.5):
    """Fallback host discovery using TCP connect probes instead of ICMP/ARP.

    Doesn't need root. Less reliable than ARP (misses hosts with all common
    ports firewalled) but works everywhere, useful when scapy/root isn't
    available. Probes a handful of near-universally-open ports per host.
    """
    net = ipaddress.ip_network(subnet, strict=False)
    probe_ports = [80, 443, 22, 445, 139, 3389]

    def probe(ip):
        ip = str(ip)
        for port in probe_ports:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(timeout)
                    if s.connect_ex((ip, port)) == 0:
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
    subnet = subnet or get_default_subnet()
    if not subnet:
        raise RuntimeError(
            "Could not auto-detect your subnet. Pass one explicitly, e.g. --subnet 192.168.1.0/24"
        )

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
