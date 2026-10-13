"""TCP (and best-effort UDP) port scanning.

TCP uses a full connect() scan (not a raw SYN scan) so it needs no special
privileges and works identically on every OS -- the tradeoff is it's a bit
slower and slightly more visible to the target than a SYN scan.

UDP scanning is inherently unreliable (there's no handshake). We send a
service-appropriate probe and interpret the OS's response: on most systems a
connected UDP socket surfaces an ICMP port-unreachable as ConnectionRefusedError
(=> closed), an application reply means open, and silence means open|filtered.

A timing level (0..5, nmap-style) tunes connect timeout, concurrency, and
per-probe jitter -- useful for slower/stealthier or faster/louder sweeps.
"""

import random
import socket
import time
import concurrent.futures

from .utils import port_name, timing_profile, COMMON_UDP_PORTS

COMMON_SCAN_PORTS = sorted({
    21, 22, 23, 25, 53, 67, 68, 80, 110, 111, 123, 135, 139, 143, 161,
    389, 443, 445, 465, 514, 587, 631, 993, 995, 1433, 1521, 1723,
    2049, 3000, 3306, 3389, 5060, 5432, 5900, 6379, 8000, 8080, 8443,
    9200, 27017,
})

# Service-specific UDP probes: a payload likely to elicit a reply from a real
# service on that port. Empty bytes = just an empty datagram.
_UDP_PROBES = {
    53: b"\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00",  # minimal DNS
    123: b"\x1b" + 47 * b"\0",                                # NTP client req
    161: (  # SNMPv1 get sysDescr.0, community "public"
        b"\x30\x26\x02\x01\x00\x04\x06public\xa0\x19\x02\x01\x01\x02\x01"
        b"\x00\x02\x01\x00\x30\x0e\x30\x0c\x06\x08\x2b\x06\x01\x02\x01"
        b"\x01\x01\x00\x05\x00"
    ),
    137: b"\x80\xf0\x00\x10\x00\x01\x00\x00\x00\x00\x00\x00\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00\x00\x21\x00\x01",
    5353: b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x09_services\x07_dns-sd\x04_udp\x05local\x00\x00\x0c\x00\x01",
}


def _clean_ports(ports):
    """Validate and de-duplicate a port collection (order preserved).

    Raises ValueError for anything outside 1-65535 or not an integer; without
    this an out-of-range port makes ``connect_ex`` raise OverflowError (not an
    OSError) from a worker thread and abort the whole scan.
    """
    out, seen = [], set()
    for p in ports:
        if isinstance(p, bool) or not isinstance(p, int):
            raise ValueError(f"invalid port {p!r}: ports must be integers")
        if not 1 <= p <= 65535:
            raise ValueError(f"invalid port {p}: must be between 1 and 65535")
        if p not in seen:
            seen.add(p)
            out.append(p)
    return out


def _resolve(host: str) -> str:
    """Resolve once up front (clear error) so workers don't each do a DNS lookup."""
    try:
        return socket.gethostbyname(host)
    except (socket.gaierror, UnicodeError) as e:
        raise RuntimeError(f"Could not resolve host '{host}': {e}") from e


def scan_port(host: str, port: int, timeout: float = 0.75):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            if s.connect_ex((host, port)) == 0:
                return port
    except (OSError, OverflowError):
        pass
    return None


def scan(host: str, ports=None, max_workers: int = None, timeout: float = None,
         timing: int = None):
    """Scan `host` over `ports` (defaults to COMMON_SCAN_PORTS, or pass range(1,1025)
    for a full well-known-port sweep). Returns sorted list of {port, service} dicts
    for ports found open.

    `timing` (0..5) sets connect timeout / concurrency / jitter; explicit
    `max_workers` / `timeout` override the profile.
    """
    ports = _clean_ports(ports if ports is not None else COMMON_SCAN_PORTS)
    prof = timing_profile(timing)
    timeout = prof["timeout"] if timeout is None else timeout
    max_workers = prof["workers"] if max_workers is None else max_workers
    jitter = prof["jitter"]

    ip = _resolve(host)
    if not ports:
        return []

    # Randomise port order so a scan is less obviously sequential.
    random.shuffle(ports)

    def probe(p):
        lo, hi = jitter
        if hi > 0:
            time.sleep(random.uniform(lo, hi))
        return scan_port(ip, p, timeout)

    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {ex.submit(probe, p): p for p in ports}
        for fut in concurrent.futures.as_completed(futures):
            port = fut.result()
            if port is not None:
                open_ports.append(port)

    open_ports.sort()
    return [{"port": p, "service": port_name(p)} for p in open_ports]


def scan_udp_port(host: str, port: int, timeout: float = 1.5):
    """Probe a single UDP port. Returns 'open', 'closed', or 'open|filtered'."""
    probe = _UDP_PROBES.get(port, b"\x00")
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.connect((host, port))          # so ICMP errors come back to us
            s.send(probe)
            try:
                s.recv(1024)
                # Any application-layer reply (even an empty datagram) means the
                # port is definitively open.
                return "open"
            except socket.timeout:
                # No reply and no ICMP error -> can't tell if open or filtered.
                return "open|filtered"
            except ConnectionRefusedError:
                # ICMP port-unreachable delivered as ECONNREFUSED -> closed.
                return "closed"
    except (OSError, OverflowError):
        return "open|filtered"


def scan_udp(host: str, ports=None, max_workers: int = 50, timeout: float = 1.5):
    """UDP sweep. Returns sorted list of {port, service, state} for ports that
    are 'open' or 'open|filtered' (closed ports are omitted).
    """
    ports = _clean_ports(ports if ports is not None else COMMON_UDP_PORTS)
    ip = _resolve(host)
    if not ports:
        return []

    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {ex.submit(scan_udp_port, ip, p, timeout): p for p in ports}
        for fut in concurrent.futures.as_completed(futures):
            port = futures[fut]
            state = fut.result()
            if state != "closed":
                results.append({"port": port, "service": port_name(port), "state": state})

    results.sort(key=lambda r: r["port"])
    return results
