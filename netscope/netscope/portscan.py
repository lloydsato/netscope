"""TCP port scanning: simple threaded connect() scan.

Uses a full TCP connect (not a raw SYN scan) so it needs no special
privileges and works identically on every OS -- the tradeoff is it's a bit
slower and slightly more visible to the target than a SYN scan.
"""

import socket
import concurrent.futures

from .utils import port_name

COMMON_SCAN_PORTS = sorted({
    21, 22, 23, 25, 53, 67, 68, 80, 110, 111, 123, 135, 139, 143, 161,
    389, 443, 445, 465, 514, 587, 631, 993, 995, 1433, 1521, 1723,
    2049, 3000, 3306, 3389, 5060, 5432, 5900, 6379, 8000, 8080, 8443,
    9200, 27017,
})


def scan_port(host: str, port: int, timeout: float = 0.75):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            if s.connect_ex((host, port)) == 0:
                return port
    except OSError:
        pass
    return None


def scan(host: str, ports=None, max_workers: int = 100, timeout: float = 0.75):
    """Scan `host` over `ports` (defaults to COMMON_SCAN_PORTS, or pass range(1,1025)
    for a full well-known-port sweep). Returns sorted list of {port, service} dicts
    for ports found open.
    """
    ports = ports if ports is not None else COMMON_SCAN_PORTS
    # Resolve hostname once up front so errors are clear.
    try:
        socket.gethostbyname(host)
    except socket.gaierror as e:
        raise RuntimeError(f"Could not resolve host '{host}': {e}") from e

    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {ex.submit(scan_port, host, p, timeout): p for p in ports}
        for fut in concurrent.futures.as_completed(futures):
            port = fut.result()
            if port is not None:
                open_ports.append(port)

    open_ports.sort()
    return [{"port": p, "service": port_name(p)} for p in open_ports]
