"""Service fingerprinting: grab banners from open ports and make a light-touch
guess at the software/OS behind them.

This is standard defensive inventory (what `nmap -sV` does, kept lightweight):
we connect to a port and read whatever the service volunteers, or send a
minimal HTTP request and read the Server header. No exploitation, just reading
what a service already announces about itself.
"""

import socket
import ssl
import re

from .utils import port_name, family_for, host_header

# Ports where the server sends a banner immediately on connect.
_SERVER_SPEAKS_FIRST = {21, 22, 23, 25, 110, 143, 587, 3306, 5432}
# Ports we should send a small HTTP request to.
_HTTP_PORTS = {80, 8000, 8080, 8443, 443, 3000, 9200}
# HTTP ports that normally speak TLS (we try a TLS handshake first on these).
_HTTPS_FIRST_PORTS = {443, 8443}
# Elasticsearch reports its version in the JSON body of GET /, not in headers.
_BODY_PORTS = {9200}
_REDIS_PORTS = {6379}
_MAX_HTTP_READ = 4096


def _clean(data: bytes, limit: int = 200) -> str:
    """Printable-ASCII view of a banner. CR/LF/TAB become single spaces so that
    multi-line banners stay tokenised (``version:6.0.9 next_key``) rather than
    having their lines glued together; all other control bytes are dropped.
    """
    text = data.decode("latin-1", "replace")
    text = text.replace("\r", " ").replace("\n", " ").replace("\t", " ")
    text = "".join(ch for ch in text if ch.isprintable())
    return " ".join(text.split())[:limit]


def _grab_generic(host: str, port: int, timeout: float) -> str:
    try:
        with socket.socket(family_for(host), socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((host, port))
            data = s.recv(256)
            return _clean(data)
    except OSError:
        return ""


def _read_http(sock, want_body: bool) -> bytes:
    """Read an HTTP/1.0 response (the server closes when done). Stops at the end
    of the headers unless ``want_body``, or at a size cap -- a single recv()
    can return just part of the headers if they span TCP segments.
    """
    data = b""
    while len(data) < _MAX_HTTP_READ:
        try:
            chunk = sock.recv(1024)
        except (socket.timeout, ssl.SSLError):
            break
        if not chunk:
            break
        data += chunk
        if not want_body and b"\r\n\r\n" in data:
            break
    return data


def _grab_http(host: str, port: int, timeout: float, tls: bool = False,
               want_body: bool = False) -> str:
    """Fetch the Server header (or status line) of an HTTP(S) service. With
    ``want_body``, issue GET and append a short excerpt of the body."""
    method = "GET" if want_body else "HEAD"
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            raw.settimeout(timeout)
            sock = raw
            if tls:
                sock = _permissive_tls_context().wrap_socket(raw, server_hostname=host)
            with sock:
                req = f"{method} / HTTP/1.0\r\nHost: {host_header(host)}\r\nUser-Agent: netscope\r\n\r\n"
                sock.sendall(req.encode())
                data = _read_http(sock, want_body)
    except (OSError, ssl.SSLError):
        return ""
    head, _, body = data.partition(b"\r\n\r\n")
    text = head.decode("latin-1", "replace")
    # Pull out the Server: header if present, else the status line.
    m = re.search(r"(?im)^server:[ \t]*(.+)$", text)
    if m:
        banner = "Server: " + _clean(m.group(1).encode("latin-1", "replace"), 120)
    else:
        banner = _clean(text.splitlines()[0].encode("latin-1", "replace"), 120) if text.strip() else ""
    if want_body and body:
        banner = (banner + " " + _clean(body, 600)).strip()
    return banner


def _permissive_tls_context():
    """A client context that accepts any certificate/protocol: we are inventorying
    what a service says about itself, not trusting it (see tlsaudit for audits)."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED
        ctx.set_ciphers("ALL:@SECLEVEL=0")
    except (ssl.SSLError, ValueError, AttributeError):
        pass
    return ctx


def _grab_redis(host: str, port: int, timeout: float) -> str:
    """Ask Redis for ``INFO server`` (read-only). A server that requires auth
    answers ``-NOAUTH`` and we learn nothing -- which is the right outcome."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall(b"INFO server\r\n")
            return _clean(s.recv(2048), 400)
    except OSError:
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


# Product + version extraction from banners, the way `nmap -sV` reports
# ``product`` / ``version``. Each entry maps a regex (with a version capture
# group) to a canonical product name used to key the offline vuln database.
# Order matters: more specific patterns should come first.
_PRODUCT_SIGS = [
    (re.compile(r"OpenSSH_for_Windows_([0-9][\w.]*)", re.I), "openssh"),
    (re.compile(r"OpenSSH[_/ ]([0-9][\w.]*)", re.I), "openssh"),
    (re.compile(r"\bnginx/([0-9][\w.]*)", re.I), "nginx"),
    (re.compile(r"Apache/([0-9][\w.]*)", re.I), "apache_http_server"),
    (re.compile(r"lighttpd/([0-9][\w.]*)", re.I), "lighttpd"),
    (re.compile(r"Microsoft-IIS/([0-9][\w.]*)", re.I), "iis"),
    (re.compile(r"vsftpd\s*([0-9][\w.]*)", re.I), "vsftpd"),
    (re.compile(r"ProFTPD\s*([0-9][\w.]*)", re.I), "proftpd"),
    (re.compile(r"Pure-FTPd", re.I), "pure-ftpd"),
    (re.compile(r"\(?Exim\)?\s*([0-9][\w.]*)", re.I), "exim"),
    (re.compile(r"Postfix", re.I), "postfix"),
    (re.compile(r"Dovecot", re.I), "dovecot"),
    (re.compile(r"\b(?:mysql|mariadb)[- ]?([0-9][\w.]*)", re.I), "mysql"),
    (re.compile(r"PostgreSQL\s*([0-9][\w.]*)", re.I), "postgresql"),
    (re.compile(r"redis_version:([0-9][\w.]*)", re.I), "redis"),
    (re.compile(r"MongoDB[^0-9]*([0-9][\w.]*)", re.I), "mongodb"),
    # Only trust a bare JSON "number" key when the body is recognisably Elasticsearch.
    (re.compile(r'"number"\s*:\s*"([0-9][\w.]*)"', re.I), "elasticsearch",
     re.compile(r"lucene_version|You Know, for Search", re.I)),
    (re.compile(r"RouterOS\s*v?([0-9][\w.]*)", re.I), "routeros"),
    # MikroTik FTP/telnet banners: "(MikroTik 6.40.5)" / "MikroTik v6.40.5"
    (re.compile(r"MikroTik\s+v?([0-9][\w.]*)", re.I), "routeros"),
    (re.compile(r"Server:\s*Apache", re.I), "apache_http_server"),
]


def parse_service(banner: str, port: int = None) -> dict:
    """Best-effort extraction of ``{product, version}`` from a service banner.

    Mirrors what ``nmap -sV`` surfaces so the result can be handed straight to
    the offline vuln database. ``version`` is "" when a product is recognised
    but its version isn't advertised.
    """
    if not banner:
        return {"product": "", "version": ""}
    for sig in _PRODUCT_SIGS:
        pat, product = sig[0], sig[1]
        if len(sig) > 2 and not sig[2].search(banner):
            continue
        m = pat.search(banner)
        if m:
            version = m.group(1) if m.groups() else ""
            return {"product": product, "version": version or ""}
    return {"product": "", "version": ""}


def fingerprint_port(host: str, port: int, timeout: float = 2.0) -> dict:
    if port in _HTTP_PORTS:
        want_body = port in _BODY_PORTS
        tls_first = port in _HTTPS_FIRST_PORTS
        # Try the likelier transport first, then the other (a 9200 with security
        # enabled is HTTPS; an odd 443 may be plain HTTP).
        banner = _grab_http(host, port, timeout, tls=tls_first, want_body=want_body)
        if not banner:
            banner = _grab_http(host, port, timeout, tls=not tls_first, want_body=want_body)
    elif port in _REDIS_PORTS:
        banner = _grab_redis(host, port, timeout)
    else:
        # Servers in _SERVER_SPEAKS_FIRST greet us; for everything else a passive
        # read is still worth a try as many services volunteer a banner.
        banner = _grab_generic(host, port, timeout)
        if not banner:
            # Silent on connect: most likely a client-speaks-first protocol such
            # as HTTP(S) on a non-standard port (8081, 9000, 5000, ...). Plain
            # first; a TLS-only service answers the second attempt.
            banner = (_grab_http(host, port, timeout)
                      or _grab_http(host, port, timeout, tls=True))

    svc = parse_service(banner, port)
    return {
        "port": port,
        "service": port_name(port),
        "banner": banner,
        "os_hint": _infer(banner),
        "product": svc["product"],
        "version": svc["version"],
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
        # Most frequent hint; sorted() makes ties deterministic across runs
        # (set iteration order of strings varies with hash randomisation).
        os_guess = max(sorted(set(hints)), key=hints.count)

    return {"host": host, "ports": results, "os_guess": os_guess}
