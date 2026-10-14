"""Name & service discovery: mDNS, SSDP/UPnP and NetBIOS.

OUI vendor lookup only says who made a network card. Home and IoT gear is
usually far more talkative than that: it announces a hostname over mDNS, a
model name over UPnP, and a NetBIOS name on Windows/Samba boxes. This module
asks (read-only, stdlib UDP sockets, no extra dependencies) and folds the answers
into each host dict as ``hostname`` / ``model`` / ``manufacturer`` / ``services``.

Everything read off the wire is attacker-controlled (any device on the LAN can
answer), so it is parsed defensively -- bounds-checked DNS/NetBIOS decoding, no
XML parser for UPnP descriptions (regex extraction of three fields only), only
HTTP fetches back to the *responding* host -- and sanitised with ``safe_text``
before it is ever stored or printed.
"""

import concurrent.futures
import re
import socket
import struct
import time
import urllib.parse

from .utils import safe_text

MDNS_GROUP = ("224.0.0.251", 5353)
SSDP_GROUP = ("239.255.255.250", 1900)
NETBIOS_PORT = 137

_MAX_NAME_LEN = 64            # hostnames/models longer than this are not plausible
_MAX_DESC_BYTES = 65536       # cap on a UPnP description document
_MAX_DNS_JUMPS = 16           # compression-pointer loop guard


# ---------- DNS-wire parsing (mDNS) ----------

def _read_name(data, off):
    """Decode a (possibly compressed) DNS name at ``off`` -> (name, next_offset).

    Raises ValueError on truncation, bad labels or pointer loops.
    """
    labels, jumped, end, hops = [], False, off, 0
    while True:
        if off >= len(data):
            raise ValueError("truncated name")
        n = data[off]
        if n == 0:
            off += 1
            break
        if n & 0xC0 == 0xC0:
            if off + 1 >= len(data):
                raise ValueError("truncated pointer")
            ptr = ((n & 0x3F) << 8) | data[off + 1]
            if not jumped:
                end = off + 2
            jumped = True
            hops += 1
            if hops > _MAX_DNS_JUMPS or ptr >= len(data):
                raise ValueError("bad compression pointer")
            off = ptr
            continue
        if n & 0xC0:
            raise ValueError("bad label")
        if off + 1 + n > len(data):
            raise ValueError("truncated label")
        labels.append(data[off + 1:off + 1 + n].decode("utf-8", "replace"))
        off += 1 + n
        if len(labels) > 64:
            raise ValueError("too many labels")
    return ".".join(labels), (end if jumped else off)


def build_mdns_query(name="_services._dns-sd._udp.local", qtype=12):
    """A multicast DNS question (default: PTR for DNS-SD service enumeration)."""
    q = b"".join(bytes([len(p)]) + p.encode("ascii") for p in name.split("."))
    # QU bit (0x8000) asks for a unicast reply; class IN.
    return struct.pack(">HHHHHH", 0, 0, 1, 0, 0, 0) + q + b"\x00" + struct.pack(">HH", qtype, 0x8001)


def parse_mdns(data):
    """Parse an mDNS response -> {"a": {name: ip}, "ptr": [(owner, target)]}.

    Malformed packets yield whatever parsed cleanly before the damage (possibly
    empty); this never raises.
    """
    out = {"a": {}, "ptr": []}
    try:
        if len(data) < 12:
            return out
        _id, flags, qd, an, ns, ar = struct.unpack(">HHHHHH", data[:12])
        if not flags & 0x8000:                       # a query, not a response
            return out
        off = 12
        for _ in range(min(qd, 32)):
            _, off = _read_name(data, off)
            off += 4
        for _ in range(min(an + ns + ar, 128)):
            owner, off = _read_name(data, off)
            if off + 10 > len(data):
                break
            rtype, _cls, _ttl, rdlen = struct.unpack(">HHIH", data[off:off + 10])
            off += 10
            rdata_off = off
            off += rdlen
            if off > len(data):
                break
            if rtype == 1 and rdlen == 4:            # A
                out["a"][owner] = socket.inet_ntoa(data[rdata_off:rdata_off + 4])
            elif rtype == 12:                        # PTR
                target, _ = _read_name(data, rdata_off)
                out["ptr"].append((owner.lower(), target))
    except (ValueError, struct.error, UnicodeError):
        pass
    return out


def _clean_host(name):
    """'My-TV.local.' -> 'My-TV'; None if it isn't a plausible hostname."""
    name = safe_text(name, _MAX_NAME_LEN + 8).strip().rstrip(".")
    if name.lower().endswith(".local"):
        name = name[:-6]
    return name if name and len(name) <= _MAX_NAME_LEN else None


def collect_mdns(responses):
    """Fold [(src_ip, packet_bytes)] into {ip: {hostname, services[]}}."""
    info = {}
    for src, data in responses:
        parsed = parse_mdns(data)
        entry = info.setdefault(src, {"hostname": "", "services": []})
        for name, ip in parsed["a"].items():
            if ip == src and not entry["hostname"]:
                entry["hostname"] = _clean_host(name) or ""
        for owner, target in parsed["ptr"]:
            if owner == "_services._dns-sd._udp.local":
                svc = safe_text(target, 64)
                if svc and svc not in entry["services"]:
                    entry["services"].append(svc)
    return info


# ---------- SSDP / UPnP ----------

SSDP_REQUEST = (
    "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n"
    'MAN: "ssdp:discover"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n'
).encode("ascii")


def parse_ssdp(data):
    """SSDP response -> {lower-case header: value}; {} unless it's an HTTP 200."""
    try:
        head = data[:4096].decode("utf-8", "replace").split("\r\n\r\n", 1)[0]
    except Exception:
        return {}
    lines = head.split("\r\n")
    if not lines or not lines[0].upper().startswith("HTTP/1.1 200"):
        return {}
    hdr = {}
    for line in lines[1:]:
        k, sep, v = line.partition(":")
        if sep:
            hdr[k.strip().lower()] = v.strip()
    return hdr


_DESC_FIELDS = {
    "hostname": re.compile(r"<friendlyName>([^<]{1,128})</friendlyName>", re.I),
    "model": re.compile(r"<modelName>([^<]{1,128})</modelName>", re.I),
    "manufacturer": re.compile(r"<manufacturer>([^<]{1,128})</manufacturer>", re.I),
}


def parse_upnp_description(text):
    """Pull friendlyName/modelName/manufacturer out of a UPnP description.

    Regex on purpose: a hostile LAN device controls this document, and a real
    XML parser is an attack surface (entity expansion) we don't need for three
    fields.
    """
    out = {}
    for key, rx in _DESC_FIELDS.items():
        m = rx.search(text or "")
        if m:
            val = safe_text(m.group(1), _MAX_NAME_LEN).strip()
            if val:
                out[key] = val
    return out


def _fetch_description(url, expect_ip, timeout):
    """GET a UPnP description, but only from the host that announced it."""
    try:
        u = urllib.parse.urlsplit(url)
        if u.scheme != "http" or u.hostname != expect_ip:
            return ""
        port = u.port or 80
        path = (u.path or "/") + (f"?{u.query}" if u.query else "")
        with socket.create_connection((expect_ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall(f"GET {path} HTTP/1.0\r\nHost: {expect_ip}\r\n\r\n".encode("ascii", "replace"))
            buf = b""
            while len(buf) < _MAX_DESC_BYTES:
                chunk = s.recv(4096)
                if not chunk:
                    break
                buf += chunk
        return buf.decode("utf-8", "replace")
    except (OSError, ValueError, UnicodeError):
        return ""


def collect_ssdp(responses, fetch=None, timeout=2.0):
    """Fold [(src_ip, packet_bytes)] into {ip: {hostname, model, manufacturer, server}}."""
    fetch = fetch or _fetch_description
    info, fetched = {}, set()
    for src, data in responses:
        hdr = parse_ssdp(data)
        if not hdr:
            continue
        entry = info.setdefault(src, {"server": safe_text(hdr.get("server", ""), 96)})
        if not entry.get("server"):
            entry["server"] = safe_text(hdr.get("server", ""), 96)
        loc = hdr.get("location", "")
        if loc and src not in fetched:
            fetched.add(src)
            entry.update(parse_upnp_description(fetch(loc, src, timeout)))
    return info


# ---------- NetBIOS node status ----------

def build_netbios_query():
    """NBSTAT ('*') node-status request."""
    name = b"\x20" + b"CK" + b"AA" * 15 + b"\x00"       # encoded wildcard name '*'
    return struct.pack(">HHHHHH", 0x4E53, 0, 1, 0, 0, 0) + name + struct.pack(">HH", 0x0021, 1)


def parse_netbios(data):
    """NBSTAT response -> {"hostname": str, "workgroup": str}; {} if not parseable."""
    try:
        if len(data) < 12:
            return {}
        _id, flags, _qd, an = struct.unpack(">HHHH", data[:8])
        if not flags & 0x8000 or an < 1:
            return {}
        _, off = _read_name(data, 12)                    # answer owner name (NetBIOS-encoded)
        rtype, _cls, _ttl, rdlen = struct.unpack(">HHIH", data[off:off + 10])
        off += 10
        if rtype != 0x0021 or off + rdlen > len(data) or rdlen < 1:
            return {}
        count = data[off]
        off += 1
        host = group = ""
        for _ in range(min(count, 32)):
            if off + 18 > len(data):
                break
            raw, suffix = data[off:off + 15], data[off + 15]
            nflags = struct.unpack(">H", data[off + 16:off + 18])[0]
            off += 18
            if suffix != 0x00:
                continue
            name = safe_text(raw.decode("ascii", "replace"), 15).strip()
            if nflags & 0x8000:                           # group name
                group = group or name
            else:
                host = host or name
        out = {}
        if host and len(host) <= _MAX_NAME_LEN:
            out["hostname"] = host
        if group:
            out["workgroup"] = group
        return out
    except (ValueError, struct.error, IndexError):
        return {}


def _netbios_probe(ip, timeout):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(build_netbios_query(), (ip, NETBIOS_PORT))
            data, addr = s.recvfrom(1024)
        if addr[0] != ip:
            return {}
        return parse_netbios(data)
    except OSError:
        return {}


# ---------- network I/O ----------

def _multicast_collect(payload, group, timeout):
    """Send ``payload`` to ``group`` and gather [(src_ip, data)] until timeout."""
    out = []
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
            s.bind(("", 0))
            s.sendto(payload, group)
            deadline = time.monotonic() + timeout
            while True:
                left = deadline - time.monotonic()
                if left <= 0:
                    break
                s.settimeout(left)
                try:
                    data, addr = s.recvfrom(9000)
                except socket.timeout:
                    break
                out.append((addr[0], data))
                if len(out) >= 2048:                     # a flooding LAN must not grow us unboundedly
                    break
    except OSError:
        pass
    return out


def discover_names(hosts, timeout=2.0, mdns=True, ssdp=True, netbios=True):
    """Query the LAN and return {ip: info} for the given hosts.

    ``info`` keys: hostname, model, manufacturer, workgroup, services (list),
    exposures (list of 'ssdp'/'netbios'). Only IPs in ``hosts`` are reported, so
    a stray responder outside the audited scope can't appear in results.
    """
    ips = {h["ip"] if isinstance(h, dict) else h for h in hosts}
    merged = {ip: {"hostname": "", "model": "", "manufacturer": "", "workgroup": "",
                   "services": [], "exposures": []} for ip in ips}

    if mdns:
        for ip, i in collect_mdns(_multicast_collect(build_mdns_query(), MDNS_GROUP, timeout)).items():
            if ip in merged:
                merged[ip]["hostname"] = merged[ip]["hostname"] or i["hostname"]
                merged[ip]["services"] += [s for s in i["services"] if s not in merged[ip]["services"]]
    if ssdp:
        for ip, i in collect_ssdp(_multicast_collect(SSDP_REQUEST, SSDP_GROUP, timeout), timeout=timeout).items():
            if ip in merged:
                m = merged[ip]
                m["hostname"] = m["hostname"] or i.get("hostname", "")
                m["model"] = i.get("model", "")
                m["manufacturer"] = i.get("manufacturer", "")
                m["exposures"].append("ssdp")
    if netbios and ips:
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(32, len(ips))) as ex:
            for ip, i in zip(sorted(ips), ex.map(lambda ip: _netbios_probe(ip, min(timeout, 1.5)), sorted(ips))):
                if i:
                    m = merged[ip]
                    m["hostname"] = m["hostname"] or i.get("hostname", "")
                    m["workgroup"] = i.get("workgroup", "")
                    m["exposures"].append("netbios")
    return merged


def enrich_hosts(hosts, **kw):
    """Add hostname/model/manufacturer/workgroup/services/exposures to each host dict."""
    names = discover_names(hosts, **kw)
    for h in hosts:
        info = names.get(h["ip"], {})
        for k in ("hostname", "model", "manufacturer", "workgroup"):
            if info.get(k):
                h[k] = info[k]
        if info.get("services"):
            h["services"] = info["services"]
        if info.get("exposures"):
            h["exposures"] = info["exposures"]
    return hosts
