"""Read-only checks for services exposed with weak or default authentication.

These confirm *exposure* -- "this service answered me over the network with no
credentials, or with a well-known default" -- and stop there. In the spirit of
netscope's plaintext detector, they surface the risk without harvesting data:
each probe reads only an identity/version string (or a single benign status
reply) and never enumerates, modifies, or exfiltrates anything.

All probes use the standard library only. Each returns a list of finding dicts
(possibly empty) shaped for ``findings.from_probes``:
``{category, severity, title, host, port, detail, evidence}``.
"""

import socket
import struct


def _finding(category, severity, title, host, port, detail, evidence=""):
    return {"category": category, "severity": severity, "title": title,
            "host": host, "port": port, "detail": detail, "evidence": evidence}


def check_ftp_anonymous(host, port=21, timeout=4.0):
    """Detect anonymous FTP login (USER anonymous / PASS anonymous@)."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            s.recv(256)  # greeting
            s.sendall(b"USER anonymous\r\n")
            s.recv(256)
            s.sendall(b"PASS anonymous@example.com\r\n")
            resp = s.recv(256).decode("latin-1", "replace")
            s.sendall(b"QUIT\r\n")
    except OSError:
        return []
    if resp.startswith("230"):
        return [_finding(
            "weak-auth", "high", "Anonymous FTP login allowed", host, port,
            "The FTP server accepted an anonymous login, exposing its contents "
            "to anyone on the network.", evidence=resp.strip()[:80],
        )]
    return []


def check_redis(host, port=6379, timeout=4.0):
    """Detect an unauthenticated Redis (PING answered without AUTH)."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall(b"PING\r\n")
            resp = s.recv(64).decode("latin-1", "replace")
            version = ""
            if resp.startswith("+PONG"):
                # Grab the version only (read-only, no data access).
                s.sendall(b"INFO server\r\n")
                info = s.recv(2048).decode("latin-1", "replace")
                for line in info.splitlines():
                    if line.startswith("redis_version:"):
                        version = line.split(":", 1)[1].strip()
                        break
    except OSError:
        return []
    if resp.startswith("+PONG"):
        return [_finding(
            "weak-auth", "critical", "Unauthenticated Redis exposed", host, port,
            "Redis answered PING with no authentication -- anyone on the network "
            "can read and modify all keys." + (f" Version {version}." if version else ""),
            evidence=f"redis_version={version}" if version else "+PONG",
        )]
    if "NOAUTH" in resp:
        # Auth is required (good) -- nothing to report.
        return []
    return []


def check_mongodb(host, port=27017, timeout=4.0):
    """Detect an unauthenticated MongoDB via a wire-protocol isMaster query."""
    # OP_QUERY for {isMaster:1} against admin.$cmd. Read-only handshake command.
    doc = b"\x13\x00\x00\x00\x10isMaster\x00\x01\x00\x00\x00\x00"
    full_coll = b"admin.$cmd\x00"
    body = struct.pack("<i", 0) + full_coll + struct.pack("<ii", 0, -1) + doc
    header = struct.pack("<iiii", 16 + len(body), 1, 0, 2004)  # opcode 2004 = OP_QUERY
    packet = header + body
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall(packet)
            resp = s.recv(1024)
    except OSError:
        return []
    # A MongoDB reply starts with a message length then responseTo/opcode; if we
    # got a well-formed reply containing "ismaster"/"maxWireVersion", it answered
    # our unauthenticated handshake.
    if resp and (b"ismaster" in resp.lower() or b"maxwireversion" in resp.lower()
                 or b"maxbsonobjectsize" in resp.lower()):
        return [_finding(
            "weak-auth", "critical", "Unauthenticated MongoDB exposed", host, port,
            "MongoDB answered an isMaster handshake with no authentication -- "
            "the database is reachable and likely readable off-host.",
            evidence="isMaster reply received",
        )]
    return []


def check_elasticsearch(host, port=9200, timeout=4.0):
    """Detect an unauthenticated Elasticsearch (HTTP GET / returns cluster info)."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            req = (f"GET / HTTP/1.0\r\nHost: {host}\r\nUser-Agent: netscope\r\n\r\n")
            s.sendall(req.encode())
            resp = s.recv(4096).decode("latin-1", "replace")
    except OSError:
        return []
    status = resp.splitlines()[0] if resp else ""
    if "200" in status and ('"cluster_name"' in resp or '"lucene_version"' in resp):
        version = ""
        import re
        m = re.search(r'"number"\s*:\s*"([0-9][\w.]*)"', resp)
        if m:
            version = m.group(1)
        return [_finding(
            "weak-auth", "high", "Unauthenticated Elasticsearch exposed", host, port,
            "Elasticsearch returned cluster info to an unauthenticated request -- "
            "all indices may be readable/modifiable." + (f" Version {version}." if version else ""),
            evidence=f"version={version}" if version else status.strip()[:80],
        )]
    return []


def check_snmp_default_community(host, port=161, communities=("public", "private"),
                                 timeout=3.0):
    """Detect SNMP reachable with a default community string.

    Sends a minimal SNMPv1 GetRequest for sysDescr.0 with each community and
    reports any that produce a GetResponse (SNMP PDU type 0xA2). Reads only the
    system description, nothing more.
    """
    out = []
    for community in communities:
        packet = _snmp_get_sysdescr(community)
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(timeout)
                s.sendto(packet, (host, port))
                data, _ = s.recvfrom(2048)
        except OSError:
            continue
        # A GetResponse PDU (0xA2) anywhere in the reply means the community was
        # accepted. Try to lift the printable sysDescr for evidence only.
        if data and b"\xa2" in data:
            descr = _extract_printable(data)
            out.append(_finding(
                "weak-auth", "high",
                f"SNMP readable with default community '{community}'", host, port,
                f"The device responded to SNMP GET with the default community "
                f"'{community}', exposing system information.",
                evidence=(descr[:80] if descr else f"community={community}"),
            ))
    return out


def run_all(host, open_ports):
    """Run every applicable probe based on which ports are open.

    ``open_ports`` is a list of {'port': int, ...} dicts (or ints). Returns a
    flat list of finding dicts.
    """
    ports = {p["port"] if isinstance(p, dict) else p for p in open_ports}
    findings = []
    if 21 in ports:
        findings += check_ftp_anonymous(host)
    if 6379 in ports:
        findings += check_redis(host)
    if 27017 in ports:
        findings += check_mongodb(host)
    if 9200 in ports:
        findings += check_elasticsearch(host)
    return findings


# ---------- SNMP helpers (hand-built BER, no pysnmp dependency) ----------

def _ber_len(n):
    if n < 0x80:
        return bytes([n])
    out = []
    while n:
        out.insert(0, n & 0xFF)
        n >>= 8
    return bytes([0x80 | len(out)]) + bytes(out)


def _tlv(tag, value):
    return bytes([tag]) + _ber_len(len(value)) + value


def _snmp_get_sysdescr(community: str) -> bytes:
    """Build an SNMPv1 GetRequest for 1.3.6.1.2.1.1.1.0 (sysDescr.0)."""
    version = _tlv(0x02, b"\x00")                       # INTEGER version 0 (v1)
    comm = _tlv(0x04, community.encode())              # OCTET STRING community
    request_id = _tlv(0x02, b"\x01")                    # INTEGER request-id
    err_status = _tlv(0x02, b"\x00")
    err_index = _tlv(0x02, b"\x00")
    # OID 1.3.6.1.2.1.1.1.0 -> BER: 2b 06 01 02 01 01 01 00
    oid = _tlv(0x06, bytes([0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00]))
    null = _tlv(0x05, b"")
    varbind = _tlv(0x30, oid + null)
    varbind_list = _tlv(0x30, varbind)
    pdu = _tlv(0xA0, request_id + err_status + err_index + varbind_list)  # GetRequest
    return _tlv(0x30, version + comm + pdu)


def _extract_printable(data: bytes) -> str:
    """Pull the longest run of printable ASCII from a byte string (for evidence)."""
    best, cur = "", ""
    for b in data:
        if 32 <= b < 127:
            cur += chr(b)
        else:
            if len(cur) > len(best):
                best = cur
            cur = ""
    if len(cur) > len(best):
        best = cur
    return best.strip()
