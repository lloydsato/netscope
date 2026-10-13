"""Read-only checks for services exposed with weak or default authentication.

These confirm *exposure* -- "this service answered me over the network with no
credentials, or with a well-known default" -- and stop there. In the spirit of
netscope's plaintext detector, they surface the risk without harvesting data:
each probe reads only an identity/version string (or a single benign status
reply) and never enumerates, modifies, or exfiltrates anything.

All probes use the standard library only. Each returns a list of finding dicts
(possibly empty) shaped for ``findings.from_probes``:
``{category, severity, title, host, port, detail, evidence}``.

A probe only reports what it positively confirmed. Anything ambiguous (timeouts,
auth required, unexpected replies, malformed data) yields no finding rather
than a guess -- a false "critical" is worse than a missed informational.
"""

import re
import socket
import struct
import time


def _finding(category, severity, title, host, port, detail, evidence=""):
    return {"category": category, "severity": severity, "title": title,
            "host": host, "port": port, "detail": detail, "evidence": evidence}


def _read_until_close(sock, limit=16384):
    """Read until the peer closes, a timeout, or ``limit`` bytes. A single recv()
    may return just the first TCP segment (e.g. HTTP headers without the body)."""
    data = b""
    while len(data) < limit:
        try:
            chunk = sock.recv(4096)
        except socket.timeout:
            break
        if not chunk:
            break
        data += chunk
    return data


# ---------- FTP ----------

def _ftp_reply(f):
    """Read one (possibly multi-line, RFC 959) FTP reply from a binary file
    object. Returns ``(code, text)``; code is None if nothing parseable arrived.
    A multi-line reply starts ``NNN-`` and ends with a line starting ``NNN ``.
    """
    code, lines = None, []
    for _ in range(100):  # cap runaway banners
        raw = f.readline(1024)
        if not raw:
            break
        line = raw.decode("latin-1", "replace").rstrip("\r\n")
        lines.append(line)
        m = re.match(r"^(\d{3})([ -])", line)
        if code is None:
            if not m:
                continue  # stray text before the first coded line
            code = int(m.group(1))
            if m.group(2) == " ":
                break
        elif m and int(m.group(1)) == code and m.group(2) == " ":
            break
    return code, "\n".join(lines)


def check_ftp_anonymous(host, port=21, timeout=4.0):
    """Detect anonymous FTP login (USER anonymous / PASS anonymous@)."""
    evidence = ""
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            f = s.makefile("rb")
            code, _ = _ftp_reply(f)                 # greeting
            if code != 220:
                return []
            s.sendall(b"USER anonymous\r\n")
            code, text = _ftp_reply(f)
            if code in (331, 332):                  # password please
                s.sendall(b"PASS anonymous@example.com\r\n")
                code, text = _ftp_reply(f)
            logged_in = code == 230                 # (some servers 230 on USER alone)
            evidence = text.strip().splitlines()[-1][:80] if text.strip() else ""
            try:
                s.sendall(b"QUIT\r\n")
            except OSError:
                pass
    except OSError:
        return []
    if logged_in:
        return [_finding(
            "weak-auth", "high", "Anonymous FTP login allowed", host, port,
            "The FTP server accepted an anonymous login, exposing its contents "
            "to anyone on the network.", evidence=evidence,
        )]
    return []


# ---------- Redis ----------

def check_redis(host, port=6379, timeout=4.0):
    """Detect an unauthenticated Redis (PING answered without AUTH)."""
    version = ""
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall(b"PING\r\n")
            resp = s.recv(64).decode("latin-1", "replace")
            if resp.startswith("+PONG"):
                # Grab the version only (read-only, no data access). Failing to
                # get it must not discard the confirmed unauthenticated PING.
                try:
                    s.sendall(b"INFO server\r\n")
                    info = s.recv(2048).decode("latin-1", "replace")
                    m = re.search(r"redis_version:([0-9][\w.]*)", info)
                    if m:
                        version = m.group(1)
                except OSError:
                    pass
    except OSError:
        return []
    if resp.startswith("+PONG"):
        return [_finding(
            "weak-auth", "critical", "Unauthenticated Redis exposed", host, port,
            "Redis answered PING with no authentication -- anyone on the network "
            "can read and modify all keys." + (f" Version {version}." if version else ""),
            evidence=f"redis_version={version}" if version else "+PONG",
        )]
    # "-NOAUTH ..." / "-DENIED ..." (auth or protected mode in force) is the
    # healthy outcome: nothing to report.
    return []


# ---------- MongoDB ----------
#
# ``isMaster``/``hello`` is answered by *every* mongod, with or without
# --auth (drivers need it to negotiate), so its mere success proves nothing.
# We instead run ``hostInfo``, which requires authentication on a secured
# server (error code 13 "Unauthorized") and returns only host/OS facts.

def _bson_cstr(s):
    return s.encode("utf-8") + b"\x00"


def _bson_doc(*elements):
    body = b"".join(elements) + b"\x00"
    return struct.pack("<i", len(body) + 4) + body


def _bson_int32(name, value):
    return b"\x10" + _bson_cstr(name) + struct.pack("<i", value)


def _bson_string(name, value):
    raw = _bson_cstr(value)
    return b"\x02" + _bson_cstr(name) + struct.pack("<i", len(raw)) + raw


_BSON_FIXED = {0x01: 8, 0x07: 12, 0x09: 8, 0x11: 8, 0x12: 8, 0x13: 16,
               0x06: 0, 0x0A: 0, 0xFF: 0, 0x7F: 0, 0x08: 1, 0x10: 4}


def _bson_parse(data, depth=0):
    """Tolerant top-level BSON reader -> dict. Understands the scalar types and
    nested documents/arrays; stops (returning what it has) at anything else, and
    returns {} on malformed input rather than raising."""
    out = {}
    try:
        total = struct.unpack_from("<i", data, 0)[0]
        end = min(total, len(data)) - 1
        i = 4
        while i < end:
            etype = data[i]
            i += 1
            nul = data.index(b"\x00", i)
            name = data[i:nul].decode("utf-8", "replace")
            i = nul + 1
            if etype == 0x01:
                out[name] = struct.unpack_from("<d", data, i)[0]; i += 8
            elif etype == 0x02:
                n = struct.unpack_from("<i", data, i)[0]
                out[name] = data[i + 4:i + 4 + n - 1].decode("utf-8", "replace"); i += 4 + n
            elif etype in (0x03, 0x04):
                n = struct.unpack_from("<i", data, i)[0]
                out[name] = _bson_parse(data[i:i + n], depth + 1) if depth < 4 else {}
                i += n
            elif etype == 0x08:
                out[name] = bool(data[i]); i += 1
            elif etype == 0x10:
                out[name] = struct.unpack_from("<i", data, i)[0]; i += 4
            elif etype == 0x12:
                out[name] = struct.unpack_from("<q", data, i)[0]; i += 8
            elif etype in _BSON_FIXED:
                i += _BSON_FIXED[etype]
            else:
                break  # binary/regex/js/...: not needed, stop rather than guess
    except (struct.error, ValueError, IndexError):
        return out
    return out


def _mongo_op_msg(command, request_id=1):
    doc = _bson_doc(_bson_int32(command, 1), _bson_string("$db", "admin"))
    body = struct.pack("<I", 0) + b"\x00" + doc          # flagBits, section kind 0
    return struct.pack("<iiii", 16 + len(body), request_id, 0, 2013) + body


def _mongo_op_query(command, request_id=1):
    doc = _bson_doc(_bson_int32(command, 1))
    body = (struct.pack("<i", 0) + _bson_cstr("admin.$cmd") +
            struct.pack("<ii", 0, -1) + doc)
    return struct.pack("<iiii", 16 + len(body), request_id, 0, 2004) + body


def _mongo_reply_doc(msg):
    """Extract the first reply document (as a dict) from a full wire message."""
    if len(msg) < 21:
        return None
    opcode = struct.unpack_from("<i", msg, 12)[0]
    if opcode == 2013:                      # OP_MSG: flags(4) + kind(1) + BSON
        return _bson_parse(msg[21:])
    if opcode == 1:                         # OP_REPLY: flags+cursor+from+count = 20
        return _bson_parse(msg[36:])
    return None


def _mongo_roundtrip(host, port, packet, timeout):
    """Send one wire message, return the complete reply message (or None)."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall(packet)
            head = b""
            while len(head) < 4:
                chunk = s.recv(4 - len(head))
                if not chunk:
                    return None
                head += chunk
            length = struct.unpack("<i", head)[0]
            if not 16 <= length <= 262144:
                return None
            msg = head
            while len(msg) < length:
                chunk = s.recv(length - len(msg))
                if not chunk:
                    break
                msg += chunk
            return msg
    except OSError:
        return None


def check_mongodb(host, port=27017, timeout=4.0):
    """Detect an unauthenticated MongoDB: ``hostInfo`` succeeds without credentials."""
    reply = None
    # OP_MSG works on 3.6+ (and is the only option from 5.1); older servers drop
    # the unknown opcode, so fall back to the legacy OP_QUERY form.
    for packet in (_mongo_op_msg("hostInfo"), _mongo_op_query("hostInfo")):
        msg = _mongo_roundtrip(host, port, packet, timeout)
        doc = _mongo_reply_doc(msg) if msg else None
        if doc:
            reply = doc
            break
    if not reply:
        return []
    ok = reply.get("ok")
    if ok in (1, 1.0) and ("system" in reply or "os" in reply):
        return [_finding(
            "weak-auth", "critical", "Unauthenticated MongoDB exposed", host, port,
            "MongoDB executed an administrative command (hostInfo) with no "
            "authentication -- the database is reachable and likely readable off-host.",
            evidence="hostInfo succeeded without credentials",
        )]
    # ok:0 (typically code 13 Unauthorized) means authorization is enforced.
    return []


# ---------- Elasticsearch ----------

def check_elasticsearch(host, port=9200, timeout=4.0):
    """Detect an unauthenticated Elasticsearch (HTTP GET / returns cluster info)."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            req = (f"GET / HTTP/1.0\r\nHost: {host}\r\nUser-Agent: netscope\r\n\r\n")
            s.sendall(req.encode())
            resp = _read_until_close(s).decode("latin-1", "replace")
    except OSError:
        return []
    status = resp.splitlines()[0] if resp else ""
    if " 200" in status and ('"cluster_name"' in resp or '"lucene_version"' in resp):
        version = ""
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


# ---------- SNMP ----------

_SNMP_VERSIONS = {0: "v1", 1: "v2c"}


def check_snmp_default_community(host, port=161, communities=("public", "private"),
                                 timeout=3.0):
    """Detect SNMP reachable with a default community string.

    Sends a minimal GetRequest for sysDescr.0 per community, as both SNMPv1 and
    SNMPv2c (v2c-only agents ignore v1), all at once on one connected UDP socket
    so the whole check costs at most one ``timeout``. A reply only counts if it
    parses as a GetResponse (PDU 0xA2) that echoes our community and request-id.
    Reads only the system description, nothing more.
    """
    communities = [c for c in dict.fromkeys(communities) if c]
    if not communities:
        return []

    pending = {}          # request-id -> (community, version)
    packets = []
    rid = 0
    for community in communities:
        for version in _SNMP_VERSIONS:
            rid += 1
            pending[rid] = (community, version)
            packets.append(_snmp_get_sysdescr(community, version=version, request_id=rid))

    accepted = {}         # community -> evidence
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect((host, port))      # the kernel now drops replies from other sources
            for pkt in packets:
                s.send(pkt)
            deadline = time.monotonic() + timeout
            while pending and time.monotonic() < deadline:
                s.settimeout(max(0.05, deadline - time.monotonic()))
                try:
                    data = s.recv(4096)
                except socket.timeout:
                    break
                resp = _snmp_parse_response(data)
                if not resp or resp["request_id"] not in pending:
                    continue
                community, _ = pending.pop(resp["request_id"])
                if resp["community"] == community and community not in accepted:
                    accepted[community] = resp["sysdescr"]
                    # Both versions of a community answered? Drop the twin request.
                    for k in [k for k, (c, _) in pending.items() if c == community]:
                        pending.pop(k)
    except OSError:
        # ConnectionRefusedError == ICMP port-unreachable: nothing is listening.
        pass

    out = []
    for community in communities:
        if community in accepted:
            descr = _printable_only(accepted[community])
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


def _snmp_get_sysdescr(community: str, version: int = 0, request_id: int = 1) -> bytes:
    """Build an SNMP GetRequest for 1.3.6.1.2.1.1.1.0 (sysDescr.0).

    ``version`` is the on-the-wire SNMP version field: 0 = SNMPv1, 1 = SNMPv2c.
    """
    ver = _tlv(0x02, bytes([version]))                  # INTEGER version
    comm = _tlv(0x04, community.encode())              # OCTET STRING community
    req_id = _tlv(0x02, _ber_int(request_id))           # INTEGER request-id
    err_status = _tlv(0x02, b"\x00")
    err_index = _tlv(0x02, b"\x00")
    # OID 1.3.6.1.2.1.1.1.0 -> BER: 2b 06 01 02 01 01 01 00
    oid = _tlv(0x06, bytes([0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00]))
    null = _tlv(0x05, b"")
    varbind = _tlv(0x30, oid + null)
    varbind_list = _tlv(0x30, varbind)
    pdu = _tlv(0xA0, req_id + err_status + err_index + varbind_list)  # GetRequest
    return _tlv(0x30, ver + comm + pdu)


def _ber_int(n: int) -> bytes:
    """Minimal two's-complement encoding of a non-negative integer."""
    out = n.to_bytes(max(1, (n.bit_length() + 8) // 8), "big")
    return out


def _ber_read(data: bytes, i: int):
    """Read one TLV at offset ``i`` -> (tag, value_bytes, next_offset); raises
    ValueError on truncated/oversized input."""
    if i + 2 > len(data):
        raise ValueError("truncated TLV")
    tag, length = data[i], data[i + 1]
    i += 2
    if length & 0x80:
        n = length & 0x7F
        if n == 0 or n > 4 or i + n > len(data):
            raise ValueError("bad BER length")
        length = int.from_bytes(data[i:i + n], "big")
        i += n
    if i + length > len(data):
        raise ValueError("TLV exceeds buffer")
    return tag, data[i:i + length], i + length


def _snmp_parse_response(data: bytes):
    """Parse an SNMP GetResponse -> {version, community, request_id, error_status,
    sysdescr} or None if ``data`` is not a well-formed v1/v2c GetResponse."""
    try:
        tag, msg, _ = _ber_read(data, 0)
        if tag != 0x30:
            return None
        t, ver, i = _ber_read(msg, 0)
        if t != 0x02:
            return None
        t, comm, i = _ber_read(msg, i)
        if t != 0x04:
            return None
        t, pdu, _ = _ber_read(msg, i)
        if t != 0xA2:                               # GetResponse-PDU
            return None
        t, rid, j = _ber_read(pdu, 0)
        if t != 0x02:
            return None
        t, err, j = _ber_read(pdu, j)
        if t != 0x02:
            return None
        _, _, j = _ber_read(pdu, j)                 # error-index
        sysdescr = ""
        t, vbl, _ = _ber_read(pdu, j)
        if t == 0x30:
            t, vb, _ = _ber_read(vbl, 0)
            if t == 0x30:
                _, _, k = _ber_read(vb, 0)          # skip OID
                vt, val, _ = _ber_read(vb, k)
                if vt == 0x04:
                    sysdescr = val.decode("latin-1", "replace")
        return {
            "version": int.from_bytes(ver, "big"),
            "community": comm.decode("latin-1", "replace"),
            "request_id": int.from_bytes(rid, "big", signed=True),
            "error_status": int.from_bytes(err, "big", signed=True),
            "sysdescr": sysdescr,
        }
    except (ValueError, IndexError):
        return None


def _printable_only(text: str) -> str:
    return " ".join("".join(ch if ch.isprintable() else " " for ch in text).split())


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
