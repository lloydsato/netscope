"""TLS / certificate auditing using only the standard library.

For a host:port speaking TLS, netscope reports the certificate's identity and
validity and the protocol/cipher actually negotiated, then flags the classic
audit issues: expired or soon-to-expire certs, self-signed certs, weak
signature algorithms, obsolete protocol versions, weak ciphers, and hostname
mismatches.

Everything here is read-only reconnaissance of what a server volunteers during
a normal handshake -- the same information a browser sees. No stdlib-external
crypto library is required: the certificate is taken from the handshake itself
(with verification off, so self-signed and expired certs still work) and decoded
with the long-stable ``ssl._ssl._test_decode_cert`` helper.

Python's default client refuses TLS < 1.2 and weak ciphers, which would hide
exactly the legacy servers an audit exists to find, so the handshakes here use a
deliberately permissive client context (see ``_client_context``).
"""

import math
import os
import socket
import ssl
import tempfile
import time
import warnings

from .probes import _ber_read

# Certs expiring within this many days are flagged as a warning.
_EXPIRY_WARN_DAYS = 21

# Protocol versions we consider obsolete (anything below TLS 1.2, RFC 8996).
_OBSOLETE_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}

# Substrings in an OpenSSL cipher name that indicate a weak cipher. (OpenSSL
# spells anonymous suites ADH-/AECDH- and export suites EXP-.)
_WEAK_CIPHER_TOKENS = ("RC4", "3DES", "DES-", "NULL", "EXPORT", "EXP-", "MD5",
                       "ANON", "ADH-", "AECDH-", "RC2")

# Certificate signature algorithms (by OID) that are cryptographically broken.
_WEAK_SIG_OIDS = {
    "1.2.840.113549.1.1.2": "md2WithRSAEncryption",
    "1.2.840.113549.1.1.4": "md5WithRSAEncryption",
    "1.2.840.113549.1.1.5": "sha1WithRSAEncryption",
    "1.2.840.10040.4.3": "dsa-with-sha1",
    "1.2.840.10045.4.1": "ecdsa-with-SHA1",
}

# Legacy versions probed individually, because a modern client never negotiates
# them when the server also supports TLS 1.2+ -- "negotiated" alone would miss a
# server that still accepts TLS 1.0 next to 1.3.
_LEGACY_PROBES = (("TLSv1", "TLSv1"), ("TLSv1.1", "TLSv1_1"))


def _decode_cert_pem(pem: str) -> dict:
    """Decode a PEM certificate to the dict shape ``getpeercert()`` returns.

    Uses ``ssl._ssl._test_decode_cert``, a private-but-stable helper present in
    CPython 3.x. Returns {} if decoding isn't possible on this build.
    """
    tmp = tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False)
    try:
        tmp.write(pem)
        tmp.flush()
        tmp.close()
        return ssl._ssl._test_decode_cert(tmp.name)  # noqa: SLF001 (stable helper)
    except Exception:
        return {}
    finally:
        try:
            os.unlink(tmp.name)
        except OSError:
            pass


def _parse_notafter(value: str):
    """Parse the cert 'notAfter' string (e.g. 'Jun  1 12:00:00 2025 GMT') into
    epoch seconds, or None. ``ssl.cert_time_to_seconds`` is locale-independent;
    ``strptime('%b')`` is not, and would silently skip the expiry check on a
    non-English system."""
    try:
        return ssl.cert_time_to_seconds(value)
    except (ValueError, TypeError, OverflowError):
        return None


def _oid_to_str(raw: bytes) -> str:
    if not raw:
        return ""
    arcs, value = [raw[0] // 40, raw[0] % 40], 0
    for b in raw[1:]:
        value = (value << 7) | (b & 0x7F)
        if not b & 0x80:
            arcs.append(value)
            value = 0
    return ".".join(str(a) for a in arcs)


def _signature_oid(der: bytes) -> str:
    """Signature algorithm OID (dotted) of a DER X.509 certificate, or "".

    Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }
    and signatureAlgorithm ::= SEQUENCE { algorithm OID, parameters ANY }.
    """
    try:
        _, cert, _ = _ber_read(der, 0)
        _, _, after_tbs = _ber_read(cert, 0)
        _, alg, _ = _ber_read(cert, after_tbs)
        tag, oid, _ = _ber_read(alg, 0)
        return _oid_to_str(oid) if tag == 0x06 else ""
    except (ValueError, IndexError):
        return ""


def _rdn_value(rdn_seq, key):
    """Pull a value (e.g. commonName) out of the nested subject/issuer structure."""
    for rdn in rdn_seq or ():
        for attr in rdn:
            if attr[0] == key:
                return attr[1]
    return None


def _san_names(cert):
    return [v for k, v in cert.get("subjectAltName", ()) if k == "DNS"]


def _client_context(version_name=None):
    """A client context that accepts anything: we audit what a server offers, we
    don't trust it. Python/OpenSSL defaults refuse TLS < 1.2 and weak ciphers, which
    would make exactly the servers worth flagging un-auditable. ``version_name``
    ('TLSv1', 'TLSv1_1', ...) pins min = max to probe a single protocol."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.set_ciphers("ALL:@SECLEVEL=0")
    except ssl.SSLError:
        pass
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        if version_name:
            version = getattr(ssl.TLSVersion, version_name)   # AttributeError if unsupported
            ctx.minimum_version = version                      # ValueError if unsupported
            ctx.maximum_version = version
        else:
            try:
                ctx.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED
            except (ValueError, ssl.SSLError):
                pass
    return ctx


def _handshake(host, port, timeout, version_name=None):
    """Complete one handshake (accepting any cert). Returns a dict with
    ``protocol``, ``cipher``, ``der`` (peer cert bytes) and ``error``."""
    out = {"protocol": None, "cipher": "", "der": None, "error": None}
    try:
        ctx = _client_context(version_name)
    except (AttributeError, ValueError, ssl.SSLError) as e:
        out["error"] = f"client cannot probe {version_name}: {e}"
        out["unsupported_client"] = True
        return out
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as ss:
                cipher = ss.cipher()
                out.update(protocol=ss.version(), cipher=cipher[0] if cipher else "",
                           der=ss.getpeercert(binary_form=True))
    except Exception as e:  # noqa: BLE001 -- report, don't crash an audit
        out["error"] = str(e) or e.__class__.__name__
    return out


def _supported_legacy(host, port, timeout, negotiated):
    """Obsolete protocol versions the server accepts (probed one at a time)."""
    found = []
    for name, attr in _LEGACY_PROBES:
        if negotiated == name:
            found.append(name)
            continue
        r = _handshake(host, port, timeout, version_name=attr)
        if r["error"] is None and r["protocol"] == name:
            found.append(name)
    return found


def inspect(host: str, port: int = 443, timeout: float = 4.0) -> dict:
    """Inspect the TLS service at host:port.

    Returns a dict with the parsed certificate summary, negotiated protocol and
    cipher, and a ``findings`` list of {severity, title, detail, evidence, key}.
    ``ok`` is False (with ``error``) if no TLS service answered.
    """
    findings = []
    hs = _handshake(host, port, timeout)
    proto, cipher = hs["protocol"], hs["cipher"]
    if hs["error"] is not None:
        return {"host": host, "port": port, "ok": False, "error": hs["error"],
                "protocol": proto, "cipher": cipher, "findings": findings}

    cert, cert_error = {}, None
    if hs["der"]:
        cert = _decode_cert_pem(ssl.DER_cert_to_PEM_cert(hs["der"]))
        if not cert:
            cert_error = "certificate could not be decoded on this Python build"
    else:
        cert_error = "server presented no certificate"
    subject_cn = _rdn_value(cert.get("subject"), "commonName")
    issuer_cn = _rdn_value(cert.get("issuer"), "commonName")
    sans = _san_names(cert)
    not_after_raw = cert.get("notAfter")
    not_after = _parse_notafter(not_after_raw) if not_after_raw else None

    # --- expiry ---
    # ``key`` keeps the finding id stable from run to run: the day count in the
    # detail changes daily and would otherwise make `diff` report the same issue
    # as one resolved + one new finding every time.
    if not_after is not None:
        seconds_left = not_after - time.time()
        if seconds_left < 0:
            days_ago = int((-seconds_left) // 86400)
            when = f"{days_ago} day(s) ago" if days_ago else "earlier today"
            findings.append({
                "severity": "high", "title": "Expired TLS certificate", "key": "expired",
                "detail": f"Certificate expired {when} ({not_after_raw}).",
                "evidence": f"notAfter={not_after_raw}",
            })
        elif seconds_left <= _EXPIRY_WARN_DAYS * 86400:
            days_left = math.floor(seconds_left / 86400)
            findings.append({
                "severity": "medium", "title": "TLS certificate expiring soon", "key": "expiring",
                "detail": f"Certificate expires in {days_left} day(s) ({not_after_raw}).",
                "evidence": f"notAfter={not_after_raw}",
            })

    # --- self-signed: the whole subject DN equals the whole issuer DN ---
    # (comparing only the CN would miss certs with no CN and flag unrelated
    # certs that merely share a common name).
    if cert.get("subject") and cert.get("subject") == cert.get("issuer"):
        label = subject_cn or ", ".join(f"{k}={v}" for rdn in cert["subject"] for k, v in rdn)
        findings.append({
            "severity": "medium", "title": "Self-signed TLS certificate", "key": "self-signed",
            "detail": f"Subject and issuer are both '{label}' -- certificate is self-signed.",
            "evidence": f"subject/issuer={label}",
        })

    # --- hostname / CN mismatch (only when host is a name, not a bare IP) ---
    if _looks_like_hostname(host):
        # RFC 6125: when DNS SANs are present the CN is not consulted.
        names = set(sans) if sans else ({subject_cn} if subject_cn else set())
        if names and not any(_host_matches(host, n) for n in names):
            findings.append({
                "severity": "low", "title": "TLS certificate hostname mismatch", "key": "hostname",
                "detail": f"'{host}' is not covered by the certificate ({', '.join(sorted(names))}).",
                "evidence": f"CN={subject_cn} SAN={sans}",
            })

    # --- weak signature algorithm (MD5 / SHA-1 / MD2) ---
    sig_name = _WEAK_SIG_OIDS.get(_signature_oid(hs["der"] or b""))
    if sig_name:
        findings.append({
            "severity": "medium", "title": "Weak certificate signature algorithm", "key": "weak-signature",
            "detail": f"The certificate is signed with {sig_name}, which is no longer "
                      f"collision-resistant; browsers reject it.",
            "evidence": f"signatureAlgorithm={sig_name}",
        })

    # --- obsolete protocols (negotiated, or merely accepted alongside TLS 1.2+) ---
    obsolete = _supported_legacy(host, port, timeout, proto)
    if proto in _OBSOLETE_PROTOCOLS and proto not in obsolete:
        obsolete.insert(0, proto)
    for name in obsolete:
        findings.append({
            "severity": "high", "title": f"Obsolete TLS protocol ({name})", "key": f"proto-{name}",
            "detail": f"The server accepts {name}, which is deprecated and insecure (RFC 8996).",
            "evidence": f"protocol={name}",
        })

    # --- weak cipher ---
    if cipher and any(tok in cipher.upper() for tok in _WEAK_CIPHER_TOKENS):
        findings.append({
            "severity": "medium", "title": "Weak TLS cipher negotiated", "key": "weak-cipher",
            "detail": f"The negotiated cipher '{cipher}' uses a weak/legacy algorithm.",
            "evidence": f"cipher={cipher}",
        })

    return {
        "host": host, "port": port, "ok": True,
        "protocol": proto, "cipher": cipher,
        "subject": subject_cn, "issuer": issuer_cn,
        "san": sans, "not_after": not_after_raw,
        "obsolete_protocols": obsolete,
        "cert_error": cert_error,
        "negotiate_error": None,
        "findings": findings,
    }


def _looks_like_hostname(host: str) -> bool:
    try:
        socket.inet_aton(host)
        return False  # it's an IPv4 literal
    except OSError:
        return ":" not in host  # crude IPv6 exclusion; anything else is a name


def _host_matches(host: str, cert_name: str) -> bool:
    """Match a hostname against a (possibly wildcard) certificate name."""
    host = host.lower().rstrip(".")
    cert_name = cert_name.lower().rstrip(".")
    if cert_name.startswith("*."):
        # Wildcard matches exactly one non-empty left-most label, so the host
        # must have a label to spare ('com' must not match '*.com').
        head, dot, tail = host.partition(".")
        return bool(head) and bool(dot) and tail == cert_name[2:]
    return host == cert_name
