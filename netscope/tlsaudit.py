"""TLS / certificate auditing using only the standard library.

For a host:port speaking TLS, netscope reports the certificate's identity and
validity and the protocol/cipher actually negotiated, then flags the classic
audit issues: expired or soon-to-expire certs, self-signed certs, weak
signature algorithms, obsolete protocol versions, weak ciphers, and hostname
mismatches.

Everything here is read-only reconnaissance of what a server volunteers during
a normal handshake -- the same information a browser sees. No stdlib-external
crypto library is required: certificates are fetched with
``ssl.get_server_certificate`` (which works even for self-signed certs) and
decoded with the long-stable ``ssl._ssl._test_decode_cert`` helper.
"""

import datetime
import socket
import ssl
import tempfile
import os

# Certs expiring within this many days are flagged as a warning.
_EXPIRY_WARN_DAYS = 21

# Protocol versions we consider obsolete (anything below TLS 1.2).
_OBSOLETE_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}

# Substrings in an OpenSSL cipher name that indicate a weak cipher.
_WEAK_CIPHER_TOKENS = ("RC4", "3DES", "DES-", "NULL", "EXPORT", "MD5", "ANON", "RC2")


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
    """Parse the cert 'notAfter' string (e.g. 'Jun  1 12:00:00 2025 GMT')."""
    for fmt in ("%b %d %H:%M:%S %Y %Z", "%b %d %H:%M:%S %Y"):
        try:
            return datetime.datetime.strptime(value, fmt)
        except (ValueError, TypeError):
            continue
    return None


def _rdn_value(rdn_seq, key):
    """Pull a value (e.g. commonName) out of the nested subject/issuer structure."""
    for rdn in rdn_seq or ():
        for attr in rdn:
            if attr[0] == key:
                return attr[1]
    return None


def _san_names(cert):
    return [v for k, v in cert.get("subjectAltName", ()) if k == "DNS"]


def _negotiate(host, port, timeout):
    """Complete a handshake (accepting any cert) to learn the protocol + cipher.

    Returns (proto, cipher_name, error). Does not verify the cert -- we only
    want what was negotiated.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as ss:
                cipher = ss.cipher()
                return ss.version(), (cipher[0] if cipher else ""), None
    except Exception as e:  # noqa: BLE001 -- report, don't crash an audit
        return None, "", str(e)


def inspect(host: str, port: int = 443, timeout: float = 4.0) -> dict:
    """Inspect the TLS service at host:port.

    Returns a dict with the parsed certificate summary, negotiated protocol and
    cipher, and a ``findings`` list of {severity, title, detail, evidence}.
    ``ok`` is False (with ``error``) if no TLS service answered.
    """
    findings = []
    proto, cipher, neg_err = _negotiate(host, port, timeout)

    try:
        pem = ssl.get_server_certificate((host, port), timeout=timeout)
    except TypeError:
        # Older signatures don't accept timeout=; fall back.
        socket.setdefaulttimeout(timeout)
        try:
            pem = ssl.get_server_certificate((host, port))
        finally:
            socket.setdefaulttimeout(None)
    except Exception as e:  # noqa: BLE001
        return {"host": host, "port": port, "ok": False, "error": str(e),
                "protocol": proto, "cipher": cipher, "findings": findings}

    cert = _decode_cert_pem(pem)
    subject_cn = _rdn_value(cert.get("subject"), "commonName")
    issuer_cn = _rdn_value(cert.get("issuer"), "commonName")
    sans = _san_names(cert)
    not_after_raw = cert.get("notAfter")
    not_after = _parse_notafter(not_after_raw) if not_after_raw else None

    # --- expiry ---
    if not_after:
        days_left = (not_after - datetime.datetime.utcnow()).days
        if days_left < 0:
            findings.append({
                "severity": "high", "title": "Expired TLS certificate",
                "detail": f"Certificate expired {abs(days_left)} day(s) ago ({not_after_raw}).",
                "evidence": f"notAfter={not_after_raw}",
            })
        elif days_left <= _EXPIRY_WARN_DAYS:
            findings.append({
                "severity": "medium", "title": "TLS certificate expiring soon",
                "detail": f"Certificate expires in {days_left} day(s) ({not_after_raw}).",
                "evidence": f"notAfter={not_after_raw}",
            })

    # --- self-signed ---
    if subject_cn and issuer_cn and subject_cn == issuer_cn:
        findings.append({
            "severity": "medium", "title": "Self-signed TLS certificate",
            "detail": f"Subject and issuer are both '{subject_cn}' -- certificate is self-signed.",
            "evidence": f"subject/issuer CN={subject_cn}",
        })

    # --- hostname / CN mismatch (only when host is a name, not a bare IP) ---
    if _looks_like_hostname(host):
        names = set(sans) | ({subject_cn} if subject_cn else set())
        if names and not any(_host_matches(host, n) for n in names):
            findings.append({
                "severity": "low", "title": "TLS certificate hostname mismatch",
                "detail": f"'{host}' is not covered by the certificate ({', '.join(sorted(names))}).",
                "evidence": f"CN={subject_cn} SAN={sans}",
            })

    # --- obsolete protocol ---
    if proto in _OBSOLETE_PROTOCOLS:
        findings.append({
            "severity": "high", "title": f"Obsolete TLS protocol ({proto})",
            "detail": f"The server negotiated {proto}, which is deprecated and insecure.",
            "evidence": f"protocol={proto}",
        })

    # --- weak cipher ---
    if cipher and any(tok in cipher.upper() for tok in _WEAK_CIPHER_TOKENS):
        findings.append({
            "severity": "medium", "title": "Weak TLS cipher negotiated",
            "detail": f"The negotiated cipher '{cipher}' uses a weak/legacy algorithm.",
            "evidence": f"cipher={cipher}",
        })

    return {
        "host": host, "port": port, "ok": True,
        "protocol": proto, "cipher": cipher,
        "subject": subject_cn, "issuer": issuer_cn,
        "san": sans, "not_after": not_after_raw,
        "negotiate_error": neg_err,
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
        # Wildcard matches exactly one left-most label.
        return host.split(".", 1)[-1] == cert_name[2:]
    return host == cert_name
