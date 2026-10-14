"""Remediation guidance: "what do I do about it?" for each kind of finding.

Kept separate from the checks themselves so the advice can be improved without
touching detection logic, and so every finding source (risky ports, CVEs, TLS,
weak-auth, name services, passive traffic alerts) gets it from one place.
``findings.make_finding`` calls :func:`for_finding` when a producer doesn't
supply its own text. The text is static -- never derived from network data.
"""

_PORT_FIX = {
    21: "Replace FTP with SFTP or FTPS, or disable it. If it must stay, restrict it to trusted hosts with a firewall.",
    23: "Disable Telnet and use SSH instead. Firewall port 23 from untrusted networks.",
    111: "Disable rpcbind if NFS/NIS aren't in use, or firewall it to trusted hosts only.",
    139: "Disable NetBIOS over TCP/IP and legacy SMB1; firewall 139 from untrusted networks.",
    445: "Patch SMB, disable SMB1, and firewall 445 so it is reachable only from hosts that need file sharing.",
    1433: "Bind MSSQL to a private interface and firewall 1433 to the application servers that need it.",
    1723: "Migrate off PPTP to WireGuard, OpenVPN or IKEv2/IPsec, then disable PPTP.",
    3306: "Bind MySQL to localhost or a private interface and firewall 3306 to the application servers that need it.",
    3389: "Put RDP behind a VPN or gateway, enable Network Level Authentication, and never expose 3389 to the internet.",
    5432: "Bind Postgres to a private interface, restrict pg_hba.conf, and firewall 5432 to the application servers that need it.",
    5900: "Require a strong VNC password or, better, tunnel VNC through SSH/VPN; firewall 5900 from untrusted networks.",
    6379: "Set requirepass or ACLs, bind Redis to localhost/private interfaces, and firewall 6379.",
    27017: "Enable MongoDB authorization, bind to trusted interfaces only, and firewall 27017.",
}

_PORT_FALLBACK = ("Close or firewall this port if the service isn't needed, and restrict it to trusted "
                  "hosts if it is.")

_CVE = ("Upgrade to a release that fixes this issue. Distributions often backport fixes without changing "
        "the version string, so check your distro's security tracker or package changelog before "
        "treating it as confirmed.")

# (substring of lower-cased title, advice) -- first match wins.
_TLS = [
    ("expired", "Renew the certificate now and automate renewal (for example with ACME)."),
    ("expiring", "Renew the certificate before it expires and automate renewal (for example with ACME)."),
    ("self-signed", "Install a certificate from a trusted CA (or your internal CA) and distribute that root to clients."),
    ("hostname mismatch", "Reissue the certificate with the name or IP that clients actually connect to in its SAN."),
    ("signature algorithm", "Reissue the certificate with a SHA-256 (or stronger) signature."),
    ("obsolete tls", "Disable SSLv3/TLS 1.0/TLS 1.1 in the server configuration and require TLS 1.2 or newer."),
    ("cipher", "Disable RC4, 3DES, export and NULL ciphers; prefer AEAD suites (AES-GCM, ChaCha20-Poly1305)."),
]

_WEAK_AUTH = [
    ("anonymous ftp", "Disable anonymous login in the FTP server config, or move to SFTP with real accounts."),
    ("redis", "Set requirepass or ACLs, bind Redis to localhost/private interfaces, and firewall port 6379."),
    ("mongodb", "Enable authorization (security.authorization: enabled), bind to trusted interfaces only, and firewall 27017."),
    ("elasticsearch", "Enable Elasticsearch security (authentication and TLS) and don't expose 9200 to untrusted networks."),
    ("snmp", "Change the community strings, prefer SNMPv3 with authentication and encryption, and restrict SNMP by source address."),
]

_NAME_SERVICE = [
    ("upnp", "Disable UPnP on the device and the router if it isn't needed, and block udp/1900 at the perimeter."),
    ("netbios", "Disable NetBIOS over TCP/IP (adapter settings or DHCP option 001) and LLMNR where they aren't required."),
]

_TRAFFIC = {
    "traffic-arp": "Use static ARP entries or Dynamic ARP Inspection for the gateway, and investigate the MAC making the conflicting claim.",
    "traffic-dhcp": "Enable DHCP snooping on your switches and remove the unauthorized DHCP server.",
    "traffic-scan": "Identify the scanning host. If it isn't an approved scanner, isolate it and check it for compromise.",
    "traffic-beacon": "Investigate the source host for malware, check the destination's reputation, and block the egress if malicious.",
    "traffic-dns-tunnel": "Investigate the source host and restrict outbound DNS to your own resolvers.",
    "traffic-plaintext": "Replace the cleartext protocol with its encrypted equivalent (SSH, HTTPS, SFTP/FTPS, IMAPS) and rotate any credentials that crossed the wire.",
}

_WEAK_DEFAULT = ("Enable authentication, bind the service to a private interface, and follow the product's "
                 "hardening guide before exposing it to the network.")


def _first(rules, title):
    t = (title or "").lower()
    for needle, advice in rules:
        if needle in t:
            return advice
    return ""


def for_finding(category, title="", port=None):
    """Return remediation text for a finding, or "" if there's no useful advice."""
    if category == "exposed-port":
        return _PORT_FIX.get(port, _PORT_FALLBACK)
    if category == "cve":
        return _CVE
    if category == "tls":
        return _first(_TLS, title)
    if category == "weak-auth":
        return _first(_WEAK_AUTH, title)
    if category == "weak-default":
        return _WEAK_DEFAULT
    if category == "name-service":
        return _first(_NAME_SERVICE, title)
    return _TRAFFIC.get(category, "")
