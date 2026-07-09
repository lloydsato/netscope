#!/usr/bin/env python3
"""Build netscope's bundled offline vulnerability snapshot.

Writes ``netscope/data/vulns.json.gz`` from the curated ``RECORDS`` and
``WEAK_DEFAULTS`` below. netscope is a defensive auditing aid, not a full
vulnerability scanner, so this is a deliberately small, high-signal set of
well-known issues for the services netscope fingerprints -- enough to catch the
"you're running something years out of date and internet-known-bad" cases.

Each record: {product, affected (version predicate), cve, cvss, severity?,
title, description, ref}. Version predicates are evaluated by
``netscope.vulndb._version_match`` ("<7.7", ">=3.0,<3.4", "*", "==2.4.49").

Run: ``python scripts/build_vulndb.py``
"""

import gzip
import json
import os

RECORDS = [
    # ---- OpenSSH ----
    {
        "product": "openssh", "affected": "<7.7", "cve": "CVE-2018-15473",
        "cvss": 5.3, "title": "OpenSSH username enumeration",
        "description": "Pre-7.7 OpenSSH allows remote username enumeration via "
                       "malformed authentication requests.",
        "ref": "https://nvd.nist.gov/vuln/detail/CVE-2018-15473",
    },
    {
        "product": "openssh", "affected": "<9.3p2", "cve": "CVE-2023-38408",
        "cvss": 9.8, "title": "OpenSSH ssh-agent forwarded PKCS#11 RCE",
        "description": "Remote code execution via forwarded ssh-agent PKCS#11 "
                       "provider loading in versions before 9.3p2.",
        "ref": "https://nvd.nist.gov/vuln/detail/CVE-2023-38408",
    },
    {
        "product": "openssh", "affected": ">=8.5p1,<9.8p1", "cve": "CVE-2024-6387",
        "cvss": 8.1, "title": "OpenSSH regreSSHion signal-handler RCE",
        "description": "Unauthenticated remote code execution (regreSSHion) via a "
                       "signal handler race in sshd, 8.5p1 up to before 9.8p1.",
        "ref": "https://nvd.nist.gov/vuln/detail/CVE-2024-6387",
    },
    # ---- Apache httpd ----
    {
        "product": "apache_http_server", "affected": "==2.4.49", "cve": "CVE-2021-41773",
        "cvss": 7.5, "title": "Apache httpd path traversal / RCE (2.4.49)",
        "description": "Path traversal and file disclosure (RCE with mod_cgi) in "
                       "Apache HTTP Server 2.4.49.",
        "ref": "https://nvd.nist.gov/vuln/detail/CVE-2021-41773",
    },
    {
        "product": "apache_http_server", "affected": "<=2.4.50", "cve": "CVE-2021-42013",
        "cvss": 9.8, "title": "Apache httpd path traversal / RCE (2.4.50)",
        "description": "Incomplete fix for CVE-2021-41773; traversal and RCE "
                       "through 2.4.50.",
        "ref": "https://nvd.nist.gov/vuln/detail/CVE-2021-42013",
    },
    # ---- nginx ----
    {
        "product": "nginx", "affected": ">=0.5.6,<1.13.6", "cve": "CVE-2017-7529",
        "cvss": 7.5, "title": "nginx range filter integer overflow",
        "description": "Integer overflow in the range filter can leak cached file "
                       "contents; fixed in 1.13.6 / 1.12.1.",
        "ref": "https://nvd.nist.gov/vuln/detail/CVE-2017-7529",
    },
    # ---- vsftpd ----
    {
        "product": "vsftpd", "affected": "==2.3.4", "cve": "CVE-2011-2523",
        "cvss": 9.8, "title": "vsftpd 2.3.4 backdoor",
        "description": "The 2.3.4 tarball was trojaned with a backdoor that opens "
                       "a root shell on port 6200.",
        "ref": "https://nvd.nist.gov/vuln/detail/CVE-2011-2523",
    },
    # ---- ProFTPD ----
    {
        "product": "proftpd", "affected": ">=1.3.5,<1.3.5a", "cve": "CVE-2015-3306",
        "cvss": 10.0, "title": "ProFTPD mod_copy unauthenticated RCE",
        "description": "SITE CPFR/CPTO in mod_copy lets unauthenticated users "
                       "copy files, leading to remote code execution.",
        "ref": "https://nvd.nist.gov/vuln/detail/CVE-2015-3306",
    },
    # ---- Exim ----
    {
        "product": "exim", "affected": ">=4.87,<4.91", "cve": "CVE-2019-10149",
        "cvss": 9.8, "title": "Exim 'Return of the Wizard' RCE",
        "description": "Improper validation of the recipient address allows remote "
                       "command execution (4.87 through 4.91).",
        "ref": "https://nvd.nist.gov/vuln/detail/CVE-2019-10149",
    },
    # ---- Redis ----
    {
        "product": "redis", "affected": "<7.0.12", "cve": "CVE-2023-28425",
        "cvss": 6.5, "title": "Redis MSETNX denial of service",
        "description": "A specially crafted MSETNX command can crash the server "
                       "in versions before 7.0.12.",
        "ref": "https://nvd.nist.gov/vuln/detail/CVE-2023-28425",
    },
    # ---- Elasticsearch ----
    {
        "product": "elasticsearch", "affected": ">=1.2.0,<1.6.1", "cve": "CVE-2015-1427",
        "cvss": 9.8, "title": "Elasticsearch Groovy sandbox RCE",
        "description": "The Groovy scripting engine sandbox can be bypassed for "
                       "remote code execution (1.2.0 through 1.6.0).",
        "ref": "https://nvd.nist.gov/vuln/detail/CVE-2015-1427",
    },
    # ---- MongoDB ----
    {
        "product": "mongodb", "affected": "<2.6.0", "cve": "CVE-2013-1892",
        "cvss": 8.5, "title": "MongoDB nativeHelper RCE",
        "description": "The nativeHelper.apply function permits arbitrary code "
                       "execution against pre-2.6 servers.",
        "ref": "https://nvd.nist.gov/vuln/detail/CVE-2013-1892",
    },
    # ---- MikroTik RouterOS ----
    {
        "product": "routeros", "affected": ">=6.29,<6.42.1", "cve": "CVE-2018-14847",
        "cvss": 9.1, "title": "MikroTik Winbox path traversal (credential disclosure)",
        "description": "Winbox allows unauthenticated remote attackers to read "
                       "files including the user database (Chimay Red / VPNFilter).",
        "ref": "https://nvd.nist.gov/vuln/detail/CVE-2018-14847",
    },
]

# Products that historically shipped with no / trivial authentication, flagged
# whenever they're seen network-exposed regardless of version.
WEAK_DEFAULTS = {
    "redis": "Redis historically ships with no authentication -- if reachable "
             "off-host, anyone on the network can read/write all data.",
    "mongodb": "MongoDB historically bound to all interfaces with no auth -- "
               "verify authorization is enabled and it isn't internet-facing.",
    "elasticsearch": "Elasticsearch has no authentication in its default open "
                     "distribution -- exposed nodes leak/allow modification of all indices.",
}


def build():
    data = {"records": RECORDS, "weak_defaults": WEAK_DEFAULTS,
            "note": "Curated offline snapshot for netscope; not exhaustive."}
    out_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                           "netscope", "data")
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, "vulns.json.gz")
    raw = json.dumps(data, separators=(",", ":")).encode("utf-8")
    with gzip.open(out_path, "wb") as f:
        f.write(raw)
    print(f"Wrote {out_path} ({len(RECORDS)} records, {len(raw)} bytes uncompressed JSON)")


if __name__ == "__main__":
    build()
