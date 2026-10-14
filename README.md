# netscope

A CLI for auditing your own local network. It discovers devices and identifies
them by vendor, fingerprints their services down to **product + version**,
correlates what's running against a **bundled offline CVE database**, audits
**TLS certificates** and checks for **weak/default authentication**, scans for
risky exposed TCP/UDP ports, captures (or replays) traffic and passively
detects attacks -- including **C2 beaconing** and **DNS tunnelling** -- scores
everything into unified **findings** you can export as **JSON / NDJSON / CSV /
SARIF**, diffs one audit against the next, and renders a standalone HTML report.

Everything works **fully offline** (the only third-party dependency is scapy):
the CVE data, OUI vendor data, TLS parsing, and weak-auth probes all use bundled
data and the Python standard library -- suited to isolated audit environments.

Built for your own network / systems you're authorized to test. Scanning or
capturing traffic on networks or hosts you don't own or have permission to
assess is illegal in most places -- keep this pointed at your own LAN. The
weak-auth probes are deliberately **read-only**: they confirm that a service is
exposed with no/default credentials and read only an identity/version string --
they never enumerate, modify, or exfiltrate data.

## Install

```bash
pip install -r requirements.txt
pip install -e .        # installs the `netscope` command
```

Or run without installing:

```bash
python3 -m netscope.cli <command> ...
```

---

## What's new in 0.3 -- audit-grade upgrade

Built for security researchers and network auditors, all offline:

- **Version-aware fingerprinting + offline CVE correlation** -- banners are
  parsed for `product + version` (OpenSSH, Apache, nginx, vsftpd, Redis, Mongo,
  RouterOS, ...) and matched against a bundled vulnerability snapshot, so you
  see *"OpenSSH 7.2 -> CVE-2018-15473"*, not just *"port 22 open"*.
- **TLS / certificate auditing** -- expired / expiring / self-signed certs, weak
  protocols (< TLS 1.2) and ciphers, and hostname mismatches (`netscope tls`).
- **Weak / default-auth checks** -- read-only confirmation of anonymous FTP,
  unauthenticated Redis / MongoDB / Elasticsearch, and SNMP default community
  strings (`netscope snmp`).
- **UDP scanning + timing templates** -- `portscan --udp` and `-T 0..5`
  (stealthy .. fastest, nmap-style).
- **Advanced passive detection** -- adds **C2 beaconing** (regular-interval
  check-ins) and **DNS tunnelling** (long, high-entropy, high-volume subdomains)
  to the threat feed, plus TLS SNI extraction. `capture --read file.pcap`
  analyses an existing capture **offline, no root needed**.
- **Unified findings + risk scoring + export** -- every risk source becomes a
  severity-scored *finding*; get a 0-100 risk score per host and export the lot
  as **JSON / NDJSON / CSV / SARIF** (upload SARIF straight to code scanning).
- **Baseline diffing** -- `netscope diff` shows what changed between two audits
  (new vs. resolved findings), so you can track remediation over time.
- **`audit`** -- one flagship command that ties discovery, the deep audit,
  scoring, the HTML report, and export together.

### Still here from 0.2

- **Device identification** via a bundled IEEE OUI snapshot (~40k vendors;
  randomized/private phone MACs detected).
- **Passive threat detection**: ARP-spoofing/MITM, rogue DHCP, port scans, and
  insecure plaintext protocols (surfaces *that* creds are exposed, never the
  creds themselves), plus DNS + bandwidth summaries.
- **Persistent history** in SQLite (`~/.netscope/netscope.db`), **continuous
  monitoring** (`watch`) with webhook alerts, and standalone **HTML reports**.

---

## Commands

### `discover` -- find and identify devices

```bash
sudo netscope discover
netscope discover --method sweep              # no root, less reliable
sudo netscope discover --fingerprint          # add banner grab + OS guess
sudo netscope discover --names                # add hostname/model via mDNS, SSDP, NetBIOS
sudo netscope discover --save                 # record to history
```

Shows IP, MAC, and vendor for every device. ARP-based by default (needs root),
falls back to a TCP ping sweep.

`--names` adds a hostname and device model by asking the LAN directly (read-only,
stdlib UDP, no root needed for this step): **mDNS** (self-announced `.local`
names and service types), **SSDP/UPnP** (`friendlyName` / `modelName` /
`manufacturer` from the device's description document) and **NetBIOS** node
status (machine + workgroup name). Everything off the wire is untrusted: names are
sanitised, UPnP descriptions are only fetched from the host that announced them
and are never run through an XML parser, and results for IPs outside the audited
set are discarded. `audit` does this by default on subnet audits (`--no-names` to
skip; not run for `--host`), and turns exposed UPnP/SSDP (medium) and NetBIOS
(low) into findings. Hostnames are saved with `--save` and shown in `history`
and the HTML report.

### `portscan` -- check a host's open ports

```bash
netscope portscan 192.168.1.1
netscope portscan 192.168.1.1 --full          # all of 1-1024
netscope portscan 192.168.1.1 --fingerprint   # banners + product/version + OS
netscope portscan 192.168.1.1 --ports 8000-8100,3306
netscope portscan 192.168.1.1 --udp           # UDP sweep (best-effort)
netscope portscan 192.168.1.1 -T 1            # slower / stealthier (0..5)
```

No root needed. Risky ports are flagged; `--fingerprint` now reports the parsed
product/version. `-T/--timing` tunes concurrency, timeout, and jitter.

### `audit` -- the full deep audit (flagship)

```bash
sudo netscope audit                                   # discover + deep-audit all
netscope audit --host 192.168.1.1                     # one host, no root
netscope audit --save --diff                          # snapshot + compare to last
netscope audit --report audit.html --export sarif --export-out out.sarif
```

Discovers hosts, fingerprints each service for product/version, correlates
against the offline CVE DB, audits TLS, runs the read-only weak-auth probes,
and rolls it all into severity-scored findings with a **0-100 risk score** per
host and overall. `--report` also writes the HTML report; `--export` emits
`json`/`ndjson`/`csv`/`sarif`/`markdown`; `--save` records a snapshot for `diff`.

### `security` -- risky ports, or a deep audit

```bash
netscope security --host 192.168.1.1                  # port-number heuristics
netscope security --host 192.168.1.1 --deep           # + CVE / TLS / weak-auth
sudo netscope security --deep --save --export csv     # audit whole LAN, export
```

Without `--deep` it's the original fast risky-port sweep: it flags ports with a
known security history (Telnet, exposed Redis/Mongo, RDP, etc.) with a short
explanation of why each matters, and `--save` records the results. `--deep`
promotes it to the full finding-producing audit (same engine as `audit`).

### `tls` -- inspect a TLS service

```bash
netscope tls 192.168.1.1                              # defaults to :443
netscope tls mail.lan:993
```

Reports the certificate identity/expiry, negotiated protocol and cipher, and
flags expired/expiring/self-signed certs, weak signature algorithms (SHA-1/MD5),
hostname mismatches, weak ciphers, and **obsolete protocols**. Because a server
that speaks TLS 1.3 may *also* still accept TLS 1.0/1.1, those two versions are
probed individually with a deliberately permissive client -- so legacy-only
servers are audited rather than reported as "not TLS".

### `snmp` -- check for default community strings

```bash
netscope snmp 192.168.1.1
netscope snmp 192.168.1.1 --communities public,private,community
```

Flags a device that answers SNMP with a default community string (reads only
the system description as evidence). Each community is tried as both SNMPv1 and
v2c at once, replies are parsed and matched to the request (so an unrelated UDP
service can't produce a false hit), and a closed port returns immediately.

### `diff` -- what changed between two audits

```bash
netscope diff                                         # two most recent snapshots
netscope diff --old 3 --new 7 --export sarif
```

Shows **new** and **resolved** findings between saved snapshots -- track
remediation, or catch drift, over time. Snapshots come from `audit --save` or
`security --deep --save`.

By default a snapshot is compared with the previous snapshot **of the same
target** (same subnet / `--host`), so auditing several targets into one database
doesn't produce nonsense diffs. `--old` and `--new` must be given together and
must name existing snapshots; comparing different targets prints a warning.
Findings whose text changes daily (e.g. "certificate expires in N days") keep a
stable identity, so they aren't reported as new + resolved every run.

### `capture` -- capture traffic and detect threats

```bash
sudo netscope capture --duration 30
sudo netscope capture --iface eth0 --gateway 192.168.1.1
sudo netscope capture --filter "tcp port 443" --pcap out.pcap
netscope capture --read existing.pcap                 # offline analysis, no root
```

Prints protocol breakdown, top bandwidth, top DNS lookups, top TLS destinations
(SNI), and a **threat feed** of anything suspicious (ARP spoofing, rogue DHCP,
port scans, plaintext protocols, **C2 beaconing**, **DNS tunnelling**). Port scans are recognised by *spread* (many ports on one host, or one
non-web port across many hosts), not by raw SYN counts, and cleartext
Telnet/FTP is only reported once data actually flows. Captured names (DNS, SNI)
are sanitised before display. Detection is IPv4-only (IPv6 traffic is counted
but not analysed). Live capture needs root; `--read FILE.pcap` runs every
detection on an existing capture with **no root required**. Pass `--gateway` to sharpen the ARP/DHCP
checks and `--pcap` to save a file for Wireshark.

### `watch` -- continuous monitoring with alerts

```bash
sudo netscope watch --interval 60                     # until Ctrl-C
sudo netscope watch --rounds 10 --scan-ports          # also alert on new ports
sudo netscope watch --webhook https://hooks.slack.com/services/XXX
```

Re-discovers on each interval, diffs against history, and alerts on new devices
and (with `--scan-ports`) newly-opened ports. Alerts print, get logged to the
event history, and can be POSTed to a Slack/Discord/ntfy webhook (`http(s)://`
only; a failing webhook is reported once on stderr, never silently).

The first run against an empty database only **establishes a baseline** (no
alerts for devices that were already there), and a device's open ports are only
compared once they have been recorded at least once. `--scan-ports` checks the
same ~40 common ports as `portscan`'s default -- a listener on an arbitrary high
port won't be noticed. A transient error mid-run is logged and retried on the
next round instead of ending the monitor.

### `report` -- generate an HTML report

```bash
sudo netscope report -o home-network.html
sudo netscope report --capture-seconds 30 --gateway 192.168.1.1 -o report.html
```

Discovers + scans + fingerprints every device and writes a standalone HTML
report (opens offline, no external assets). Add `--capture-seconds N` to also
run a passive capture and include the threat feed.

### `history` -- review what's been recorded

```bash
netscope history                 # devices, with first/last seen
netscope history --events        # the event log (new devices, new ports, alerts)
```

---

## Permissions

- No root needed: `portscan` (TCP and UDP), `security` / `audit --host`, `tls`,
  `snmp`, `diff`, `history`, `capture --read`, and `discover --method sweep`.
- Root/admin needed (raw sockets): `discover` (ARP mode), live `capture`, and
  `watch`/`report`/`audit` when they discover via ARP or capture live traffic.
  Use `sudo` on Linux/macOS, or an Administrator shell +
  [Npcap](https://npcap.com/) on Windows.

Note: `portscan --udp` relies on ICMP port-unreachable messages to mark ports
closed; on hosts/paths that rate-limit or drop ICMP, closed ports show as
`open|filtered` (the usual UDP-scanning caveat).

## JSON output

Most commands accept `--json` for structured output you can pipe elsewhere
(`netscope portscan 192.168.1.1 --json | jq`). With `--json` -- or with
`--export FORMAT` and no `--export-out` -- **stdout carries only the payload**;
all progress and summary text goes to stderr. Empty results are still valid
documents (`[]`, or an object with empty lists). `--json` and a stdout `--export`
can't be combined (use `--export-out FILE`). Exit codes: `0` ok, `1` runtime
error (printed as `Error: ...`), `2` bad arguments, `130` interrupted.

## Project layout

Each capability is a small, independently-usable module under `netscope/`:

| module | purpose |
|---|---|
| `discovery.py` | ARP scan + ping-sweep host discovery |
| `oui.py` | MAC to vendor lookup (bundled IEEE data) |
| `nameservices.py` | hostname/model discovery via mDNS, SSDP/UPnP, NetBIOS |
| `portscan.py` | threaded TCP connect + UDP scanning, timing templates |
| `fingerprint.py` | banner grabbing + product/version + OS inference |
| `vulndb.py` | offline CVE correlation (bundled `data/vulns.json.gz`) |
| `tlsaudit.py` | TLS certificate + protocol/cipher auditing (stdlib `ssl`) |
| `probes.py` | read-only weak/default-auth checks (SNMP/FTP/Redis/Mongo/ES) |
| `capture.py` | live capture / offline pcap replay + data collection |
| `analysis.py` | passive threat detection (ARP/DHCP/scan/beacon/DNS-tunnel) |
| `security.py` | risky-port checks + the deep audit pipeline |
| `findings.py` | unified findings model, risk scoring, JSON/CSV/SARIF/Markdown export |
| `remediation.py` | static "how do I fix it" advice attached to every finding |
| `storage.py` | SQLite device/port history + audit snapshots for diffing |
| `monitor.py` | continuous monitoring loop |
| `report.py` | standalone HTML report generation |
| `cli.py` | command-line interface |

`RISKY_PORTS`, `COMMON_PORTS`, and `COMMON_UDP_PORTS` in `utils.py` are plain
dicts/sets you can extend. The bundled CVE snapshot is generated from the
curated list in `scripts/build_vulndb.py` -- edit it and re-run to regenerate
`netscope/data/vulns.json.gz`.

## Findings export & CI

Every finding carries a `remediation` field -- static, per-category advice on
what to do about it (renew the certificate, disable Telnet, set `requirepass`,
...). It appears in the JSON/NDJSON/CSV/Markdown exports, in SARIF
`properties.remediation`, and in the HTML report. It is not part of a finding's
identity, so improving the wording never changes `diff` or suppression results.
`--export markdown` renders a readable report grouped by host, with all
network-derived text escaped so a hostile banner can't forge headings or links.

`audit`, `security --deep`, and `diff` accept `--export {json,ndjson,csv,sarif,markdown}`
(with `--export-out FILE`). SARIF 2.1.0 output (validated against the
official schema) can be uploaded to GitHub code scanning, so a scheduled
`netscope audit --export sarif` becomes a network posture check in CI. Network
findings have no source file, so each result is anchored to a synthetic location
`netscope/<host>/<port>` (code scanning only displays results that have one) and
carries a `partialFingerprints` id so alerts track across runs.

## A note on the plaintext / credential detection

The insecure-protocol detector reports that cleartext authentication is
happening and between which hosts, so you can go fix it. It is intentionally
built to surface the *exposure*, not to decode, store, or display the actual
usernames and passwords -- this keeps it a defensive auditing tool rather than a
credential sniffer.

## Accuracy notes & known limitations

netscope is an auditing aid, not an oracle. Things to keep in mind when reading
its output:

- **CVE matching is banner-based.** A distro that backports a fix (Debian,
  Ubuntu, RHEL) keeps the old version string, so a patched `OpenSSH 7.4p1` still
  matches advisories for 7.4. Treat CVE findings as "verify this", not proof. The
  bundled snapshot is small and curated; each record's affected range was checked
  against NVD (nginx against the vendor's own advisory). Regenerate with
  `python scripts/build_vulndb.py`; a test keeps the shipped file in sync with
  that script.
- **Version detection needs a version to be advertised.** Products are only
  identified from banners (SSH/FTP/SMTP greetings, HTTP `Server:` headers, Redis
  `INFO`, the Elasticsearch root document, MikroTik banners). Hardened services
  that hide their version, and MongoDB (whose version isn't in any banner), report
  no version -- so no CVE correlation for them. HTTP(S) servers on non-standard
  ports are found by an HTTP fallback probe.
- **Weak-auth probes only report what they confirm.** MongoDB is checked with
  `hostInfo`, which needs authentication on a secured server -- `isMaster` is
  answered by every mongod and proves nothing. Timeouts, auth-required replies and
  malformed data produce *no* finding rather than a guess.
- **IPv4 only.** Discovery, scanning and capture analysis are IPv4. Subnets larger
  than a /16 are refused. Default subnet auto-detection assumes a /24.
- **Discovery.** ARP needs root. The non-root TCP sweep treats a refused (RST)
  connection as "host is up", but silently-dropping hosts are missed.
- **Passive detection is heuristic.** Beaconing, DNS-tunnelling, port-scan and
  ARP-spoof checks can false-positive on unusual-but-legitimate traffic (VRRP,
  proxy ARP, DHCP servers that aren't the gateway when `--gateway` is given).
