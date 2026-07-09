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
sudo netscope discover --save                 # record to history
```

Shows IP, MAC, and vendor for every device. ARP-based by default (needs root),
falls back to a TCP ping sweep.

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
`json`/`ndjson`/`csv`/`sarif`; `--save` records a snapshot for `diff`.

### `security` -- risky ports, or a deep audit

```bash
netscope security --host 192.168.1.1                  # port-number heuristics
netscope security --host 192.168.1.1 --deep           # + CVE / TLS / weak-auth
sudo netscope security --deep --save --export csv     # audit whole LAN, export
```

Without `--deep` it's the original fast risky-port sweep. `--deep` promotes it
to the full finding-producing audit (same engine as `audit`).

### `tls` -- inspect a TLS service

```bash
netscope tls 192.168.1.1                              # defaults to :443
netscope tls mail.lan:993
```

Reports the certificate identity/expiry, negotiated protocol and cipher, and
flags expired/self-signed certs, obsolete protocols, and weak ciphers.

### `snmp` -- check for default community strings

```bash
netscope snmp 192.168.1.1
netscope snmp 192.168.1.1 --communities public,private,community
```

Flags a device that answers SNMP with a default community string (reads only
the system description as evidence).

### `diff` -- what changed between two audits

```bash
netscope diff                                         # two most recent snapshots
netscope diff --old 3 --new 7 --export sarif
```

Shows **new** and **resolved** findings between saved snapshots -- track
remediation, or catch drift, over time. Snapshots come from `audit --save` or
`security --deep --save`.

### `capture` -- capture traffic and detect threats

```bash
sudo netscope capture --duration 30
sudo netscope capture --iface eth0 --gateway 192.168.1.1
sudo netscope capture --filter "tcp port 443" --pcap out.pcap
netscope capture --read existing.pcap                 # offline analysis, no root
```

Prints protocol breakdown, top bandwidth, top DNS lookups, top TLS destinations
(SNI), and a **threat feed** of anything suspicious (ARP spoofing, rogue DHCP,
port scans, plaintext protocols, **C2 beaconing**, **DNS tunnelling**). Live
capture needs root; `--read FILE.pcap` runs every detection on an existing
capture with **no root required**. Pass `--gateway` to sharpen the ARP/DHCP
checks and `--pcap` to save a file for Wireshark.

### `watch` -- continuous monitoring with alerts

```bash
sudo netscope watch --interval 60                     # until Ctrl-C
sudo netscope watch --rounds 10 --scan-ports          # also alert on new ports
sudo netscope watch --webhook https://hooks.slack.com/services/XXX
```

Re-discovers on each interval, diffs against history, and alerts on new devices
and (with `--scan-ports`) newly-opened ports. Alerts print, get logged to the
event history, and can be POSTed to a Slack/Discord/ntfy webhook.

### `security` -- sweep for risky exposed ports

```bash
sudo netscope security                        # discover + scan every host
netscope security --host 192.168.1.1          # one host, no root
sudo netscope security --save                 # record results
```

Flags ports with a known security history (Telnet, exposed Redis/Mongo, RDP,
etc.) with a short explanation of why each matters.

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

Most commands accept `--json` for structured output you can pipe elsewhere.

## Project layout

Each capability is a small, independently-usable module under `netscope/`:

| module | purpose |
|---|---|
| `discovery.py` | ARP scan + ping-sweep host discovery |
| `oui.py` | MAC to vendor lookup (bundled IEEE data) |
| `portscan.py` | threaded TCP connect + UDP scanning, timing templates |
| `fingerprint.py` | banner grabbing + product/version + OS inference |
| `vulndb.py` | offline CVE correlation (bundled `data/vulns.json.gz`) |
| `tlsaudit.py` | TLS certificate + protocol/cipher auditing (stdlib `ssl`) |
| `probes.py` | read-only weak/default-auth checks (SNMP/FTP/Redis/Mongo/ES) |
| `capture.py` | live capture / offline pcap replay + data collection |
| `analysis.py` | passive threat detection (ARP/DHCP/scan/beacon/DNS-tunnel) |
| `security.py` | risky-port checks + the deep audit pipeline |
| `findings.py` | unified findings model, risk scoring, JSON/CSV/SARIF export |
| `storage.py` | SQLite device/port history + audit snapshots for diffing |
| `monitor.py` | continuous monitoring loop |
| `report.py` | standalone HTML report generation |
| `cli.py` | command-line interface |

`RISKY_PORTS`, `COMMON_PORTS`, and `COMMON_UDP_PORTS` in `utils.py` are plain
dicts/sets you can extend. The bundled CVE snapshot is generated from the
curated list in `scripts/build_vulndb.py` -- edit it and re-run to regenerate
`netscope/data/vulns.json.gz`.

## Findings export & CI

`audit`, `security --deep`, and `diff` accept `--export {json,ndjson,csv,sarif}`
(with `--export-out FILE`). SARIF 2.1.0 output can be uploaded to GitHub code
scanning, so a scheduled `netscope audit --export sarif` becomes a network
posture check in CI.

## A note on the plaintext / credential detection

The insecure-protocol detector reports that cleartext authentication is
happening and between which hosts, so you can go fix it. It is intentionally
built to surface the *exposure*, not to decode, store, or display the actual
usernames and passwords -- this keeps it a defensive auditing tool rather than a
credential sniffer.
