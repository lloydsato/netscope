# netscope

A CLI for analyzing your own local network. It discovers devices and
identifies them by vendor, fingerprints their services, scans for risky
exposed ports, captures live traffic and passively detects attacks against
your network, tracks everything over time, monitors continuously with
alerting, and renders a standalone HTML report.

Built for your own network / systems you're authorized to test. Scanning or
capturing traffic on networks or hosts you don't own or have permission to
assess is illegal in most places -- keep this pointed at your own LAN.

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

## What's new in 0.2

- **Device identification** -- every discovered MAC is resolved to its
  manufacturer using a bundled snapshot of the IEEE registry (~40k vendors,
  works fully offline). Randomized/private phone MACs are detected and labelled.
- **Service fingerprinting** -- grabs banners from open ports and makes a
  best-effort OS guess (Ubuntu, Windows, MikroTik, etc.).
- **Passive threat detection** in captured traffic:
  - **ARP-spoofing / MITM detection** -- flags when one IP (especially your
    gateway) is claimed by multiple MACs.
  - **Rogue DHCP detection** -- flags unexpected or multiple DHCP servers.
  - **Port-scan detection** -- flags hosts sending floods of half-open SYNs.
  - **Insecure-protocol detection** -- flags Telnet, FTP, and cleartext HTTP
    Basic auth in use (it reports *that* credentials are exposed and between
    which hosts -- it deliberately does **not** capture or print the credentials
    themselves).
  - Plus DNS-query extraction (top domains contacted) and per-host bandwidth.
- **Persistent history** -- devices and their open ports are tracked over time
  in a local SQLite database (`~/.netscope/netscope.db`).
- **Continuous monitoring** (`watch`) -- re-scans on an interval and alerts when
  a new device joins or a new port opens, with optional webhook notifications.
- **HTML reports** (`report`) -- a self-contained, offline network report.

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
netscope portscan 192.168.1.1 --fingerprint   # grab banners + guess OS
netscope portscan 192.168.1.1 --ports 8000-8100,3306
```

No root needed. Risky ports are flagged; `--fingerprint` adds service banners.

### `capture` -- capture traffic and detect threats

```bash
sudo netscope capture --duration 30
sudo netscope capture --iface eth0 --gateway 192.168.1.1
sudo netscope capture --filter "tcp port 443" --pcap out.pcap
```

Needs root. Prints protocol breakdown, top bandwidth, top DNS lookups, and a
**threat feed** of anything suspicious (ARP spoofing, rogue DHCP, port scans,
plaintext protocols). Pass `--gateway` to sharpen the ARP/DHCP checks. Add
`--pcap` to save a file for Wireshark.

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

- No root needed: `portscan`, `security --host`, `history`, and `discover --method sweep`.
- Root/admin needed (raw sockets): `discover` (ARP mode), `capture`, and
  `watch`/`report` when they discover via ARP or capture traffic. Use `sudo` on
  Linux/macOS, or an Administrator shell + [Npcap](https://npcap.com/) on Windows.

## JSON output

Most commands accept `--json` for structured output you can pipe elsewhere.

## Project layout

Each capability is a small, independently-usable module under `netscope/`:

| module | purpose |
|---|---|
| `discovery.py` | ARP scan + ping-sweep host discovery |
| `oui.py` | MAC to vendor lookup (bundled IEEE data) |
| `portscan.py` | threaded TCP connect scanning |
| `fingerprint.py` | banner grabbing + OS inference |
| `capture.py` | live packet capture + data collection |
| `analysis.py` | passive threat-detection heuristics |
| `security.py` | risky-port checks |
| `storage.py` | SQLite device/port history |
| `monitor.py` | continuous monitoring loop |
| `report.py` | standalone HTML report generation |
| `cli.py` | command-line interface |

`RISKY_PORTS` and `COMMON_PORTS` in `utils.py` are plain dicts you can extend.

## A note on the plaintext / credential detection

The insecure-protocol detector reports that cleartext authentication is
happening and between which hosts, so you can go fix it. It is intentionally
built to surface the *exposure*, not to decode, store, or display the actual
usernames and passwords -- this keeps it a defensive auditing tool rather than a
credential sniffer.
