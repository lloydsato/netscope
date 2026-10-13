"""Live traffic capture and analysis, built on scapy.

Needs root/administrator, same as any packet sniffer (tcpdump, Wireshark).
Beyond a basic protocol/talker summary, this collects data used by
netscope.analysis for passive threat detection: per-host bandwidth, DNS
queries, ARP mappings (ARP-spoof detection), DHCP servers (rogue-DHCP
detection), and use of insecure plaintext protocols.
"""

import collections
import os
import time

from .utils import is_root, shannon_entropy, safe_text
from . import analysis

# Long captures on busy networks must not grow memory without bound: hostile or
# merely chatty traffic can produce millions of distinct names / flows.
_MAX_DNS_NAMES = 50_000          # distinct qnames tracked for the "top DNS" list
_MAX_DNS_PARENTS = 20_000        # distinct parent domains tracked for tunnelling stats
_MAX_UNIQUE_PER_PARENT = 5_000   # unique subdomains counted per parent (saturates)
_MAX_LABELS_PER_PARENT = 8       # longest labels kept per parent
_MAX_FLOWS = 100_000             # distinct (src,dst,dport) beacon timelines
_MAX_TIMES_PER_FLOW = 500        # timestamps kept per timeline
_MAX_SCAN_SOURCES = 5_000        # sources tracked for port-scan spread

# Second-level labels that, under a 2-letter country TLD, are part of the public
# suffix (bbc.co.uk, example.com.au): the registrable domain has 3 labels there.
_SLD_UNDER_CCTLD = {"co", "com", "org", "net", "gov", "edu", "ac", "ne", "or",
                    "go", "gob", "mil", "sch", "ltd", "plc", "me", "nom"}


def capture(
    iface: str = None,
    duration: int = 15,
    bpf_filter: str = None,
    pcap_out: str = None,
    max_packets: int = 0,
    gateway_ip: str = None,
    read_pcap: str = None,
):
    """Sniff for `duration` seconds (or `max_packets` packets, whichever first)
    and return a rich summary dict. Optionally write a .pcap for Wireshark.

    Pass ``read_pcap`` to analyse an existing capture file offline instead of
    sniffing live -- this needs no root and is how the same threat detections
    can be run against captures collected elsewhere (or in tests).
    """
    try:
        from scapy.all import (
            sniff, PcapReader, PcapWriter, IP, IPv6, TCP, UDP, ICMP, ARP, DNS, DNSQR, Raw,
        )
        try:
            from scapy.layers.dhcp import DHCP
            _have_dhcp = True
        except Exception:
            _have_dhcp = False
    except ImportError as e:
        raise RuntimeError(
            "scapy is required for capture. Install with: pip install scapy"
        ) from e

    offline = read_pcap is not None
    if offline and not os.path.isfile(read_pcap):
        raise RuntimeError(f"Cannot read pcap '{read_pcap}': no such file")
    if not offline and is_root() is False:
        raise RuntimeError(
            "Packet capture needs raw socket access. Re-run with sudo (Linux/macOS) "
            "or as Administrator (Windows, with Npcap installed). To analyse an "
            "existing capture instead, use --read FILE.pcap (no root needed)."
        )

    total_packets = 0
    writer = None
    if pcap_out:
        try:
            writer = PcapWriter(pcap_out)   # streamed to disk: no need to hold every packet
        except OSError as e:
            raise RuntimeError(f"Cannot write pcap '{pcap_out}': {e}") from e
    proto_counts = collections.Counter()
    talkers = collections.Counter()          # packets per src
    bandwidth = collections.Counter()         # bytes per host (src or dst)
    conversations = collections.Counter()
    syn_targets = {}                          # src -> {dst: {dport,...}} (port-scan spread)
    dns_queries = collections.Counter()       # domain -> count
    ip_to_macs = collections.defaultdict(set) # ip -> {mac,...}  (ARP-spoof detection)
    dhcp_servers = {}                         # server_ip -> mac
    insecure = []                             # list of {proto, src, dst}
    _insecure_seen = set()                    # dedupe (proto, src, dst)
    conn_times = {}                           # (src,dst,dport) -> [ts,...] beaconing
    dns_stats = {}                            # parent domain -> tunnelling stats
    sni_hosts = collections.Counter()         # TLS SNI hostname -> count

    def note_insecure(proto, src, dst):
        key = (proto, src, dst)
        if key not in _insecure_seen:
            _insecure_seen.add(key)
            insecure.append({"proto": proto, "src": src, "dst": dst})

    def note_dns(qname, qtype):
        parent = _parent_domain(qname)
        st = dns_stats.get(parent)
        if st is None:
            if len(dns_stats) >= _MAX_DNS_PARENTS:
                return
            st = dns_stats[parent] = {"count": 0, "labels": [], "unique_set": set(),
                                      "max_entropy": 0.0, "txt": 0}
        st["count"] += 1
        if len(st["unique_set"]) < _MAX_UNIQUE_PER_PARENT:
            st["unique_set"].add(qname)
        longest = max(qname.split("."), key=len, default="")
        labels = st["labels"]
        if len(labels) < _MAX_LABELS_PER_PARENT:
            labels.append(longest)
        elif len(longest) > min(len(l) for l in labels):
            labels[min(range(len(labels)), key=lambda i: len(labels[i]))] = longest
        st["max_entropy"] = max(st["max_entropy"], shannon_entropy(longest))
        if qtype in (16, 10):  # TXT / NULL are tunnelling-associated
            st["txt"] += 1

    def note_sni(pkt_bytes):
        host = safe_text(_extract_sni(pkt_bytes))
        if host:
            sni_hosts[host] += 1

    def note_syn(src, dst, dport, ts):
        targets = syn_targets.get(src)
        if targets is None:
            if len(syn_targets) >= _MAX_SCAN_SOURCES:
                return
            targets = syn_targets[src] = {}
        targets.setdefault(dst, set()).add(dport)
        key = (src, dst, dport)
        times = conn_times.get(key)
        if times is None:
            if len(conn_times) >= _MAX_FLOWS:
                return
            times = conn_times[key] = []
        if len(times) < _MAX_TIMES_PER_FLOW:
            times.append(ts)

    def handle(pkt):
        nonlocal total_packets
        total_packets += 1
        if writer is not None:
            writer.write(pkt)
        size = len(pkt)
        ts = float(getattr(pkt, "time", 0)) or time.time()

        if ARP in pkt:
            # Record who claims which IP (op==2 is a reply; requests also carry psrc/hwsrc)
            psrc = pkt[ARP].psrc
            hwsrc = pkt[ARP].hwsrc
            if psrc and hwsrc and psrc != "0.0.0.0":
                ip_to_macs[psrc].add(hwsrc)

        if IP in pkt:
            src, dst = pkt[IP].src, pkt[IP].dst
            talkers[src] += 1
            bandwidth[src] += size
            bandwidth[dst] += size
            conversations[tuple(sorted((src, dst)))] += 1

            if TCP in pkt:
                proto_counts["TCP"] += 1
                flags = pkt[TCP].flags
                sport, dport = pkt[TCP].sport, pkt[TCP].dport
                if flags & 0x02 and not flags & 0x10:   # SYN and not ACK -> new conn attempt
                    note_syn(src, dst, dport, ts)       # port-scan spread + beaconing timeline
                if Raw in pkt:
                    try:
                        payload = bytes(pkt[Raw].load)
                    except Exception:
                        payload = b""
                    # Telnet / FTP control channels are cleartext by definition -- but
                    # only once data actually flows. A bare SYN/RST (a port scan, or
                    # netscope's own portscan) is not a session. Report client -> server.
                    if payload:
                        for svc_port, proto in ((23, "Telnet"), (21, "FTP")):
                            if dport == svc_port:
                                note_insecure(proto, src, dst)
                            elif sport == svc_port:
                                note_insecure(proto, dst, src)
                    # HTTP Basic auth over cleartext -- look for the header, do NOT decode it.
                    if ((80 in (sport, dport) or 8080 in (sport, dport))
                            and b"authorization: basic" in payload.lower()):
                        note_insecure("HTTP Basic auth (cleartext)", src, dst)
                    # TLS ClientHello SNI (destination hostname; no decryption)
                    if 443 in (sport, dport) and payload[:1] == b"\x16":
                        note_sni(payload)

            elif UDP in pkt:
                proto_counts["UDP"] += 1
                # DNS query extraction
                if DNS in pkt and pkt[DNS].qr == 0 and pkt[DNS].qd is not None:
                    try:
                        qname = safe_text(pkt[DNSQR].qname.decode("latin-1", "replace").rstrip("."))
                        qtype = int(getattr(pkt[DNSQR], "qtype", 0))
                        if qname:
                            if qname in dns_queries or len(dns_queries) < _MAX_DNS_NAMES:
                                dns_queries[qname] += 1
                            note_dns(qname, qtype)
                    except Exception:
                        pass
                # Rogue DHCP: capture servers that send OFFER(2)/ACK(5)
                if _have_dhcp and DHCP in pkt:
                    msg_types = [o[1] for o in pkt[DHCP].options if isinstance(o, tuple) and o[0] == "message-type"]
                    if msg_types and msg_types[0] in (2, 5):   # OFFER or ACK => a server spoke
                        server_ip = pkt[IP].src
                        server_mac = pkt.src if hasattr(pkt, "src") else None
                        dhcp_servers[server_ip] = server_mac

            elif ICMP in pkt:
                proto_counts["ICMP"] += 1
            else:
                proto_counts["OTHER"] += 1
        elif ARP in pkt:
            proto_counts["ARP"] += 1
        elif IPv6 in pkt:
            proto_counts["IPv6"] += 1      # counted, not (yet) analysed
        else:
            proto_counts["NON-IP"] += 1

    try:
        if offline:
            try:
                reader = PcapReader(read_pcap)
            except Exception as e:  # noqa: BLE001 -- scapy raises several types here
                raise RuntimeError(f"Cannot read pcap '{read_pcap}': {e}") from e
            try:
                for pkt in reader:
                    handle(pkt)
            except Exception as e:  # noqa: BLE001 -- truncated/corrupt capture
                raise RuntimeError(
                    f"Error while reading pcap '{read_pcap}' after {total_packets} packet(s): {e}"
                ) from e
            finally:
                reader.close()
        else:
            kwargs = dict(prn=handle, store=False, timeout=duration)
            if iface:
                kwargs["iface"] = iface
            if bpf_filter:
                kwargs["filter"] = bpf_filter
            if max_packets:
                kwargs["count"] = max_packets
            try:
                sniff(**kwargs)
            except PermissionError as e:
                raise RuntimeError(f"Packet capture not permitted: {e}. Try sudo.") from e
            except (OSError, ValueError) as e:
                # Bad interface name or an invalid BPF filter surface here.
                raise RuntimeError(f"Capture failed: {e}") from e
            except Exception as e:  # noqa: BLE001 -- scapy.error.Scapy_Exception etc.
                raise RuntimeError(f"Capture failed: {e}") from e
    finally:
        if writer is not None:
            writer.close()
            if total_packets == 0:
                try:
                    os.unlink(pcap_out)       # don't leave a header-only file behind
                except OSError:
                    pass

    # Finalise DNS tunnelling stats (unique count from the accumulated set).
    dns_stats_final = {
        parent: {
            "count": st["count"], "labels": st["labels"],
            "unique": len(st["unique_set"]), "max_entropy": st["max_entropy"],
            "txt": st["txt"],
        }
        for parent, st in dns_stats.items()
    }

    # Derive detections
    scanners = analysis.detect_port_scans(syn_targets)

    arp_anomalies = analysis.detect_arp_spoofing(ip_to_macs, gateway_ip)
    dhcp_findings = analysis.detect_rogue_dhcp(dhcp_servers, gateway_ip)
    beaconing = analysis.detect_beaconing(conn_times)
    dns_tunneling = analysis.detect_dns_tunneling(dns_stats_final)

    summary = {
        "source": read_pcap if offline else (iface or "default"),
        "offline": offline,
        "duration": 0 if offline else duration,
        "total_packets": total_packets,
        "protocol_counts": dict(proto_counts),
        "top_talkers": talkers.most_common(10),
        "top_bandwidth": [
            {"host": h, "bytes": b, "human": _human_bytes(b)}
            for h, b in bandwidth.most_common(10)
        ],
        "top_conversations": [
            {"pair": pair, "count": count} for pair, count in conversations.most_common(10)
        ],
        "top_dns": dns_queries.most_common(15),
        "top_sni": sni_hosts.most_common(15),
        "possible_scanners": scanners,
        "arp_anomalies": arp_anomalies,
        "dhcp_servers": dhcp_servers,
        "dhcp_findings": dhcp_findings,
        "beaconing": beaconing,
        "dns_tunneling": dns_tunneling,
        "insecure_protocols": insecure,
        "pcap_out": pcap_out if (pcap_out and total_packets) else None,
    }
    summary["alerts"] = analysis.summarize_findings(summary)
    return summary


def _parent_domain(qname: str) -> str:
    """Registrable-ish parent: last two labels (e.g. a.b.evil.com -> evil.com)."""
    parts = qname.rstrip(".").split(".")
    if len(parts) <= 2:
        return qname.rstrip(".")
    # bbc.co.uk / example.com.au: under a country TLD the registrable domain is
    # three labels, otherwise every *.co.uk lookup would be lumped into one
    # "co.uk" bucket and look like a tunnel.
    if len(parts[-1]) == 2 and parts[-2] in _SLD_UNDER_CCTLD:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def _extract_sni(data: bytes) -> str:
    """Extract the SNI hostname from a TLS ClientHello record. Returns "" if not
    found. Best-effort byte walk -- no decryption, just the cleartext handshake.
    """
    try:
        # TLS record: type(1) ver(2) len(2); handshake: type(1) len(3) ver(2)
        # random(32) sessid... We scan for the server_name extension (type 0).
        if len(data) < 45 or data[0] != 0x16 or data[5] != 0x01:
            return ""
        idx = 43  # skip record(5) + handshake header(4) + version(2) + random(32)
        sid_len = data[idx]; idx += 1 + sid_len
        cs_len = int.from_bytes(data[idx:idx + 2], "big"); idx += 2 + cs_len
        comp_len = data[idx]; idx += 1 + comp_len
        if idx + 2 > len(data):
            return ""
        idx += 2  # extensions total length
        while idx + 4 <= len(data):
            ext_type = int.from_bytes(data[idx:idx + 2], "big")
            ext_len = int.from_bytes(data[idx + 2:idx + 4], "big")
            idx += 4
            if ext_type == 0x00:  # server_name
                # server_name_list(2) + name_type(1) + name_len(2) + name
                name_len = int.from_bytes(data[idx + 3:idx + 5], "big")
                host = data[idx + 5:idx + 5 + name_len]
                return host.decode("latin-1", "replace")
            idx += ext_len
    except Exception:
        return ""
    return ""


def _human_bytes(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.0f}{unit}" if unit == "B" else f"{n:.1f}{unit}"
        n /= 1024
    return f"{n:.1f}TB"
