"""Live traffic capture and analysis, built on scapy.

Needs root/administrator, same as any packet sniffer (tcpdump, Wireshark).
Beyond a basic protocol/talker summary, this collects data used by
netscope.analysis for passive threat detection: per-host bandwidth, DNS
queries, ARP mappings (ARP-spoof detection), DHCP servers (rogue-DHCP
detection), and use of insecure plaintext protocols.
"""

import collections
import time

from .utils import is_root, shannon_entropy
from . import analysis


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
            sniff, rdpcap, wrpcap, IP, TCP, UDP, ICMP, ARP, DNS, DNSQR, Raw,
        )
        try:
            from scapy.layers.dhcp import DHCP, BOOTP
            _have_dhcp = True
        except Exception:
            _have_dhcp = False
    except ImportError as e:
        raise RuntimeError(
            "scapy is required for capture. Install with: pip install scapy"
        ) from e

    offline = read_pcap is not None
    if not offline and is_root() is False:
        raise RuntimeError(
            "Packet capture needs raw socket access. Re-run with sudo (Linux/macOS) "
            "or as Administrator (Windows, with Npcap installed). To analyse an "
            "existing capture instead, use --read FILE.pcap (no root needed)."
        )

    packets = []
    proto_counts = collections.Counter()
    talkers = collections.Counter()          # packets per src
    bandwidth = collections.Counter()         # bytes per host (src or dst)
    conversations = collections.Counter()
    syn_counts = collections.Counter()        # src -> half-open SYN count
    dns_queries = collections.Counter()       # domain -> count
    ip_to_macs = collections.defaultdict(set) # ip -> {mac,...}  (ARP-spoof detection)
    dhcp_servers = {}                         # server_ip -> mac
    insecure = []                             # list of {proto, src, dst}
    _insecure_seen = set()                    # dedupe (proto, src, dst)
    conn_times = collections.defaultdict(list)  # (src,dst,dport) -> [ts,...] beaconing
    dns_stats = {}                            # parent domain -> tunnelling stats
    sni_hosts = collections.Counter()         # TLS SNI hostname -> count

    def note_insecure(proto, src, dst):
        key = (proto, src, dst)
        if key not in _insecure_seen:
            _insecure_seen.add(key)
            insecure.append({"proto": proto, "src": src, "dst": dst})

    def note_dns(qname, qtype):
        parent = _parent_domain(qname)
        st = dns_stats.setdefault(parent, {"count": 0, "labels": [], "unique_set": set(),
                                           "max_entropy": 0.0, "txt": 0})
        st["count"] += 1
        st["unique_set"].add(qname)
        longest = max(qname.split("."), key=len, default="")
        st["labels"].append(longest)
        st["max_entropy"] = max(st["max_entropy"], shannon_entropy(longest))
        if qtype in (16, 10):  # TXT / NULL are tunnelling-associated
            st["txt"] += 1

    def note_sni(pkt_bytes):
        host = _extract_sni(pkt_bytes)
        if host:
            sni_hosts[host] += 1

    def handle(pkt):
        packets.append(pkt)
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
                    syn_counts[src] += 1
                    conn_times[(src, dst, dport)].append(ts)   # beaconing timeline
                # Telnet / FTP control channels = cleartext by definition.
                if 23 in (sport, dport):
                    note_insecure("Telnet", src, dst)
                if 21 in (sport, dport):
                    note_insecure("FTP", src, dst)
                if Raw in pkt:
                    try:
                        payload = bytes(pkt[Raw].load)
                    except Exception:
                        payload = b""
                    # HTTP Basic auth over cleartext -- look for the header, do NOT decode it.
                    if (80 in (sport, dport) or 8080 in (sport, dport)) and b"Authorization: Basic" in payload:
                        note_insecure("HTTP Basic auth (cleartext)", src, dst)
                    # TLS ClientHello SNI (destination hostname; no decryption)
                    if 443 in (sport, dport) and payload[:1] == b"\x16":
                        note_sni(payload)

            elif UDP in pkt:
                proto_counts["UDP"] += 1
                # DNS query extraction
                if DNS in pkt and pkt[DNS].qr == 0 and pkt[DNS].qd is not None:
                    try:
                        qname = pkt[DNSQR].qname.decode("latin-1", "replace").rstrip(".")
                        qtype = int(getattr(pkt[DNSQR], "qtype", 0))
                        if qname:
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
        else:
            proto_counts["NON-IP"] += 1

    if offline:
        for pkt in rdpcap(read_pcap):
            handle(pkt)
    else:
        kwargs = dict(prn=handle, store=False, timeout=duration)
        if iface:
            kwargs["iface"] = iface
        if bpf_filter:
            kwargs["filter"] = bpf_filter
        if max_packets:
            kwargs["count"] = max_packets
        sniff(**kwargs)

    if pcap_out and packets:
        wrpcap(pcap_out, packets)

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
    scanners = [
        {"ip": ip, "syn_count": c} for ip, c in syn_counts.items() if c >= 20
    ]
    scanners.sort(key=lambda s: -s["syn_count"])

    arp_anomalies = analysis.detect_arp_spoofing(ip_to_macs, gateway_ip)
    dhcp_findings = analysis.detect_rogue_dhcp(dhcp_servers, gateway_ip)
    beaconing = analysis.detect_beaconing(conn_times)
    dns_tunneling = analysis.detect_dns_tunneling(dns_stats_final)

    summary = {
        "source": read_pcap if offline else (iface or "default"),
        "offline": offline,
        "duration": 0 if offline else duration,
        "total_packets": len(packets),
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
        "pcap_out": pcap_out if (pcap_out and packets) else None,
    }
    summary["alerts"] = analysis.summarize_findings(summary)
    return summary


def _parent_domain(qname: str) -> str:
    """Registrable-ish parent: last two labels (e.g. a.b.evil.com -> evil.com)."""
    parts = qname.rstrip(".").split(".")
    if len(parts) <= 2:
        return qname.rstrip(".")
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
