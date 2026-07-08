"""Live traffic capture and analysis, built on scapy.

Needs root/administrator, same as any packet sniffer (tcpdump, Wireshark).
Beyond a basic protocol/talker summary, this collects data used by
netscope.analysis for passive threat detection: per-host bandwidth, DNS
queries, ARP mappings (ARP-spoof detection), DHCP servers (rogue-DHCP
detection), and use of insecure plaintext protocols.
"""

import collections

from .utils import is_root
from . import analysis


def capture(
    iface: str = None,
    duration: int = 15,
    bpf_filter: str = None,
    pcap_out: str = None,
    max_packets: int = 0,
    gateway_ip: str = None,
):
    """Sniff for `duration` seconds (or `max_packets` packets, whichever first)
    and return a rich summary dict. Optionally write a .pcap for Wireshark.
    """
    try:
        from scapy.all import (
            sniff, wrpcap, IP, TCP, UDP, ICMP, ARP, DNS, DNSQR, Raw,
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

    if is_root() is False:
        raise RuntimeError(
            "Packet capture needs raw socket access. Re-run with sudo (Linux/macOS) "
            "or as Administrator (Windows, with Npcap installed)."
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

    def note_insecure(proto, src, dst):
        key = (proto, src, dst)
        if key not in _insecure_seen:
            _insecure_seen.add(key)
            insecure.append({"proto": proto, "src": src, "dst": dst})

    def handle(pkt):
        packets.append(pkt)
        size = len(pkt)

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
                if flags & 0x02 and not flags & 0x10:   # SYN and not ACK
                    syn_counts[src] += 1

                sport, dport = pkt[TCP].sport, pkt[TCP].dport
                # Telnet / FTP control channels = cleartext by definition.
                if 23 in (sport, dport):
                    note_insecure("Telnet", src, dst)
                if 21 in (sport, dport):
                    note_insecure("FTP", src, dst)
                # HTTP Basic auth over cleartext -- look for the header, do NOT decode it.
                if Raw in pkt and (80 in (sport, dport) or 8080 in (sport, dport)):
                    try:
                        payload = bytes(pkt[Raw].load)
                        if b"Authorization: Basic" in payload:
                            note_insecure("HTTP Basic auth (cleartext)", src, dst)
                    except Exception:
                        pass

            elif UDP in pkt:
                proto_counts["UDP"] += 1
                # DNS query extraction
                if DNS in pkt and pkt[DNS].qr == 0 and pkt[DNS].qd is not None:
                    try:
                        qname = pkt[DNSQR].qname.decode("latin-1", "replace").rstrip(".")
                        if qname:
                            dns_queries[qname] += 1
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

    # Derive detections
    scanners = [
        {"ip": ip, "syn_count": c} for ip, c in syn_counts.items() if c >= 20
    ]
    scanners.sort(key=lambda s: -s["syn_count"])

    arp_anomalies = analysis.detect_arp_spoofing(ip_to_macs, gateway_ip)
    dhcp_findings = analysis.detect_rogue_dhcp(dhcp_servers, gateway_ip)

    summary = {
        "duration": duration,
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
        "possible_scanners": scanners,
        "arp_anomalies": arp_anomalies,
        "dhcp_servers": dhcp_servers,
        "dhcp_findings": dhcp_findings,
        "insecure_protocols": insecure,
        "pcap_out": pcap_out if (pcap_out and packets) else None,
    }
    summary["alerts"] = analysis.summarize_findings(summary)
    return summary


def _human_bytes(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.0f}{unit}" if unit == "B" else f"{n:.1f}{unit}"
        n /= 1024
    return f"{n:.1f}TB"
