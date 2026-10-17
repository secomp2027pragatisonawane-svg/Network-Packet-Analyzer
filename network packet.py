#!/usr/bin/env python3
"""
Network Packet Analyzer
=======================
Captures packets with Scapy, extracts key details (source/destination IP,
protocol, ports, length, payload) and presents them in an organized table,
with an end-of-capture summary. Results can be saved to CSV / JSON / PCAP.

Requirements
    pip install scapy
    Windows : install Npcap (https://npcap.com) and run the terminal as Administrator
    Linux/macOS : run with sudo (raw sockets need elevated privileges)

Examples
    sudo python3 packet_analyzer.py                       # capture until Ctrl+C
    sudo python3 packet_analyzer.py -c 50                 # capture 50 packets
    sudo python3 packet_analyzer.py -i eth0 -f "tcp port 80"
    sudo python3 packet_analyzer.py -c 100 -v --csv out.csv --json out.json --pcap out.pcap
    python3 packet_analyzer.py -r capture.pcap            # analyze an existing pcap offline

Only capture traffic on networks you own or are authorized to monitor.
"""

import argparse
import csv
import json
import sys
from collections import Counter
from datetime import datetime

try:
    from scapy.all import (
        ARP, DNS, ICMP, IP, IPv6, TCP, UDP, Raw,
        rdpcap, sniff, wrpcap,
    )
except ImportError:
    sys.exit("Scapy is not installed. Run:  pip install scapy")

# --------------------------------------------------------------------------- #
# Lookup tables
# --------------------------------------------------------------------------- #
IP_PROTOCOLS = {1: "ICMP", 2: "IGMP", 6: "TCP", 17: "UDP", 41: "IPv6-in-IP",
                47: "GRE", 50: "ESP", 58: "ICMPv6", 89: "OSPF"}

WELL_KNOWN_PORTS = {
    20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "TELNET", 25: "SMTP", 53: "DNS",
    67: "DHCP", 68: "DHCP", 80: "HTTP", 110: "POP3", 123: "NTP", 143: "IMAP",
    161: "SNMP", 443: "HTTPS", 465: "SMTPS", 587: "SMTP", 993: "IMAPS",
    995: "POP3S", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 8080: "HTTP-ALT",
}

captured = []          # raw Scapy packets (for --pcap)
records = []           # parsed dictionaries (for table, CSV, JSON, stats)


# --------------------------------------------------------------------------- #
# Packet parsing
# --------------------------------------------------------------------------- #
def printable(data: bytes, limit: int) -> str:
    """Convert bytes to a safe ASCII string ('.' for non-printable bytes)."""
    return "".join(chr(b) if 32 <= b < 127 else "." for b in data[:limit])


def hexdump(data: bytes, limit: int) -> str:
    """Classic 16-bytes-per-line hex + ASCII dump."""
    lines = []
    chunk = data[:limit]
    for off in range(0, len(chunk), 16):
        row = chunk[off:off + 16]
        hex_part = " ".join(f"{b:02x}" for b in row)
        lines.append(f"      {off:04x}  {hex_part:<47}  {printable(row, 16)}")
    if len(data) > limit:
        lines.append(f"      ... ({len(data) - limit} more bytes)")
    return "\n".join(lines)


def parse_packet(pkt, number: int, payload_limit: int) -> dict:
    """Extract the important fields from one packet into a dictionary."""
    rec = {
        "no": number,
        "time": datetime.fromtimestamp(float(pkt.time)).strftime("%H:%M:%S.%f")[:-3],
        "src": "-", "dst": "-",
        "protocol": pkt.lastlayer().name,
        "src_port": "", "dst_port": "",
        "length": len(pkt),
        "ttl": "",
        "info": "",
        "payload_len": 0,
        "payload_ascii": "",
        "_payload": b"",
    }

    # ---- Network layer ---------------------------------------------------- #
    if pkt.haslayer(ARP):
        arp = pkt[ARP]
        rec.update(src=arp.psrc, dst=arp.pdst, protocol="ARP")
        rec["info"] = ("Who has %s? Tell %s" % (arp.pdst, arp.psrc)
                       if arp.op == 1 else "%s is at %s" % (arp.psrc, arp.hwsrc))
    elif pkt.haslayer(IP):
        ip = pkt[IP]
        rec.update(src=ip.src, dst=ip.dst, ttl=ip.ttl,
                   protocol=IP_PROTOCOLS.get(ip.proto, f"IP-proto-{ip.proto}"))
    elif pkt.haslayer(IPv6):
        ip6 = pkt[IPv6]
        rec.update(src=ip6.src, dst=ip6.dst, ttl=ip6.hlim,
                   protocol=IP_PROTOCOLS.get(ip6.nh, f"IPv6-nh-{ip6.nh}"))

    # ---- Transport layer -------------------------------------------------- #
    if pkt.haslayer(TCP):
        tcp = pkt[TCP]
        rec.update(src_port=tcp.sport, dst_port=tcp.dport)
        rec["info"] = f"flags=[{tcp.flags}] seq={tcp.seq} ack={tcp.ack} win={tcp.window}"
    elif pkt.haslayer(UDP):
        udp = pkt[UDP]
        rec.update(src_port=udp.sport, dst_port=udp.dport)
        rec["info"] = f"len={udp.len}"
    elif pkt.haslayer(ICMP):
        icmp = pkt[ICMP]
        kinds = {0: "echo-reply", 3: "dest-unreachable", 8: "echo-request", 11: "time-exceeded"}
        rec["info"] = f"type={icmp.type} ({kinds.get(icmp.type, 'other')}) code={icmp.code}"

    # ---- Application layer (best-effort) ---------------------------------- #
    if pkt.haslayer(DNS):
        dns = pkt[DNS]
        rec["protocol"] = "DNS"
        if dns.qd is not None:
            name = dns.qd.qname.decode(errors="replace") if isinstance(dns.qd.qname, bytes) else str(dns.qd.qname)
            rec["info"] = ("Query " if dns.qr == 0 else "Response ") + name
    else:
        for port in (rec["dst_port"], rec["src_port"]):
            if port in WELL_KNOWN_PORTS:
                rec["protocol"] = f"{rec['protocol']}/{WELL_KNOWN_PORTS[port]}"
                break

    # ---- Payload ---------------------------------------------------------- #
    if pkt.haslayer(Raw):
        data = bytes(pkt[Raw].load)
        rec["payload_len"] = len(data)
        rec["payload_ascii"] = printable(data, payload_limit)
        rec["_payload"] = data

    return rec


# --------------------------------------------------------------------------- #
# Output helpers
# --------------------------------------------------------------------------- #
HEADER = f"{'No.':>4}  {'Time':<12}  {'Source':<26} {'Destination':<26} {'Protocol':<14} {'Len':>5}  Info"
RULE = "-" * 120


def endpoint(ip: str, port) -> str:
    return f"{ip}:{port}" if port != "" else ip


def print_row(rec: dict, verbose: bool, payload_limit: int) -> None:
    print(f"{rec['no']:>4}  {rec['time']:<12}  "
          f"{endpoint(rec['src'], rec['src_port']):<26} "
          f"{endpoint(rec['dst'], rec['dst_port']):<26} "
          f"{rec['protocol']:<14} {rec['length']:>5}  {rec['info']}")
    if verbose and rec["payload_len"]:
        print(f"      Payload: {rec['payload_len']} bytes | \"{rec['payload_ascii']}\"")
        print(hexdump(rec["_payload"], payload_limit))


def print_summary() -> None:
    if not records:
        print("\nNo packets captured.")
        return
    total_bytes = sum(r["length"] for r in records)
    protos = Counter(r["protocol"] for r in records)
    talkers = Counter(r["src"] for r in records if r["src"] != "-")
    pairs = Counter((r["src"], r["dst"]) for r in records if r["src"] != "-")

    print("\n" + "=" * 60)
    print("CAPTURE SUMMARY")
    print("=" * 60)
    print(f"Total packets : {len(records)}")
    print(f"Total bytes   : {total_bytes}")
    print(f"Time span     : {records[0]['time']} -> {records[-1]['time']}")

    print("\nProtocol distribution")
    for proto, n in protos.most_common():
        pct = 100 * n / len(records)
        print(f"  {proto:<18} {n:>5}  {pct:5.1f}%  {'#' * int(pct / 2)}")

    print("\nTop sources")
    for ip, n in talkers.most_common(5):
        print(f"  {ip:<40} {n:>5} packets")

    print("\nTop conversations")
    for (s, d), n in pairs.most_common(5):
        print(f"  {s} -> {d}  ({n} packets)")


def save_csv(path: str) -> None:
    fields = ["no", "time", "src", "dst", "protocol", "src_port", "dst_port",
              "length", "ttl", "info", "payload_len", "payload_ascii"]
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(records)
    print(f"[+] CSV saved to {path}")


def save_json(path: str) -> None:
    clean = [{k: v for k, v in r.items() if not k.startswith("_")} for r in records]
    with open(path, "w", encoding="utf-8") as f:
        json.dump(clean, f, indent=2)
    print(f"[+] JSON saved to {path}")


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #
def main() -> None:
    ap = argparse.ArgumentParser(description="Network Packet Analyzer (Scapy)")
    ap.add_argument("-i", "--iface", help="interface to sniff on (default: system default)")
    ap.add_argument("-c", "--count", type=int, default=0, help="number of packets (0 = until Ctrl+C)")
    ap.add_argument("-f", "--filter", default="", help='BPF filter, e.g. "tcp port 443" or "host 8.8.8.8"')
    ap.add_argument("-t", "--timeout", type=int, default=None, help="stop after N seconds")
    ap.add_argument("-r", "--read", help="analyze packets from an existing .pcap file instead of sniffing")
    ap.add_argument("-v", "--verbose", action="store_true", help="show payload preview + hex dump")
    ap.add_argument("--payload-bytes", type=int, default=64, help="payload bytes to display (default 64)")
    ap.add_argument("--csv", help="save results to a CSV file")
    ap.add_argument("--json", help="save results to a JSON file")
    ap.add_argument("--pcap", help="save raw packets to a .pcap file (openable in Wireshark)")
    args = ap.parse_args()

    print(HEADER)
    print(RULE)

    def handle(pkt):
        captured.append(pkt)
        rec = parse_packet(pkt, len(records) + 1, args.payload_bytes)
        records.append(rec)
        print_row(rec, args.verbose, args.payload_bytes)

    try:
        if args.read:
            for pkt in rdpcap(args.read):
                handle(pkt)
        else:
            sniff(iface=args.iface, filter=args.filter or None, prn=handle,
                  count=args.count, timeout=args.timeout, store=False)
    except PermissionError:
        sys.exit("\n[!] Permission denied - run as root/Administrator (sudo python3 packet_analyzer.py).")
    except KeyboardInterrupt:
        print("\n[!] Capture stopped by user.")
    except OSError as e:
        sys.exit(f"\n[!] Capture error: {e}\n    (On Windows make sure Npcap is installed.)")

    print_summary()
    if args.csv:
        save_csv(args.csv)
    if args.json:
        save_json(args.json)
    if args.pcap and captured:
        wrpcap(args.pcap, captured)
        print(f"[+] PCAP saved to {args.pcap}")


if __name__ == "__main__":
    main()