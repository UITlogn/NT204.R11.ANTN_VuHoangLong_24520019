import json
from datetime import datetime
from scapy.all import rdpcap, sniff
from parsers.network import parse_network
from parsers.transport import parse_transport
import argparse
import sys


pc = 0

def process_packet(packet):
    global pc
    pc += 1

    try:
        ts = float(packet.time) if hasattr(packet, "time") else datetime.now().timestamp()
        net_info = parse_network(packet)

        if not net_info:
            return

        trans_info = parse_transport(packet)

        event = {
            "packet_id": pc,
            "timestamp": ts,
            "network": net_info,
            "transport": trans_info
        }

        line = json.dumps(event)
        print(line)

    except Exception as e:
        error_event = {
            "packet_id": pc,
            "error": "malformed_packet",
            "details": str(e)
        }
        print(json.dumps(error_event) + "\n")


parser = argparse.ArgumentParser(description="Packet Capture & Parser for IDS")
parser.add_argument("--interface", type=str)
parser.add_argument("--pcap", type=str)
parser.add_argument("--output", type=str, default="output.jsonl")
args = parser.parse_args()

if not args.interface and not args.pcap:
    parser.error("Add --interface or --pcap")
    exit(0)

if args.output:
    sys.stdout = open(args.output, "a", encoding="utf-8", buffering=1)

if args.pcap:
    packets = rdpcap(args.pcap)
    for pkt in packets:
        process_packet(pkt)
elif args.interface:
    sniff(iface=args.interface, prn=process_packet, store=False)