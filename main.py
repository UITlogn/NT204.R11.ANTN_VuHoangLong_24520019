import json
from datetime import datetime
from scapy.all import rdpcap
from parsers.network import parse_network

pc = 0

def process_packet(packet):
    global pc
    pc += 1

    try:
        ts = float(packet.time) if hasattr(packet, "time") else datetime.now().timestamp()
        net_info = parse_network(packet)

        if not net_info:
            return

        event = {
            "packet_id": pc,
            "timestamp": ts,
            "network": net_info
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


packets = rdpcap("TEST/test01.pcap")
for pkt in packets:
    process_packet(pkt)