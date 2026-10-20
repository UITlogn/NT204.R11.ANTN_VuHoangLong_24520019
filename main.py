import argparse
import json
import sys
from datetime import datetime
from scapy.all import rdpcap, sniff
from parsers.network import parse_network
from parsers.transport import parse_transport
from parsers.application import parse_application
from modules.decoder import decode_payload
from modules.preprocessor import preprocess_event
from modules.flow_tracker import FlowTracker
from core.rule_loader import RuleLoader
from core.core_engine import EvaluationEngine, RuleRepository

pc = 0
tracker = FlowTracker(tcp_idle_timeout=30.0, udp_idle_timeout=15.0)

def process_packet(packet):
    global pc
    pc += 1

    try:
        ts = float(packet.time) if hasattr(packet, "time") else datetime.now().timestamp()
        net_info = parse_network(packet)

        if not net_info:
            error_event = {
                "packet_id": pc,
                "error": "malformed_packet",
                "details": "missing IPv4 layer"
            }
            print(json.dumps(preprocess_event(error_event)), flush=True)
            return

        trans_info = parse_transport(packet)
        app_proto, app_info = parse_application(packet)

        # 1. Base Event từ BT1
        event = {
            "packet_id": pc,
            "timestamp": ts,
            "network": net_info,
            "transport": trans_info,
            "application_protocol": app_proto,
            "application": app_info
        }

        # 2. Pipeline BT2: Decoder -> Preprocessor -> Flow Tracker
        event = decode_payload(event)
        event = preprocess_event(event)
        flow_summary, expired_flows = tracker.update(event)
        detections = rule_engine.evaluate(event, flow_summary) if rule_engine else []

        # Ghi các flow vừa hết hạn nếu có
        for exp in expired_flows:
            print(json.dumps({"event_type": "flow_expired", "flow": exp}), flush=True)

        print(json.dumps(event), flush=True)
        for detection in detections:
            print(json.dumps(detection), flush=True)

    except Exception as e:
        error_event = {
            "packet_id": pc,
            "error": "malformed_packet",
            "details": str(e)
        }
        err_preprocessed = preprocess_event(error_event)
        print(json.dumps(err_preprocessed), flush=True)

parser = argparse.ArgumentParser(description="IDS Pipeline: Capture, Decoder, Preprocessor & Flow Tracker")
parser.add_argument("--interface", type=str)
parser.add_argument("--pcap", type=str)
parser.add_argument("--output", type=str, default=None)
parser.add_argument("--tcp-timeout", type=float, default=30.0)
parser.add_argument("--udp-timeout", type=float, default=15.0)
parser.add_argument("--rules", nargs="*", default=[])
parser.add_argument("--disable-sid", type=int, action="append", default=[])
args = parser.parse_args()

if not args.interface and not args.pcap:
    parser.error("Add --interface or --pcap")

tracker.tcp_idle_timeout = args.tcp_timeout
tracker.udp_idle_timeout = args.udp_timeout

rule_engine = None
if args.rules:
    report = RuleLoader(disabled_sids=args.disable_sid).load_files(args.rules)
    rule_engine = EvaluationEngine(RuleRepository(report["rules"]))
    for issue in report["issues"]:
        print(json.dumps({"rule_warning": issue}), file=sys.stderr, flush=True)

out_file = None
if args.output:
    out_file = open(args.output, "a", encoding="utf-8", buffering=1)
    sys.stdout = out_file

try:
    if args.pcap:
        packets = rdpcap(args.pcap)
        for pkt in packets:
            process_packet(pkt)
    elif args.interface:
        sniff(iface=args.interface, prn=process_packet, store=False)
finally:
    if out_file:
        out_file.close()
