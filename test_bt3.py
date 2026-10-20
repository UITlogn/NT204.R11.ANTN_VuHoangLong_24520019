"""Run the 14 required Core Engine test cases and save JSON results."""

import argparse
import json
from pathlib import Path

from core.core_engine import EvaluationEngine, RuleRepository, header_matches
from core.rule_loader import RuleLoader
from core.rule_parser import RuleParser


OUTPUT_DIR = Path("TEST/BT3")


def rule(text):
    parsed = RuleParser().parse_rule(text)
    assert parsed is not None, text
    return parsed


def event(payload="GET /index HTTP/1.1", dst_port=80, flags=None, size=None):
    return {
        "timestamp": 1700000000.0,
        "flow_id": "F-001",
        "network": {"src_ip": "10.0.0.5", "dst_ip": "192.168.1.20"},
        "transport": {
            "protocol": "TCP", "src_port": 50000, "dst_port": dst_port,
            "flags": flags or ["PSH", "ACK"], "payload_text": payload,
            "payload_length": len(payload) if size is None else size,
        },
        "application_protocol": "HTTP",
        "application": {"uri": "/index"},
    }


def flow(initiator="10.0.0.5:50000", state="ESTABLISHED"):
    return {"flow_id": "F-001", "initiator": initiator, "tcp_stats": {"state": state}}


def evaluate(rules, packet=None, flow_context=None):
    return EvaluationEngine(RuleRepository(rules)).evaluate(packet or event(), flow_context or flow())


def case_01():
    report = RuleLoader().load_text("# comment\n\nalert tcp any any -> any 80 (msg:\"ok\"; sid:1; rev:1;)\n")
    assert len(report["rules"]) == 1 and not report["issues"]
    return {"valid_rules": len(report["rules"])}


def case_02():
    report = RuleLoader().load_text("alert tcp any any -> any 80 (msg:\"missing rev\"; sid:2;)")
    assert report["issues"][0]["status"] == "invalid"
    return report["issues"][0]


def case_03():
    report = RuleLoader().load_text("alert tcp any any -> any 80 (msg:\"pcre\"; sid:3; rev:1; pcre:\"/x/\";)")
    assert report["issues"][0]["status"] == "unsupported"
    return report["issues"][0]


def case_04():
    parsed = rule("alert tcp 10.0.0.0/24 1000:2000 -> 192.168.1.20 80 (msg:\"header\"; sid:4; rev:1;)")
    assert parsed["src_ip"] == "10.0.0.0/24" and parsed["src_port"] == "1000:2000"
    return {"protocol": parsed["protocol"], "src_ip": parsed["src_ip"], "src_port": parsed["src_port"]}


def case_05():
    direct = rule("alert tcp 10.0.0.5 50000 -> 192.168.1.20 80 (msg:\"direct\"; sid:5; rev:1;)")
    bidirectional = rule("alert tcp 10.0.0.5 50000 <> 192.168.1.20 80 (msg:\"both\"; sid:6; rev:1;)")
    reverse = event()
    reverse["network"]["src_ip"], reverse["network"]["dst_ip"] = reverse["network"]["dst_ip"], reverse["network"]["src_ip"]
    reverse["transport"]["src_port"], reverse["transport"]["dst_port"] = reverse["transport"]["dst_port"], reverse["transport"]["src_port"]
    assert header_matches(direct, event()) and not header_matches(direct, reverse) and header_matches(bidirectional, reverse)
    return {"direct": True, "bidirectional_reverse": True}


def case_06():
    tcp_cidr = rule("alert tcp 10.0.0.0/24 any -> any any (msg:\"tcp\"; sid:7; rev:1;)")
    tcp_any = rule("alert tcp any any -> any any (msg:\"any\"; sid:8; rev:1;)")
    udp = rule("alert udp any any -> any 53 (msg:\"dns\"; sid:9; rev:1;)")
    repository = RuleRepository([tcp_cidr, tcp_any, udp])
    tcp_sids = [item["options"]["sid"] for item in repository.candidates(event())]
    udp_event = event()
    udp_event["transport"].update({"protocol": "UDP", "dst_port": 53})
    udp_sids = [item["options"]["sid"] for item in repository.candidates(udp_event)]
    assert tcp_sids == [7, 8] and udp_sids == [9]
    return {"tcp_candidates": tcp_sids, "udp_candidates": udp_sids}


def case_07():
    repository = RuleRepository([rule("alert tcp any any -> any 80 (msg:\"no header\"; sid:10; rev:1; content:\"never\";)")])
    assert repository.candidates(event(dst_port=81)) == []
    return {"candidate_rules": 0}


def case_08():
    rules = [rule("alert tcp any any -> any any (msg:\"flow\"; sid:11; rev:1; flow:to_server,established;)")]
    assert len(evaluate(rules, event(), flow())) == 1
    assert not evaluate(rules, event(), flow("192.168.1.20:80"))
    return {"to_server_established": True}


def case_09():
    rules = [rule("alert tcp any any -> any any (msg:\"nocase\"; sid:12; rev:1; content:\"ADMIN\"; nocase;)")]
    assert len(evaluate(rules, event("get /admin HTTP/1.1"))) == 1
    return {"nocase": True}


def case_10():
    rules = [rule("alert tcp any any -> any any (msg:\"window\"; sid:13; rev:1; content:\"needle\"; offset:4; depth:6;)")]
    assert len(evaluate(rules, event("xxxxneedle"))) == 1
    assert not evaluate(rules, event("xxxxxxneedle"))
    return {"offset": 4, "depth": 6}


def case_11():
    rules = [rule("alert tcp any any -> any any (msg:\"relative\"; sid:14; rev:1; content:\"USER\"; content:\"PASS\"; distance:1; within:8;)")]
    assert len(evaluate(rules, event("USERxPASS"))) == 1
    assert not evaluate(rules, event("USERx12345678PASS"))
    return {"distance": 1, "within": 8}


def case_12():
    rules = [rule("alert tcp any any -> any any (msg:\"tcp\"; sid:15; rev:1; flags:PA; dsize:>5;)")]
    assert len(evaluate(rules, event("abcdef", flags=["PSH", "ACK"]))) == 1
    assert not evaluate(rules, event("abcdef", flags=["ACK"]))
    return {"flags": "PA", "dsize": ">5"}


def case_13():
    rules = [
        rule("alert tcp any any -> any any (msg:\"method\"; sid:16; rev:1; content:\"GET\";)"),
        rule("alert tcp any any -> any any (msg:\"path\"; sid:17; rev:1; content:\"/admin\";)"),
    ]
    detections = evaluate(rules, event("GET /admin HTTP/1.1"))
    assert [item["sid"] for item in detections] == [16, 17]
    return {"matched_sids": [item["sid"] for item in detections]}


def case_14():
    rules = [rule("alert tcp any any -> any any (msg:\"event\"; sid:18; rev:2; content:\"GET\"; classtype:web-application-attack; priority:1;)")]
    detection = evaluate(rules)[0]
    required = {"timestamp", "sid", "rev", "msg", "priority", "classtype", "src_ip", "src_port", "dst_ip", "dst_port", "protocol", "application_protocol", "flow_id", "match"}
    assert required <= detection.keys()
    return {key: detection[key] for key in ("sid", "rev", "flow_id", "protocol", "application_protocol")}


CASES = [case_01, case_02, case_03, case_04, case_05, case_06, case_07, case_08, case_09, case_10, case_11, case_12, case_13, case_14]


def run(case_number):
    result = {"case": case_number, "status": "PASS", "result": CASES[case_number - 1]()}
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    path = OUTPUT_DIR / f"case_{case_number:02d}.json"
    path.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(f"PASS case {case_number:02d} -> {path}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--case", type=int, choices=range(1, 15))
    args = parser.parse_args()
    for number in ([args.case] if args.case else range(1, 15)):
        run(number)
