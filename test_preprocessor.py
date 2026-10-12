import json
import os
from modules.preprocessor import preprocess_event

os.makedirs("TEST", exist_ok=True)

test_cases = [
    # T05: Normalization
    {
        "id": "T05",
        "file": "TEST/res_t05_normalization.jsonl",
        "event": {
            "packet_id": 5,
            "timestamp": 1790140005.0,
            "network": {"src_ip": "192.168.1.10", "dst_ip": "10.0.0.1", "version": 4, "ttl": 64, "proto": 6},
            "transport": {"protocol": "tcp", "src_port": 50005, "dst_port": 80, "flags": ["ACK"]},
            "application_protocol": "http",
            "application": {
                "type": "request",
                "method": "GET",
                "uri": "//api//v1//users/",
                "version": "HTTP/1.1",
                "headers": {
                    "HOST": "API.Target.Local",
                    "User-Agent": "Mozilla/5.0",
                    "Content-TYPE": "application/json "
                }
            }
        }
    },
    # T06: Missing field
    {
        "id": "T06",
        "file": "TEST/res_t06_missing_field.jsonl",
        "event": {
            "packet_id": 6,
            "timestamp": 1790140006.0,
            "network": {"src_ip": "192.168.1.10", "dst_ip": "10.0.0.1", "version": 4, "ttl": 64, "proto": 6}
            # Thiếu hoàn toàn transport, application_protocol, application
        }
    },
    # T14: Malformed event
    {
        "id": "T14",
        "file": "TEST/res_t14_malformed_event.jsonl",
        "event": {
            "packet_id": 14,
            "error": "malformed_packet",
            "details": "Truncated IP header length"
        }
    }
]

for tc in test_cases:
    out_file = tc["file"]
    res = preprocess_event(tc["event"])
    with open(out_file, "w", encoding="utf-8") as f:
        f.write(json.dumps(res) + "\n")
    print(f"[{tc['id']}] Done -> {out_file}")