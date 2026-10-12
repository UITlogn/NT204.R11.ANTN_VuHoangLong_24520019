import json
import os
from modules.decoder import decode_payload

os.makedirs("TEST", exist_ok=True)

test_cases = [
    # T01: HTTP URL percent-decode
    {
        "id": "T01",
        "file": "TEST/res_t01_url_decode.jsonl",
        "event": {
            "packet_id": 1,
            "timestamp": 1790140000.0,
            "network": {"src_ip": "192.168.1.10", "dst_ip": "10.0.0.1", "version": 4, "ttl": 64, "proto": 6},
            "transport": {"protocol": "TCP", "src_port": 50000, "dst_port": 80, "flags": ["ACK", "PSH"]},
            "application_protocol": "HTTP",
            "application": {
                "type": "request",
                "method": "GET",
                "uri": "/search?q=%27%20OR%201%3D1",
                "version": "HTTP/1.1",
                "headers": {"Host": "target.local"}
            }
        }
    },
    # T02: HTML Entity decode
    {
        "id": "T02",
        "file": "TEST/res_t02_html_entity.jsonl",
        "event": {
            "packet_id": 2,
            "timestamp": 1790140001.0,
            "network": {"src_ip": "192.168.1.10", "dst_ip": "10.0.0.1", "version": 4, "ttl": 64, "proto": 6},
            "transport": {"protocol": "TCP", "src_port": 50001, "dst_port": 80, "flags": ["ACK", "PSH"]},
            "application_protocol": "HTTP",
            "application": {
                "type": "request",
                "method": "POST",
                "uri": "/comment",
                "version": "HTTP/1.1",
                "headers": {"Host": "target.local", "Content-Type": "application/x-www-form-urlencoded"},
                "body": "comment=&lt;script&gt;alert(1)&lt;/script&gt;&amp;user=admin"
            }
        }
    },
    # T03: SMTP Base64 & Quoted-Printable decode
    {
        "id": "T03",
        "file": "TEST/res_t03_smtp_mime.jsonl",
        "event": {
            "packet_id": 3,
            "timestamp": 1790140002.0,
            "network": {"src_ip": "192.168.1.10", "dst_ip": "10.0.0.25", "version": 4, "ttl": 64, "proto": 6},
            "transport": {"protocol": "TCP", "src_port": 50002, "dst_port": 25, "flags": ["ACK", "PSH"]},
            "application_protocol": "SMTP",
            "application": {
                "type": "command",
                "command": "DATA",
                "encoding": "base64",
                "body": "SGVsbG8sIHRoaXMgaXMgYSBkZWNvZGVkIGVtYWlsIQ=="
            }
        }
    },
    # T04: Invalid bytes handling
    {
        "id": "T04",
        "file": "TEST/res_t04_invalid_bytes.jsonl",
        "event": {
            "packet_id": 4,
            "timestamp": 1790140003.0,
            "network": {"src_ip": "192.168.1.10", "dst_ip": "10.0.0.25", "version": 4, "ttl": 64, "proto": 6},
            "transport": {"protocol": "TCP", "src_port": 50003, "dst_port": 25, "flags": ["ACK", "PSH"]},
            "application_protocol": "SMTP",
            "application": {
                "type": "command",
                "command": "DATA",
                "encoding": "base64",
                "body": "%%%INVALID_BASE64_SEQUENCE%%%"
            }
        }
    }
]

for tc in test_cases:
    out_file = tc["file"]
    processed = decode_payload(tc["event"])
    
    with open(out_file, "w", encoding="utf-8") as f:
        f.write(json.dumps(processed) + "\n")
        
    print(f"[{tc['id']}] Done -> {out_file}")