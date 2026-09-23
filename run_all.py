import os
import subprocess
import sys

COMBINED_OUTPUT = "TEST/all_results.jsonl"

TEST_CASES = [
    {
        "pcap": "TEST/test_tcp_handshake.pcap",
        "output": "TEST/res_tcp_handshake.jsonl",
        "msg": "Test TCP handshake parsing"
    },
    {
        "pcap": "TEST/test_tcp_data.pcap",
        "output": "TEST/res_tcp_data.jsonl",
        "msg": "Test TCP data parsing"
    },
    {
        "pcap": "TEST/test_udp.pcap",
        "output": "TEST/res_udp.jsonl",
        "msg": "Test UDP packet parsing"
    },
    {
        "pcap": "TEST/test_http_get.pcap",
        "output": "TEST/res_http_get.jsonl",
        "msg": "Test HTTP GET request parsing"
    },
    {
        "pcap": "TEST/test_http_post.pcap",
        "output": "TEST/res_http_post.jsonl",
        "msg": "Test HTTP POST request parsing with body"
    },
    {
        "pcap": "TEST/test_http_response.pcap",
        "output": "TEST/res_http_response.jsonl",
        "msg": "Test HTTP response parsing"
    },
    {
        "pcap": "TEST/test_dns_query.pcap",
        "output": "TEST/res_dns_query.jsonl",
        "msg": "Test DNS query parsing"
    },
    {
        "pcap": "TEST/test_dns_response.pcap",
        "output": "TEST/res_dns_response.jsonl",
        "msg": "Test DNS response parsing with answer section"
    },
    {
        "pcap": "TEST/test_smtp_command.pcap",
        "output": "TEST/res_smtp_command.jsonl",
        "msg": "Test SMTP command parsing"
    },
    {
        "pcap": "TEST/test_smtp_response.pcap",
        "output": "TEST/res_smtp_response.jsonl",
        "msg": "Test SMTP response parsing"
    },
    {
        "pcap": "TEST/test_malformed.pcap",
        "output": "TEST/res_malformed.jsonl",
        "msg": "Test unknown protocols and malformed packet handling without crash"
    }
]

if os.path.exists(COMBINED_OUTPUT):
    os.remove(COMBINED_OUTPUT)

for idx, tc in enumerate(TEST_CASES, 1):
    pcap_path = tc["pcap"]
    out_path = tc["output"]
    msg = tc["msg"]

    if os.path.exists(out_path):
        os.remove(out_path)

    print(f"[{idx}/11] Running: {pcap_path} -> {out_path}")
    res = subprocess.run([sys.executable, "main.py", "--pcap", pcap_path, "--output", out_path])
    
    if res.returncode != 0:
        print(f"Error executing test case: {pcap_path}")
        sys.exit(1)

    if os.path.exists(out_path):
        with open(out_path, "r", encoding="utf-8") as f_in, open(COMBINED_OUTPUT, "a", encoding="utf-8") as f_out:
            f_out.write(f_in.read())

print("Finished all 11 test cases, updated TEST/all_results.jsonl")