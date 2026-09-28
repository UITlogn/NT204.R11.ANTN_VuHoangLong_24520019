import json
import subprocess
import sys
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent
TEST_DIR = BASE_DIR / "TEST"
COMBINED_OUTPUT = TEST_DIR / "all_results.jsonl"


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def one_event(events):
    require(len(events) == 1, f"expected 1 event, got {len(events)}")
    return events[0]


def validate_tcp_handshake(events):
    require(len(events) == 3, f"expected 3 handshake packets, got {len(events)}")
    flags = [event["transport"]["flags"] for event in events]
    require(flags == [["SYN"], ["SYN", "ACK"], ["ACK"]], f"wrong TCP flags: {flags}")


def validate_tcp_data(events):
    event = one_event(events)
    transport = event["transport"]
    require(transport["protocol"] == "TCP", "packet was not parsed as TCP")
    require(transport["payload_length"] > 0, "TCP payload is empty")
    require(
        transport["payload_text"] == "Sample TCP payload stream",
        "TCP payload text was not preserved",
    )


def validate_udp(events):
    event = one_event(events)
    transport = event["transport"]
    require(transport["protocol"] == "UDP", "packet was not parsed as UDP")
    require(transport["payload_text"] == "Sample UDP datagram", "UDP payload is wrong")


def validate_http_get(events):
    application = one_event(events)["application"]
    require(application["type"] == "request", "HTTP GET was not parsed as a request")
    require(application["method"] == "GET", "HTTP method is not GET")
    require(application["uri"] == "/index.html", "HTTP GET URI is wrong")


def validate_http_post(events):
    application = one_event(events)["application"]
    require(application["method"] == "POST", "HTTP method is not POST")
    require(application["body"] == '{"user": "admin"}', "HTTP POST body is wrong")


def validate_http_response(events):
    application = one_event(events)["application"]
    require(application["type"] == "response", "HTTP response type is wrong")
    require(application["status_code"] == 200, "HTTP status code is not 200")
    require("Content-Type" in application["headers"], "HTTP response header is missing")


def validate_dns_query(events):
    application = one_event(events)["application"]
    require(application["qr"] == "query", "DNS packet is not a query")
    require(application["queries"][0]["qname"] == "uit.edu.vn", "DNS name is wrong")
    require(application["queries"][0]["qtype"] == 1, "DNS query type is not A")


def validate_dns_response(events):
    application = one_event(events)["application"]
    require(application["qr"] == "response", "DNS packet is not a response")
    require(len(application["answers"]) >= 1, "DNS response has no answer")


def validate_smtp_command(events):
    application = one_event(events)["application"]
    require(application["type"] == "command", "SMTP packet is not a command")
    require(application["command"] == "MAIL FROM", "SMTP command is wrong")


def validate_smtp_response(events):
    application = one_event(events)["application"]
    require(application["type"] == "response", "SMTP packet is not a response")
    require(application["status_code"] == 250, "SMTP status code is not 250")


def validate_unknown_protocol(events):
    event = one_event(events)
    require(event["network"]["proto"] == 99, "unknown IPv4 protocol was not preserved")
    require(event["transport"] is None, "unknown protocol unexpectedly has transport data")
    require(event["application_protocol"] == "UNKNOWN", "protocol was not marked UNKNOWN")
    require(event.get("error") is None, "valid unknown protocol was marked malformed")


def validate_malformed_packet(events):
    event = one_event(events)
    require(event["error"] == "malformed_packet", "malformed packet error is missing")


TEST_CASES = [
    ("TCP handshake", "test_tcp_handshake.pcap", "res_tcp_handshake.jsonl", validate_tcp_handshake),
    ("TCP data", "test_tcp_data.pcap", "res_tcp_data.jsonl", validate_tcp_data),
    ("UDP", "test_udp.pcap", "res_udp.jsonl", validate_udp),
    ("HTTP GET", "test_http_get.pcap", "res_http_get.jsonl", validate_http_get),
    ("HTTP POST", "test_http_post.pcap", "res_http_post.jsonl", validate_http_post),
    ("HTTP response", "test_http_response.pcap", "res_http_response.jsonl", validate_http_response),
    ("DNS query", "test_dns_query.pcap", "res_dns_query.jsonl", validate_dns_query),
    ("DNS response", "test_dns_response.pcap", "res_dns_response.jsonl", validate_dns_response),
    ("SMTP command", "test_smtp_command.pcap", "res_smtp_command.jsonl", validate_smtp_command),
    ("SMTP response", "test_smtp_response.pcap", "res_smtp_response.jsonl", validate_smtp_response),
    ("Unknown protocol", "test_unknown_protocol.pcap", "res_unknown_protocol.jsonl", validate_unknown_protocol),
    ("Malformed packet", "test_malformed.pcap", "res_malformed.jsonl", validate_malformed_packet),
]


def load_events(output_path):
    events = []
    with output_path.open("r", encoding="utf-8") as output_file:
        for line_number, line in enumerate(output_file, 1):
            if not line.strip():
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise AssertionError(
                    f"invalid JSON on line {line_number}: {exc}"
                ) from exc
    require(events, "output JSONL is empty")
    return events


def run_test_case(index, test_case):
    name, pcap_name, output_name, validator = test_case
    pcap_path = TEST_DIR / pcap_name
    output_path = TEST_DIR / output_name
    output_path.unlink(missing_ok=True)

    print(f"[{index}/{len(TEST_CASES)}] {name}")
    result = subprocess.run(
        [
            sys.executable,
            str(BASE_DIR / "main.py"),
            "--pcap",
            str(pcap_path),
            "--output",
            str(output_path),
        ],
        cwd=BASE_DIR,
        capture_output=True,
        text=True,
        check=False,
    )
    require(result.returncode == 0, f"process exited with {result.returncode}: {result.stderr}")
    require(output_path.exists(), "result file was not created")

    events = load_events(output_path)
    validator(events)
    print(f"    PASS ({len(events)} event(s))")
    return output_path


def main():
    result_paths = []
    try:
        for index, test_case in enumerate(TEST_CASES, 1):
            result_paths.append(run_test_case(index, test_case))
    except (AssertionError, OSError) as exc:
        print(f"    FAIL: {exc}", file=sys.stderr)
        return 1

    with COMBINED_OUTPUT.open("w", encoding="utf-8") as combined_file:
        for result_path in result_paths:
            combined_file.write(result_path.read_text(encoding="utf-8"))

    print(f"All {len(TEST_CASES)} test cases passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
