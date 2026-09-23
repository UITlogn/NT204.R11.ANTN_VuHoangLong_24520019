import re
from scapy.layers.dns import DNS, DNSRR
from scapy.packet import Raw

HTTP_METHODS = [b"GET", b"POST", b"PUT", b"DELETE", b"HEAD", b"OPTIONS", b"PATCH"]

def detect_protocol(packet, payload_bytes):
    if packet.haslayer(DNS):
        return "DNS"

    if payload_bytes:
        first_line = payload_bytes.split(b"\r\n")[0]
        # Payload-based detection cho HTTP Request
        for m in HTTP_METHODS:
            if first_line.startswith(m + b" "):
                return "HTTP"
        # Payload-based detection cho HTTP Response
        if first_line.startswith(b"HTTP/1."):
            return "HTTP"

    return "UNKNOWN"

def parse_dns(packet):
    dns = packet[DNS]
    data = {
        "id": int(dns.id),
        "qr": "response" if dns.qr == 1 else "query",
        "queries": [],
        "answers": []
    }

    if dns.qdcount > 0 and dns.qd:
        curr_qd = dns.qd
        while curr_qd:
            qname = curr_qd.qname.decode("utf-8", errors="ignore").rstrip(".") if hasattr(curr_qd, "qname") else ""
            data["queries"].append({
                "qname": qname,
                "qtype": int(curr_qd.qtype)
            })
            curr_qd = curr_qd.payload if hasattr(curr_qd, "payload") and isinstance(curr_qd.payload, type(dns.qd)) else None

    if dns.ancount > 0 and dns.an:
        curr_an = dns.an
        while curr_an:
            if isinstance(curr_an, DNSRR):
                rdata = curr_an.rdata
                if isinstance(rdata, bytes):
                    rdata = rdata.decode("utf-8", errors="ignore")
                rrname = curr_an.rrname.decode("utf-8", errors="ignore").rstrip(".") if hasattr(curr_an, "rrname") else ""
                data["answers"].append({
                    "rrname": rrname,
                    "type": int(curr_an.type),
                    "rdata": str(rdata),
                    "ttl": int(curr_an.ttl)
                })
            curr_an = curr_an.payload if hasattr(curr_an, "payload") and isinstance(curr_an.payload, DNSRR) else None

    return data

def parse_http(payload_bytes):
    data = {}
    try:
        parts = payload_bytes.split(b"\r\n\r\n", 1)
        header_raw = parts[0].decode("utf-8", errors="ignore")
        body_raw = parts[1] if len(parts) > 1 else b""

        lines = header_raw.split("\r\n")
        start_line = lines[0]

        if start_line.startswith("HTTP/1."):
            # HTTP Response
            tokens = start_line.split(" ", 2)
            data["type"] = "response"
            data["version"] = tokens[0]
            data["status_code"] = int(tokens[1]) if len(tokens) > 1 and tokens[1].isdigit() else tokens[1]
            data["status_message"] = tokens[2] if len(tokens) > 2 else ""
        else:
            # HTTP Request
            tokens = start_line.split(" ", 2)
            data["type"] = "request"
            data["method"] = tokens[0]
            data["uri"] = tokens[1] if len(tokens) > 1 else ""
            data["version"] = tokens[2] if len(tokens) > 2 else ""

        headers = {}
        for line in lines[1:]:
            if ": " in line:
                k, v = line.split(": ", 1)
                headers[k.strip()] = v.strip()
        data["headers"] = headers

        if body_raw:
            data["body"] = body_raw.decode("utf-8", errors="ignore")

    except Exception:
        data["error"] = "malformed_http"

    return data

def parse_application(packet):
    payload_bytes = bytes(packet[Raw].load) if packet.haslayer(Raw) else b""
    proto = detect_protocol(packet, payload_bytes)

    if proto == "DNS":
        return proto, parse_dns(packet)
    if proto == "HTTP":
        return proto, parse_http(payload_bytes)

    return "UNKNOWN", None