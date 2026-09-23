import re
from scapy.layers.dns import DNS, DNSRR
from scapy.packet import Raw

HTTP_METHODS = [b"GET", b"POST", b"PUT", b"DELETE", b"HEAD", b"OPTIONS", b"PATCH"]
SMTP_COMMANDS = [b"HELO", b"EHLO", b"MAIL FROM:", b"RCPT TO:", b"DATA", b"QUIT", b"RSET", b"STARTTLS", b"AUTH"]

def detect_protocol(packet, payload_bytes):
    if packet.haslayer(DNS):
        return "DNS"

    if payload_bytes:
        first_line = payload_bytes.split(b"\r\n")[0].strip()

        for m in HTTP_METHODS:
            if first_line.startswith(m + b" "):
                return "HTTP"
        if first_line.startswith(b"HTTP/1."):
            return "HTTP"

        first_line_upper = first_line.upper()
        for cmd in SMTP_COMMANDS:
            if first_line_upper.startswith(cmd):
                return "SMTP"

        if re.match(rb"^\d{3}[ -]", first_line):
            return "SMTP"

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
        curr = dns.qd
        for _ in range(dns.qdcount):
            if not curr:
                break
            qname = curr.qname.decode("utf-8", errors="ignore").rstrip(".") if hasattr(curr, "qname") and curr.qname else ""
            data["queries"].append({
                "qname": qname,
                "qtype": int(curr.qtype)
            })
            curr = curr.payload if hasattr(curr, "payload") and curr.payload and curr.payload.name != "NoPayload" else None

    if dns.ancount > 0:
        for i in range(1, int(dns.ancount) + 1):
            answer = packet.getlayer(DNSRR, i)
            if answer is None:
                break
            rdata = answer.rdata
            if isinstance(rdata, bytes):
                rdata = rdata.decode("utf-8", errors="ignore")
            else:
                rdata = str(rdata)
            rrname = answer.rrname
            if isinstance(rrname, bytes):
                rrname = rrname.decode("utf-8", errors="ignore")
            else:
                rrname = str(rrname)
            data["answers"].append({
                "rrname": rrname.rstrip("."),
                "type": int(answer.type),
                "rdata": rdata.rstrip("."),
                "ttl": int(answer.ttl)
            })

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
            tokens = start_line.split(" ", 2)
            data["type"] = "response"
            data["version"] = tokens[0]
            data["status_code"] = int(tokens[1]) if len(tokens) > 1 and tokens[1].isdigit() else tokens[1]
            data["status_message"] = tokens[2] if len(tokens) > 2 else ""
        else:
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

def parse_smtp(payload_bytes):
    data = {}
    try:
        text = payload_bytes.decode("utf-8", errors="ignore").strip()
        first_line = text.split("\r\n")[0]

        match_resp = re.match(r"^(\d{3})([ -])(.*)", first_line)
        if match_resp:
            data["type"] = "response"
            data["status_code"] = int(match_resp.group(1))
            data["message"] = match_resp.group(3).strip()
        else:
            data["type"] = "command"
            upper_line = first_line.upper()
            if upper_line.startswith("MAIL FROM:"):
                data["command"] = "MAIL FROM"
                data["arguments"] = first_line[10:].strip()
            elif upper_line.startswith("RCPT TO:"):
                data["command"] = "RCPT TO"
                data["arguments"] = first_line[8:].strip()
            else:
                tokens = first_line.split(" ", 1)
                data["command"] = tokens[0].upper()
                data["arguments"] = tokens[1].strip() if len(tokens) > 1 else ""
    except Exception:
        data["error"] = "malformed_smtp"

    return data

def parse_application(packet):
    payload_bytes = bytes(packet[Raw].load) if packet.haslayer(Raw) else b""
    proto = detect_protocol(packet, payload_bytes)

    if proto == "DNS":
        return proto, parse_dns(packet)
    if proto == "HTTP":
        return proto, parse_http(payload_bytes)
    if proto == "SMTP":
        return proto, parse_smtp(payload_bytes)

    return "UNKNOWN", None
