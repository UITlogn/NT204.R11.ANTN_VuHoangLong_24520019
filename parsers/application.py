from scapy.layers.dns import DNS, DNSRR
from scapy.packet import Raw

def detect_protocol(packet):
    if packet.haslayer(DNS):
        return "DNS"
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

def parse_application(packet):
    proto = detect_protocol(packet)

    if proto == "DNS":
        return proto, parse_dns(packet)

    return "UNKNOWN", None