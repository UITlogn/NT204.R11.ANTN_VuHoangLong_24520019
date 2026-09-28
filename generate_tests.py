import os

from scapy.all import Ether, IP, TCP, UDP, Raw, wrpcap
from scapy.layers.dns import DNS, DNSQR, DNSRR


os.makedirs("TEST", exist_ok=True)


def write_pcap(path, packets):
    """Write reproducible fixtures so rerunning this script does not change timestamps."""
    for index, packet in enumerate(packets):
        packet.time = 1_700_000_000 + index
    wrpcap(path, packets)


# 1. TCP handshake (SYN, SYN/ACK, ACK)
pkts_handshake = [
    IP(src="192.168.1.10", dst="192.168.1.20")
    / TCP(sport=12345, dport=80, flags="S", seq=1000),
    IP(src="192.168.1.20", dst="192.168.1.10")
    / TCP(sport=80, dport=12345, flags="SA", seq=2000, ack=1001),
    IP(src="192.168.1.10", dst="192.168.1.20")
    / TCP(sport=12345, dport=80, flags="A", seq=1001, ack=2001),
]
write_pcap("TEST/test_tcp_handshake.pcap", pkts_handshake)

# 2. TCP data
pkts_tcp_data = [
    IP(src="192.168.1.10", dst="192.168.1.20")
    / TCP(sport=12345, dport=8080, flags="PA", seq=1001, ack=2001)
    / Raw(load=b"Sample TCP payload stream")
]
write_pcap("TEST/test_tcp_data.pcap", pkts_tcp_data)

# 3. UDP
pkts_udp = [
    IP(src="192.168.1.10", dst="192.168.1.20")
    / UDP(sport=5000, dport=6000)
    / Raw(load=b"Sample UDP datagram")
]
write_pcap("TEST/test_udp.pcap", pkts_udp)

# 4. HTTP GET
http_get_payload = (
    b"GET /index.html HTTP/1.1\r\n"
    b"Host: example.com\r\n"
    b"User-Agent: IDS-Tester\r\n\r\n"
)
pkts_http_get = [
    IP(src="192.168.1.10", dst="93.184.216.34")
    / TCP(sport=43210, dport=80, flags="PA")
    / Raw(load=http_get_payload)
]
write_pcap("TEST/test_http_get.pcap", pkts_http_get)

# 5. HTTP POST with body
http_post_payload = (
    b"POST /api/login HTTP/1.1\r\n"
    b"Host: example.com\r\n"
    b"Content-Type: application/json\r\n"
    b"Content-Length: 17\r\n\r\n"
    b'{"user": "admin"}'
)
pkts_http_post = [
    IP(src="192.168.1.10", dst="93.184.216.34")
    / TCP(sport=43211, dport=80, flags="PA")
    / Raw(load=http_post_payload)
]
write_pcap("TEST/test_http_post.pcap", pkts_http_post)

# 6. HTTP response
http_response_payload = (
    b"HTTP/1.1 200 OK\r\n"
    b"Content-Type: text/html\r\n"
    b"Content-Length: 13\r\n\r\n"
    b"Hello, World!"
)
pkts_http_response = [
    IP(src="93.184.216.34", dst="192.168.1.10")
    / TCP(sport=80, dport=43210, flags="PA")
    / Raw(load=http_response_payload)
]
write_pcap("TEST/test_http_response.pcap", pkts_http_response)

# 7. DNS query
pkts_dns_query = [
    IP(src="192.168.1.10", dst="8.8.8.8")
    / UDP(sport=53535, dport=53)
    / DNS(id=0x1234, qr=0, qd=DNSQR(qname="uit.edu.vn", qtype="A"))
]
write_pcap("TEST/test_dns_query.pcap", pkts_dns_query)

# 8. DNS response with at least one answer
dns_response = DNS(
    id=0x1234,
    qr=1,
    aa=1,
    rd=1,
    ra=1,
    qdcount=1,
    ancount=1,
    qd=DNSQR(qname="uit.edu.vn", qtype="A"),
    an=DNSRR(
        rrname="uit.edu.vn",
        type="A",
        rclass="IN",
        ttl=300,
        rdata="118.69.123.10",
    ),
)
pkts_dns_response = [
    IP(src="8.8.8.8", dst="192.168.1.10")
    / UDP(sport=53, dport=53535)
    / dns_response
]
write_pcap("TEST/test_dns_response.pcap", pkts_dns_response)

# 9. SMTP command
pkts_smtp_command = [
    IP(src="192.168.1.10", dst="192.168.1.25")
    / TCP(sport=35000, dport=25, flags="PA")
    / Raw(load=b"MAIL FROM:<alice@example.com>\r\n")
]
write_pcap("TEST/test_smtp_command.pcap", pkts_smtp_command)

# 10. SMTP response
pkts_smtp_response = [
    IP(src="192.168.1.25", dst="192.168.1.10")
    / TCP(sport=25, dport=35000, flags="PA")
    / Raw(load=b"250 2.1.0 Ok\r\n")
]
write_pcap("TEST/test_smtp_response.pcap", pkts_smtp_response)

# 11. Unknown protocol: valid IPv4 with an unsupported transport protocol.
pkts_unknown = [
    IP(src="10.0.0.1", dst="10.0.0.2", proto=99)
    / Raw(load=b"\x00\x01\x02\x03\x04")
]
write_pcap("TEST/test_unknown_protocol.pcap", pkts_unknown)

# 12. Malformed packet: missing the required IPv4 header.
pkts_malformed = [
    Ether() / Raw(load=b"\xff\xfe\xfd\x00\x11\x22\x33\x44")
]
write_pcap("TEST/test_malformed.pcap", pkts_malformed)
