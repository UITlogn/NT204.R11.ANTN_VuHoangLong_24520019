import os
from scapy.all import wrpcap, Ether, IP, TCP, UDP, Raw
from scapy.layers.dns import DNS, DNSQR, DNSRR

os.makedirs("TEST", exist_ok=True)

# 1. TCP Handshake (SYN, SYN/ACK, ACK)
pkts_handshake = [
    IP(src="192.168.1.10", dst="192.168.1.20") / TCP(sport=12345, dport=80, flags="S", seq=1000),
    IP(src="192.168.1.20", dst="192.168.1.10") / TCP(sport=80, dport=12345, flags="SA", seq=2000, ack=1001),
    IP(src="192.168.1.10", dst="192.168.1.20") / TCP(sport=12345, dport=80, flags="A", seq=1001, ack=2001)
]
wrpcap("TEST/test_tcp_handshake.pcap", pkts_handshake)

# 2. TCP Data
pkts_tcp_data = [
    IP(src="192.168.1.10", dst="192.168.1.20") / TCP(sport=12345, dport=8080, flags="PA", seq=1001, ack=2001) / Raw(load=b"Sample TCP payload stream")
]
wrpcap("TEST/test_tcp_data.pcap", pkts_tcp_data)

# 3. UDP
pkts_udp = [
    IP(src="192.168.1.10", dst="192.168.1.20") / UDP(sport=5000, dport=6000) / Raw(load=b"Sample UDP datagram")
]
wrpcap("TEST/test_udp.pcap", pkts_udp)

# 4. HTTP GET
http_get_payload = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: IDS-Tester\r\n\r\n"
pkts_http_get = [
    IP(src="192.168.1.10", dst="93.184.216.34") / TCP(sport=43210, dport=80, flags="PA") / Raw(load=http_get_payload)
]
wrpcap("TEST/test_http_get.pcap", pkts_http_get)

# 5. HTTP POST (có body)
http_post_payload = b"POST /api/login HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/json\r\nContent-Length: 18\r\n\r\n{\"user\": \"admin\"}"
pkts_http_post = [
    IP(src="192.168.1.10", dst="93.184.216.34") / TCP(sport=43211, dport=80, flags="PA") / Raw(load=http_post_payload)
]
wrpcap("TEST/test_http_post.pcap", pkts_http_post)

# 6. HTTP Response
http_res_payload = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 13\r\n\r\nHello, World!"
pkts_http_res = [
    IP(src="93.184.216.34", dst="192.168.1.10") / TCP(sport=80, dport=43210, flags="PA") / Raw(load=http_res_payload)
]
wrpcap("TEST/test_http_response.pcap", pkts_http_res)

# 7. DNS Query
dns_query_pkt = [
    IP(src="192.168.1.10", dst="8.8.8.8") / UDP(sport=53535, dport=53) / DNS(id=0x1234, qr=0, qd=DNSQR(qname="uit.edu.vn", qtype="A"))
]
wrpcap("TEST/test_dns_query.pcap", dns_query_pkt)

# 8. DNS Response (chứa ít nhất 1 answer)
raw_dns_resp = DNS(
    id=0x1234,
    qr=1,
    aa=1,
    rd=1,
    ra=1,
    qdcount=1,
    ancount=1,
    qd=DNSQR(qname="uit.edu.vn", qtype="A"),
    an=DNSRR(rrname="uit.edu.vn", type="A", rclass="IN", ttl=300, rdata="118.69.123.10")
)

dns_res_pkt = [
    IP(src="8.8.8.8", dst="192.168.1.10") / UDP(sport=53, dport=53535) / raw_dns_resp
]
wrpcap("TEST/test_dns_response.pcap", dns_res_pkt)

# 9. SMTP Command
smtp_cmd_payload = b"MAIL FROM:<alice@example.com>\r\n"
pkts_smtp_cmd = [
    IP(src="192.168.1.10", dst="192.168.1.25") / TCP(sport=35000, dport=25, flags="PA") / Raw(load=smtp_cmd_payload)
]
wrpcap("TEST/test_smtp_command.pcap", pkts_smtp_cmd)

# 10. SMTP Response
smtp_res_payload = b"250 2.1.0 Ok\r\n"
pkts_smtp_res = [
    IP(src="192.168.1.25", dst="192.168.1.10") / TCP(sport=25, dport=35000, flags="PA") / Raw(load=smtp_res_payload)
]
wrpcap("TEST/test_smtp_response.pcap", pkts_smtp_res)

# 11. Unknown / Malformed Packet
pkts_malformed = [
    Ether() / Raw(load=b"\xff\xfe\xfd\x00\x11\x22\x33\x44"),  # Không có IP header
    IP(src="10.0.0.1", dst="10.0.0.2", proto=99) / Raw(load=b"\x00\x01\x02\x03\x04")  # Protocol lạ
]
wrpcap("TEST/test_malformed.pcap", pkts_malformed)
