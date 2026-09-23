import os
from scapy.all import wrpcap, Ether, IP, TCP, UDP, Raw
from scapy.layers.dns import DNS, DNSQR, DNSRR

# 8. DNS Response
pkt_dns_res = (
    IP(src="8.8.8.8", dst="192.168.1.10") /
    UDP(sport=53, dport=53535) /
    DNS(
        id=0x1234,
        qr=1,
        qd=DNSQR(qname="uit.edu.vn", qtype="A"),
        an=DNSRR(rrname="uit.edu.vn", type="A", rclass="IN", ttl=300, rdata="118.69.123.10")
    )
)
wrpcap("TEST/test_dns_response.pcap", [pkt_dns_res])