from scapy.layers.inet import IP

def parse_network(packet):
    if not packet.haslayer(IP):
        return None
    ip = packet[IP]
    return {
        "src_ip": ip.src,
        "dst_ip": ip.dst,
        "version": ip.version,
        "ttl": ip.ttl,
        "proto": ip.proto
    }