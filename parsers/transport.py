from scapy.layers.inet import TCP, UDP

def parse_transport(packet):
    if packet.haslayer(TCP):
        tcp = packet[TCP]
        flags = []
        flag_val = int(tcp.flags)
        if flag_val & 0x02: flags.append("SYN")
        if flag_val & 0x10: flags.append("ACK")
        if flag_val & 0x01: flags.append("FIN")
        if flag_val & 0x04: flags.append("RST")
        if flag_val & 0x08: flags.append("PSH")
        if flag_val & 0x20: flags.append("URG")

        return {
            "protocol": "TCP",
            "src_port": tcp.sport,
            "dst_port": tcp.dport,
            "seq": tcp.seq,
            "ack": tcp.ack,
            "flags": flags
        }

    if packet.haslayer(UDP):
        udp = packet[UDP]
        return {
            "protocol": "UDP",
            "src_port": udp.sport,
            "dst_port": udp.dport,
            "length": udp.len,
            "checksum": udp.chksum
        }

    return None