from scapy.layers.inet import TCP, UDP


def parse_payload(payload):
    payload_bytes = bytes(payload) if payload else b""
    data = {
        "payload_length": len(payload_bytes),
        "payload_hex": payload_bytes.hex() if payload_bytes else ""
    }

    if payload_bytes:
        try:
            data["payload_text"] = payload_bytes.decode("utf-8")
        except UnicodeDecodeError:
            data["payload_text"] = None
    else:
        data["payload_text"] = ""

    return data


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

        data = {
            "protocol": "TCP",
            "src_port": tcp.sport,
            "dst_port": tcp.dport,
            "seq": tcp.seq,
            "ack": tcp.ack,
            "flags": flags
        }
        data.update(parse_payload(tcp.payload))
        return data

    if packet.haslayer(UDP):
        udp = packet[UDP]
        data = {
            "protocol": "UDP",
            "src_port": udp.sport,
            "dst_port": udp.dport,
            "length": udp.len,
            "checksum": udp.chksum
        }
        data.update(parse_payload(udp.payload))
        return data

    return None
