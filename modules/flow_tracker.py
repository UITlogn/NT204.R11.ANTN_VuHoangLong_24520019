import hashlib

class FlowTracker:
    def __init__(self, tcp_idle_timeout=30.0, udp_idle_timeout=15.0):
        self.tcp_idle_timeout = tcp_idle_timeout
        self.udp_idle_timeout = udp_idle_timeout
        self.active_flows = {}

    def _generate_flow_key(self, src_ip, dst_ip, src_port, dst_port, protocol):
        ep1 = (src_ip, src_port)
        ep2 = (dst_ip, dst_port)
        if ep1 < ep2:
            base_str = f"{src_ip}:{src_port}<->{dst_ip}:{dst_port}_{protocol}"
            direction = "forward"
        else:
            base_str = f"{dst_ip}:{dst_port}<->{src_ip}:{src_port}_{protocol}"
            direction = "backward"

        flow_id = hashlib.md5(base_str.encode("utf-8")).hexdigest()[:16]
        return base_str, flow_id, direction

    def update(self, event):
        net = event.get("network")
        trans = event.get("transport")
        if not net or not trans:
            return None, []

        src_ip = net.get("src_ip")
        dst_ip = net.get("dst_ip")
        src_port = trans.get("src_port")
        dst_port = trans.get("dst_port")
        proto = trans.get("protocol", "UNKNOWN").upper()
        ts = float(event.get("timestamp", 0.0))
        byte_len = int(net.get("total_length", 0) or trans.get("length", 0) or 60)

        flow_key, flow_id, direction = self._generate_flow_key(src_ip, dst_ip, src_port, dst_port, proto)

        expired_flows = self.check_timeouts(current_time=ts)

        flow = self.active_flows.get(flow_key)
        if not flow:
            flow = {
                "flow_id": flow_id,
                "protocol": proto,
                "application_protocol": event.get("application_protocol", "UNKNOWN"),
                "endpoint_a": f"{src_ip}:{src_port}",
                "endpoint_b": f"{dst_ip}:{dst_port}",
                "start_time": ts,
                "last_seen": ts,
                "duration": 0.0,
                "packet_count": 0,
                "byte_count": 0,
                "fwd_packet_count": 0,
                "bwd_packet_count": 0,
                "fwd_byte_count": 0,
                "bwd_byte_count": 0,
                "tcp_stats": {
                    "syn_count": 0,
                    "ack_count": 0,
                    "fin_count": 0,
                    "rst_count": 0,
                    "state": "NEW" if proto == "TCP" else "NONE"
                }
            }
            self.active_flows[flow_key] = flow

        flow["last_seen"] = ts
        flow["duration"] = round(ts - flow["start_time"], 4)
        flow["packet_count"] += 1
        flow["byte_count"] += byte_len

        if direction == "forward":
            flow["fwd_packet_count"] += 1
            flow["fwd_byte_count"] += byte_len
        else:
            flow["bwd_packet_count"] += 1
            flow["bwd_byte_count"] += byte_len

        if proto == "TCP":
            flags = trans.get("flags", [])
            has_syn = "SYN" in flags
            has_ack = "ACK" in flags
            has_fin = "FIN" in flags
            has_rst = "RST" in flags

            if has_syn: flow["tcp_stats"]["syn_count"] += 1
            if has_ack: flow["tcp_stats"]["ack_count"] += 1
            if has_fin: flow["tcp_stats"]["fin_count"] += 1
            if has_rst: flow["tcp_stats"]["rst_count"] += 1

            current_state = flow["tcp_stats"]["state"]
            if has_rst:
                flow["tcp_stats"]["state"] = "RESET"
            elif has_fin:
                flow["tcp_stats"]["state"] = "CLOSING"
            elif current_state in ("NEW", "HANDSHAKE"):
                if has_syn and not has_ack:
                    flow["tcp_stats"]["state"] = "HANDSHAKE"
                elif has_ack:
                    flow["tcp_stats"]["state"] = "ESTABLISHED"
            elif current_state == "CLOSING" and has_ack:
                flow["tcp_stats"]["state"] = "CLOSED"

        event["flow_id"] = flow_id
        event["direction"] = direction
        return flow, expired_flows

    def check_timeouts(self, current_time):
        expired = []
        keys_to_remove = []

        for key, flow in self.active_flows.items():
            timeout = self.tcp_idle_timeout if flow["protocol"] == "TCP" else self.udp_idle_timeout
            if (current_time - flow["last_seen"]) > timeout:
                expired.append(flow)
                keys_to_remove.append(key)

        for k in keys_to_remove:
            del self.active_flows[k]

        return expired