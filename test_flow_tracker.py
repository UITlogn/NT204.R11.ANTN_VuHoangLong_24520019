import json
import os
from modules.flow_tracker import FlowTracker

os.makedirs("TEST", exist_ok=True)

# T07: TCP Handshake -> ESTABLISHED
tracker_t07 = FlowTracker()
pkts_t07 = [
    {"packet_id": 1, "timestamp": 100.0, "network": {"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2"}, "transport": {"protocol": "TCP", "src_port": 1234, "dst_port": 80, "flags": ["SYN"]}},
    {"packet_id": 2, "timestamp": 100.1, "network": {"src_ip": "10.0.0.2", "dst_ip": "10.0.0.1"}, "transport": {"protocol": "TCP", "src_port": 80, "dst_port": 1234, "flags": ["SYN", "ACK"]}},
    {"packet_id": 3, "timestamp": 100.2, "network": {"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2"}, "transport": {"protocol": "TCP", "src_port": 1234, "dst_port": 80, "flags": ["ACK"]}}
]
res_t07 = None
for p in pkts_t07:
    res_t07, _ = tracker_t07.update(p)
with open("TEST/res_t07_tcp_handshake.jsonl", "w", encoding="utf-8") as f:
    f.write(json.dumps(res_t07) + "\n")

# T08: Bidirectional flow (A->B và B->A)
tracker_t08 = FlowTracker()
pkt_a = {"packet_id": 1, "timestamp": 200.0, "network": {"src_ip": "192.168.1.5", "dst_ip": "8.8.8.8"}, "transport": {"protocol": "TCP", "src_port": 4000, "dst_port": 53, "flags": ["ACK"]}}
pkt_b = {"packet_id": 2, "timestamp": 200.1, "network": {"src_ip": "8.8.8.8", "dst_ip": "192.168.1.5"}, "transport": {"protocol": "TCP", "src_port": 53, "dst_port": 4000, "flags": ["ACK"]}}
_, _ = tracker_t08.update(pkt_a)
res_t08, _ = tracker_t08.update(pkt_b)
with open("TEST/res_t08_bidirectional_flow.jsonl", "w", encoding="utf-8") as f:
    f.write(json.dumps(res_t08) + "\n")

# T09: TCP close (FIN/ACK & RST)
tracker_t09 = FlowTracker()
pkts_t09 = [
    {"packet_id": 1, "timestamp": 300.0, "network": {"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2"}, "transport": {"protocol": "TCP", "src_port": 5000, "dst_port": 80, "flags": ["ACK"]}},
    {"packet_id": 2, "timestamp": 300.1, "network": {"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2"}, "transport": {"protocol": "TCP", "src_port": 5000, "dst_port": 80, "flags": ["FIN", "ACK"]}},
    {"packet_id": 3, "timestamp": 300.2, "network": {"src_ip": "10.0.0.2", "dst_ip": "10.0.0.1"}, "transport": {"protocol": "TCP", "src_port": 80, "dst_port": 5000, "flags": ["ACK"]}}
]
res_t09 = None
for p in pkts_t09:
    res_t09, _ = tracker_t09.update(p)
with open("TEST/res_t09_tcp_close.jsonl", "w", encoding="utf-8") as f:
    f.write(json.dumps(res_t09) + "\n")

# T10: UDP query/response
tracker_t10 = FlowTracker()
pkts_t10 = [
    {"packet_id": 1, "timestamp": 400.0, "network": {"src_ip": "192.168.1.10", "dst_ip": "8.8.8.8", "total_length": 64}, "transport": {"protocol": "UDP", "src_port": 53535, "dst_port": 53}},
    {"packet_id": 2, "timestamp": 400.05, "network": {"src_ip": "8.8.8.8", "dst_ip": "192.168.1.10", "total_length": 128}, "transport": {"protocol": "UDP", "src_port": 53, "dst_port": 53535}}
]
res_t10 = None
for p in pkts_t10:
    res_t10, _ = tracker_t10.update(p)
with open("TEST/res_t10_udp_flow.jsonl", "w", encoding="utf-8") as f:
    f.write(json.dumps(res_t10) + "\n")

# T11: Concurrent flows
tracker_t11 = FlowTracker()
pkt_f1 = {"packet_id": 1, "timestamp": 500.0, "network": {"src_ip": "10.0.0.1", "dst_ip": "1.1.1.1"}, "transport": {"protocol": "TCP", "src_port": 1111, "dst_port": 80, "flags": ["SYN"]}}
pkt_f2 = {"packet_id": 2, "timestamp": 500.1, "network": {"src_ip": "10.0.0.1", "dst_ip": "8.8.8.8"}, "transport": {"protocol": "TCP", "src_port": 2222, "dst_port": 53, "flags": ["SYN"]}}
res_f1, _ = tracker_t11.update(pkt_f1)
res_f2, _ = tracker_t11.update(pkt_f2)
with open("TEST/res_t11_concurrent_flows.jsonl", "w", encoding="utf-8") as f:
    f.write(json.dumps({"flow_count": len(tracker_t11.active_flows), "f1_id": res_f1["flow_id"], "f2_id": res_f2["flow_id"]}) + "\n")

# T12: Idle timeout
tracker_t12 = FlowTracker(tcp_idle_timeout=5.0)
pkt_early = {"packet_id": 1, "timestamp": 600.0, "network": {"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2"}, "transport": {"protocol": "TCP", "src_port": 3000, "dst_port": 80, "flags": ["ACK"]}}
tracker_t12.update(pkt_early)
# Gói tin sau đó 10s -> kích hoạt timeout flow cũ
pkt_late = {"packet_id": 2, "timestamp": 610.0, "network": {"src_ip": "10.0.0.5", "dst_ip": "10.0.0.6"}, "transport": {"protocol": "TCP", "src_port": 4000, "dst_port": 80, "flags": ["SYN"]}}
_, expired = tracker_t12.update(pkt_late)
with open("TEST/res_t12_idle_timeout.jsonl", "w", encoding="utf-8") as f:
    f.write(json.dumps({"expired_count": len(expired), "expired_flow_id": expired[0]["flow_id"] if expired else None}) + "\n")

# T13: Statistics
tracker_t13 = FlowTracker()
for i in range(10):
    src = "10.0.0.1" if i % 2 == 0 else "10.0.0.2"
    dst = "10.0.0.2" if i % 2 == 0 else "10.0.0.1"
    sport = 9000 if i % 2 == 0 else 80
    dport = 80 if i % 2 == 0 else 9000
    pkt = {"packet_id": i+1, "timestamp": 700.0 + i*0.5, "network": {"src_ip": src, "dst_ip": dst, "total_length": 100}, "transport": {"protocol": "TCP", "src_port": sport, "dst_port": dport, "flags": ["ACK"]}}
    res_t13, _ = tracker_t13.update(pkt)
with open("TEST/res_t13_statistics.jsonl", "w", encoding="utf-8") as f:
    f.write(json.dumps(res_t13) + "\n")

print("Hoàn thành toàn bộ test cases T07 - T13 cho Flow Tracker.")