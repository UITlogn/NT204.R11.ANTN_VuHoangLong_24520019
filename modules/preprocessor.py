import ipaddress
import re

def is_valid_ip(ip_str):
    try:
        ipaddress.ip_address(ip_str)
        return True
    except Exception:
        return False

def preprocess_event(event):
    metadata = {
        "preprocess_status": "valid",
        "processing_action": "forward",
        "reason": []
    }

    # kiểm tra gói tin rỗng/lỗi từ capture
    if not isinstance(event, dict) or "error" in event:
        return {
            "packet_id": event.get("packet_id", 0) if isinstance(event, dict) else 0,
            "preprocess_status": "invalid",
            "processing_action": "drop",
            "reason": [event.get("error", "malformed_packet") if isinstance(event, dict) else "not_a_dict"],
            "raw_event": event
        }

    net = event.get("network")
    trans = event.get("transport")

    if not net or not isinstance(net, dict):
        metadata["preprocess_status"] = "invalid"
        metadata["processing_action"] = "drop"
        metadata["reason"].append("missing_network_layer")
        event["preprocessed"] = metadata
        return event

    src_ip = net.get("src_ip", "")
    dst_ip = net.get("dst_ip", "")
    if not (is_valid_ip(src_ip) and is_valid_ip(dst_ip)):
        metadata["preprocess_status"] = "invalid"
        metadata["processing_action"] = "drop"
        metadata["reason"].append("invalid_ip_format")

    # kiểm tra cổng nếu có tầng transport
    if trans and isinstance(trans, dict):
        src_port = trans.get("src_port")
        dst_port = trans.get("dst_port")
        if src_port is not None and not (0 <= src_port <= 65535):
            metadata["preprocess_status"] = "invalid"
            metadata["reason"].append("src_port_out_of_range")
        if dst_port is not None and not (0 <= dst_port <= 65535):
            metadata["preprocess_status"] = "invalid"
            metadata["reason"].append("dst_port_out_of_range")

    if trans and isinstance(trans, dict):
        if "protocol" in trans:
            trans["protocol"] = str(trans["protocol"]).upper()

    if "application_protocol" in event and event["application_protocol"]:
        event["application_protocol"] = str(event["application_protocol"]).upper()

    app = event.get("application")
    if app and isinstance(app, dict):
        # chuẩn hóa HTTP Headers sang lowercase
        if "headers" in app and isinstance(app["headers"], dict):
            normalized_headers = {}
            for k, v in app["headers"].items():
                normalized_headers[k.strip().lower()] = v.strip() if isinstance(v, str) else v
            app["headers"] = normalized_headers

        # chuẩn hóa URI/Path
        if "uri" in app and isinstance(app["uri"], str):
            app["uri"] = re.sub(r"/+", "/", app["uri"].strip())

        # chuẩn hóa domain trong DNS Queries
        if "queries" in app and isinstance(app["queries"], list):
            for q in app["queries"]:
                if "qname" in q and isinstance(q["qname"], str):
                    q["qname"] = q["qname"].strip().lower()

    # xử lý Missing fields
    if "transport" not in event or event["transport"] is None:
        event["transport"] = None
    if "application" not in event or event["application"] is None:
        event["application"] = None

    if metadata["reason"] and metadata["preprocess_status"] != "invalid":
        metadata["preprocess_status"] = "partial"

    event["preprocessed"] = metadata
    return event