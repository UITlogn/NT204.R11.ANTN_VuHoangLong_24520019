"""Repository, matcher, evaluator, and Detection Event for IDS Core Engine."""

import ipaddress
import re


class RuleRepository:
    def __init__(self, rules=()):
        self.rules = list(rules)
        self.index = {}
        for rule in self.rules:
            self.index.setdefault(rule["protocol"], []).append(rule)

    def candidates(self, event):
        protocol = str((event.get("transport") or {}).get("protocol", "")).lower()
        return [rule for rule in self.index.get(protocol, []) if header_matches(rule, event)]


class RuleMatcher:
    def match(self, rule, event, flow=None):
        if not header_matches(rule, event) or not self._flow_matches(rule["options"].get("flow", []), event, flow or {}):
            return False, {}

        transport = event.get("transport") or {}
        data = self._data(event)
        if not self._flags_match(rule["options"].get("flags"), transport.get("flags", [])):
            return False, {}
        if not self._dsize_match(rule["options"].get("dsize"), transport.get("payload_length", len(data))):
            return False, {}

        matches = self._contents_match(rule["options"].get("content", []), data)
        return matches is not None, {"contents": matches or []}

    def _data(self, event):
        transport = event.get("transport") or {}
        payload = transport.get("payload_text") or ""
        if not payload and transport.get("payload_hex"):
            try:
                payload = bytes.fromhex(transport["payload_hex"]).decode("latin1")
            except ValueError:
                pass
        application = event.get("application")
        return payload + ("\n" + str(application) if application else "")

    def _flow_matches(self, checks, event, flow):
        state = str((flow.get("tcp_stats") or {}).get("state", "")).upper()
        established = state in {"ESTABLISHED", "CLOSING", "CLOSED"}
        if ("established" in checks and not established) or ("not_established" in checks and established):
            return False
        direction = self._flow_direction(event, flow)
        return not (("to_server" in checks and direction != "to_server") or ("to_client" in checks and direction != "to_client"))

    def _flow_direction(self, event, flow):
        network, transport = event.get("network") or {}, event.get("transport") or {}
        source = f"{network.get('src_ip')}:{transport.get('src_port')}"
        if flow.get("initiator"):
            return "to_server" if source == flow["initiator"] else "to_client"
        source_port, destination_port = transport.get("src_port"), transport.get("dst_port")
        if isinstance(source_port, int) and isinstance(destination_port, int):
            if destination_port <= 1024 < source_port:
                return "to_server"
            if source_port <= 1024 < destination_port:
                return "to_client"
        return None

    def _flags_match(self, expected, actual):
        if not expected:
            return True
        names = {"F": "FIN", "S": "SYN", "R": "RST", "P": "PSH", "A": "ACK", "U": "URG"}
        required = {names.get(flag, flag) for flag in str(expected).upper()}
        return required <= {str(flag).upper() for flag in actual}

    def _dsize_match(self, condition, size):
        if not condition:
            return True
        text = str(condition).replace(" ", "")
        try:
            if "<>" in text:
                lower, upper = map(int, text.split("<>"))
                return lower <= int(size) <= upper
            match = re.fullmatch(r"(<=|>=|<|>|=)?(\d+)", text)
            if not match:
                return False
            operator, value = match.groups()
            value = int(value)
            return {None: int(size) == value, "=": int(size) == value, ">": int(size) > value, ">=": int(size) >= value, "<": int(size) < value, "<=": int(size) <= value}[operator]
        except (TypeError, ValueError):
            return False

    def _contents_match(self, contents, data):
        previous_end, matches = 0, []
        for content in contents:
            start = content.get("offset", previous_end + content.get("distance", 0))
            end = len(data)
            if "depth" in content:
                end = min(end, start + content["depth"])
            if "within" in content:
                end = min(end, start + content["within"])
            needle = content["value"]
            haystack = data.lower() if content["nocase"] else data
            position = haystack.find(needle.lower() if content["nocase"] else needle, start, end)
            if position < 0:
                return None
            previous_end = position + len(needle)
            matches.append({"content": needle, "start": position, "end": previous_end})
        return matches


class EvaluationEngine:
    def __init__(self, repository):
        self.repository = repository
        self.matcher = RuleMatcher()
        self.stats = {"events_evaluated": 0, "candidate_rules": 0, "matches": 0}

    def evaluate(self, event, flow=None):
        candidates = self.repository.candidates(event)
        self.stats["events_evaluated"] += 1
        self.stats["candidate_rules"] += len(candidates)
        detections = []
        for rule in candidates:
            matched, match_info = self.matcher.match(rule, event, flow)
            if matched:
                detections.append(generate_detection_event(rule, event, flow, match_info))
        self.stats["matches"] += len(detections)
        return detections


def header_matches(rule, event):
    network, transport = event.get("network") or {}, event.get("transport") or {}
    if str(transport.get("protocol", "")).lower() != rule["protocol"]:
        return False
    source = (network.get("src_ip"), transport.get("src_port"))
    destination = (network.get("dst_ip"), transport.get("dst_port"))
    direct = endpoint_matches(rule["src_ip"], rule["src_port"], source) and endpoint_matches(rule["dst_ip"], rule["dst_port"], destination)
    return direct or (rule["direction"] == "<>" and endpoint_matches(rule["src_ip"], rule["src_port"], destination) and endpoint_matches(rule["dst_ip"], rule["dst_port"], source))


def endpoint_matches(rule_ip, rule_port, endpoint):
    return ip_matches(rule_ip, endpoint[0]) and port_matches(rule_port, endpoint[1])


def ip_matches(rule_ip, event_ip):
    if rule_ip.lower() == "any":
        return True
    try:
        return ipaddress.IPv4Address(event_ip) in ipaddress.IPv4Network(rule_ip, strict=False)
    except ValueError:
        return False


def port_matches(rule_port, event_port):
    if rule_port.lower() == "any":
        return True
    try:
        start, end = (re.split("[:-]", rule_port, maxsplit=1) if ":" in rule_port or "-" in rule_port else (rule_port, rule_port))
        return int(start) <= int(event_port) <= int(end)
    except (TypeError, ValueError):
        return False


def generate_detection_event(rule, event, flow, match_info):
    network, transport, options = event.get("network") or {}, event.get("transport") or {}, rule["options"]
    detection = {
        "event_type": "detection", "timestamp": event.get("timestamp"),
        "sid": options["sid"], "rev": options["rev"], "msg": options["msg"],
        "src_ip": network.get("src_ip"), "src_port": transport.get("src_port"),
        "dst_ip": network.get("dst_ip"), "dst_port": transport.get("dst_port"),
        "protocol": str(transport.get("protocol", "UNKNOWN")).upper(),
        "application_protocol": event.get("application_protocol", "UNKNOWN"),
        "flow_id": event.get("flow_id") or (flow or {}).get("flow_id"), "match": match_info,
    }
    for key in ("priority", "classtype"):
        if key in options:
            detection[key] = options[key]
    return detection
