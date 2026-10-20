"""Parse the supported Snort rule subset into simple dictionaries."""

import ipaddress
import re


SUPPORTED_PROTOCOLS = {"tcp", "udp"}
SUPPORTED_OPTIONS = {
    "msg", "sid", "rev", "content", "nocase", "offset", "depth",
    "distance", "within", "flags", "dsize", "flow", "classtype", "priority",
}


class RuleParser:
    def __init__(self):
        self.rules = []
        self.stats = {"valid": 0, "invalid": 0, "unsupported": 0}
        self.last_status = None
        self.last_reason = None

    def parse_file(self, filepath):
        try:
            with open(filepath, "r", encoding="utf-8") as rule_file:
                for line in rule_file:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        self.parse_rule(line)
        except OSError as error:
            self._error("invalid", f"cannot read rule file: {error}")
        return self.rules

    def parse_rule(self, rule_text):
        self.last_status = self.last_reason = None
        pattern = r"^(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(->|<>)\s+(\S+)\s+(\S+)\s+\((.*)\)$"
        match = re.match(pattern, rule_text.strip())
        if not match:
            return self._error("invalid", "invalid rule header")

        action, protocol, src_ip, src_port, direction, dst_ip, dst_port, option_text = match.groups()
        if action.lower() != "alert":
            return self._error("unsupported", f"unsupported action: {action}")
        if protocol.lower() not in SUPPORTED_PROTOCOLS:
            return self._error("unsupported", f"unsupported protocol: {protocol}")
        if not self._valid_ip(src_ip) or not self._valid_ip(dst_ip):
            return self._error("invalid", "invalid IPv4/CIDR address")
        if not self._valid_port(src_port) or not self._valid_port(dst_port):
            return self._error("invalid", "invalid port or range")

        options = self._parse_options(option_text)
        if options is None:
            return None
        missing = [name for name in ("msg", "sid", "rev") if name not in options]
        if missing:
            return self._error("invalid", f"missing required option: {', '.join(missing)}")

        rule = {
            "raw": rule_text.strip(), "action": "alert", "protocol": protocol.lower(),
            "src_ip": src_ip, "src_port": src_port, "direction": direction,
            "dst_ip": dst_ip, "dst_port": dst_port, "options": options,
        }
        self.rules.append(rule)
        self.stats["valid"] += 1
        self.last_status = "valid"
        return rule

    def _parse_options(self, option_text):
        options = {}
        for item in (part.strip() for part in option_text.split(";") if part.strip()):
            key, _, value = item.partition(":")
            key, value = key.strip().lower(), value.strip()
            if key not in SUPPORTED_OPTIONS:
                return self._error("unsupported", f"unsupported keyword: {key}")
            if key == "content":
                if not (value.startswith('"') and value.endswith('"')):
                    return self._error("invalid", "content must be quoted")
                options.setdefault("content", []).append({"value": value[1:-1], "nocase": False})
            elif key == "nocase":
                if "content" not in options:
                    return self._error("invalid", "nocase must follow content")
                options["content"][-1]["nocase"] = True
            elif key in {"offset", "depth", "distance", "within"}:
                if "content" not in options or not value.isdigit():
                    return self._error("invalid", f"invalid {key}")
                options["content"][-1][key] = int(value)
            elif key in {"sid", "rev", "priority"}:
                if not value.isdigit():
                    return self._error("invalid", f"{key} must be an integer")
                options[key] = int(value)
            elif key == "msg":
                if not (value.startswith('"') and value.endswith('"')):
                    return self._error("invalid", "msg must be quoted")
                options[key] = value[1:-1]
            elif key == "flow":
                values = [part.strip() for part in value.split(",")]
                allowed = {"to_server", "to_client", "established", "not_established"}
                if not value or any(part not in allowed for part in values):
                    return self._error("unsupported", f"unsupported flow option: {value}")
                options[key] = values
            elif not value:
                return self._error("invalid", f"{key} requires a value")
            else:
                options[key] = value
        return options

    def _valid_ip(self, value):
        if value.lower() == "any":
            return True
        try:
            ipaddress.IPv4Network(value, strict=False)
            return True
        except ValueError:
            return False

    def _valid_port(self, value):
        if value.lower() == "any":
            return True
        try:
            start, end = (re.split("[:-]", value, maxsplit=1) if ":" in value or "-" in value else (value, value))
            return 0 <= int(start) <= int(end) <= 65535
        except ValueError:
            return False

    def _error(self, status, reason):
        self.stats[status] += 1
        self.last_status, self.last_reason = status, reason
        return None
