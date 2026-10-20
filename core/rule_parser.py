"""Parser and validator for the supported subset of Snort rules."""

from __future__ import annotations

import re
from ipaddress import IPv4Network
from typing import Iterable

from .models import ContentSpec, DsizeSpec, IpSpec, PortSpec, Rule, RuleHeader, RuleParseResult


SUPPORTED_ACTIONS = {"alert"}
SUPPORTED_PROTOCOLS = {"tcp", "udp"}
SUPPORTED_FLOW_OPTIONS = {"to_server", "to_client", "established", "not_established"}
FLAG_MAP = {"F": "FIN", "S": "SYN", "R": "RST", "P": "PSH", "A": "ACK", "U": "URG"}


class RuleError(ValueError):
    """A parse error whose category is safe to show in loader reports."""

    def __init__(self, status: str, reason: str):
        super().__init__(reason)
        self.status = status
        self.reason = reason


def parse_rule(text: str, *, source_file: str | None = None, source_line: int | None = None) -> RuleParseResult:
    """Parse one rule into an internal object.

    Invalid and unsupported rules are returned as data rather than raised so a
    malformed rule never stops an entire rule file from loading.
    """

    try:
        header_text, option_text = _split_rule(text)
        header = _parse_header(header_text)
        options = _parse_options(option_text)
        _require_identification(options)
        return RuleParseResult(
            status="valid",
            rule=Rule(
                header=header,
                msg=options["msg"],
                sid=options["sid"],
                rev=options["rev"],
                contents=options["contents"],
                flow=frozenset(options["flow"]),
                flags=frozenset(options["flags"]),
                dsize=options["dsize"],
                classtype=options["classtype"],
                priority=options["priority"],
                raw=text.strip(),
                source_file=source_file,
                source_line=source_line,
            ),
        )
    except RuleError as exc:
        return RuleParseResult(status=exc.status, reason=exc.reason)


def _split_rule(text: str) -> tuple[str, str]:
    match = re.fullmatch(r"\s*(.*?)\s*\((.*)\)\s*", text, flags=re.DOTALL)
    if not match:
        raise RuleError("invalid", "rule must contain a header and parenthesized options")
    return match.group(1), match.group(2)


def _parse_header(text: str) -> RuleHeader:
    parts = text.split()
    if len(parts) != 7:
        raise RuleError("invalid", "header must have action, protocol, addresses, ports, and direction")

    action, protocol, src_ip, src_port, direction, dst_ip, dst_port = parts
    action = action.lower()
    protocol = protocol.lower()
    if action not in SUPPORTED_ACTIONS:
        raise RuleError("unsupported", f"unsupported action: {action}")
    if protocol not in SUPPORTED_PROTOCOLS:
        raise RuleError("unsupported", f"unsupported protocol: {protocol}")
    if direction not in {"->", "<>"}:
        raise RuleError("invalid", f"unsupported direction syntax: {direction}")

    return RuleHeader(
        action=action,
        protocol=protocol,
        src_ip=_parse_ip(src_ip),
        src_port=_parse_port(src_port),
        direction=direction,
        dst_ip=_parse_ip(dst_ip),
        dst_port=_parse_port(dst_port),
    )


def _parse_ip(value: str) -> IpSpec:
    if value.lower() == "any":
        return IpSpec(raw="any")
    try:
        network = IPv4Network(value, strict=False)
    except ValueError as exc:
        raise RuleError("invalid", f"invalid IPv4 or CIDR address: {value}") from exc
    return IpSpec(raw=value, network=network)


def _parse_port(value: str) -> PortSpec:
    if value.lower() == "any":
        return PortSpec(raw="any")

    separator = ":" if ":" in value else "-" if "-" in value else None
    try:
        if separator:
            first, last = value.split(separator, 1)
            if not first or not last:
                raise ValueError
            start, end = int(first), int(last)
        else:
            start = end = int(value)
    except ValueError as exc:
        raise RuleError("invalid", f"invalid port specification: {value}") from exc

    if not 0 <= start <= end <= 65535:
        raise RuleError("invalid", f"port out of range: {value}")
    return PortSpec(raw=value, start=start, end=end)


def _parse_options(text: str) -> dict[str, object]:
    options: dict[str, object] = {
        "msg": None,
        "sid": None,
        "rev": None,
        "contents": [],
        "flow": set(),
        "flags": set(),
        "dsize": None,
        "classtype": None,
        "priority": None,
    }
    seen: set[str] = set()
    last_content: ContentSpec | None = None

    for token in _split_options(text):
        if not token:
            continue
        key, value = _option_key_value(token)
        key = key.lower()

        if key == "content":
            if value is None:
                raise RuleError("invalid", "content requires a quoted value")
            last_content = ContentSpec(pattern=_parse_content(value))
            options["contents"].append(last_content)
            continue

        if key in {"nocase", "offset", "depth", "distance", "within"}:
            if last_content is None:
                raise RuleError("invalid", f"{key} must follow a content option")
            if key == "nocase":
                if value is not None:
                    raise RuleError("invalid", "nocase does not take a value")
                if last_content.nocase:
                    raise RuleError("invalid", "duplicate nocase modifier")
                last_content.nocase = True
            else:
                parsed = _parse_non_negative_int(value, key)
                if getattr(last_content, key) is not None:
                    raise RuleError("invalid", f"duplicate {key} modifier")
                setattr(last_content, key, parsed)
            continue

        if key not in {"msg", "sid", "rev", "flow", "flags", "dsize", "classtype", "priority"}:
            raise RuleError("unsupported", f"unsupported keyword: {key}")
        if key in seen:
            raise RuleError("invalid", f"duplicate option: {key}")
        seen.add(key)

        if key == "msg":
            options["msg"] = _parse_quoted(value, "msg")
        elif key == "sid":
            sid = _parse_non_negative_int(value, "sid")
            if sid == 0:
                raise RuleError("invalid", "sid must be greater than zero")
            options["sid"] = sid
        elif key == "rev":
            options["rev"] = _parse_non_negative_int(value, "rev")
        elif key == "flow":
            options["flow"] = _parse_flow(value)
        elif key == "flags":
            options["flags"] = _parse_flags(value)
        elif key == "dsize":
            options["dsize"] = _parse_dsize(value)
        elif key == "classtype":
            options["classtype"] = _parse_plain_value(value, "classtype")
        elif key == "priority":
            options["priority"] = _parse_non_negative_int(value, "priority")

    return options


def _require_identification(options: dict[str, object]) -> None:
    missing = [key for key in ("msg", "sid", "rev") if options[key] is None]
    if missing:
        raise RuleError("invalid", f"missing required option(s): {', '.join(missing)}")


def _split_options(text: str) -> Iterable[str]:
    tokens: list[str] = []
    current: list[str] = []
    in_quote = False
    escaped = False
    for character in text:
        if escaped:
            current.append(character)
            escaped = False
            continue
        if character == "\\":
            current.append(character)
            escaped = True
            continue
        if character == '"':
            in_quote = not in_quote
            current.append(character)
            continue
        if character == ";" and not in_quote:
            tokens.append("".join(current).strip())
            current = []
            continue
        current.append(character)
    if in_quote:
        raise RuleError("invalid", "unterminated quoted option")
    trailing = "".join(current).strip()
    if trailing:
        tokens.append(trailing)
    return tokens


def _option_key_value(token: str) -> tuple[str, str | None]:
    if ":" not in token:
        return token.strip(), None
    key, value = token.split(":", 1)
    if not key.strip() or not value.strip():
        raise RuleError("invalid", f"invalid option syntax: {token}")
    return key.strip(), value.strip()


def _parse_quoted(value: str | None, name: str) -> str:
    if value is None or len(value) < 2 or value[0] != '"' or value[-1] != '"':
        raise RuleError("invalid", f"{name} requires a quoted value")
    return _decode_escaped_text(value[1:-1])


def _parse_content(value: str) -> bytes:
    return _decode_content(_parse_quoted(value, "content"))


def _decode_escaped_text(value: str) -> str:
    result: list[str] = []
    index = 0
    while index < len(value):
        character = value[index]
        if character != "\\" or index + 1 == len(value):
            result.append(character)
            index += 1
            continue
        next_character = value[index + 1]
        replacements = {"n": "\n", "r": "\r", "t": "\t", '"': '"', "\\": "\\"}
        if next_character == "x" and index + 3 < len(value):
            pair = value[index + 2 : index + 4]
            try:
                result.append(chr(int(pair, 16)))
                index += 4
                continue
            except ValueError:
                pass
        result.append(replacements.get(next_character, next_character))
        index += 2
    return "".join(result)


def _decode_content(value: str) -> bytes:
    output = bytearray()
    index = 0
    while index < len(value):
        if value[index] == "|":
            end = value.find("|", index + 1)
            if end == -1:
                raise RuleError("invalid", "unterminated hex content")
            hex_values = value[index + 1 : end].split()
            if not hex_values or any(not re.fullmatch(r"[0-9a-fA-F]{2}", part) for part in hex_values):
                raise RuleError("invalid", "invalid hex content")
            output.extend(int(part, 16) for part in hex_values)
            index = end + 1
            continue
        output.extend(value[index].encode("utf-8"))
        index += 1
    return bytes(output)


def _parse_non_negative_int(value: str | None, name: str) -> int:
    if value is None or not re.fullmatch(r"\d+", value.strip()):
        raise RuleError("invalid", f"{name} must be a non-negative integer")
    return int(value)


def _parse_plain_value(value: str | None, name: str) -> str:
    if value is None or not value.strip():
        raise RuleError("invalid", f"{name} requires a value")
    return value.strip()


def _parse_flow(value: str | None) -> set[str]:
    raw_values = [part.strip().lower() for part in _parse_plain_value(value, "flow").split(",")]
    if not raw_values or any(not item for item in raw_values):
        raise RuleError("invalid", "flow contains an empty value")
    unsupported = set(raw_values) - SUPPORTED_FLOW_OPTIONS
    if unsupported:
        raise RuleError("unsupported", f"unsupported flow option(s): {', '.join(sorted(unsupported))}")
    selected = set(raw_values)
    if {"to_server", "to_client"} <= selected:
        raise RuleError("invalid", "flow cannot contain both to_server and to_client")
    if {"established", "not_established"} <= selected:
        raise RuleError("invalid", "flow cannot contain both established and not_established")
    return selected


def _parse_flags(value: str | None) -> set[str]:
    text = _parse_plain_value(value, "flags").upper()
    if any(character not in FLAG_MAP for character in text):
        raise RuleError("unsupported", f"unsupported flags expression: {text}")
    return {FLAG_MAP[character] for character in text}


def _parse_dsize(value: str | None) -> DsizeSpec:
    text = _parse_plain_value(value, "dsize").replace(" ", "")
    range_match = re.fullmatch(r"(\d+)<>(\d+)", text)
    if range_match:
        lower, upper = (int(group) for group in range_match.groups())
        if lower > upper:
            raise RuleError("invalid", "dsize range lower bound exceeds upper bound")
        return DsizeSpec(operator="range", value=lower, upper=upper)
    comparison_match = re.fullmatch(r"(<=|>=|<|>|=)?(\d+)", text)
    if not comparison_match:
        raise RuleError("invalid", f"invalid dsize expression: {text}")
    operator, number = comparison_match.groups()
    return DsizeSpec(operator=operator or "=", value=int(number))
