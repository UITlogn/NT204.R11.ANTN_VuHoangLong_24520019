"""Rule storage and lightweight header-based candidate selection."""

from __future__ import annotations

from collections import defaultdict
from typing import Iterable

from .models import Rule, RuleHeader


class RuleRepository:
    """Stores validated rules and avoids content checks for impossible headers."""

    def __init__(self, rules: Iterable[Rule] = ()):
        self._rules: list[Rule] = []
        self._protocol_index: dict[str, list[Rule]] = defaultdict(list)
        self.add_rules(rules)

    @property
    def rules(self) -> tuple[Rule, ...]:
        return tuple(self._rules)

    def __len__(self) -> int:
        return len(self._rules)

    def add_rules(self, rules: Iterable[Rule]) -> None:
        for rule in rules:
            if not rule.enabled:
                continue
            self._rules.append(rule)
            self._protocol_index[rule.header.protocol].append(rule)

    def candidates(self, event: dict) -> list[Rule]:
        """Return only rules with a protocol, IP, and port header that can match."""

        transport = event.get("transport") if isinstance(event, dict) else None
        if not isinstance(transport, dict):
            return []
        protocol = str(transport.get("protocol", "")).lower()
        return [
            rule
            for rule in self._protocol_index.get(protocol, [])
            if header_matches_event(rule.header, event)
        ]


def header_matches_event(header: RuleHeader, event: dict) -> bool:
    """Match header endpoints, including the reverse leg of a <> rule."""

    network = event.get("network") if isinstance(event, dict) else None
    transport = event.get("transport") if isinstance(event, dict) else None
    if not isinstance(network, dict) or not isinstance(transport, dict):
        return False
    if str(transport.get("protocol", "")).lower() != header.protocol:
        return False

    source = (network.get("src_ip"), transport.get("src_port"))
    destination = (network.get("dst_ip"), transport.get("dst_port"))
    if _endpoint_pair_matches(header, source, destination):
        return True
    return header.direction == "<>" and _endpoint_pair_matches(header, destination, source)


def _endpoint_pair_matches(header: RuleHeader, source: tuple[object, object], destination: tuple[object, object]) -> bool:
    return (
        header.src_ip.matches(source[0])
        and header.src_port.matches(source[1])
        and header.dst_ip.matches(destination[0])
        and header.dst_port.matches(destination[1])
    )
