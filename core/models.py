"""Shared internal data models for the IDS Core Engine."""

from __future__ import annotations

from dataclasses import dataclass, field
from ipaddress import IPv4Address, IPv4Network
from typing import Optional


@dataclass(frozen=True)
class IpSpec:
    """An IPv4 selector from a Snort rule header."""

    raw: str
    network: Optional[IPv4Network] = None

    def matches(self, address: object) -> bool:
        if self.network is None:
            return True
        try:
            return IPv4Address(str(address)) in self.network
        except ValueError:
            return False


@dataclass(frozen=True)
class PortSpec:
    """An inclusive port selector from a Snort rule header."""

    raw: str
    start: Optional[int] = None
    end: Optional[int] = None

    def matches(self, port: object) -> bool:
        if self.start is None:
            return True
        try:
            value = int(port)
        except (TypeError, ValueError):
            return False
        return self.start <= value <= self.end


@dataclass
class ContentSpec:
    """One content option and the modifiers that apply to it."""

    pattern: bytes
    nocase: bool = False
    offset: Optional[int] = None
    depth: Optional[int] = None
    distance: Optional[int] = None
    within: Optional[int] = None


@dataclass(frozen=True)
class DsizeSpec:
    """A packet payload-size comparison."""

    operator: str
    value: int
    upper: Optional[int] = None

    def matches(self, size: int) -> bool:
        if self.operator == "=":
            return size == self.value
        if self.operator == ">":
            return size > self.value
        if self.operator == ">=":
            return size >= self.value
        if self.operator == "<":
            return size < self.value
        if self.operator == "<=":
            return size <= self.value
        if self.operator == "range" and self.upper is not None:
            return self.value <= size <= self.upper
        return False


@dataclass(frozen=True)
class RuleHeader:
    action: str
    protocol: str
    src_ip: IpSpec
    src_port: PortSpec
    direction: str
    dst_ip: IpSpec
    dst_port: PortSpec


@dataclass
class Rule:
    """Validated internal representation of one supported Snort rule."""

    header: RuleHeader
    msg: str
    sid: int
    rev: int
    contents: list[ContentSpec] = field(default_factory=list)
    flow: frozenset[str] = field(default_factory=frozenset)
    flags: frozenset[str] = field(default_factory=frozenset)
    dsize: Optional[DsizeSpec] = None
    classtype: Optional[str] = None
    priority: Optional[int] = None
    raw: str = ""
    source_file: Optional[str] = None
    source_line: Optional[int] = None
    enabled: bool = True


@dataclass(frozen=True)
class RuleParseResult:
    """Result of parsing a single rule without aborting a larger load."""

    status: str
    rule: Optional[Rule] = None
    reason: Optional[str] = None
