"""Fault-tolerant loading of Snort rule files."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Optional

from .models import Rule
from .rule_parser import parse_rule


@dataclass(frozen=True)
class RuleLoadIssue:
    source_file: str
    line_number: Optional[int]
    status: str
    reason: str
    rule_text: str = ""


@dataclass
class RuleLoadConfig:
    """Optional configuration for enabling rule files and individual rules."""

    enabled_files: Optional[set[str]] = None
    disabled_files: set[str] = field(default_factory=set)
    disabled_sids: set[int] = field(default_factory=set)


@dataclass
class RuleLoadReport:
    rules: list[Rule] = field(default_factory=list)
    issues: list[RuleLoadIssue] = field(default_factory=list)
    skipped_files: list[str] = field(default_factory=list)

    @property
    def valid_count(self) -> int:
        return len(self.rules)


class RuleLoader:
    """Loads every usable rule while retaining errors for later inspection."""

    def __init__(self, config: RuleLoadConfig | None = None):
        self.config = config or RuleLoadConfig()

    def load_files(self, paths: Iterable[str | Path]) -> RuleLoadReport:
        report = RuleLoadReport()
        for path_value in paths:
            path = Path(path_value)
            if not self._is_file_enabled(path):
                report.skipped_files.append(str(path))
                continue
            try:
                with path.open("r", encoding="utf-8-sig") as rule_file:
                    self._load_lines(rule_file, str(path), report)
            except OSError as exc:
                report.issues.append(
                    RuleLoadIssue(str(path), None, "invalid", f"unable to read rule file: {exc}")
                )
        return report

    def load_text(self, text: str, source_name: str = "<memory>") -> RuleLoadReport:
        """Load rules from text, useful for tests and programmatic configurations."""

        report = RuleLoadReport()
        self._load_lines(text.splitlines(), source_name, report)
        return report

    def _load_lines(self, lines: Iterable[str], source_file: str, report: RuleLoadReport) -> None:
        for line_number, raw_line in enumerate(lines, 1):
            rule_text = _strip_comment(raw_line).strip()
            if not rule_text:
                continue
            result = parse_rule(rule_text, source_file=source_file, source_line=line_number)
            if result.status != "valid" or result.rule is None:
                report.issues.append(
                    RuleLoadIssue(source_file, line_number, result.status, result.reason or "invalid rule", rule_text)
                )
                continue
            if result.rule.sid in self.config.disabled_sids:
                report.issues.append(
                    RuleLoadIssue(source_file, line_number, "disabled", f"sid {result.rule.sid} disabled by configuration", rule_text)
                )
                continue
            report.rules.append(result.rule)

    def _is_file_enabled(self, path: Path) -> bool:
        configured_names = {str(path), path.name}
        try:
            configured_names.add(str(path.resolve()))
        except OSError:
            pass
        if configured_names & self.config.disabled_files:
            return False
        if self.config.enabled_files is None:
            return True
        return bool(configured_names & self.config.enabled_files)


def _strip_comment(line: str) -> str:
    """Remove a Snort comment without treating a # inside msg/content as one."""

    in_quote = False
    escaped = False
    for index, character in enumerate(line):
        if escaped:
            escaped = False
            continue
        if character == "\\":
            escaped = True
        elif character == '"':
            in_quote = not in_quote
        elif character == "#" and not in_quote:
            return line[:index]
    return line
