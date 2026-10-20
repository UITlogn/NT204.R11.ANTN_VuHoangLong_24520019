"""Load rule files without letting one bad rule stop the IDS."""

from pathlib import Path

from .rule_parser import RuleParser


class RuleLoader:
    def __init__(self, enabled_files=None, disabled_files=None, disabled_sids=None):
        self.enabled_files = set(enabled_files) if enabled_files else None
        self.disabled_files = set(disabled_files or [])
        self.disabled_sids = {int(sid) for sid in (disabled_sids or [])}

    def load_files(self, filepaths):
        report = {"rules": [], "issues": [], "skipped_files": []}
        for filepath in filepaths:
            path = Path(filepath)
            if not self._enabled(path):
                report["skipped_files"].append(str(path))
                continue
            try:
                with path.open("r", encoding="utf-8") as rule_file:
                    self._load_lines(rule_file, str(path), report)
            except OSError as error:
                report["issues"].append({"file": str(path), "line": None, "status": "invalid", "reason": str(error)})
        return report

    def load_text(self, text, name="<memory>"):
        report = {"rules": [], "issues": [], "skipped_files": []}
        self._load_lines(text.splitlines(), name, report)
        return report

    def _load_lines(self, lines, name, report):
        parser = RuleParser()
        for line_number, line in enumerate(lines, 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            rule = parser.parse_rule(line)
            if rule is None:
                report["issues"].append({"file": name, "line": line_number, "status": parser.last_status, "reason": parser.last_reason})
            elif rule["options"]["sid"] in self.disabled_sids:
                report["issues"].append({"file": name, "line": line_number, "status": "disabled", "reason": "sid disabled by config"})
            else:
                report["rules"].append(rule)

    def _enabled(self, path):
        names = {str(path), path.name}
        if names & self.disabled_files:
            return False
        return self.enabled_files is None or bool(names & self.enabled_files)
