"""Decision log in JSON lines, also used to notice an agent retrying a blocked call."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

DEFAULT_LOG = Path.home() / ".local" / "state" / "ai-sandbox-guard" / "decisions.jsonl"


class DecisionLog:
    def __init__(self, path: Path = DEFAULT_LOG) -> None:
        self.path = path

    def record(self, tool: str, call: str, allowed: bool, reason: str = "") -> None:
        entry = {
            "at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "tool": tool,
            "call": call,
            "decision": "allow" if allowed else "deny",
        }
        if reason:
            entry["reason"] = reason
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as log:
            log.write(json.dumps(entry) + "\n")

    def denied_in_a_row(self, tool: str, call: str) -> int:
        """How often this exact call was blocked right before now."""
        count = 0
        for entry in reversed(self._tail()):
            if entry.get("tool") != tool or entry.get("call") != call:
                break
            if entry.get("decision") != "deny":
                break
            count += 1
        return count

    def _tail(self, lines: int = 50) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        entries = []
        for line in self.path.read_text(encoding="utf-8").splitlines()[-lines:]:
            try:
                entry = json.loads(line)
            except ValueError:
                continue
            if isinstance(entry, dict):
                entries.append(entry)
        return entries
