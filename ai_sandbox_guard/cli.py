"""Hook entry point plus `selftest` and `doctor`."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

from . import __version__, selftest
from .guard import HostPolicy, evaluate, summary
from .log import DEFAULT_LOG, DecisionLog

BLOCK = 2  # exit code that makes Claude Code refuse the call and show stderr to the model
GUARDED_TOOLS = ("Bash", "WebFetch", "WebSearch")
REPEAT_WARNING = (
    " This exact call has now been blocked three times in a row. Do not retry it, change"
    " the approach."
)


def hook(args: argparse.Namespace) -> int:
    try:
        event = json.load(sys.stdin)
    except ValueError:
        # A hook that cannot read its input must not lock up the whole session. Its job
        # is to close the known paths, and an unreadable event is not one of them.
        return 0
    if not isinstance(event, dict):
        return 0
    tool, call = str(event.get("tool_name", "")), summary(event)
    decision = evaluate(event, HostPolicy(args.allow))
    log = DecisionLog(args.log)
    if decision.allow:
        log.record(tool, call, allowed=True)
        return 0
    reason = decision.reason
    if args.broker:
        reason += f" Use {args.broker} for anything outside this machine."
    if log.denied_in_a_row(tool, call) >= 2:
        reason += REPEAT_WARNING
    log.record(tool, call, allowed=False, reason=reason)
    print(reason, file=sys.stderr)
    return BLOCK


def run_selftest(args: argparse.Namespace) -> int:
    results = selftest.run()
    for name, passed in results:
        print(f"{'PASS' if passed else 'FAIL'}  {name}")
    failed = sum(not passed for _, passed in results)
    print(f"{len(results) - failed} passed, {failed} failed")
    return 1 if failed else 0


def doctor(args: argparse.Namespace) -> int:
    checks: list[tuple[str, bool]] = []
    try:
        settings: Any = json.loads(args.settings.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        settings = None
    checks.append((f"{_display(args.settings)} is readable JSON", isinstance(settings, dict)))
    entries = _guard_entries(settings)
    checks.append(("a PreToolUse hook runs ai-sandbox-guard", bool(entries)))
    for tool in GUARDED_TOOLS:
        covered = any(_matches(entry.get("matcher"), tool) for entry in entries)
        checks.append((f"the hook covers {tool}", covered))
    checks.append(("all self-test cases pass", all(passed for _, passed in selftest.run())))
    for name, passed in checks:
        print(f"{'PASS' if passed else 'FAIL'}  {name}")
    return 0 if all(passed for _, passed in checks) else 1


def _display(path: Path) -> str:
    try:
        return f"~/{path.relative_to(Path.home())}"
    except ValueError:
        return str(path)


def _guard_entries(settings: Any) -> list[dict[str, Any]]:
    hooks = settings.get("hooks") if isinstance(settings, dict) else None
    entries = hooks.get("PreToolUse") if isinstance(hooks, dict) else None
    found = []
    for entry in entries if isinstance(entries, list) else []:
        commands = entry.get("hooks", []) if isinstance(entry, dict) else []
        if any(
            isinstance(command, dict) and "ai-sandbox-guard" in str(command.get("command", ""))
            for command in commands
        ):
            found.append(entry)
    return found


def _matches(matcher: Any, tool: str) -> bool:
    if matcher in (None, "", "*"):
        return True
    try:
        return re.fullmatch(str(matcher), tool) is not None
    except re.error:
        return False


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ai-sandbox-guard",
        description="PreToolUse hook for Claude Code that blocks direct internet access."
        " Without a command it reads one hook event from stdin.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument(
        "--allow",
        action="append",
        default=[],
        metavar="HOST",
        help="also allow this host name, glob (*.lan) or network (10.0.0.0/8), repeatable",
    )
    parser.add_argument("--broker", help="what the agent should use instead, named in the reason")
    parser.add_argument("--log", type=Path, default=DEFAULT_LOG, help="decision log (JSON lines)")
    parser.set_defaults(handler=hook)
    commands = parser.add_subparsers(dest="command", metavar="COMMAND")
    commands.add_parser("selftest", help="run the bypass attempts").set_defaults(
        handler=run_selftest
    )
    check = commands.add_parser("doctor", help="check the installation and run the self-test")
    check.add_argument("--settings", type=Path, default=Path.home() / ".claude" / "settings.json")
    check.set_defaults(handler=doctor)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return int(args.handler(args))
