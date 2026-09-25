"""Attempts to get past the guard. Every case states what the guard has to do."""

from __future__ import annotations

from typing import Any

from .guard import HostPolicy, evaluate


def _bash(command: str) -> dict[str, Any]:
    return {"tool_name": "Bash", "tool_input": {"command": command}}


def _fetch(url: str) -> dict[str, Any]:
    return {"tool_name": "WebFetch", "tool_input": {"url": url}}


# (description, event, expected to be allowed)
CASES: list[tuple[str, dict[str, Any], bool]] = [
    ("curl to an external host", _bash("curl -s https://example.com"), False),
    ("curl to loopback", _bash("curl -s http://127.0.0.1:8080/health"), True),
    ("built-in web search", {"tool_name": "WebSearch", "tool_input": {"query": "x"}}, False),
    ("WebFetch of an external page", _fetch("https://example.com/docs"), False),
    ("WebFetch of loopback", _fetch("http://localhost:3000/"), True),
    ("loopback name in the query string", _fetch("https://example.com/?next=localhost"), False),
    ("loopback name as user info", _bash("curl https://localhost@example.com/"), False),
    ("loopback address as a subdomain", _bash("wget http://127.0.0.1.example.com/x"), False),
    (
        "one internal and one external URL",
        _bash("curl http://localhost:1/ https://example.com"),
        False,
    ),
    ("network command without a URL", _bash("wget example.com"), False),
    ("netcat to an external host", _bash("nc example.com 80"), False),
    (
        "HTTP from inline Python",
        _bash("python3 -c \"import requests; requests.get('https://example.com')\""),
        False,
    ),
    ("IPv6 loopback", _bash("curl -g 'http://[::1]:8080/'"), True),
    ("an ordinary command", _bash("ls -la /tmp"), True),
    ("an unrelated tool", {"tool_name": "Read", "tool_input": {"file_path": "x"}}, True),
]


def run(policy: HostPolicy | None = None) -> list[tuple[str, bool]]:
    """(description, passed) for every case, checked against loopback-only rules by default."""
    policy = policy or HostPolicy()
    return [(name, evaluate(event, policy).allow is expected) for name, event, expected in CASES]
