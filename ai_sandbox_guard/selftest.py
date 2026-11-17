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
    (
        "urllib imported from the package",
        _bash("python3 -c \"from urllib import request; request.urlopen('https://example.com')\""),
        False,
    ),
    ("external host without a scheme", _bash("curl http://127.0.0.1/ example.com"), False),
    ("loopback URL in a comment", _bash("nc example.com 80 # http://127.0.0.1/"), False),
    ("quotes gluing loopback to a host", _bash('curl "http://localhost"@example.com/'), False),
    ("backslash before the user info", _fetch("http://example.com\\@127.0.0.1/"), False),
    ("external proxy", _bash("curl -x example.com:8080 http://localhost/"), False),
    ("proxy variable", _bash("https_proxy=example.com:3128 curl https://localhost/"), False),
    ("connection redirected", _bash("curl --connect-to ::example.com: http://localhost/"), False),
    ("command inside a shell string", _bash("bash -c 'curl example.com'"), False),
    ("URL list from a file", _bash("wget -i urls.txt"), False),
    ("output file and redirection", _bash("curl -sSo out.json http://[::1]/ 2>/dev/null"), True),
    ("netcat to loopback", _bash("nc -z localhost 8080"), True),
    ("IPv6 loopback", _bash("curl -g 'http://[::1]:8080/'"), True),
    ("an ordinary command", _bash("ls -la /tmp"), True),
    ("an unrelated tool", {"tool_name": "Read", "tool_input": {"file_path": "x"}}, True),
]


def run(policy: HostPolicy | None = None) -> list[tuple[str, bool]]:
    """(description, passed) for every case, checked against loopback-only rules by default."""
    policy = policy or HostPolicy()
    return [(name, evaluate(event, policy).allow is expected) for name, event, expected in CASES]
