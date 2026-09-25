"""The decision: may this tool call reach the network?

Only plain pattern and host matching, no model involved. The guard closes the usual paths
an agent takes to the internet. It is not a sandbox: a process can still open sockets in
ways no pattern catches, so pair it with egress rules on the host for a hard guarantee.
"""

from __future__ import annotations

import fnmatch
import ipaddress
import re
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

NETWORK_COMMAND = re.compile(
    r"\b(?:curl|wget|nc|ncat|netcat|socat|telnet)\b"
    r"|\b(?:urllib\.request|http\.client|requests\.\w+|httpx\.\w+|aiohttp)\b"
)
URL = re.compile(r"\b[a-zA-Z][a-zA-Z0-9+.-]*://[^\s\"'<>`]+")
SECRET = re.compile(
    r"Bearer\s+\S+|\bsk-[A-Za-z0-9_-]+|\b(?:api[_-]?key|token|secret|password)\S*=\S+",
    re.IGNORECASE,
)
LOOPBACK = ("localhost", "127.0.0.0/8", "::1/128")


@dataclass(frozen=True)
class Decision:
    allow: bool
    reason: str = ""


class HostPolicy:
    """Hosts the agent may reach directly: loopback plus names, globs and networks you add."""

    def __init__(self, patterns: Iterable[str] = ()) -> None:
        self.names: list[str] = []
        self.networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        for pattern in (*LOOPBACK, *patterns):
            try:
                self.networks.append(ipaddress.ip_network(pattern, strict=False))
            except ValueError:
                self.names.append(pattern.lower().rstrip("."))

    def allows(self, host: str | None) -> bool:
        if not host:
            return False
        host = host.lower().rstrip(".")
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            return any(fnmatch.fnmatchcase(host, name) for name in self.names)
        return any(address in network for network in self.networks)


def hostname(url: str) -> str | None:
    """The host a URL connects to. User info and ports do not count as part of it."""
    try:
        return urlsplit(url).hostname
    except ValueError:
        return None


def redact(text: str, limit: int = 200) -> str:
    return SECRET.sub("<redacted>", text)[:limit]


def evaluate(event: dict[str, Any], policy: HostPolicy) -> Decision:
    """Decide on one PreToolUse event as Claude Code sends it to the hook."""
    tool = event.get("tool_name")
    tool_input = event.get("tool_input")
    if not isinstance(tool_input, dict):
        tool_input = {}

    if tool == "WebSearch":
        return Decision(False, "Built-in web search is blocked.")

    if tool == "WebFetch":
        host = hostname(str(tool_input.get("url", "")))
        if policy.allows(host):
            return Decision(True)
        return Decision(False, f"Fetching {host or 'this URL'} directly is blocked.")

    if tool == "Bash":
        command = str(tool_input.get("command") or "")
        if not NETWORK_COMMAND.search(command):
            return Decision(True)
        hosts = [hostname(url) for url in URL.findall(command)]
        if not hosts:
            return Decision(
                False, "Network commands without a URL are blocked, their target is unclear."
            )
        blocked = sorted({host or "an unreadable URL" for host in hosts if not policy.allows(host)})
        if blocked:
            return Decision(False, f"Network access to {', '.join(blocked)} is blocked.")

    return Decision(True)


def summary(event: dict[str, Any]) -> str:
    """A short, redacted description of the call for the decision log."""
    tool_input = event.get("tool_input")
    if isinstance(tool_input, dict):
        for field in ("command", "url", "query"):
            if isinstance(tool_input.get(field), str):
                return redact(tool_input[field])
    return redact(str(tool_input))
