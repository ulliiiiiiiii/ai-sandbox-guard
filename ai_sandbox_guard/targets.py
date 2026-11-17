"""Which hosts a tool call connects to.

Shell commands are read word by word, the way the shell splits them after removing quotes, so
quoting cannot glue an allowed URL to another host, and a URL somewhere else in the command (in
a comment, say) does not vouch for the target of a network command. Obfuscation stays out of
reach for any pattern: variables, `eval` of strings built at run time and brace expansion need
egress rules on the host.
"""

from __future__ import annotations

import posixpath
import re
import shlex
from collections.abc import Iterator
from dataclasses import dataclass
from urllib.parse import urlsplit

URL = re.compile(r"\b[a-zA-Z][a-zA-Z0-9+.-]*://[^\s\"'<>`]+")
TOOL_WORD = re.compile(r"\b(?:curl|wget|nc|ncat|netcat|socat|telnet)\b")
LIBRARY = re.compile(r"\b(?:urllib\.request|http\.client|requests\.\w+|httpx\.\w+|aiohttp)\b")
# imports count only next to an interpreter, so `grep "import requests"` is no network command
IMPORT = re.compile(r"\b(?:from|import)\s+(?:urllib3?|http\.client|requests|httpx|aiohttp)\b")
INTERPRETER = re.compile(r"\b(?:python|pypy|ipython)[\d.]*\b")
# a name with a dot, an IPv4 address or an IPv6 address in brackets, as in host:port values
HOST = re.compile(
    r"(?<![\w.-])(?:\[[0-9A-Fa-f:.]+\]|(?:\d{1,3}\.){3}\d{1,3}|localhost"
    r"|(?:[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?\.)+[A-Za-z][A-Za-z0-9-]*)(?![\w-])"
)
SOCAT_CONNECT = re.compile(r"(?:tcp|udp|sctp|dccp|openssl|ssl|socks|proxy)[\w-]*", re.IGNORECASE)
OPERATORS = frozenset("();<>|&")
NESTING = 3  # shell strings inside shell strings, as in bash -c "ssh host 'curl ...'"


def _names(text: str) -> frozenset[str]:
    return frozenset(text.split())


@dataclass(frozen=True)
class Tool:
    """How a network command names the hosts it connects to."""

    operands: str  # "urls": every operand is a URL, scheme optional; "host": the first operand
    # is the host; "addresses": socat address specifications
    short: str = ""  # short options that take a value
    long: frozenset[str] = frozenset()  # long options that take a value
    via: frozenset[str] = frozenset()  # options whose value names a host the traffic goes to
    hidden: frozenset[str] = frozenset()  # options that read targets from a file or config


CURL = Tool(
    "urls",
    short="AbcCdDeEFHKmoPQrtTuUwxXyYz",
    long=_names(
        "--data --data-ascii --data-binary --data-raw --data-urlencode --json --form"
        " --form-string --header --proxy-header --output --output-dir --upload-file --user-agent"
        " --user --proxy-user --write-out --request --dump-header --cookie --cookie-jar --cert"
        " --key --cacert --capath --max-time --connect-timeout --range --continue-at --time-cond"
        " --retry --retry-delay --retry-max-time --limit-rate --max-filesize --max-redirs"
        " --trace --trace-ascii --stderr --oauth2-bearer --referer --variable --url-query"
        " --unix-socket --interface --local-port --config --url --proxy --preproxy --socks4"
        " --socks4a --socks5 --socks5-hostname --resolve --connect-to --dns-servers --doh-url"
    ),
    via=_names(
        "-x --proxy --preproxy --socks4 --socks4a --socks5 --socks5-hostname --resolve"
        " --connect-to --dns-servers --doh-url"
    ),
    hidden=_names("-K --config"),
)
WGET = Tool(
    "urls",
    short="aABDeiIloOPQRtTUwX",
    long=_names(
        "--output-document --output-file --append-output --directory-prefix --user-agent"
        " --header --post-data --post-file --body-data --body-file --method --timeout"
        " --dns-timeout --connect-timeout --read-timeout --tries --wait --waitretry --user"
        " --password --http-user --http-password --quota --limit-rate --load-cookies"
        " --save-cookies --ca-certificate --certificate --private-key --level --domains"
        " --exclude-domains --accept --reject --include-directories --exclude-directories"
        " --referer --input-file --execute --base --config --bind-address --max-redirect"
    ),
    hidden=_names("-i --input-file -e --execute --config"),
)
NETCAT = Tool(
    "host",
    short="cegGiIMmOpPqsTVwWXx",
    long=_names(
        "--exec --sh-exec --lua-exec --proxy --proxy-type --proxy-auth --source --source-port"
        " --wait --idle-timeout --output --hex-dump --append-output --max-conns --allow"
        " --allowfile --deny --denyfile --ssl-cert --ssl-key --ssl-trustfile --ssl-ciphers"
        " --ssl-servername --ssl-alpn"
    ),
    via=_names("-x --proxy -g"),
)
TOOLS = {
    "curl": CURL,
    "wget": WGET,
    "nc": NETCAT,
    "ncat": NETCAT,
    "netcat": NETCAT,
    "telnet": Tool("host", short="bleknX"),
    "socat": Tool("addresses"),
}


def hostname(url: str) -> str | None:
    """The host a URL connects to. User info and ports do not count as part of it.

    A backslash or a control character means no host: parsers disagree about where the host
    ends then, and the one that makes the request may read a different host than this one.
    """
    if "\\" in url or any(ord(char) < 0x21 or ord(char) == 0x7F for char in url):
        return None
    try:
        return urlsplit(url).hostname
    except ValueError:
        return None


def bash_targets(command: str) -> tuple[bool, list[str | None]]:
    """Whether a shell command uses the network, and the hosts it connects to.

    None stands for a target that cannot be read, such as a URL list in a file.
    """
    hosts: list[str | None] = []
    return _scan(command, hosts, NESTING), hosts


def _scan(command: str, hosts: list[str | None], depth: int) -> bool:
    words = _words(command)
    unquoted = " ".join(words or ())  # c''url is curl to the shell
    library = LIBRARY.search(command) or (IMPORT.search(command) and INTERPRETER.search(command))
    if not (TOOL_WORD.search(command) or TOOL_WORD.search(unquoted) or library):
        return False
    hosts.extend(hostname(url) for url in URL.findall(command))
    if words is None:
        hosts.append(None)
        return True
    for word in words:
        hosts.extend(hostname(url) for url in URL.findall(word))
        if depth and any(char.isspace() for char in word):
            _scan(word, hosts, depth - 1)  # bash -c "...", ssh host "..."
    for segment in _segments(words):
        hosts.extend(_invocation(segment))
    return True


def _words(command: str) -> list[str] | None:
    """The words of a command after quote removal; ; | & ( ) < > are words of their own."""
    lexer = shlex.shlex(command, posix=True, punctuation_chars=True)
    lexer.whitespace_split = True
    lexer.commenters = ""  # a # inside a word is no comment for the shell either
    try:
        return list(lexer)
    except ValueError:  # an unclosed quote
        return None


def _segments(words: list[str]) -> list[list[str]]:
    """Simple commands without their redirections: in `2>/dev/null` nothing is an argument."""
    segments: list[list[str]] = [[]]
    redirect_target = False
    for word in words:
        if redirect_target:
            redirect_target = False
        elif word and set(word) <= OPERATORS:
            if "<" in word or ">" in word:
                if segments[-1] and segments[-1][-1].isdigit():
                    segments[-1].pop()  # the descriptor in 2>
                redirect_target = True
            else:
                segments.append([])
        else:
            segments[-1].append(word)
    return [segment for segment in segments if segment]


def _invocation(segment: list[str]) -> list[str | None]:
    """The hosts of the network command in one simple command, if it runs one."""
    for index, word in enumerate(segment):
        tool = TOOLS.get(posixpath.basename(word.lstrip("`")))
        if tool is None:
            continue
        hosts: list[str | None] = []
        for prefix in segment[:index]:  # variables, sudo, env, timeout, xargs ...
            name, assigned, value = prefix.partition("=")
            if assigned and "proxy" in name.lower() and not name.lower().startswith("no_"):
                hosts.extend(_hosts_in(value))
            elif posixpath.basename(prefix) == "xargs":
                hosts.append(None)  # further arguments arrive on stdin
        return hosts + _arguments(tool, segment[index + 1 :])
    return []


def _arguments(tool: Tool, args: list[str]) -> list[str | None]:
    hosts: list[str | None] = []
    operands: list[str] = []
    rest = iter(args)
    for arg in rest:
        if arg == "--":
            operands.extend(rest)
            break
        if not arg.startswith("-") or arg == "-":
            operands.append(arg)
            continue
        option, value = _option(tool, arg, rest)
        if option in tool.hidden:
            hosts.append(None)
        elif option == "--url":
            operands.append(value)
        elif option in tool.via:
            hosts.extend(_hosts_in(value))
    if tool.operands == "urls":
        hosts.extend(hostname(op if "://" in op else f"http://{op}") for op in operands)
    elif tool.operands == "host":
        hosts.extend(op.strip("[]") for op in operands[:1])
    else:
        for op in operands:
            hosts.extend(_socat_hosts(op))
    return hosts


def _option(tool: Tool, arg: str, rest: Iterator[str]) -> tuple[str | None, str]:
    """The option in `arg` that takes a value, and the value; (None, "") for plain flags.

    Short options can be bundled: in `-sSo out.json` only the o takes a value.
    """
    if arg.startswith("--"):
        name, assigned, value = arg.partition("=")
        if assigned:
            return name, value
        if name in tool.long:
            return name, next(rest, "")
        return None, ""
    for after, char in enumerate(arg[1:], start=2):
        if char in tool.short:
            return f"-{char}", arg[after:] or next(rest, "")
    return None, ""


def _hosts_in(value: str) -> list[str | None]:
    """Hosts named in an option value: a proxy URL, host:port or host:port:address."""
    if "://" in value:
        return [hostname(value)]
    hosts: list[str | None] = [match.strip("[]") for match in HOST.findall(value)]
    return hosts or [None]


def _socat_hosts(address: str) -> list[str | None]:
    """Hosts a socat address connects to; listening addresses connect nowhere."""
    kind, colon, rest = address.partition(":")
    if not colon or not SOCAT_CONNECT.fullmatch(kind) or re.search("listen|recv", kind, re.I):
        return []
    parts = re.findall(r"\[[^\]]*\]|[^:,]+", rest.split(",", 1)[0])
    hosts: list[str | None] = [part.strip("[]") for part in parts if not part.isdigit()]
    return hosts or [None]
