# ai-sandbox-guard

[![CI](https://github.com/ulliiiiiiiii/ai-sandbox-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/ulliiiiiiiii/ai-sandbox-guard/actions/workflows/ci.yml)

A deterministic PreToolUse hook for Claude Code. Agents reach the internet only through a
broker you control: the built-in web search, fetches of external URLs and `curl`, `wget` or
HTTP libraries in shell commands are blocked before they run. No model decides anything
here. The checks are plain pattern and host matching.

Asking a model not to make external requests is not a security boundary. The hook sits in
front of every tool call and blocks by exit code, whatever the model intends at that moment.

## Rules

| Tool call | Decision |
| --- | --- |
| `WebSearch` | always blocked |
| `WebFetch` | allowed for allowed hosts only |
| `Bash` using `curl`, `wget`, `nc`, `socat`, `telnet`, `urllib`, `requests`, `httpx` or `aiohttp` | allowed only if every target points to an allowed host |
| anything else | allowed |

Loopback (`localhost`, `127.0.0.0/8`, `::1`) is always allowed. `--allow` adds host names,
globs like `*.lan` and networks like `10.0.0.0/8`. Hosts are compared after the URL has been
parsed, so `https://localhost@example.com` counts as `example.com` and `127.0.0.1.example.com`
is not loopback. A URL with a backslash or a control character has no host at all, because
parsers disagree about where its host ends.

Shell commands are read word by word, the way the shell splits them after removing quotes. The
targets of a command are every URL in it, the operands of `curl` and `wget` with or without a
scheme, the host of `nc` and `telnet`, socat addresses, proxies (`-x`, `--proxy`, `*_proxy`
variables) and the hosts in `--resolve` and `--connect-to`. Strings run through `bash -c` or
`ssh` are read the same way. Inline Python that uses `urllib`, `requests`, `httpx` or `aiohttp`,
imported in any form, is judged by the URLs it contains. A network command is blocked if it has
no readable target or reads its targets from a file (`wget -i`, `curl -K`).

When the same call is blocked three times in a row, the reason tells the agent to stop
retrying and change its approach. Every decision is written to a JSON lines log with secrets
redacted, by default `~/.local/state/ai-sandbox-guard/decisions.jsonl`.

If the hook cannot read its input, it lets the call through. A broken hook must not lock up
the session, and its job is to close the known paths.

This is not a sandbox. A process can still open sockets in ways no pattern catches, so pair
the hook with egress rules on the host if you need a hard guarantee.

## Install

```sh
pipx install git+https://github.com/ulliiiiiiiii/ai-sandbox-guard
```

Register it in `~/.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash|WebFetch|WebSearch",
        "hooks": [
          {
            "type": "command",
            "command": "ai-sandbox-guard --allow '*.lan' --broker 'the research MCP server'"
          }
        ]
      }
    ]
  }
}
```

`--broker` names what the agent should use instead. It becomes part of every reason the
agent sees.

## Checking it

`doctor` checks the settings and runs every bypass attempt from the self-test:

```console
$ ai-sandbox-guard doctor
PASS  ~/.claude/settings.json is readable JSON
PASS  a PreToolUse hook runs ai-sandbox-guard
PASS  the hook covers Bash
PASS  the hook covers WebFetch
PASS  the hook covers WebSearch
PASS  all self-test cases pass
```

`ai-sandbox-guard selftest` lists the attempts one by one. A single event can be tested by
hand:

```console
$ echo '{"tool_name": "Bash", "tool_input": {"command": "curl -s https://localhost@example.com/"}}' \
    | ai-sandbox-guard --broker 'the research MCP server'
Network access to example.com is blocked. Use the research MCP server for anything outside this machine.
$ echo $?
2
```

## Development

```sh
python -m venv .venv && . .venv/bin/activate
pip install -e '.[dev]'
pytest
ruff check . && ruff format --check . && mypy
```

## License

[MIT](LICENSE)
