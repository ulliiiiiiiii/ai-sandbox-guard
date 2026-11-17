import pytest

from ai_sandbox_guard.guard import HostPolicy, evaluate, hostname, redact, summary
from ai_sandbox_guard.selftest import CASES


@pytest.mark.parametrize(("name", "event", "allowed"), CASES, ids=[case[0] for case in CASES])
def test_bypass_attempts(name, event, allowed):
    assert evaluate(event, HostPolicy()).allow is allowed


@pytest.mark.parametrize(
    ("patterns", "host", "allowed"),
    [
        ((), "localhost", True),
        ((), "LOCALHOST.", True),
        ((), "127.8.9.10", True),
        ((), "::1", True),
        ((), "example.com", False),
        ((), None, False),
        ((), "", False),
        ((), "2130706433", False),
        (("*.lan",), "nas.lan", True),
        (("*.lan",), "lan.example.com", False),
        (("10.0.0.0/8",), "10.1.2.3", True),
        (("10.0.0.0/8",), "11.1.2.3", False),
        (("build.internal",), "build.internal", True),
        (("build.internal",), "evil-build.internal", False),
        (("fd00::/8",), "fd12::1", True),
    ],
)
def test_host_policy(patterns, host, allowed):
    assert HostPolicy(patterns).allows(host) is allowed


def test_allowed_hosts_extend_the_bash_and_fetch_rules():
    policy = HostPolicy(["*.lan"])
    bash = {"tool_name": "Bash", "tool_input": {"command": "curl -s http://nas.lan:9000/status"}}
    fetch = {"tool_name": "WebFetch", "tool_input": {"url": "http://wiki.lan/page"}}
    assert evaluate(bash, policy).allow
    assert evaluate(fetch, policy).allow


def test_reasons_name_the_blocked_hosts():
    event = {
        "tool_name": "Bash",
        "tool_input": {"command": "curl https://b.example https://a.example"},
    }
    assert evaluate(event, HostPolicy()).reason == (
        "Network access to a.example, b.example is blocked."
    )


@pytest.mark.parametrize(
    "event",
    [
        {"tool_name": "WebFetch", "tool_input": None},
        {"tool_name": "WebFetch", "tool_input": {"url": "http://[broken/"}},
        {"tool_name": "Bash", "tool_input": {"command": None}},
        {},
    ],
)
def test_malformed_events_do_not_raise(event):
    evaluate(event, HostPolicy())


@pytest.mark.parametrize(
    ("command", "allowed"),
    [
        ("curl -d @body.json -H 'Accept: a.b' http://localhost:8080/api | jq .id > id.txt", True),
        ("wget -q -O- --timeout 5 http://localhost/health", True),
        ("curl --max-time 2.5 -X POST http://localhost/ 2>&1", True),
        ("socat TCP-LISTEN:8080,fork TCP:localhost:80", True),
        ("echo $(curl http://localhost/) `curl -s http://127.0.0.1/`", True),
        ("socat - TCP:example.com:80", False),
        ("nc -x example.com:1080 localhost 80", False),
        ("curl --resolve localhost:443:10.1.2.3 https://localhost/", False),
        ("curl -K settings.txt", False),
        ("ls | xargs curl http://localhost/", False),
        ("echo `curl example.com`", False),
        ("curl 'http://localhost/", False),
        ("c''url http://localhost/ example.com", False),
        ("curl http://localhost/ -- example.com", False),
        ("ssh host \"bash -c 'curl example.com'\"", False),
    ],
)
def test_shell_targets(command, allowed):
    event = {"tool_name": "Bash", "tool_input": {"command": command}}
    assert evaluate(event, HostPolicy()).allow is allowed


def test_unreadable_targets_are_named():
    event = {"tool_name": "Bash", "tool_input": {"command": "wget -i urls.txt"}}
    assert evaluate(event, HostPolicy()).reason == (
        "Network access to an unreadable target is blocked."
    )


def test_hostname_ignores_user_info_and_port():
    assert hostname("https://user:pw@example.com:8443/path") == "example.com"
    assert hostname("http://[broken/") is None


@pytest.mark.parametrize("url", ["http://example.com\\@127.0.0.1/", "http://local\thost/"])
def test_hostname_refuses_urls_parsers_disagree_on(url):
    assert hostname(url) is None


def test_redact():
    text = (
        "curl -H 'Authorization: Bearer abc.def'"
        " 'https://x.example/?api_key=123&token=456' sk-live_99"
    )
    assert "abc.def" not in redact(text, limit=500)
    assert "123" not in redact(text, limit=500)
    assert "sk-live_99" not in redact(text, limit=500)
    assert len(redact("x" * 500)) == 200


def test_summary_uses_the_relevant_field():
    assert summary({"tool_input": {"command": "ls"}}) == "ls"
    assert summary({"tool_input": {"url": "https://example.com"}}) == "https://example.com"
    assert summary({"tool_input": {"query": "weather"}}) == "weather"
