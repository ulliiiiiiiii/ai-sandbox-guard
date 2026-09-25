import io
import json
import subprocess
import sys

import pytest

from ai_sandbox_guard import __version__
from ai_sandbox_guard.cli import main
from ai_sandbox_guard.selftest import CASES


@pytest.fixture
def hook(tmp_path, monkeypatch, capsys):
    log = tmp_path / "decisions.jsonl"

    def run(event, *options):
        stdin = event if isinstance(event, str) else json.dumps(event)
        monkeypatch.setattr(sys, "stdin", io.StringIO(stdin))
        code = main(["--log", str(log), *options])
        return code, capsys.readouterr().err

    run.log = log
    return run


CURL = {"tool_name": "Bash", "tool_input": {"command": "curl https://example.com"}}


def test_allows_and_logs_ordinary_calls(hook):
    assert hook({"tool_name": "Bash", "tool_input": {"command": "ls"}}) == (0, "")
    assert json.loads(hook.log.read_text())["decision"] == "allow"


def test_blocks_with_exit_code_two_and_names_the_broker(hook):
    code, err = hook(CURL, "--broker", "the research MCP server")
    assert code == 2
    assert err.strip() == (
        "Network access to example.com is blocked."
        " Use the research MCP server for anything outside this machine."
    )


def test_warns_on_the_third_identical_attempt(hook):
    assert "three times" not in hook(CURL)[1]
    assert "three times" not in hook(CURL)[1]
    assert "three times in a row" in hook(CURL)[1]


def test_allow_option(hook):
    event = {"tool_name": "Bash", "tool_input": {"command": "curl http://nas.lan/"}}
    assert hook(event)[0] == 2
    assert hook(event, "--allow", "*.lan")[0] == 0


@pytest.mark.parametrize("stdin", ["", "not json", "[1, 2]"])
def test_unreadable_input_lets_the_call_through(hook, stdin):
    assert hook(stdin) == (0, "")


def test_selftest(capsys):
    assert main(["selftest"]) == 0
    assert capsys.readouterr().out.endswith(f"{len(CASES)} passed, 0 failed\n")


def settings(tmp_path, matcher):
    entry = {"hooks": [{"type": "command", "command": "ai-sandbox-guard --allow '*.lan'"}]}
    if matcher is not None:
        entry["matcher"] = matcher
    path = tmp_path / "settings.json"
    path.write_text(json.dumps({"hooks": {"PreToolUse": [entry]}}))
    return path


@pytest.mark.parametrize("matcher", ["Bash|WebFetch|WebSearch", "*", None])
def test_doctor_accepts_a_complete_installation(tmp_path, capsys, matcher):
    assert main(["doctor", "--settings", str(settings(tmp_path, matcher))]) == 0
    assert "FAIL" not in capsys.readouterr().out


def test_doctor_reports_uncovered_tools(tmp_path, capsys):
    assert main(["doctor", "--settings", str(settings(tmp_path, "Bash"))]) == 1
    out = capsys.readouterr().out
    assert "FAIL  the hook covers WebFetch" in out
    assert "PASS  the hook covers Bash" in out


def test_doctor_without_settings(tmp_path, capsys):
    assert main(["doctor", "--settings", str(tmp_path / "missing.json")]) == 1
    assert "FAIL  a PreToolUse hook runs ai-sandbox-guard" in capsys.readouterr().out


def test_version(capsys):
    with pytest.raises(SystemExit):
        main(["--version"])
    assert capsys.readouterr().out == f"ai-sandbox-guard {__version__}\n"


def test_runs_as_a_module():
    event = json.dumps({"tool_name": "WebSearch", "tool_input": {"query": "x"}})
    result = subprocess.run(
        [sys.executable, "-m", "ai_sandbox_guard", "--log", "/dev/null"],
        input=event,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 2
    assert result.stderr.strip() == "Built-in web search is blocked."
