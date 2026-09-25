from ai_sandbox_guard.log import DecisionLog


def test_counts_consecutive_denials_of_the_same_call(tmp_path):
    log = DecisionLog(tmp_path / "state" / "decisions.jsonl")
    assert log.denied_in_a_row("Bash", "curl x") == 0
    log.record("Bash", "curl x", allowed=False, reason="blocked")
    log.record("Bash", "curl x", allowed=False, reason="blocked")
    assert log.denied_in_a_row("Bash", "curl x") == 2
    assert log.denied_in_a_row("Bash", "curl y") == 0


def test_an_allowed_or_different_call_resets_the_count(tmp_path):
    log = DecisionLog(tmp_path / "decisions.jsonl")
    log.record("Bash", "curl x", allowed=False)
    log.record("Bash", "ls", allowed=True)
    log.record("Bash", "curl x", allowed=False)
    assert log.denied_in_a_row("Bash", "curl x") == 1


def test_broken_lines_are_skipped(tmp_path):
    path = tmp_path / "decisions.jsonl"
    log = DecisionLog(path)
    log.record("Bash", "curl x", allowed=False)
    with path.open("a") as file:
        file.write("not json\n[]\n")
    log.record("Bash", "curl x", allowed=False)
    assert log.denied_in_a_row("Bash", "curl x") == 2
