"""Accuracy-fix tests for orchestration: proposal parsing, agent tracking, findings."""

from unittest.mock import MagicMock

from harness import Orchestrator
from state import create_state, add_target


def _text_response(text):
    block = MagicMock()
    block.type = "text"
    block.text = text
    resp = MagicMock()
    resp.content = [block]
    resp.stop_reason = "end_turn"
    return resp


def test_parse_proposal_handles_single_line_pipe_format():
    orch = Orchestrator(MagicMock(), create_state())
    parsed = orch.parse_proposal(
        "ACTION: recon | TARGET: 10.0.0.1 | TASK: scan it | REASON: init"
    )
    assert parsed["action"] == "recon"
    assert parsed["target"] == "10.0.0.1"
    assert parsed["task"] == "scan it"


def test_dispatch_does_not_mark_done_and_records_agent():
    client = MagicMock()
    client.messages.create.return_value = _text_response("recon output, nothing special")
    state = create_state()
    add_target(state, "h")
    orch = Orchestrator(client, state)

    orch.dispatch("recon", "h", "task")

    assert state["targets"]["h"]["status"] != "done"
    assert "recon" in state["targets"]["h"]["agents_run"]


def test_dispatch_populates_structured_findings():
    client = MagicMock()
    client.messages.create.return_value = _text_response(
        "22/tcp open ssh\n80/tcp open http\nfound flag{pwned}"
    )
    state = create_state()
    add_target(state, "h")
    orch = Orchestrator(client, state)

    orch.dispatch("recon", "h", "task")

    ports = state["targets"]["h"]["findings"]["ports"]
    assert 22 in ports and 80 in ports
    dump = " ".join(
        state["targets"]["h"]["findings"]["notes"]
        + state["targets"]["h"]["findings"]["vulns"]
    )
    assert "flag{pwned}" in dump


def test_extract_signals():
    from state import extract_signals

    ports, flags = extract_signals("22/tcp open ssh\n443/tcp open https\nflag{abc}")
    assert ports == [22, 443]
    assert "flag{abc}" in flags
