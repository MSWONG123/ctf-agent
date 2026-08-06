"""State-persistence tests: save/load round-trip and dispatch autosave."""

from unittest.mock import MagicMock

from harness import Orchestrator
from state import (
    create_state, add_target, update_findings, record_agent_run,
    save_state, load_state,
)


def _text_response(text):
    block = MagicMock()
    block.type = "text"
    block.text = text
    resp = MagicMock()
    resp.content = [block]
    resp.stop_reason = "end_turn"
    return resp


def test_save_and_load_roundtrip(tmp_path):
    state = create_state()
    add_target(state, "h")
    update_findings(state, "h", "ports", [22, 80])
    record_agent_run(state, "h", "recon")
    path = tmp_path / "s.json"

    save_state(state, str(path))

    assert load_state(str(path)) == state


def test_load_missing_returns_fresh_state(tmp_path):
    assert load_state(str(tmp_path / "nope.json")) == create_state()


def test_dispatch_persists_to_disk(tmp_path):
    client = MagicMock()
    client.messages.create.return_value = _text_response("done")
    state = create_state()
    add_target(state, "h")
    path = tmp_path / "s.json"
    orch = Orchestrator(client, state, state_path=str(path))

    orch.dispatch("recon", "h", "task")

    loaded = load_state(str(path))
    assert "recon" in loaded["targets"]["h"]["agents_run"]
