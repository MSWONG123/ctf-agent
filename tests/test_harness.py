from unittest.mock import MagicMock, patch
from harness import Orchestrator
from state import create_state, add_target, update_findings


def make_text_response(text):
    block = MagicMock()
    block.type = "text"
    block.text = text
    resp = MagicMock()
    resp.content = [block]
    resp.stop_reason = "end_turn"
    return resp


def test_orchestrator_init():
    client = MagicMock()
    state = create_state()
    orch = Orchestrator(client, state)
    assert orch.auto_mode is False


def test_orchestrator_propose_action():
    client = MagicMock()
    client.messages.create.return_value = make_text_response(
        "ACTION: recon | TARGET: 10.10.10.1 | REASON: Initial scan needed"
    )
    state = create_state()
    add_target(state, "10.10.10.1")
    orch = Orchestrator(client, state)
    proposal = orch.propose_action()
    assert "10.10.10.1" in proposal


def test_orchestrator_dispatch_recon():
    client = MagicMock()
    client.messages.create.return_value = make_text_response("Recon complete.")
    state = create_state()
    add_target(state, "10.10.10.1")
    orch = Orchestrator(client, state)
    result = orch.dispatch("recon", "10.10.10.1", "Run recon on 10.10.10.1")
    assert isinstance(result, str)


def test_orchestrator_dispatch_unknown_agent():
    client = MagicMock()
    state = create_state()
    orch = Orchestrator(client, state)
    result = orch.dispatch("unknown_agent", "10.10.10.1", "test")
    assert "Unknown agent" in result
