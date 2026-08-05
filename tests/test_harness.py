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


def test_orchestrator_has_all_agents():
    client = MagicMock()
    state = create_state()
    orch = Orchestrator(client, state)
    expected = {"recon", "web_exploit", "crypto", "netcat", "reversing", "forensics", "blockchain", "ai_ml"}
    assert set(orch.agents.keys()) == expected


def test_orchestrator_dispatch_reversing():
    client = MagicMock()
    client.messages.create.return_value = make_text_response("Analysis complete.")
    state = create_state()
    add_target(state, "binary.elf")
    orch = Orchestrator(client, state)
    result = orch.dispatch("reversing", "binary.elf", "Analyze binary")
    assert isinstance(result, str)


def test_orchestrator_dispatch_forensics():
    client = MagicMock()
    client.messages.create.return_value = make_text_response("Forensics complete.")
    state = create_state()
    add_target(state, "evidence.img")
    orch = Orchestrator(client, state)
    result = orch.dispatch("forensics", "evidence.img", "Analyze evidence")
    assert isinstance(result, str)
