"""#3 — orchestrator robustness: guard propose_action and bound the notes blob."""

from unittest.mock import MagicMock

from harness import Orchestrator
from state import create_state, add_target, update_findings


def _text_response(text):
    block = MagicMock()
    block.type = "text"
    block.text = text
    resp = MagicMock()
    resp.content = [block]
    resp.stop_reason = "end_turn"
    return resp


def test_propose_action_survives_api_error():
    """A transient API error in the orchestrator must not crash the loop."""
    client = MagicMock()
    client.messages.create.side_effect = RuntimeError("boom")
    state = create_state()
    add_target(state, "h")
    orch = Orchestrator(client, state)

    result = orch.propose_action()  # must not raise

    assert isinstance(result, str)


def test_propose_action_bounds_prompt_size():
    """The orchestrator prompt must stay bounded even as notes accumulate."""
    client = MagicMock()
    client.messages.create.return_value = _text_response("ACTION: report")
    state = create_state()
    add_target(state, "h")
    update_findings(state, "h", "notes", ["[recon] " + "X" * 200000])
    orch = Orchestrator(client, state)

    orch.propose_action()

    prompt = client.messages.create.call_args.kwargs["messages"][0]["content"]
    assert len(prompt) < 20000, f"prompt not bounded: {len(prompt)} chars"
