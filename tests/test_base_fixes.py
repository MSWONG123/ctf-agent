"""Robustness-fix tests for the BaseAgent agentic loop."""

from unittest.mock import MagicMock

from agents.base import BaseAgent


def _text_block(text):
    b = MagicMock()
    b.type = "text"
    b.text = text
    return b


def _tool_block(name, inp=None, tuid="t1"):
    b = MagicMock()
    b.type = "tool_use"
    b.name = name
    b.input = inp or {}
    b.id = tuid
    return b


def _response(blocks, stop_reason):
    r = MagicMock()
    r.content = blocks
    r.stop_reason = stop_reason
    return r


_NOOP_TOOL = {"name": "boom", "description": "", "input_schema": {"type": "object", "properties": {}}}


def test_raising_tool_does_not_crash_the_loop():
    client = MagicMock()
    client.messages.create.side_effect = [
        _response([_tool_block("boom")], "tool_use"),
        _response([_text_block("recovered")], "end_turn"),
    ]

    def raising_tool(**kwargs):
        raise ValueError("kaboom")

    agent = BaseAgent("t", "sys", [_NOOP_TOOL], {"boom": raising_tool}, client)
    result = agent.run("go", {})

    assert "recovered" in result


def test_non_end_turn_without_tool_use_returns_partial_text():
    client = MagicMock()
    client.messages.create.return_value = _response([_text_block("partial answer")], "max_tokens")

    agent = BaseAgent("t", "sys", [], {}, client)
    result = agent.run("go", {})

    assert "partial answer" in result
    # Must not have looped 40 times trying to continue a truncated turn.
    assert client.messages.create.call_count == 1


def test_max_iterations_returns_partial_progress():
    client = MagicMock()
    client.messages.create.return_value = _response(
        [_text_block("progress note"), _tool_block("boom")], "tool_use"
    )

    agent = BaseAgent("t", "sys", [_NOOP_TOOL], {"boom": lambda **kw: "ok"}, client)
    agent.max_iterations = 2
    result = agent.run("go", {})

    assert "progress note" in result
