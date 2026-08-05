import pytest
from unittest.mock import MagicMock, patch
from agents.base import BaseAgent


def make_mock_client(responses):
    """Create a mock Anthropic client that returns predefined responses."""
    client = MagicMock()
    call_count = [0]

    def mock_create(**kwargs):
        idx = min(call_count[0], len(responses) - 1)
        call_count[0] += 1
        return responses[idx]

    client.messages.create = MagicMock(side_effect=mock_create)
    return client


def make_text_response(text):
    """Mock response with just text (end_turn)."""
    block = MagicMock()
    block.type = "text"
    block.text = text
    resp = MagicMock()
    resp.content = [block]
    resp.stop_reason = "end_turn"
    return resp


def make_tool_response(tool_name, tool_input, tool_id="tc_1"):
    """Mock response with a tool call."""
    block = MagicMock()
    block.type = "tool_use"
    block.name = tool_name
    block.input = tool_input
    block.id = tool_id
    resp = MagicMock()
    resp.content = [block]
    resp.stop_reason = "tool_use"
    return resp


def test_base_agent_init():
    client = MagicMock()
    agent = BaseAgent("test", "You are a test agent.", [], {}, client)
    assert agent.name == "test"
    assert agent.max_iterations == 20


def test_base_agent_run_text_only():
    client = make_mock_client([make_text_response("Hello world")])
    agent = BaseAgent("test", "You are a test agent.", [], {}, client)
    result = agent.run("say hello", {})
    assert result == "Hello world"


def test_base_agent_run_with_tool_call():
    tool_resp = make_tool_response("echo", {"msg": "hi"})
    text_resp = make_text_response("Done")
    client = make_mock_client([tool_resp, text_resp])

    dispatch = {"echo": lambda msg: f"echoed: {msg}"}
    tools = [{"name": "echo", "description": "echo", "input_schema": {"type": "object", "properties": {"msg": {"type": "string"}}, "required": ["msg"]}}]

    agent = BaseAgent("test", "prompt", tools, dispatch, client)
    result = agent.run("echo hi", {})
    assert result == "Done"
    assert client.messages.create.call_count == 2


def test_base_agent_max_iterations():
    tool_resp = make_tool_response("echo", {"msg": "hi"})
    client = make_mock_client([tool_resp] * 25)

    dispatch = {"echo": lambda msg: f"echoed: {msg}"}
    tools = [{"name": "echo", "description": "echo", "input_schema": {"type": "object", "properties": {"msg": {"type": "string"}}, "required": ["msg"]}}]

    agent = BaseAgent("test", "prompt", tools, dispatch, client)
    agent.max_iterations = 3
    result = agent.run("loop forever", {})
    assert client.messages.create.call_count == 3
