from unittest.mock import MagicMock
from agents.ai_ml import (
    create_ai_ml_agent, AI_ML_TOOLS, AI_ML_DISPATCH,
    tool_binary_search_boundary, tool_linear_solve,
    tool_confusion_matrix, tool_ascii_pattern_send,
)


def test_ai_ml_tools_defined():
    names = [t["name"] for t in AI_ML_TOOLS]
    assert "probe_model" in names
    assert "binary_search_boundary" in names
    assert "grid_probe_2d" in names
    assert "linear_solve" in names
    assert "confusion_matrix" in names
    assert "adversarial_search" in names
    assert "ascii_pattern_send" in names


def test_dispatch_matches_tools():
    tool_names = {t["name"] for t in AI_ML_TOOLS}
    dispatch_names = set(AI_ML_DISPATCH.keys())
    assert tool_names == dispatch_names


def test_create_ai_ml_agent():
    client = MagicMock()
    agent = create_ai_ml_agent(client)
    assert agent.name == "ai_ml"


def test_binary_search_boundary():
    # Simulate: fires when x >= 3
    observations = [
        {"input": -10, "output": 0},
        {"input": 10, "output": 1},
        {"input": 0, "output": 0},
        {"input": 5, "output": 1},
        {"input": 2, "output": 0},
        {"input": 3, "output": 1},
    ]
    result = tool_binary_search_boundary(observations=observations)
    assert "2" in result and "3" in result


def test_linear_solve_2x2():
    # 2x + 3y = 8, x - y = 1  =>  x=2.2, y=1.2
    equations = [[2, 3, 8], [1, -1, 1]]
    result = tool_linear_solve(equations=equations)
    assert "2.2" in result or "2.20" in result


def test_linear_solve_identity():
    # x = 5, y = 3
    equations = [[1, 0, 5], [0, 1, 3]]
    result = tool_linear_solve(equations=equations)
    assert "5" in result and "3" in result


def test_confusion_matrix():
    data = [
        {"input": "cat", "expected": 1, "actual": 1},
        {"input": "dog", "expected": 0, "actual": 0},
        {"input": "cat2", "expected": 1, "actual": 0},
    ]
    result = tool_confusion_matrix(data=data)
    assert "TP" in result or "True Positive" in result.replace("_", " ").title()


def test_ascii_pattern_send():
    result = tool_ascii_pattern_send(
        target_bits="01110000",
        zero_values=[-10, -9],
        one_values=[10, 9],
    )
    assert len(result) == 8
    # Verify no back-to-back repeats
    for i in range(1, len(result)):
        assert result[i] != result[i - 1]
