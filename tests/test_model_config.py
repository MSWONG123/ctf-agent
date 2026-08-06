"""Model-config tests: base.py must honor RECON_MODEL, consistent with the rest."""

from unittest.mock import MagicMock

from agents.base import BaseAgent, get_model


def test_get_model_defaults(monkeypatch):
    monkeypatch.delenv("RECON_MODEL", raising=False)
    assert get_model() == "claude-sonnet-4-6"


def test_get_model_reads_env(monkeypatch):
    monkeypatch.setenv("RECON_MODEL", "claude-haiku-4-5")
    assert get_model() == "claude-haiku-4-5"


def test_base_agent_defaults_model(monkeypatch):
    monkeypatch.delenv("RECON_MODEL", raising=False)
    agent = BaseAgent("t", "sys", [], {}, MagicMock())
    assert agent.model == "claude-sonnet-4-6"


def test_base_agent_honors_recon_model(monkeypatch):
    monkeypatch.setenv("RECON_MODEL", "claude-opus-5")
    agent = BaseAgent("t", "sys", [], {}, MagicMock())
    assert agent.model == "claude-opus-5"
