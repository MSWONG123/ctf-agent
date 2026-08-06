"""#4 — per-agent model-tier escalation (strong model for hard categories)."""

from unittest.mock import MagicMock

from agents.base import BaseAgent, get_model


def test_hard_agents_escalate_to_strong_model(monkeypatch):
    monkeypatch.delenv("RECON_MODEL", raising=False)
    monkeypatch.delenv("RECON_STRONG_MODEL", raising=False)
    for name in ("crypto", "reversing", "blockchain"):
        assert get_model(name) == "claude-opus-5", name


def test_routine_agents_and_router_use_default(monkeypatch):
    monkeypatch.delenv("RECON_MODEL", raising=False)
    assert get_model("recon") == "claude-sonnet-4-6"
    assert get_model("web_exploit") == "claude-sonnet-4-6"
    assert get_model() == "claude-sonnet-4-6"  # orchestrator routing tier


def test_global_recon_model_forces_all_tiers(monkeypatch):
    monkeypatch.setenv("RECON_MODEL", "claude-haiku-4-5")
    assert get_model("crypto") == "claude-haiku-4-5"
    assert get_model("recon") == "claude-haiku-4-5"


def test_per_agent_env_override_wins(monkeypatch):
    monkeypatch.setenv("RECON_MODEL", "claude-haiku-4-5")
    monkeypatch.setenv("RECON_MODEL_CRYPTO", "claude-opus-5")
    assert get_model("crypto") == "claude-opus-5"
    assert get_model("web_exploit") == "claude-haiku-4-5"


def test_strong_model_env_override(monkeypatch):
    monkeypatch.delenv("RECON_MODEL", raising=False)
    monkeypatch.setenv("RECON_STRONG_MODEL", "claude-fable-5")
    assert get_model("crypto") == "claude-fable-5"


def test_base_agent_resolves_model_from_its_name(monkeypatch):
    monkeypatch.delenv("RECON_MODEL", raising=False)
    monkeypatch.delenv("RECON_STRONG_MODEL", raising=False)
    agent = BaseAgent("crypto", "sys", [], {}, MagicMock())
    assert agent.model == "claude-opus-5"
