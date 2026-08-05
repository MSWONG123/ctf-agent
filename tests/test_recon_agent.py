from unittest.mock import MagicMock
from agents.recon import create_recon_agent, RECON_TOOLS, RECON_DISPATCH, RECON_SYSTEM_PROMPT


def test_recon_tools_defined():
    assert len(RECON_TOOLS) == 10
    names = [t["name"] for t in RECON_TOOLS]
    assert "nmap_scan" in names
    assert "dns_lookup" in names
    assert "gobuster_scan" in names
    assert "nikto_scan" in names
    assert "subfinder_enum" in names


def test_recon_dispatch_matches_tools():
    tool_names = {t["name"] for t in RECON_TOOLS}
    dispatch_names = set(RECON_DISPATCH.keys())
    assert tool_names == dispatch_names


def test_recon_system_prompt_exists():
    assert "reconnaissance" in RECON_SYSTEM_PROMPT.lower()


def test_create_recon_agent():
    client = MagicMock()
    agent = create_recon_agent(client)
    assert agent.name == "recon"
    assert len(agent.tools) == 10
    assert len(agent.tool_dispatch) == 10
