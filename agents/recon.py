"""Recon agent — wraps the existing recon_agent.py tools into a BaseAgent."""

import anthropic

from agents.base import BaseAgent
from recon_agent import TOOLS as RECON_TOOLS
from recon_agent import TOOL_DISPATCH as RECON_DISPATCH
from recon_agent import SYSTEM_PROMPT as RECON_SYSTEM_PROMPT


def create_recon_agent(client: anthropic.Anthropic) -> BaseAgent:
    """Create a recon agent instance."""
    return BaseAgent(
        name="recon",
        system_prompt=RECON_SYSTEM_PROMPT,
        tools=RECON_TOOLS,
        tool_dispatch=RECON_DISPATCH,
        client=client,
    )
