"""Report agent — consolidates findings into a markdown report."""

import os
from datetime import datetime, timezone

import anthropic

from agents.base import BaseAgent
from state import format_target_findings


REPORT_SYSTEM_PROMPT = """You are a report agent for CTF competitions and authorized security testing.
Your job is to take raw findings from recon, web exploitation, and crypto analysis
and produce a clear, structured markdown report.

Structure the report as:
1. Executive summary (1-2 sentences)
2. For each target:
   a. Target info (IP, hostname, status)
   b. Open ports and services
   c. Web paths discovered
   d. Vulnerabilities found (with severity and evidence)
   e. Crypto findings (decoded values, cracked hashes)
   f. Notable observations
3. Prioritized next steps / attack recommendations

Be concise. Use tables where appropriate. Flag critical findings clearly."""


def create_report_agent(client: anthropic.Anthropic) -> BaseAgent:
    """Create a report agent instance (no tools — reads state only)."""
    return BaseAgent(
        name="report",
        system_prompt=REPORT_SYSTEM_PROMPT,
        tools=[],
        tool_dispatch={},
        client=client,
    )


def generate_report(state: dict, client: anthropic.Anthropic, output_dir: str = "reports") -> str:
    """Generate a consolidated report from state and save to output_dir. Returns file path."""
    os.makedirs(output_dir, exist_ok=True)

    # Build findings summary for the LLM
    findings_text = ""
    for target in state["targets"]:
        findings_text += format_target_findings(state, target) + "\n\n"

    if state["history"]:
        findings_text += "Activity log:\n" + "\n".join(state["history"][-30:])

    agent = create_report_agent(client)
    report_content = agent.run(
        f"Generate a comprehensive CTF recon report from these findings:\n\n{findings_text}",
        state,
    )

    # Save to file
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    targets = list(state["targets"].keys())
    name_part = targets[0].replace(".", "-") if targets else "report"
    filename = f"{name_part}-{timestamp}.md"
    filepath = os.path.join(output_dir, filename)

    with open(filepath, "w", encoding="utf-8") as f:
        f.write(report_content)

    print(f"\n[+] Report saved to: {filepath}")
    return filepath
