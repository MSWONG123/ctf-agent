"""Agent harness — semi-autonomous orchestrator for CTF competitions."""

import os
import re
import sys

import anthropic

# Fix Windows terminal encoding
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
sys.stderr.reconfigure(encoding='utf-8', errors='replace')

from agents.recon import create_recon_agent
from agents.web_exploit import create_web_exploit_agent
from agents.crypto import create_crypto_agent
from agents.netcat import create_netcat_agent
from agents.reversing import create_reversing_agent
from agents.forensics import create_forensics_agent
from agents.blockchain import create_blockchain_agent
from agents.ai_ml import create_ai_ml_agent
from agents.report import generate_report
from recon_agent import load_api_key
from state import (
    create_state, add_target, set_target_status, add_history,
    update_findings, format_state_summary, format_target_findings,
    get_pending_targets,
)

MODEL = os.getenv("RECON_MODEL", "claude-sonnet-4-6")

ORCHESTRATOR_SYSTEM_PROMPT = """You are a CTF orchestrator. You coordinate specialized agents to attack targets.

Available agents:
- recon: Port scanning, DNS, web discovery, enumeration
- web_exploit: SQLi, XSS, LFI, SSRF, SSTI, command injection, JWT, cookies
- crypto: Classical ciphers, RSA, AES, hashing, encoding chains, PRNG
- reversing: Binary analysis, disassembly, ELF parsing, buffer overflow, ROP, shellcode
- forensics: File carving, steganography, metadata, pcap, entropy, ZIP cracking
- blockchain: Smart contract analysis, Solidity vulns, ABI/tx decoding, EVM bytecode
- ai_ml: Model probing, boundary finding, weight recovery, adversarial inputs
- netcat: Raw interactive TCP sessions (fallback for live socket IO)

Based on the current state of all targets, propose the SINGLE best next action.

Response format (strict — follow exactly):
ACTION: <agent_name>
TARGET: <target>
TASK: <specific instruction for the agent>
REASON: <why this action is the best next step>

Rules:
- Always run recon first on new network targets before other agents.
- Run web_exploit only after recon has found web services.
- Run reversing when challenge involves a binary file.
- Run forensics when challenge involves an image, pcap, archive, or unknown file.
- Run blockchain when challenge involves Solidity, EVM, or on-chain data.
- Run ai_ml when challenge involves a model, perceptron, or classifier.
- Run crypto when encoded/encrypted data is found.
- Run netcat as fallback for interactive services not covered by other agents.
- If all targets are fully scanned, respond with: ACTION: report
- Be specific in TASK — reference actual ports, paths, and findings."""


class Orchestrator:
    def __init__(self, client: anthropic.Anthropic, state: dict):
        self.client = client
        self.state = state
        self.auto_mode = False
        self.agents = {
            "recon": lambda: create_recon_agent(client),
            "web_exploit": lambda: create_web_exploit_agent(client),
            "crypto": lambda: create_crypto_agent(client),
            "netcat": lambda: create_netcat_agent(client),
            "reversing": lambda: create_reversing_agent(client),
            "forensics": lambda: create_forensics_agent(client),
            "blockchain": lambda: create_blockchain_agent(client),
            "ai_ml": lambda: create_ai_ml_agent(client),
        }

    def propose_action(self) -> str:
        """Ask the LLM what to do next based on current state."""
        state_summary = format_state_summary(self.state)

        # Include detailed findings for each target
        details = ""
        for target in self.state["targets"]:
            details += format_target_findings(self.state, target) + "\n\n"

        recent_history = "\n".join(self.state["history"][-10:]) if self.state["history"] else "No actions yet."

        prompt = f"""Current state:
{state_summary}

Detailed findings:
{details}

Recent history:
{recent_history}

What should we do next?"""

        response = self.client.messages.create(
            model=MODEL,
            system=ORCHESTRATOR_SYSTEM_PROMPT,
            messages=[{"role": "user", "content": prompt}],
            max_tokens=500,
        )

        for block in response.content:
            if block.type == "text":
                return block.text
        return ""

    def dispatch(self, agent_name: str, target: str, task: str) -> str:
        """Run an agent on a target with the given task."""
        if agent_name not in self.agents:
            return f"Unknown agent: {agent_name}"

        agent = self.agents[agent_name]()
        set_target_status(self.state, target, "scanning")
        add_history(self.state, f"Running {agent_name} on {target}")

        result = agent.run(task, self.state)

        # Store the agent's output into state so the report agent can see it
        update_findings(self.state, target, "notes", [f"[{agent_name}] {result}"])

        set_target_status(self.state, target, "done")
        add_history(self.state, f"Completed {agent_name} on {target}")

        return result

    def parse_proposal(self, proposal: str) -> dict:
        """Parse the orchestrator's ACTION/TARGET/TASK/REASON response."""
        parsed = {}
        for line in proposal.strip().split("\n"):
            for key in ["ACTION", "TARGET", "TASK", "REASON"]:
                if line.strip().upper().startswith(key + ":"):
                    parsed[key.lower()] = line.split(":", 1)[1].strip()
        return parsed


def main():
    api_key = load_api_key()
    client = anthropic.Anthropic(api_key=api_key)
    state = create_state()
    orch = Orchestrator(client, state)

    print("=" * 60)
    print("  CTF AGENT HARNESS")
    print("  Type 'help' for commands")
    print("=" * 60)
    print()

    # Check for targets from command line
    import argparse
    parser = argparse.ArgumentParser(description="CTF Agent Harness")
    parser.add_argument("targets", nargs="*", help="Initial targets to add")
    args = parser.parse_args()

    for t in args.targets:
        t = t.strip()
        if re.match(r'^[a-zA-Z0-9._:\-/]+$', t):
            add_target(state, t)
            print(f"  [+] Added target: {t}")

    while True:
        try:
            user_input = input("\nharness> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nExiting.")
            break

        if not user_input:
            continue

        # Parse CLI commands
        if user_input == "help":
            print("Commands:")
            print("  add <target>       — Add a new target")
            print("  status             — Show all targets and status")
            print("  findings <target>  — Show findings for a target")
            print("  report             — Generate report now")
            print("  auto               — Toggle autonomous mode")
            print("  start              — Start orchestration loop")
            print("  quit               — Exit")
            continue

        if user_input.startswith("add "):
            target = user_input[4:].strip()
            if re.match(r'^[a-zA-Z0-9._:\-/]+$', target):
                add_target(state, target)
                print(f"  [+] Added target: {target}")
            else:
                print("  ERROR: Invalid target format")
            continue

        if user_input == "status":
            print(format_state_summary(state))
            continue

        if user_input.startswith("findings "):
            target = user_input[9:].strip()
            if target in state["targets"]:
                print(format_target_findings(state, target))
            else:
                print(f"  Target '{target}' not found")
            continue

        if user_input == "report":
            if not state["targets"]:
                print("  No targets to report on.")
            else:
                print("  Generating report...")
                path = generate_report(state, client)
                print(f"  Report saved to: {path}")
            continue

        if user_input == "auto":
            orch.auto_mode = not orch.auto_mode
            mode = "ON" if orch.auto_mode else "OFF"
            print(f"  Autonomous mode: {mode}")
            continue

        if user_input == "quit":
            print("Exiting.")
            break

        if user_input == "start":
            if not state["targets"]:
                print("  No targets added. Use 'add <target>' first.")
                continue

            print("\n  Starting orchestration loop...\n")
            while True:
                proposal_text = orch.propose_action()
                parsed = orch.parse_proposal(proposal_text)

                if not parsed.get("action"):
                    print(f"  [Orchestrator] {proposal_text}")
                    break

                if parsed["action"] == "report":
                    print("  [Orchestrator] All targets scanned. Generating report...")
                    path = generate_report(state, client)
                    print(f"  Report saved to: {path}")
                    break

                action = parsed.get("action", "?")
                target = parsed.get("target", "?")
                task = parsed.get("task", "?")
                reason = parsed.get("reason", "")

                print(f"  [Orchestrator] Proposed:")
                print(f"    Agent:  {action}")
                print(f"    Target: {target}")
                print(f"    Task:   {task}")
                print(f"    Reason: {reason}")

                if orch.auto_mode:
                    approve = "y"
                    print("    Auto-approved.")
                else:
                    try:
                        approve = input("    Approve? [y/n/skip/quit] ").strip().lower()
                    except (EOFError, KeyboardInterrupt):
                        print("\n  Stopping orchestration.")
                        break

                if approve == "y":
                    if target not in state["targets"]:
                        add_target(state, target)
                    result = orch.dispatch(action, target, task)
                    print(f"\n  [Result preview] {result[:300]}...")
                elif approve == "quit":
                    break
                elif approve == "skip":
                    add_history(state, f"Skipped {action} on {target}")
                    continue
                else:
                    add_history(state, f"Denied {action} on {target}")
                    continue

            continue

        print(f"  Unknown command: {user_input}. Type 'help' for commands.")


if __name__ == "__main__":
    main()
