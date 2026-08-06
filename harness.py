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
from agents.base import get_model
from state import (
    create_state, add_target, set_target_status, add_history,
    update_findings, format_state_summary, format_target_findings,
    get_pending_targets, extract_signals, record_agent_run,
    save_state, load_state,
)

MODEL = get_model()
STATE_PATH = os.getenv("HARNESS_STATE", "harness_state.json")

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
    def __init__(self, client: anthropic.Anthropic, state: dict, state_path: str = None):
        self.client = client
        self.state = state
        self.state_path = state_path
        self.auto_mode = True
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

        # Bounded detailed findings — cap notes so the orchestrator prompt can't
        # grow without limit (and overflow the context window) as a run
        # accumulates agent output.
        details = ""
        for target in self.state["targets"]:
            details += format_target_findings(
                self.state, target, max_notes=3, note_chars=600
            ) + "\n\n"
        if len(details) > 6000:
            details = details[:6000] + "\n…(findings truncated — see report for full output)"

        recent_history = "\n".join(self.state["history"][-10:]) if self.state["history"] else "No actions yet."

        prompt = f"""Current state:
{state_summary}

Detailed findings:
{details}

Recent history:
{recent_history}

What should we do next?"""

        try:
            response = self.client.messages.create(
                model=MODEL,
                system=ORCHESTRATOR_SYSTEM_PROMPT,
                messages=[{"role": "user", "content": prompt}],
                max_tokens=500,
            )
        except Exception as e:
            # Don't let a transient error / over-length prompt kill the loop;
            # returning "" makes the start loop stop cleanly (state is persisted).
            print(f"  [Orchestrator] ERROR: proposal request failed: {e}")
            return ""

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

        # Extract structured signal (open ports, flags) so the orchestrator
        # reasons over real findings instead of a perpetually-empty state.
        ports, flags = extract_signals(result)
        existing_ports = set(self.state["targets"][target]["findings"]["ports"])
        new_ports = [p for p in ports if p not in existing_ports]
        if new_ports:
            update_findings(self.state, target, "ports", new_ports)
        if flags:
            update_findings(self.state, target, "vulns", [f"FLAG: {f}" for f in flags])

        # Store the agent's output into state so the report agent can see it
        update_findings(self.state, target, "notes", [f"[{agent_name}] {result}"])

        # Record which agent ran; keep the target open so later phases
        # (recon -> web_exploit -> crypto) can still run instead of being
        # cut off by a premature 'done'.
        record_agent_run(self.state, target, agent_name)
        set_target_status(self.state, target, "analyzed")
        add_history(self.state, f"Completed {agent_name} on {target}")

        # Persist after each agent so a crash/exit doesn't lose progress.
        if self.state_path:
            save_state(self.state, self.state_path)

        return result

    def parse_proposal(self, proposal: str) -> dict:
        """Parse the orchestrator's ACTION/TARGET/TASK/REASON response.

        Tolerant of both multi-line output and single-line pipe-delimited output
        ("ACTION: x | TARGET: y | ..."), and case-insensitive in the field keys.
        """
        parsed = {}
        for seg in re.split(r"[\n|]", proposal.strip()):
            seg = seg.strip()
            for key in ["ACTION", "TARGET", "TASK", "REASON"]:
                if seg.upper().startswith(key + ":"):
                    parsed[key.lower()] = seg.split(":", 1)[1].strip()
        return parsed


def main():
    api_key = load_api_key()
    client = anthropic.Anthropic(api_key=api_key)
    state = load_state(STATE_PATH)  # resume prior run if present
    orch = Orchestrator(client, state, state_path=STATE_PATH)
    if state["targets"]:
        print(f"  [+] Resumed {len(state['targets'])} target(s) from {STATE_PATH}")

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
            max_steps = 50
            steps = 0
            while True:
                steps += 1
                if steps > max_steps:
                    print(f"  [Orchestrator] Reached step cap ({max_steps}). Generating report...")
                    path = generate_report(state, client)
                    print(f"  Report saved to: {path}")
                    break

                proposal_text = orch.propose_action()
                parsed = orch.parse_proposal(proposal_text)

                action = parsed.get("action", "").strip().lower()

                if not action:
                    print(f"  [Orchestrator] {proposal_text}")
                    break

                if action == "report":
                    print("  [Orchestrator] All targets scanned. Generating report...")
                    path = generate_report(state, client)
                    print(f"  Report saved to: {path}")
                    break

                # Validate against the known agents so a malformed proposal can't
                # spin the loop forever on an unrecognized (no-op) action.
                if action not in orch.agents:
                    print(f"  [Orchestrator] Unrecognized action '{action}'. Stopping to avoid a loop.")
                    add_history(state, f"Unrecognized action: {action}")
                    break

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
                        # Validate LLM-proposed targets with the same regex used
                        # for CLI-entered ones, so scope can't silently expand.
                        if not re.match(r'^[a-zA-Z0-9._:\-/]+$', target):
                            print(f"    ERROR: Invalid target format '{target}'. Skipping.")
                            add_history(state, f"Rejected malformed target: {target}")
                            continue
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
