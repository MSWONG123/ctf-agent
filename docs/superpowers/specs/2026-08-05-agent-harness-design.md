# Agent Harness Design Spec

**Date:** 2026-08-05
**Goal:** Build a multi-agent orchestration harness for CTF competitions
**Deadline:** 2026-08-07 (Thursday CTF)

---

## Overview

A semi-autonomous agent harness that orchestrates 4 specialized agents (Recon, Web Exploit, Crypto, Report) across multiple targets. The orchestrator proposes actions and the user approves/denies. Targets can be added upfront or discovered mid-competition.

## Project Structure

```
CTF/
├── harness.py              # CLI entry point + orchestrator agent
├── state.py                # shared state store (targets, findings)
├── agents/
│   ├── __init__.py
│   ├── base.py             # base agent class (shared agentic loop)
│   ├── recon.py            # recon agent (migrated from recon_agent.py)
│   ├── web_exploit.py      # web exploit agent
│   ├── crypto.py           # crypto agent
│   └── report.py           # report agent
├── tools/                  # external tool binaries (existing)
├── wordlists/              # existing wordlists
├── reports/                # saved report output dir
├── recon_agent.py          # standalone recon (kept for direct use)
├── .env                    # API key
└── .env.example
```

## Shared State

All agents read from and write to a shared in-memory state dict. This is how findings flow between agents.

```python
state = {
    "targets": {
        "<target>": {
            "status": "pending | scanning | done",
            "assigned_agent": "<agent_name>",
            "findings": {
                "ports": [],
                "services": {},
                "web_paths": [],
                "dns": {},
                "vulns": [],
                "crypto": [],
                "notes": []
            }
        }
    },
    "queue": [],
    "history": []
}
```

### Data flow between agents:
- **Recon** writes: `ports`, `services`, `web_paths`, `dns`
- **Web Exploit** reads: `web_paths`, `services` -- writes: `vulns`
- **Crypto** reads: any encoded/encrypted strings from other findings -- writes: `crypto`
- **Report** reads: everything -- writes: markdown file to `reports/`
- **History** logs all agent actions and user approvals

## Agent Architecture

### Base Agent (`agents/base.py`)

```python
class BaseAgent:
    def __init__(self, name, system_prompt, tools, tool_dispatch)
    def run(self, task, state) -> findings
```

Shared logic:
- Anthropic API client setup (reuses single client from harness)
- Agentic loop: LLM decides tools -> execute -> observe -> repeat
- Max iteration safety limit
- UTF-8 output handling
- Tool result truncation for large outputs

### Recon Agent (`agents/recon.py`)

- **Tools:** nmap, dns_lookup, reverse_dns, curl, gobuster, nikto, subfinder, whois, ssl_check, ping
- **Input:** target IP/domain
- **Output:** populates `ports`, `services`, `web_paths`, `dns` in state
- **Migrated from:** existing `recon_agent.py` (same tools and system prompt)

### Web Exploit Agent (`agents/web_exploit.py`)

- **Tools:** curl (with attack payloads), sqlmap, directory traversal probes, header injection checks
- **Input:** target + discovered web paths/services from recon
- **Output:** populates `vulns` with confirmed or suspected vulnerabilities
- **Scope:** SQLi, XSS, LFI, directory traversal, header injection, authentication bypass probes

### Crypto Agent (`agents/crypto.py`)

- **Tools:** base64 decode/encode, hex decode, hash identification (hashid), ROT/Caesar brute, XOR brute, frequency analysis
- **Input:** suspicious strings, tokens, cookies, or files found by other agents
- **Output:** populates `crypto` with decoded/cracked values
- **All tools implemented in Python** (no external dependencies needed)

### Report Agent (`agents/report.py`)

- **Tools:** none (reads state only)
- **Input:** full state for all targets
- **Output:** consolidated markdown report saved to `reports/<target>-<timestamp>.md`
- **Sections:** target summary, open ports/services, web paths, vulnerabilities, crypto findings, attack surface summary

## Orchestrator (`harness.py`)

The orchestrator is an LLM call that sees current state and proposes the next action. The user approves or denies.

### Semi-autonomous flow:

1. User adds targets via CLI
2. Orchestrator proposes an action (e.g., "Run recon on 10.10.10.1?")
3. User responds: `y` (approve), `n` (deny), `skip` (next target)
4. Agent runs, findings populate state
5. Orchestrator sees new findings, proposes next action
6. Repeat until all targets are done
7. Report agent generates final report

### CLI commands during session:

| Command | Action |
|---|---|
| `add <target>` | Add a new target to the queue |
| `status` | Show all targets and their current state |
| `findings <target>` | Show findings for a specific target |
| `report` | Force generate report now |
| `auto` | Switch to fully autonomous mode (no approvals) |
| `quit` | Stop and save current state |

### Orchestrator system prompt responsibilities:
- Analyze current state across all targets
- Decide which agent to run next and on which target
- Chain findings intelligently (recon -> web exploit on discovered paths -> crypto on tokens)
- Propose one action at a time for user approval
- In `auto` mode, execute without approval

## Technical Decisions

- **LLM:** Claude Sonnet 4.6 (`claude-sonnet-4-6`) for all agents and orchestrator
- **Single API client:** shared across all agents to avoid redundant connections
- **No external frameworks:** pure Python + Anthropic SDK (no LangChain, no CrewAI)
- **State is in-memory:** simple dict, no database. CTF sessions are short-lived.
- **Reports saved as markdown:** easy to read, copy, and share
- **Nikto timeout:** 120s (core findings come within first 2 minutes)
- **Max iterations per agent:** 20 (safety limit)

## Out of Scope

- Persistent state across sessions (not needed for single-day CTF)
- Web UI / dashboard
- Parallel agent execution (sequential is simpler and avoids API rate limits)
- Forensics or privilege escalation agents (not requested)
