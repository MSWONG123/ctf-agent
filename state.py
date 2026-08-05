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
            "binaries": [],
            "files": [],
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
