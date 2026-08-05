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
