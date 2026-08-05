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
    assert t["findings"]["binaries"] == []
    assert t["findings"]["files"] == []
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
