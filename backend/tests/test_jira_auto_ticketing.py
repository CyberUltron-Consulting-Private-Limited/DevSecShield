"""Hermetic tests for per-finding auto-Jira create and close-on-fixed."""
import os
import sys

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

os.environ.setdefault("JWT_SECRET_KEY", "jira-auto-ticket-test-secret-not-for-prod")

from backend.utilities.integrations.jira_ticketing import (  # noqa: E402
    MAX_AUTO_TICKETS,
    auto_create_enabled,
    extract_finding_summary,
    finding_ticket_description,
    pick_done_transition_id,
)


def test_auto_create_requires_explicit_toggle() -> None:
    assert auto_create_enabled(None) is False
    assert auto_create_enabled({}) is False
    assert auto_create_enabled({"jira": {"jira_project_id": "10001"}}) is False
    assert auto_create_enabled({"jira": {"jira_project_id": "10001", "auto_create_tickets": False}}) is False
    assert auto_create_enabled({"jira": {"jira_project_id": "10001", "auto_create_tickets": True}}) is True


def test_extract_finding_summary_prefers_title() -> None:
    assert extract_finding_summary({"title": "Reflected XSS", "description": "n/a"}) == "Reflected XSS"
    assert extract_finding_summary({"vulnerability_title": "SQL injection"}) == "SQL injection"
    assert extract_finding_summary({"name": "CVE-2024-1"}) == "CVE-2024-1"
    assert extract_finding_summary({}) == "Security finding"


def test_finding_ticket_description_includes_scan_and_impact() -> None:
    text = finding_ticket_description(
        scan_type="dast",
        scan_id=263,
        finding={"title": "XSS", "impact": "High", "url": "https://demo.testfire.net/", "description": "reflected"},
    )
    assert "dast" in text.lower()
    assert "263" in text
    assert "High" in text
    assert "demo.testfire.net" in text


def test_pick_done_transition_prefers_done_category() -> None:
    transitions = [
        {"id": "11", "name": "In Progress", "to": {"statusCategory": {"key": "indeterminate"}}},
        {"id": "31", "name": "Done", "to": {"statusCategory": {"key": "done"}}},
    ]
    assert pick_done_transition_id(transitions) == "31"


def test_pick_done_transition_falls_back_to_name() -> None:
    transitions = [
        {"id": "21", "name": "Complete", "to": {"name": "Complete"}},
    ]
    assert pick_done_transition_id(transitions) == "21"


def test_max_auto_tickets_is_bounded() -> None:
    assert MAX_AUTO_TICKETS >= 1
    assert MAX_AUTO_TICKETS <= 100
