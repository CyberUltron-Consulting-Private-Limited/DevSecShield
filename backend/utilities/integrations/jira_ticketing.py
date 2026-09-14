"""Per-finding Jira auto-create and close-on-fixed helpers."""
from __future__ import annotations

from typing import Any

from rich.console import Console
from sqlalchemy.engine import Engine
from sqlmodel import Session, select

from backend.new_models import Scan, Team
from backend.utilities.db.encryption import decrypt_if_encrypted
from backend.utilities.integrations.jira import (
    create_issue_in_project,
    list_issue_transitions,
    transition_issue,
)

console = Console(markup=False)

MAX_AUTO_TICKETS = 50
_SUMMARY_MAX = 255
_DONE_TRANSITION_NAMES = {
    "done",
    "complete",
    "completed",
    "close",
    "closed",
    "resolve",
    "resolved",
    "finish",
    "finished",
}


def auto_create_enabled(integration_settings: dict | None) -> bool:
    if not isinstance(integration_settings, dict):
        return False
    jira = integration_settings.get("jira") or {}
    if not isinstance(jira, dict):
        return False
    flag = jira.get("auto_create_tickets")
    return flag is True or flag == "true" or flag == 1


def extract_finding_summary(finding_data: dict | None) -> str:
    data = finding_data if isinstance(finding_data, dict) else {}
    for key in (
        "title",
        "vulnerability_title",
        "name",
        "check_id",
        "rule_id",
        "vulnerability_id",
        "message",
        "logical_component_title",
    ):
        value = data.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()[:_SUMMARY_MAX]
    return "Security finding"


def finding_ticket_description(scan_type: str, scan_id: int, finding: dict | None) -> str:
    data = finding if isinstance(finding, dict) else {}
    impact = (data.get("impact") or data.get("severity") or "").strip() or "—"
    url = (data.get("url") or data.get("file") or data.get("path") or "").strip() or "—"
    desc = (data.get("description") or data.get("message") or "").strip()
    if len(desc) > 1200:
        desc = desc[:1200] + "…"
    return (
        f"DevSecShield {scan_type} finding from scan {scan_id}.\n"
        f"Impact: {impact}\n"
        f"Location: {url}\n\n"
        f"{desc}"
    )


def pick_done_transition_id(transitions: list[dict] | None) -> str | None:
    items = transitions or []
    for item in items:
        to = item.get("to") or {}
        category = ((to.get("statusCategory") or {}).get("key") or "").lower()
        if category == "done":
            return str(item.get("id") or "") or None
    for item in items:
        name = (item.get("name") or "").strip().lower()
        if name in _DONE_TRANSITION_NAMES:
            return str(item.get("id") or "") or None
    return None


def _jira_creds(team: Team) -> tuple[str, str, str] | None:
    settings = (team.integration_settings or {}).get("jira") or {}
    if not isinstance(settings, dict):
        return None
    email = (settings.get("email") or "").strip()
    url = (settings.get("url") or "").rstrip("/")
    token = decrypt_if_encrypted(settings.get("api_token"))
    if not email or not url or not token:
        return None
    return email, token, url


def _project_id(scan_or_integration_settings: dict | None) -> str | None:
    if not isinstance(scan_or_integration_settings, dict):
        return None
    jira = scan_or_integration_settings.get("jira") or {}
    if not isinstance(jira, dict):
        return None
    project_id = jira.get("jira_project_id")
    if project_id is None:
        return None
    text = str(project_id).strip()
    return text or None


def close_jira_issue_for_finding(finding_doc: dict, team: Team) -> None:
    info = finding_doc.get("info") if isinstance(finding_doc.get("info"), dict) else {}
    issue_key = (info.get("jira_issue_key") or "").strip()
    if not issue_key:
        return
    creds = _jira_creds(team)
    if not creds:
        raise Exception("Jira credentials are missing; cannot close ticket")
    email, token, url = creds
    transitions = list_issue_transitions(url, token, issue_key, jira_email=email)
    transition_id = pick_done_transition_id(transitions)
    if not transition_id:
        raise Exception(f"No Done/Complete transition available for {issue_key}")
    transition_issue(url, token, issue_key, transition_id, jira_email=email)


def create_jira_issue_for_finding(
    *,
    team: Team,
    project_id: str,
    scan_type: str,
    scan_id: int,
    finding_data: dict | None,
) -> str:
    creds = _jira_creds(team)
    if not creds:
        raise Exception("Jira credentials are missing; cannot create ticket")
    email, token, url = creds
    summary = f"[{scan_type}] {extract_finding_summary(finding_data)}"[:_SUMMARY_MAX]
    description = finding_ticket_description(scan_type, scan_id, finding_data)
    created = create_issue_in_project(
        jira_url=url,
        jira_token=token,
        project_id=project_id,
        summary=summary,
        description=description,
        jira_email=email,
    )
    key = (created or {}).get("key")
    if not key:
        raise Exception("Jira did not return an issue key")
    return str(key)


def auto_create_tickets_for_successful_scan(scan_id: int, engine: Engine) -> int:
    """Create one Jira Task per finding when the scan opted in. Returns tickets created."""
    from backend.get_db import get_mongo_client_db

    mongo_db = get_mongo_client_db()
    created = 0
    with Session(engine) as session:
        scan = session.exec(select(Scan).where(Scan.id == scan_id)).first()
        if not scan or scan.scan_status != "success":
            return 0
        if not auto_create_enabled(scan.integration_settings):
            return 0
        project_id = _project_id(scan.integration_settings)
        team = session.exec(select(Team).where(Team.id == scan.team_id)).first()
        if not team or not project_id or not _jira_creds(team):
            console.print(f"Skipping auto-Jira for scan {scan_id}: project or team Jira creds missing", style="yellow")
            return 0
        scan_type = scan.scan_type
        findings = list(mongo_db["scan_findings"].find({"scan_id": scan_id}))
        for finding in findings:
            if created >= MAX_AUTO_TICKETS:
                console.print(
                    f"Auto-Jira cap {MAX_AUTO_TICKETS} reached for scan {scan_id}; remaining findings skipped",
                    style="yellow",
                )
                break
            info = finding.get("info") if isinstance(finding.get("info"), dict) else {}
            if (info.get("jira_issue_key") or "").strip():
                continue
            try:
                key = create_jira_issue_for_finding(
                    team=team,
                    project_id=project_id,
                    scan_type=scan_type,
                    scan_id=scan_id,
                    finding_data=finding.get("finding_data") if isinstance(finding.get("finding_data"), dict) else {},
                )
                mongo_db["scan_findings"].update_one(
                    {"_id": finding["_id"]},
                    {"$set": {"info": {**info, "jira_issue_key": key, "jira_project_id": project_id}}},
                )
                created += 1
            except Exception as exc:
                console.print(
                    f"Auto-Jira failed for finding {finding.get('_id')} on scan {scan_id}: {exc}",
                    style="red",
                )
    return created


def create_tickets_from_result_rows(
    *,
    team: Team,
    project_id: str,
    scan_type: str,
    scan_id: int | None,
    rows: list[dict],
) -> list[str]:
    """Used by zip CI/CD (no persisted Scan findings). One issue per row, capped."""
    keys: list[str] = []
    sid = scan_id or 0
    for row in rows[:MAX_AUTO_TICKETS]:
        if not isinstance(row, dict):
            continue
        try:
            keys.append(
                create_jira_issue_for_finding(
                    team=team,
                    project_id=project_id,
                    scan_type=scan_type,
                    scan_id=sid,
                    finding_data=row,
                )
            )
        except Exception as exc:
            console.print(f"CI auto-Jira failed for a result row: {exc}", style="red")
    return keys


def flatten_scan_result_rows(scan_type: str, results: Any) -> list[dict]:
    """Best-effort flatten of worker result payloads into finding-like dicts."""
    if not results:
        return []
    if scan_type == "sast":
        rows: list[dict] = []
        for item in (results.get("results") or []) if isinstance(results, dict) else []:
            if not isinstance(item, dict):
                continue
            title = item.get("logical_component_title")
            for vuln in item.get("vulnerabilities") or []:
                if isinstance(vuln, dict):
                    payload = dict(vuln)
                    if title:
                        payload.setdefault("logical_component_title", title)
                    rows.append(payload)
        return rows
    if scan_type in ("iac", "dast", "sbom_sca", "cbom", "ai_bom"):
        items = results.get("results") if isinstance(results, dict) else results
        return [x for x in (items or []) if isinstance(x, dict)]
    if scan_type == "llm":
        inner = (results.get("results") or {}) if isinstance(results, dict) else {}
        return [x for x in (inner.get("vulnerabilities") or []) if isinstance(x, dict)]
    if scan_type == "mcp":
        inner = (results.get("results") or {}) if isinstance(results, dict) else {}
        rows = []
        for group in ("tools", "prompts", "resources"):
            for item in inner.get(group) or []:
                if not isinstance(item, dict):
                    continue
                for vuln in item.get("vulnerabilities") or []:
                    if isinstance(vuln, dict):
                        rows.append(vuln)
        return rows
    if isinstance(results, list):
        return [x for x in results if isinstance(x, dict)]
    return []
