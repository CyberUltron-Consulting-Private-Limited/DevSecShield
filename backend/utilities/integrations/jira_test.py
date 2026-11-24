"""Jira in Settings > Integrations (SOW S2): the connection test and the "Raise test ticket" action.

The connection is the team's Jira (``team.integration_settings["jira"]``: URL, account email, encrypted API token),
the one the code-scan and CBOM Sources tickets already use; the project and issue type are the CBOM Sources ticketing
settings (``cbomcollectionsettings.jira_project_key`` / ``jira_issue_type``).

* ``connection_test``: ``GET /rest/api/3/myself`` (the credentials work), then ``GET /rest/api/3/project/{key}`` when a
  project is set (the account can see it). Creates nothing.
* ``raise_test_ticket``: one clearly labelled issue ("[ZeroShield] Integration test ticket - safe to close", labels
  ``zs-test`` and ``zs-test-<hash of team and click>``). When a click is retried after an unknown outcome (a timeout,
  a lost answer) the label is searched first, so one click never makes two issues.

Every message is safe to show and to log: Jira's own error text or an HTTP status, never a response body, a URL with
credentials or the token. All calls go through ``jira.validate_jira_url`` (the SSRF rules of every integration).
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from urllib.parse import quote

import requests
from requests.auth import HTTPBasicAuth
from requests.exceptions import ConnectTimeout, RequestException, Timeout

from backend.utilities.integrations import jira as JIRA

TEST_LABEL = "zs-test"
SUMMARY = "[ZeroShield] Integration test ticket - safe to close"


@dataclass
class Result:
    status: str  # "ok" | "failed" | "uncertain" (the issue may exist: Jira timed out or failed after the request)
    message: str
    key: str | None = None
    url: str | None = None
    found: bool = False  # an issue of this click already existed (a retried click)


def click_label(team_id: int, click_id: str) -> str:
    return f"{TEST_LABEL}-" + hashlib.sha256(f"{team_id}|{click_id}".encode("utf-8")).hexdigest()[:16]


def browse_url(base: str, key: str) -> str:
    return f"{base.rstrip('/')}/browse/{quote(key, safe='-')}"


def _get(url: str, email: str, token: str) -> requests.Response:
    return requests.request("GET", url, headers={"Accept": "application/json"}, auth=HTTPBasicAuth(email, token),
                            timeout=JIRA.REQUEST_TIMEOUT, allow_redirects=False)


def connection_test(base: str, email: str, token: str, project: str | None) -> Result:
    """Signs in and, when a project is set, checks the account can see it. Creates nothing."""
    try:
        JIRA.validate_jira_url(base)
    except ValueError as exc:
        return Result("failed", str(exc)[:240])
    root = base.rstrip("/")
    try:
        me = _get(f"{root}/rest/api/3/myself", email, token)
        if me.status_code in (401, 403):
            return Result("failed", f"HTTP {me.status_code}: Jira refused the email and API token")
        if me.status_code != 200:
            return Result("failed", f"HTTP {me.status_code} signing in to Jira")
        if not project:
            return Result("ok", "HTTP 200: signed in to Jira. Set the CBOM project to raise tickets")
        seen = _get(f"{root}/rest/api/3/project/{quote(project, safe='')}", email, token)
    except (ConnectTimeout, Timeout):
        return Result("failed", "Jira did not answer in time")
    except RequestException as exc:
        return Result("failed", f"Jira could not be reached ({type(exc).__name__})")
    if seen.status_code == 200:
        return Result("ok", f"HTTP 200: signed in to Jira and can see project {project}")
    if seen.status_code == 404:
        return Result("failed", f"HTTP 404: project {project} does not exist or this account cannot see it")
    return Result("failed", f"HTTP {seen.status_code} reading project {project}")


def _description(team_id: int, click_id: str) -> str:
    return ("This ticket was raised by the \"Raise test ticket\" button in ZeroShield DevSecShield "
            "(Settings > Integrations) to prove that CBOM findings can be ticketed in this project. "
            f"It is not a finding. Team {team_id}, request {click_id}. Safe to close or delete.")


def raise_test_ticket(base: str, email: str, token: str, project: str, issue_type: str, team_id: int,
                      click_id: str, *, search_first: bool) -> Result:
    from backend.utilities.cbom_sources.run_tickets import project_ref

    label = click_label(team_id, click_id)
    try:
        if search_first:
            key = JIRA.find_issue_by_label(base, token, label, jira_email=email)
            if key:
                return Result("ok", f"already raised {key}", key=key, url=browse_url(base, key), found=True)
        answer = JIRA.create_issue_in_project(jira_url=base, jira_token=token, summary=SUMMARY,
                                              description=_description(team_id, click_id), jira_email=email,
                                              issue_type=issue_type, labels=[TEST_LABEL, label],
                                              **project_ref(project))
    except ValueError as exc:  # validate_jira_url
        return Result("failed", str(exc)[:240])
    except JIRA.JiraError as exc:
        status = "uncertain" if exc.kind in ("timeout", "http_5xx") else "failed"
        return Result(status, str(exc)[:240])
    key = (answer or {}).get("key") if isinstance(answer, dict) else None
    if not isinstance(key, str) or not key:
        return Result("uncertain", "Jira answered without an issue key")
    return Result("ok", f"created {key}", key=key, url=browse_url(base, key))
