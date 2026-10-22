"""The E2E world as data: plan Appendix B, written down once (standard library only).

``seed_team.py`` stores exactly what ``planned_scans()`` returns; ``oracle_check.py`` verifies exactly
what it returns.  So the thing the oracle checks is the thing the database receives.

Scan numbers (``PlannedScan.key``) are the Appendix-B numbers AND the database ids: the seed inserts
them with explicit ids and aborts when the database disagrees, because the PDFs print scan ids
("scan #4", "latest #2") and ``fixtures/expected.json`` quotes them.

Team 1 (``E2E Demo Team``)::

    1  payments-service #1     success      21 d  tree payments-service-v1           history of source A
    2  payments-service #2     success       7 d  tree payments-service-v2           CURRENT of source A
    3  identity-gateway        success      14 d  tree identity-gateway
    4  crypto-misuse-lab       success      10 d  tree crypto-misuse-lab
    5  pqc-pilot               success       5 d  tree pqc-pilot  (branch ``release``)
    6  cert-lifecycle-lab      success       3 d  tree cert-lifecycle-lab  (a ZIP upload, no URL)
    7  vendor-sdk-manifests    success       2 d  tree vendor-sdk-manifests  (0 rows, 18 libraries)
    8  legacy-billing          success      60 d  the committed Tier-B file (reduced fidelity)
    9  payments-service FAILED failure       1 d  canary payload; same source as #1/#2
    10 queued                  NOT_STARTED   0 d  canary payload
    11 running                 started       0 d  canary payload
    12 sbom noise              sbom_sca      4 d  canary payload (a different scan type)
    13 success-but-empty       success       4 d  scan_data == {}
    Team 2 (``Other Team``):  14 other-team scan, success, 3 d, tree other-team-app (canary cert)
    Team 3 (``Empty Team``):  no scans
    Team 4 (``Perf Team``):   optional, built by seed_team.py when E2E_SEED_PERF is set

Hostile spellings are deliberate: they must collapse to the Appendix-B source keys and must never
reach a PDF - mixed-case host with ``.git`` (scan 1), a trailing ``/`` (scan 9) and a credentials
section in the URL (scan 8).  The ``NOT-A-REAL-TOKEN-CANARY`` token is a fixed fake, never a secret.
"""

from __future__ import annotations

import copy
from datetime import datetime, timedelta
from typing import Any, NamedTuple

REPO = "https://github.com/e2e-demo/"
LEGACY_URL = "https://x-access-token:NOT-A-REAL-TOKEN-CANARY@github.com/e2e-demo/legacy-billing.git"

TEAM_DEMO, TEAM_OTHER, TEAM_EMPTY, TEAM_PERF = 1, 2, 3, 4
TEAM_NAMES = {
    TEAM_DEMO: "E2E Demo Team",
    TEAM_OTHER: "Other Team",
    TEAM_EMPTY: "Empty Team",
    TEAM_PERF: "Perf Team",
}

# persona -> (database user id, env key prefix, first name, last name, default team, [(team, role)])
PERSONAS: dict[str, dict[str, Any]] = {
    "admin": {"id": 1, "env": "E2E_ADMIN", "first": "E2E", "last": "Admin", "default_team": TEAM_DEMO,
              "teams": [(TEAM_DEMO, "admin")]},
    "other": {"id": 2, "env": "E2E_OTHER", "first": "E2E", "last": "Other", "default_team": TEAM_OTHER,
              "teams": [(TEAM_OTHER, "admin")]},
    "empty": {"id": 3, "env": "E2E_EMPTY", "first": "E2E", "last": "Empty", "default_team": TEAM_EMPTY,
              "teams": [(TEAM_EMPTY, "admin")]},
}  # fmt: skip

# Trees (directories under .work/trees) the aibom-scan container must have produced.
TREES = (
    "payments-service-v1",
    "payments-service-v2",
    "identity-gateway",
    "crypto-misuse-lab",
    "pqc-pilot",
    "cert-lifecycle-lab",
    "vendor-sdk-manifests",
    "other-team-app",
)


class PlannedScan(NamedTuple):
    key: int  # Appendix-B number == database id
    team: int
    scan_type: str
    title: str
    status: str  # raw DB value
    age_days: int
    meta: dict[str, Any]  # scan_metadata, shaped like backend/utilities/db/metadata.py (cbom)
    payload: tuple[Any, ...]  # ("tree", name) | ("legacy",) | ("raw", scan_data)


def repo_meta(url: str, branch: str = "main") -> dict[str, Any]:
    return {
        "zip_file_used": False,
        "repo_url": url,
        "repo_type": "github",
        "branch": branch,
        "cbom_file_used": False,
        "scan_binaries": False,
    }


def zip_meta() -> dict[str, Any]:
    return {
        "zip_file_used": True,
        "repo_url": None,
        "repo_type": None,
        "branch": None,
        "cbom_file_used": False,
        "scan_binaries": False,
    }


def canary(title: str) -> tuple[str, dict[str, Any]]:
    return "raw", {"results": [{"title": title}]}


SBOM_NOISE: dict[str, Any] = {
    "results": [{"title": "SBOM-TYPE-CANARY", "asset_type": "algorithm", "impact": "Critical"}]
}

SEED: tuple[PlannedScan, ...] = (
    PlannedScan(1, TEAM_DEMO, "cbom", "payments-service #1", "success", 21,
                repo_meta("https://github.com/E2E-Demo/payments-service.git"),
                ("tree", "payments-service-v1")),
    PlannedScan(2, TEAM_DEMO, "cbom", "payments-service #2", "success", 7,
                repo_meta(REPO + "payments-service"), ("tree", "payments-service-v2")),
    PlannedScan(3, TEAM_DEMO, "cbom", "identity-gateway", "success", 14,
                repo_meta(REPO + "identity-gateway"), ("tree", "identity-gateway")),
    PlannedScan(4, TEAM_DEMO, "cbom", "crypto-misuse-lab", "success", 10,
                repo_meta(REPO + "crypto-misuse-lab"), ("tree", "crypto-misuse-lab")),
    PlannedScan(5, TEAM_DEMO, "cbom", "pqc-pilot", "success", 5,
                repo_meta(REPO + "pqc-pilot", "release"), ("tree", "pqc-pilot")),
    PlannedScan(6, TEAM_DEMO, "cbom", "cert-lifecycle-lab", "success", 3,
                zip_meta(), ("tree", "cert-lifecycle-lab")),
    PlannedScan(7, TEAM_DEMO, "cbom", "vendor-sdk-manifests", "success", 2,
                repo_meta(REPO + "vendor-sdk-manifests"), ("tree", "vendor-sdk-manifests")),
    PlannedScan(8, TEAM_DEMO, "cbom", "legacy-billing", "success", 60,
                repo_meta(LEGACY_URL), ("legacy",)),
    PlannedScan(9, TEAM_DEMO, "cbom", "payments-service (FAILED)", "failure", 1,
                repo_meta(REPO + "payments-service/"), canary("FAILED-SCAN-CANARY")),
    PlannedScan(10, TEAM_DEMO, "cbom", "queued", "NOT_STARTED", 0,
                repo_meta(REPO + "queued"), canary("QUEUED-SCAN-CANARY")),
    PlannedScan(11, TEAM_DEMO, "cbom", "running", "started", 0,
                repo_meta(REPO + "running"), canary("RUNNING-SCAN-CANARY")),
    PlannedScan(12, TEAM_DEMO, "sbom_sca", "sbom noise", "success", 4,
                repo_meta(REPO + "sbom-noise"), ("raw", SBOM_NOISE)),
    PlannedScan(13, TEAM_DEMO, "cbom", "success-but-empty", "success", 4,
                repo_meta(REPO + "empty"), ("raw", {})),
    PlannedScan(14, TEAM_OTHER, "cbom", "other-team scan", "success", 3,
                repo_meta("https://github.com/other-org/other-team-canary-repo"),
                ("tree", "other-team-app")),
)  # fmt: skip

# Minutes between created_at and last_updated, by status (mirrors a real scan's life cycle).
LAG_MINUTES = {"success": 2, "failure": 2, "started": 1, "NOT_STARTED": 0}

# Strings that exist ONLY in scans (or URLs) that team-1 documents must never read or print.
CANARIES = (
    "FAILED-SCAN-CANARY",
    "QUEUED-SCAN-CANARY",
    "RUNNING-SCAN-CANARY",
    "SBOM-TYPE-CANARY",
    "other-team-canary",
    "NOT-A-REAL-TOKEN-CANARY",
    "x-access-token",
)


def iso_z(moment: datetime) -> str:
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def planned_scans(
    now: datetime,
    runs: dict[str, dict[str, Any]],
    legacy: dict[str, Any],
) -> list[dict[str, Any]]:
    """The scans to insert, in database-id order, as plain dicts.

    ``now`` is timezone-aware UTC; ``runs`` maps tree name -> run-object (``scan_trees.py`` output);
    ``legacy`` is the committed Tier-B run-object.  Every value is deep-copied so callers may mutate
    the result freely.
    """
    scans: list[dict[str, Any]] = []
    for item in SEED:
        kind = item.payload[0]
        if kind == "tree":
            scan_data: Any = runs[item.payload[1]]
        elif kind == "legacy":
            scan_data = legacy
        else:
            scan_data = item.payload[1]
        created = now - timedelta(days=item.age_days)
        scans.append(
            {
                "id": item.key,
                "team_id": item.team,
                "scan_type": item.scan_type,
                "title": item.title,
                "status": item.status,
                "age_days": item.age_days,
                "created_at": iso_z(created),
                "last_updated": iso_z(created + timedelta(minutes=LAG_MINUTES[item.status])),
                "scan_metadata": copy.deepcopy(item.meta),
                "scan_data": copy.deepcopy(scan_data),
            }
        )
    return scans
