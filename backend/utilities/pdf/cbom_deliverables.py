"""Registry of the nine team-wide CBOM regulatory deliverables (WP4, plan 5.1 item 11).

``DELIVERABLES`` is the ONE place that knows which documents exist, in which order they are
offered and which function renders each of them.  Adding a seventh deliverable is one new
``cbom_*_pdf.py`` module plus one ``_spec(...)`` line below.  The router, the manifest and the
frontend menu (pinned by ``test_cbom_deliverables_contract.py``) all read this module and nothing
else, so they cannot disagree about a slug, a number or a title.

Everything here is pure: no database, no clock, no network.  Titles and descriptions come from
``REPORT_META`` so the manifest, the page header of the PDF and the menu share one wording.  The
two helpers the manifest route needs live here too, so they are testable without HTTP:

* ``summarize_heads`` turns the heads of a team's CBOM scans (every ``Scan`` column except the
  ``scan_data`` blob) into the counts the manifest shows.  It reads no blob, so it is cheap
  enough to run every time the CBOM landing page opens.
* ``build_manifest`` assembles the JSON document of ``GET /{team_id}/cbom/deliverables``.

``available`` in the manifest is a UI hint only.  The PDF route answers 200 for every slug and
every team, with a banner when there is nothing to show (plan 4.6).
"""
from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import date, datetime, timezone
from types import ModuleType
from typing import Any

from backend.utilities.dashboard.cbom_team_rollup import (
    STATUS_FAILURE,
    STATUS_SUCCESS,
    ScanHead,
    TeamCbomView,
    source_key_for,
)
from backend.utilities.pdf import (
    cbom_assurance_register_pdf,
    cbom_board_report_pdf,
    cbom_cert_register_pdf,
    cbom_data_at_rest_pdf,
    cbom_infra_posture_pdf,
    cbom_methodology_pdf,
    cbom_network_tls_pdf,
    cbom_pqc_roadmap_pdf,
    cbom_scope_register_pdf,
)
from backend.utilities.pdf.report_branding import REPORT_META

# Shown as the tooltip of a disabled menu item (documents that are empty without scans).
REASON_NO_SCANS = "No completed CBOM scans yet. Run a CBOM scan to populate this document."


@dataclass(frozen=True)
class DeliverableSpec:
    """One downloadable document."""

    slug: str  # URL segment and file-name stem, e.g. "certificate-estate-register"
    number: int  # position in the 16-item regulatory set; printed in the Document ID ("D07")
    title: str  # REPORT_META title, also the PDF title
    description: str  # REPORT_META intro, one sentence for the manifest
    report_key: str  # REPORT_META key: the page header and footer of the PDF
    build: Callable[[TeamCbomView], bytes]  # pure renderer: view -> PDF bytes
    # True when the document is meaningless without a completed scan (certificates, post-quantum
    # roadmap, board report).  The registers and the methodology still render their manual forms.
    data_dependent: bool = False


def _spec(
    slug: str, number: int, module: ModuleType, *, data_dependent: bool = False
) -> DeliverableSpec:
    meta = REPORT_META[module.REPORT_KEY]
    return DeliverableSpec(
        slug=slug,
        number=number,
        title=meta["title"],
        description=meta["intro"],
        report_key=module.REPORT_KEY,
        build=module.build_pdf,
        data_dependent=data_dependent,
    )


# Menu order: documents #1, #3, #5, #6, #7, #9, #10, #15, #16.
_SPECS = (
    _spec("scope-baseline-register", 1, cbom_scope_register_pdf),
    _spec("methodology-evidence-plan", 3, cbom_methodology_pdf),
    _spec(
        "infrastructure-cloud-encryption-posture",
        5,
        cbom_infra_posture_pdf,
        data_dependent=True,
    ),
    _spec(
        "network-tls-protocol-assessment",
        6,
        cbom_network_tls_pdf,
        data_dependent=True,
    ),
    _spec("certificate-estate-register", 7, cbom_cert_register_pdf, data_dependent=True),
    _spec(
        "data-at-rest-encryption-assessment",
        9,
        cbom_data_at_rest_pdf,
        data_dependent=True,
    ),
    _spec("third-party-assurance-register", 10, cbom_assurance_register_pdf),
    _spec("pqc-migration-roadmap", 15, cbom_pqc_roadmap_pdf, data_dependent=True),
    _spec("board-executive-report", 16, cbom_board_report_pdf, data_dependent=True),
)
DELIVERABLES: dict[str, DeliverableSpec] = {spec.slug: spec for spec in _SPECS}


def deliverable_filename(spec: DeliverableSpec, team_id: int, as_of: date) -> str:
    """``cbom-<slug>-team<id>-<YYYYMMDD>.pdf``; the frontend builds the same name (UTC date)."""
    return f"cbom-{spec.slug}-team{int(team_id)}-{as_of:%Y%m%d}.pdf"


# ---------------------------------------------------------------------------------------------
# Manifest
# ---------------------------------------------------------------------------------------------
@dataclass(frozen=True)
class HeadsSummary:
    """What the heads of a team's CBOM scans say, without reading any ``scan_data``."""

    scans_total: int  # every CBOM scan of the team
    eligible: int  # status == success (the only scans a document may read)
    sources: int  # distinct sources among the eligible scans (an upper bound, see below)
    failure: int  # status == failure
    not_completed: int  # pending / started / retry / NOT_STARTED / anything unknown


def summarize_heads(heads: Iterable[ScanHead], *, team_id: int) -> HeadsSummary:
    """Count a team's CBOM scans by status and its eligible scans by source.

    Mirrors the selection rules of ``fold_scans`` (plan 4.1) as far as heads allow: another
    team's or another type's head is ignored and a repeated scan id counts once.  A successful
    scan whose ``scan_data`` turns out to be empty is only discovered when the blob is read, so
    ``eligible`` and ``sources`` are upper bounds of what the documents will fold.
    """
    seen: set[Any] = set()
    sources: set[str] = set()
    total = eligible = failure = not_completed = 0
    for head in heads:
        if getattr(head, "team_id", None) != team_id:
            continue
        if str(getattr(head, "scan_type", "")).strip().casefold() != "cbom":
            continue
        scan_id = getattr(head, "id", None)
        if scan_id is not None:
            if scan_id in seen:
                continue
            seen.add(scan_id)
        total += 1
        raw_status = getattr(head, "status", None)
        status = ("" if raw_status is None else str(raw_status)).strip().casefold()
        if status == STATUS_SUCCESS:
            eligible += 1
            title = getattr(head, "title", None)
            key, _label, _kind = source_key_for(
                getattr(head, "scan_metadata", None),
                title if isinstance(title, str) else "",
                scan_id if isinstance(scan_id, int) else 0,
            )
            sources.add(key)
        elif status == STATUS_FAILURE:
            failure += 1
        else:
            not_completed += 1
    return HeadsSummary(
        scans_total=total,
        eligible=eligible,
        sources=len(sources),
        failure=failure,
        not_completed=not_completed,
    )


def _utc_stamp(moment: datetime) -> str:
    aware = moment.replace(tzinfo=timezone.utc) if moment.tzinfo is None else moment
    return aware.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def build_manifest(team_id: int, generated_at: datetime, summary: HeadsSummary) -> dict[str, Any]:
    """The JSON body of ``GET /{team_id}/cbom/deliverables`` (shape pinned by T-CON-1)."""
    empty = summary.eligible == 0
    items = []
    for spec in DELIVERABLES.values():
        unavailable = spec.data_dependent and empty
        items.append(
            {
                "slug": spec.slug,
                "number": spec.number,
                "title": spec.title,
                "description": spec.description,
                "format": "pdf",
                "available": not unavailable,
                "reason": REASON_NO_SCANS if unavailable else None,
            }
        )
    return {
        "team_id": int(team_id),
        "generated_at": _utc_stamp(generated_at),
        "basis": {
            "eligible": summary.eligible,
            "included_hint": summary.eligible,
            "sources": summary.sources,
            "excluded": {"failure": summary.failure, "not_completed": summary.not_completed},
        },
        "deliverables": items,
    }


__all__ = [
    "DELIVERABLES",
    "REASON_NO_SCANS",
    "DeliverableSpec",
    "HeadsSummary",
    "build_manifest",
    "deliverable_filename",
    "summarize_heads",
]
