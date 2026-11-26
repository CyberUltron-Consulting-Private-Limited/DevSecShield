"""RBI FREE-AI / CSF compliance appendix for BOM PDF exports."""

from __future__ import annotations

from typing import Any

from reportlab.lib import colors
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import CondPageBreak, KeepTogether, Paragraph, Spacer, Table, TableStyle

from backend.utilities.dashboard.rbi_posture import build_rbi_csf_rollup


def _escape(s: Any) -> str:
    if not s:
        return ""
    return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _compliance_blob(payload: dict[str, Any]) -> dict[str, Any] | None:
    for key in ("ai_bom_compliance", "cbom_compliance", "sbom_compliance"):
        val = payload.get(key)
        if isinstance(val, dict) and val:
            return val
    return None


def _out_of_scope(fw: dict[str, Any]) -> bool:
    applicable = sum(int(fw.get(k) or 0) for k in ("pass", "pass_with_evidence", "fail", "not_bom_evidenceable"))
    return applicable == 0 and int(fw.get("out_of_scope") or 0) > 0


# The export routes put the team's regulatory profile here (``regulated_entity.team_profile``), so the CBOM
# compliance table lists the frameworks that bind the team, as D14 and every CBOM Sources page do (#485).
TEAM_PROFILE_KEY = "dss_team_regulatory_profile"


def _table(rows: list[list[Any]], widths: list[float], color: str) -> Table:
    table = Table(rows, colWidths=widths, repeatRows=1)  # the header row repeats when the table breaks a page
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor(color)),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
            ]
        )
    )
    return table


def _coverage(fw: dict[str, Any]) -> str:
    cov = fw.get("coverage")
    return "n/a" if cov is None else f"{round(float(cov) * 100)}%"


def _keep_heading(story: list, heading: Any, lead: list[Any], table: Table, rows: int) -> None:
    """The heading and its lead never sit alone at a page foot: kept with a short table, or with room for its first
    rows (a long table breaks after them and repeats its header row)."""
    if rows <= 14:
        story.append(KeepTogether([heading, *lead, table]))
    else:
        story.append(CondPageBreak(2.2 * inch))
        story.extend([heading, *lead, table])


def _append_cbom_frameworks(story: list, compliance: dict[str, Any], team: dict[str, Any] | None,
                            heading_style: ParagraphStyle, small_style: ParagraphStyle) -> None:
    """The CBOM's framework table (staging QA Q2-03): a heading that says what it is, readable framework names, and
    only the frameworks that bind the team (``regulated_entity.framework_binds``, the KB's applicability, as D14);
    the others are named below the table, never silently dropped."""
    from backend.utilities.cbom_sources.regulated_entity import DEFAULT_PROFILE, framework_binds
    from backend.utilities.pdf.cbom_deliverable_text import RBI_MAPPING_NOTE, framework_label

    profile = team if isinstance(team, dict) else DEFAULT_PROFILE
    pools = [(k, v) for k, v in compliance.items() if k != "disclaimer" and isinstance(v, dict)]
    binding = [(k, v) for k, v in pools if framework_binds(k, profile) and not _out_of_scope(v)]
    other = [framework_label(k) for k, v in pools if not framework_binds(k, profile)]
    heading = Paragraph("Regulatory and standards mapping (Advisory)", heading_style)
    lead = [Paragraph(_escape(compliance.get("disclaimer") or "Advisory mapping only; does not satisfy regulatory "
                                                                "obligations."), small_style)]
    lead.append(Paragraph(_escape(
        "Frameworks that apply to this team's regulatory profile; requirements that a code inventory cannot "
        "evidence are counted as not BOM-evidenceable."), small_style))
    if not binding:
        story.append(Spacer(1, 0.2 * inch))
        story.append(KeepTogether([heading, *lead, Paragraph("No framework of this report applies to the team's "
                                                             "regulatory profile.", small_style)]))
        return
    rows: list[list[Any]] = [["Framework", "Pass", "Fail", "Not BOM-evidenceable", "Coverage"]]
    for key, fw in binding:
        passed = int(fw.get("pass") or 0) + int(fw.get("pass_with_evidence") or 0)
        rows.append([_escape(framework_label(key)), str(passed), str(fw.get("fail", 0)),
                     str(fw.get("not_bom_evidenceable", 0)), _coverage(fw)])
    story.append(Spacer(1, 0.2 * inch))
    _keep_heading(story, heading, lead, _table(rows, [2.6 * 72, 0.6 * 72, 0.6 * 72, 1.5 * 72, 0.9 * 72], "#1E3A5F"),
                  len(rows))
    notes = []
    if any(k == "rbi_free_ai_protection" for k, _v in binding):
        notes.append(RBI_MAPPING_NOTE)
    if other:
        notes.append("Not applicable to this team's regulatory profile, so not listed: " + ", ".join(other) + ".")
    for note in notes:
        story.append(Paragraph(_escape(note), small_style))


def append_rbi_compliance_pdf_section(
    story: list,
    scan_payload: dict[str, Any],
    heading_style: ParagraphStyle,
    normal_style: ParagraphStyle,
    small_style: ParagraphStyle,
) -> None:
    """Append the framework table (and, where RBI applies, the RBI CSF pillar rollup) when compliance data is
    present."""
    compliance = _compliance_blob(scan_payload)
    if not compliance:
        return

    is_cbom = compliance is scan_payload.get("cbom_compliance")
    team = scan_payload.get(TEAM_PROFILE_KEY)
    rollup = scan_payload.get("rbi_csf_rollup")
    if not rollup and compliance:
        ai = scan_payload.get("ai_bom_compliance")
        cb = scan_payload.get("cbom_compliance")
        sb = scan_payload.get("sbom_compliance")
        rollup = build_rbi_csf_rollup(
            ai_bom_compliance=ai if isinstance(ai, dict) else None,
            cbom_compliance=cb if isinstance(cb, dict) else None,
            sbom_compliance=sb if isinstance(sb, dict) else None,
        )

    if is_cbom:
        _append_cbom_frameworks(story, compliance, team, heading_style, small_style)
        from backend.utilities.cbom_sources.regulated_entity import DEFAULT_PROFILE, framework_binds

        if not framework_binds("RBI", team if isinstance(team, dict) else DEFAULT_PROFILE):
            return  # the RBI pillar rollup only where RBI binds the team
    else:
        story.append(Spacer(1, 0.2 * inch))
        heading = Paragraph("RBI FREE-AI Compliance (Advisory)", heading_style)
        lead = [Paragraph(_escape((rollup or {}).get("disclaimer")
                                  or "Advisory mapping only; does not satisfy regulatory obligations."), small_style)]
        # A framework none of whose requirements applies (every one out of scope: the healthcare FDA / HIPAA / GMLP
        # checks on a bank's AI BOM) is not listed: a row of 0 / 0 / n/a reads as if it were assessed.
        frameworks = [
            (k, v)
            for k, v in compliance.items()
            if k != "disclaimer" and isinstance(v, dict) and not _out_of_scope(v)
        ]
        if frameworks:
            rows = [["Framework", "Pass", "Fail", "Coverage"]]
            for key, fw in frameworks:
                rows.append([_escape(key), str(fw.get("pass", 0)), str(fw.get("fail", 0)), _coverage(fw)])
            _keep_heading(story, heading, lead, _table(rows, [2.4 * 72, 0.8 * 72, 0.8 * 72, 1.0 * 72], "#1E3A5F"),
                          len(rows))
        else:
            story.append(KeepTogether([heading, *lead]))

    pillars = (rollup or {}).get("rbi_csf_rollup") if isinstance(rollup, dict) else None
    if isinstance(pillars, dict) and pillars:
        story.append(Spacer(1, 0.15 * inch))
        pillar_heading = Paragraph("RBI CSF Pillar Rollup", heading_style)
        prow = [["Pillar", "Pass", "Fail", "Coverage"]]
        for pname, pdata in pillars.items():
            if not isinstance(pdata, dict):
                continue
            prow.append([_escape(str(pname).replace("_", " ").capitalize()), str(pdata.get("pass", 0)),
                         str(pdata.get("fail", 0)), _coverage(pdata)])
        ptable = _table(prow, [2.4 * 72, 0.8 * 72, 0.8 * 72, 1.0 * 72], "#14532D")
        story.append(KeepTogether([pillar_heading, ptable]))  # the heading never sits alone at a page foot
