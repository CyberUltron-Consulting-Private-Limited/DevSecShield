"""One PDF build's options, logo and finding statuses, and the truthful scope line they imply.

Generators keep their own layout; they ask the context which sections to emit, which rows to
show (``select``) and what to say when something is left out. The default context renders
today's report exactly: every section, every row, no scope block, today's chrome.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, List, Optional, Sequence, Tuple, TypeVar

from backend.utilities.pdf.branding_input import NO_BRANDING, ReportBranding
from backend.utilities.pdf.report_options import (
    DEFAULT,
    LABEL_TEXT,
    SEVERITIES,
    STATUSES,
    ReportOptions,
    severity_bucket,
)

T = TypeVar("T")

SECTION_NAMES = {
    "summary": "summary",
    "catalog": "findings catalog",
    "details": "finding details",
    "remediation": "remediation",
    "mappings": "standards mappings",
    "compliance": "compliance appendix",
    "inventory": "package inventory",
    "notes": "scan notes",
    "posture": "posture tables",
    "provenance": "provenance",
}
STATUS_NAMES = {"not_started": "Not started", "in_progress": "In progress", "fixed": "Fixed", "ignored": "Ignored"}
SEVERITY_NAMES = {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low", "other": "Other"}


@dataclass
class ReportContext:
    options: ReportOptions = DEFAULT
    branding: ReportBranding = NO_BRANDING
    # Status of each stored finding row, in ``finding_rows.mongo_rows`` order; None = not read.
    row_statuses: Optional[List[str]] = None
    available_sections: Sequence[str] = ()
    # Filled by ``select``: what the report shows, for the scope block and response headers.
    total: int = 0
    shown: int = 0
    excluded_severity: dict = field(default_factory=dict)
    excluded_status: dict = field(default_factory=dict)
    shown_by_bucket: dict = field(default_factory=dict)
    _selected: bool = False

    # -- sections -------------------------------------------------------------------------------
    def has(self, section: str) -> bool:
        return self.options.has(section)

    @property
    def filtered(self) -> bool:
        return self.options.filtered

    @property
    def label_text(self) -> str:
        return LABEL_TEXT[self.options.label]

    # -- rows -----------------------------------------------------------------------------------
    def select(self, items: Sequence[T], severity_of: Callable[[T], str],
               status_index_of: Optional[Callable[[int, T], Optional[int]]] = None) -> List[Tuple[int, T]]:
        """``(original 1-based number, item)`` for every item the filters keep.

        ``severity_of`` returns a KPI label (``count_label``); ``status_index_of(i, item)``
        returns the item's index into ``row_statuses`` (default: its own position).
        """
        kept: List[Tuple[int, T]] = []
        sev_filter = self.options.severities
        status_filter = self.options.statuses
        for position, item in enumerate(items):
            if sev_filter is not None:
                bucket = severity_bucket(severity_of(item))
                if bucket not in sev_filter:
                    self.excluded_severity[bucket] = self.excluded_severity.get(bucket, 0) + 1
                    continue
            if status_filter is not None and self.row_statuses is not None:
                index = status_index_of(position, item) if status_index_of else position
                status = self.row_statuses[index] if index is not None and 0 <= index < len(self.row_statuses) else None
                status = status or "not_started"
                if status not in status_filter:
                    self.excluded_status[status] = self.excluded_status.get(status, 0) + 1
                    continue
            kept.append((position + 1, item))
            bucket = severity_bucket(severity_of(item))
            self.shown_by_bucket[bucket] = self.shown_by_bucket.get(bucket, 0) + 1
        self.total += len(items)
        self.shown += len(kept)
        self._selected = True
        return kept

    # -- copy -----------------------------------------------------------------------------------
    def empty_text(self, default: str) -> str:
        """What an empty list says: never "no findings were identified" when a filter hid them."""
        if self.filtered and self.total:
            return f"No findings match the selected filters ({self.total} in the full scan)."
        return default

    def scope_lines(self) -> List[str]:
        """The 'Report scope' block: every way this report differs from the full report."""
        opts = self.options
        if not opts.shapes_content:
            return []
        lines: List[str] = []
        if opts.preset:
            lines.append(f"Preset: {opts.preset.title()}")
        omitted = opts.omitted_sections(self.available_sections)
        if omitted:
            lines.append("Left out: " + ", ".join(SECTION_NAMES.get(s, s) for s in omitted))
        if opts.severities is not None:
            lines.append("Severities shown: " + ", ".join(SEVERITY_NAMES[s] for s in SEVERITIES if s in opts.severities))
        if opts.statuses is not None:
            shown = ", ".join(STATUS_NAMES[s] for s in STATUSES if s in opts.statuses)
            excluded = ", ".join(f"{n} {STATUS_NAMES.get(s, s)}" for s, n in sorted(self.excluded_status.items()))
            lines.append(f"Statuses shown: {shown}" + (f" (excluded: {excluded})" if excluded else ""))
        if opts.hide_evidence:
            lines.append("Code snippets hidden")
        if self.filtered and self._selected:
            lines.append(f"Showing {self.shown} of {self.total} findings")
        return lines

    def footer_suffix(self) -> str:
        return " · Filtered" if self.filtered else ""

    def log_fields(self) -> dict:
        fields = self.options.log_fields()
        fields.update(logo=self.branding.status, shown=self.shown, total=self.total)
        return fields


DEFAULT_CONTEXT_FACTORY = ReportContext


def context_or_default(ctx: Optional[ReportContext]) -> ReportContext:
    return ctx if ctx is not None else ReportContext()


def count_iter(items: Iterable[Any]) -> int:
    return sum(1 for _ in items)


def details_note(ctx: ReportContext, default: str) -> str:
    """The 'Each card includes ...' line, true to what the cards show."""
    if not ctx.options.shapes_content:
        return default
    parts = ["location", "description"]
    if not ctx.options.hide_evidence:
        parts.append("code evidence")
    if ctx.has("remediation"):
        parts.append("remediation")
    if ctx.has("mappings"):
        parts.append("standards mappings")
    return "Each card includes " + ", ".join(parts[:-1]) + f" and {parts[-1]}."


def join_parts(story: list, parts: list, page_break_factory) -> None:
    """Append the non-empty parts to ``story`` with a page break between them."""
    first = True
    for part in parts:
        if not part:
            continue
        if not first:
            story.append(page_break_factory())
        story.extend(part)
        first = False
