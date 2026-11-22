"""What a PDF export may leave out, filter or add, and how a request says so.

The export dialog sends these as the JSON body of a POST to the PDF routes; a GET takes the same keys and values as
query parameters (``report_http.request_options``). Leaving every one out
gives today's report, unchanged: the default ``ReportOptions`` renders exactly what the
routes rendered before this module existed (pinned by ``tests/fixtures/pdf_default_text.json``
and the byte-identity tests of the CBOM run report and deliverables).

Families decide which options a route takes. A parameter its family does not take is refused
(422) rather than ignored, so a request never believes it filtered something it did not.

The constants block below is the single source the frontend mirrors
(``frontend/utils/reportOptions.ts``, parity-tested) and the info tips cite.

Free text (``prepared_for``, ``title``) is one line of Windows-1252 (drawn in Helvetica, as always) or of the scripts
in ``TEXT_RANGES`` (Latin Extended, Greek, Cyrillic, Devanagari; drawn with the vendored Noto fonts, ``report_fonts``).
"""

from __future__ import annotations

import unicodedata
from dataclasses import dataclass, field
from typing import Iterable, Mapping, Sequence

# --- constants (frontend parity: frontend/utils/reportOptions.ts) -------------------------------
FAMILIES = ("scan", "run", "deliverable", "pack")
PRESETS = ("executive", "technical", "full")
SEVERITIES = ("critical", "high", "medium", "low", "other")
STATUSES = ("not_started", "in_progress", "fixed", "ignored")
LABELS = ("confidential", "internal", "restricted", "public")
LABEL_TEXT = {"confidential": "Confidential", "internal": "Internal", "restricted": "Restricted", "public": ""}
SCAN_SECTIONS = ("summary", "catalog", "details", "remediation", "mappings", "compliance", "inventory", "notes")
RUN_SECTIONS = ("summary", "posture", "catalog", "provenance")
PRESET_SECTIONS = {
    "scan": {
        "executive": ("summary", "compliance"),
        "technical": ("summary", "catalog", "details", "remediation", "mappings", "notes"),
        "full": SCAN_SECTIONS,
    },
    "run": {
        "executive": ("summary", "posture"),
        "technical": ("summary", "catalog"),
        "full": RUN_SECTIONS,
    },
}
# Sections each scan type actually has (the dialog shows only these; the rest are ignored).
TYPE_SECTIONS = {
    "sast": ("summary", "catalog", "details", "remediation", "mappings", "notes"),
    "iac": ("summary", "catalog", "details", "remediation", "mappings"),
    "dast": ("summary", "catalog", "details", "remediation", "mappings"),
    "mcp": ("summary", "catalog", "details", "remediation", "mappings", "notes"),
    "llm": ("summary", "catalog", "details", "remediation", "mappings"),
    "sbom_sca": ("summary", "catalog", "details", "remediation", "mappings", "compliance", "inventory"),
    "ai_bom": ("summary", "catalog", "details", "remediation", "mappings", "compliance"),
    "cbom": ("summary", "catalog", "details", "remediation", "mappings", "compliance", "notes"),
}
FAMILY_KEYS = {
    "scan": ("preset", "sections", "severities", "statuses", "prepared_for", "title", "label", "hide_evidence"),
    "run": ("preset", "sections", "severities", "prepared_for", "title", "label"),
    "deliverable": ("prepared_for", "label"),
    "pack": (),
}
PREPARED_FOR_MAX = 120
TITLE_MAX = 140
# Beyond Windows-1252 (drawn in Helvetica, as before), the code points free text may use, inclusive ranges. Each is
# drawn with a vendored Noto font that has a glyph for every one of them (report_fonts.py; test_report_fonts.py
# checks the coverage): Noto Sans for Latin, Greek and Cyrillic, Noto Sans Devanagari (shaped) for Hindi and Marathi.
TEXT_RANGES = (
    # Latin Extended-A and -B, combining diacritical marks
    (0x0100, 0x024F),
    (0x0300, 0x036F),
    # Greek (Coptic letters excluded: no glyphs)
    (0x0370, 0x0377),
    (0x037A, 0x037F),
    (0x0384, 0x038A),
    (0x038C, 0x038C),
    (0x038E, 0x03A1),
    (0x03A3, 0x03E1),
    (0x03F0, 0x03FF),
    # Cyrillic and Cyrillic Supplement
    (0x0400, 0x052F),
    # Devanagari
    (0x0900, 0x097F),
    # Latin Extended Additional (Vietnamese and others)
    (0x1E00, 0x1EFF),
    # zero-width non-joiner and joiner: they choose a Devanagari conjunct's form (Marathi eyelash ra)
    (0x200C, 0x200D),
    # Indian rupee sign
    (0x20B9, 0x20B9),
    # Devanagari Extended
    (0xA8E0, 0xA8FF),
)
# What Python's str.strip() removes from both ends of free text (every str.isspace() code point; U+FEFF is not one:
# it is a format character, refused). The browser trims exactly this set, not String.prototype.trim()'s.
STRIP_RANGES = (
    (0x0009, 0x000D),
    (0x001C, 0x0020),
    (0x0085, 0x0085),
    (0x00A0, 0x00A0),
    (0x1680, 0x1680),
    (0x2000, 0x200A),
    (0x2028, 0x2029),
    (0x202F, 0x202F),
    (0x205F, 0x205F),
    (0x3000, 0x3000),
)
# --- end constants ------------------------------------------------------------------------------

ALL_KEYS = ("preset", "sections", "severities", "statuses", "prepared_for", "title", "label", "hide_evidence")


class ReportOptionsError(ValueError):
    """A request's report options are not valid; ``field`` names the parameter."""

    def __init__(self, field_name: str, message: str) -> None:
        super().__init__(f"{field_name}: {message}")
        self.field = field_name
        self.message = message


@dataclass(frozen=True)
class ReportOptions:
    family: str = "scan"
    preset: str | None = None
    sections: frozenset[str] | None = None  # None: every section (today's report)
    severities: frozenset[str] | None = None  # None: no severity filter
    statuses: frozenset[str] | None = None  # None: no status filter (Mongo is never read)
    prepared_for: str | None = None
    title: str | None = None
    label: str = "confidential"
    hide_evidence: bool = False
    _explicit_sections: bool = field(default=False, repr=False, compare=False)

    # -- questions the renderers ask --------------------------------------------------------------
    def has(self, section: str) -> bool:
        return self.sections is None or section in self.sections

    @property
    def filtered(self) -> bool:
        """A filter hides findings (severity or status)."""
        return self.severities is not None or self.statuses is not None

    @property
    def is_default(self) -> bool:
        return (self.preset is None and self.sections is None and not self.filtered
                and self.prepared_for is None and self.title is None
                and self.label == "confidential" and not self.hide_evidence)

    @property
    def shapes_content(self) -> bool:
        """Something other than the cover changed what the report contains."""
        return self.sections is not None or self.filtered or self.hide_evidence

    @property
    def label_text(self) -> str:
        return LABEL_TEXT[self.label]

    def omitted_sections(self, available: Sequence[str]) -> list[str]:
        if self.sections is None:
            return []
        return [s for s in available if s not in self.sections]

    def log_fields(self) -> dict:
        """Enums, flags and numbers only: never the free text (it can name a client)."""
        return {
            "preset": self.preset or "-",
            "sections": ",".join(sorted(self.sections)) if self.sections is not None else "all",
            "severities": ",".join(s for s in SEVERITIES if s in self.severities) if self.severities is not None else "all",
            "statuses": ",".join(s for s in STATUSES if s in self.statuses) if self.statuses is not None else "all",
            "label": self.label,
            "hide_evidence": int(self.hide_evidence),
            "prepared_for_set": int(self.prepared_for is not None),
            "title_set": int(self.title is not None),
        }


DEFAULT = ReportOptions()


def severity_bucket(label: str) -> str:
    """Map a ``count_label`` result (the KPI buckets) to a filter bucket."""
    key = (label or "").strip().lower()
    return key if key in ("critical", "high", "medium", "low") else "other"


def _csv(field_name: str, raw: str, allowed: Sequence[str]) -> frozenset[str]:
    items = [p.strip().lower() for p in raw.split(",")]
    if not raw.strip() or any(not p for p in items):
        raise ReportOptionsError(field_name, "must list at least one value, separated by commas")
    unknown = sorted({p for p in items if p not in allowed})
    if unknown:
        raise ReportOptionsError(field_name, f"unknown value {unknown[0]!r}; allowed: {', '.join(allowed)}")
    return frozenset(items)


_JOINERS = frozenset("\u200c\u200d")  # format characters (Cf) that are part of Devanagari spelling
# combining marks (a Devanagari vowel sign, an accent): after no letter they would print on a dotted circle
_MARKS = ("Mn", "Mc", "Me")


def is_cp1252(text: str) -> bool:
    """Helvetica (WinAnsi) draws it: the report's own font, so the PDF is what it was before other scripts."""
    try:
        text.encode("cp1252")
    except UnicodeEncodeError:
        return False
    return True


def _in_ranges(ch: str) -> bool:
    code = ord(ch)
    return any(low <= code <= high for low, high in TEXT_RANGES)


def text_supported(text: str) -> bool:
    """Every character is Windows-1252 or in ``TEXT_RANGES``: the report fonts draw all of it."""
    return all(is_cp1252(ch) or _in_ranges(ch) for ch in text)


def _text(field_name: str, raw: str, limit: int) -> str | None:
    text = unicodedata.normalize("NFC", raw).strip()
    if not text:
        return None
    if len(text) > limit:
        raise ReportOptionsError(field_name, f"must be {limit} characters or fewer")
    for ch in text:
        if unicodedata.category(ch) in ("Cc", "Cf", "Zl", "Zp") and ch not in _JOINERS:
            raise ReportOptionsError(field_name, "must be one line of plain text")
    if not text_supported(text):
        raise ReportOptionsError(field_name, "can only use Latin, Greek, Cyrillic or Devanagari characters")
    previous = ""
    for ch in text:
        if unicodedata.category(ch) in _MARKS and not (previous and unicodedata.category(previous)[0] in "LM"):
            raise ReportOptionsError(field_name, "has a vowel sign or accent that follows no letter")
        previous = ch
    return text


def _items(params: Mapping[str, str] | Iterable[tuple[str, str]]) -> list[tuple[str, str]]:
    if hasattr(params, "multi_items"):  # starlette QueryParams keeps repeats
        return list(params.multi_items())
    if isinstance(params, Mapping):
        return list(params.items())
    return list(params)


def parse_report_options(params, family: str, *, scan_type: str | None = None,
                         ignore: Iterable[str] = ()) -> ReportOptions:
    """Read report options from query parameters for one family. Raises ``ReportOptionsError``.

    Keys outside ``ALL_KEYS`` (and outside ``ignore``) are left to the route; a report key the
    family does not take, or any key given twice, is refused.
    """
    if family not in FAMILY_KEYS:
        raise ValueError(f"unknown report family {family!r}")
    allowed = FAMILY_KEYS[family]
    seen: dict[str, str] = {}
    for key, value in _items(params):
        if key in ignore or key not in ALL_KEYS:
            continue
        if key not in allowed:
            raise ReportOptionsError(key, "is not available for this report")
        if key in seen:
            raise ReportOptionsError(key, "was given more than once")
        seen[key] = value

    preset = None
    if "preset" in seen:
        preset = seen["preset"].strip().lower()
        if preset not in PRESETS:
            raise ReportOptionsError("preset", f"unknown value {preset!r}; allowed: {', '.join(PRESETS)}")

    family_sections = SCAN_SECTIONS if family == "scan" else RUN_SECTIONS
    available = family_sections
    if family == "scan" and scan_type in TYPE_SECTIONS:
        available = TYPE_SECTIONS[scan_type]
    sections = None
    explicit = False
    if "sections" in seen:
        chosen = _csv("sections", seen["sections"], family_sections)
        explicit = True
    elif preset is not None and preset != "full":
        chosen = frozenset(PRESET_SECTIONS[family][preset])
    else:
        chosen = None
    if chosen is not None:
        kept = frozenset(s for s in available if s in chosen)
        if not kept:
            raise ReportOptionsError("sections", "leave nothing this report has; choose at least one of "
                                     + ", ".join(available))
        sections = None if kept == frozenset(available) else kept

    severities = None
    if "severities" in seen:
        chosen = _csv("severities", seen["severities"], SEVERITIES)
        severities = None if chosen == frozenset(SEVERITIES) else chosen

    statuses = None
    if "statuses" in seen:
        chosen = _csv("statuses", seen["statuses"], STATUSES)
        statuses = None if chosen == frozenset(STATUSES) else chosen

    label = "confidential"
    if "label" in seen:
        label = seen["label"].strip().lower()
        if label not in LABELS:
            raise ReportOptionsError("label", f"unknown value {label!r}; allowed: {', '.join(LABELS)}")

    hide = False
    if "hide_evidence" in seen:
        raw = seen["hide_evidence"].strip().lower()
        if raw not in ("true", "false"):
            raise ReportOptionsError("hide_evidence", "must be true or false")
        hide = raw == "true"

    prepared = _text("prepared_for", seen["prepared_for"], PREPARED_FOR_MAX) if "prepared_for" in seen else None
    title = _text("title", seen["title"], TITLE_MAX) if "title" in seen else None

    return ReportOptions(family=family, preset=preset, sections=sections, severities=severities,
                         statuses=statuses, prepared_for=prepared, title=title, label=label,
                         hide_evidence=hide, _explicit_sections=explicit)
