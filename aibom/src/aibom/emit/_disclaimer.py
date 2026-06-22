"""The single advisory disclaimer string carried by EVERY emitted report.

CLAUDE.md hard rule: compliance mapping is advisory only; every report carries a
disclaimer. All three reporters (CycloneDX / SPDX / SARIF) import this one
string so the caveat can never be present in one format and missing in another.
"""

ADVISORY_DISCLAIMER = (
    "Regulatory mappings are advisory only; an AI BOM creates visibility, not "
    "assurance, and does not by itself satisfy FDA, EU AI Act, or HIPAA "
    "obligations. A qualified regulatory reviewer must sign off."
)

__all__ = ["ADVISORY_DISCLAIMER"]
