"""One set of numbers for a CBOM: finding counts, severities, average risk and quantum readiness.

Every view of a CBOM (the scan dashboard, the scan list, the multi-scan dashboard, the scan PDF, the team roll-up
and its roadmap PDF, the scan-node posture) used to count on its own, so a clean AES-GCM row was a Low finding in one
place and nothing in another, and the readiness percentage had four slightly different definitions. They all call
this module now. Pure functions, no database.

* A row is a FINDING or clean INVENTORY by ``cbom_rows.is_finding`` (one read-time rule; stored scans are never
  rewritten). Severity counts, the average risk, the top risks and tickets are over findings only. Inventory
  distributions (algorithm type, strength, quantum verdicts) stay over every row: a CBOM lists everything.
* A finding without a recognised impact counts as Low (legacy rows); inventory has no severity and is shown as
  ``INFORMATIONAL_LABEL``.
* Quantum readiness: see ``quantum_readiness_pct``.
"""
from __future__ import annotations

from collections import defaultdict
from typing import Any, Iterable

from backend.utilities.cbom_sources.cbom_rows import display_row, is_finding

SEVERITIES = ("critical", "high", "medium", "low")
INFORMATIONAL = "informational"
INFORMATIONAL_LABEL = "Informational / Inventory"
# The app-wide 0-10 CBOM scale (dashboards, list page, PDF): one map, so the averages agree.
IMPACT_RISK = {"critical": 9.0, "high": 7.0, "medium": 5.0, "low": 2.0}


def quantum_readiness_pct(vulnerable: int, judged: int) -> float | None:
    """Quantum readiness: the share (in %) of JUDGED assets that are not quantum-vulnerable.

    * judged = assets with a quantum verdict. Unknown verdicts (hashes, settings, inventory with no public-key
      algorithm, rows the engine could not grade) are excluded from both numerator and denominator;
    * ready = judged minus quantum-vulnerable. Hybrid (a post-quantum key exchange next to the classical one) and
      post-quantum assets are ready; Grover-weakened assets (128-bit symmetric keys) are ready too: Grover halves
      their margin, it does not break them;
    * None when nothing was judged (no verdict is not 0 % and not 100 %).

    Rounded to one decimal. Used by the scan dashboard, the scan list, the scan PDF, the team roll-up (and its
    roadmap PDF) and the scan-node run posture.
    """
    vulnerable, judged = int(vulnerable or 0), int(judged or 0)
    if judged <= 0:
        return None
    return round(100.0 * (judged - min(vulnerable, judged)) / judged, 1)


def code_row_quantum_vulnerable(row: dict[str, Any]) -> bool | None:
    """A code-scan row's quantum verdict: True (vulnerable), False (ready) or None (not judged).

    ``quantum_safe`` is the stored tri-state (certificates, keys and protocols keep None)."""
    qs = row.get("quantum_safe") if isinstance(row, dict) else None
    if qs is True:
        return False
    if qs is False:
        return True
    return None


def finding_severity(row: dict[str, Any]) -> str | None:
    """Lower-case severity of a finding row, or None for clean inventory."""
    if not is_finding(row):
        return None
    impact = str(row.get("impact") or "").strip().lower()
    return impact if impact in IMPACT_RISK else "low"


def average_risk(severity: dict[str, int]) -> float:
    """Average 0-10 risk over findings (inventory excluded), one decimal."""
    total = sum(int(severity.get(s, 0) or 0) for s in SEVERITIES)
    if total <= 0:
        return 0.0
    weighted = sum(int(severity.get(s, 0) or 0) * IMPACT_RISK[s] for s in SEVERITIES) / total
    return round(min(10.0, max(0.0, weighted)) * 10) / 10


class CodeRowSummary:
    """Accumulates code-scan rows (one scan, or many for the scan-list dashboard)."""

    def __init__(self) -> None:
        self.rows = 0
        self.findings = 0
        self.severity = {s: 0 for s in SEVERITIES}
        self.algorithm_types: dict[str, int] = defaultdict(int)
        self.strengths = {"weak": 0, "moderate": 0, "strong": 0, "quantum_safe": 0}
        self.quantum = {"quantum_safe": 0, "quantum_vulnerable": 0}
        self.weak = 0
        self.certificates = 0
        self.keys = 0
        self.owasp: dict[str, int] = defaultdict(int)
        self.compliance: dict[str, int] = defaultdict(int)
        self.top_risks: list[dict[str, Any]] = []

    def add_rows(self, rows: Iterable[Any]) -> "CodeRowSummary":
        from backend.utilities.dashboard.bom_risk_score import cbom_finding_risk_score

        for raw in rows:
            if not isinstance(raw, dict):
                continue
            row = display_row(raw)  # old rows: library / configuration weaknesses count as weak
            self.rows += 1
            algo_type = row.get("algorithm_type") or "other"
            if str(algo_type).lower() in ("unknown", "none", "null", ""):
                algo_type = "other"
            self.algorithm_types[algo_type] += 1
            strength = row.get("crypto_strength") or "not-applicable"
            if str(strength).lower() in ("unknown", "none", "null", ""):
                strength = "not-applicable"
            if strength in self.strengths:
                self.strengths[strength] += 1
            if strength == "weak":
                self.weak += 1
            verdict = code_row_quantum_vulnerable(row)
            if verdict is False:
                self.quantum["quantum_safe"] += 1
            elif verdict is True:
                self.quantum["quantum_vulnerable"] += 1
            if algo_type == "certificate":
                self.certificates += 1
            elif algo_type in ("key", "secret"):
                self.keys += 1
            severity = finding_severity(row)
            if severity is None:
                continue  # clean inventory: listed above, never a finding
            self.findings += 1
            self.severity[severity] += 1
            for value in (row.get("owasp_top_10") or {}).values():
                self.owasp[value] += 1
            for value in (row.get("compliance_controls") or {}).values():
                self.compliance[value] += 1
            self.top_risks.append({
                "algorithm_name": row.get("algorithm_name", row.get("title", "Unknown")),
                "algorithm_type": algo_type,
                "crypto_strength": strength,
                "quantum_safe": row.get("quantum_safe", False),
                "impact": row.get("impact") or severity.capitalize(),
                "risk_score": cbom_finding_risk_score(row),
            })
        return self

    @property
    def informational(self) -> int:
        return self.rows - self.findings

    @property
    def readiness_pct(self) -> float | None:
        judged = self.quantum["quantum_safe"] + self.quantum["quantum_vulnerable"]
        return quantum_readiness_pct(self.quantum["quantum_vulnerable"], judged)

    @property
    def average_risk(self) -> float:
        return average_risk(self.severity)

    def severity_distribution(self) -> dict[str, int]:
        """Findings by severity, plus the inventory rows under ``informational`` (never in a severity)."""
        return {**self.severity, INFORMATIONAL: self.informational}

    def top(self, n: int = 10) -> list[dict[str, Any]]:
        return sorted(self.top_risks, key=lambda x: x["risk_score"], reverse=True)[:n]


def summarize_code_rows(rows: Iterable[Any]) -> CodeRowSummary:
    return CodeRowSummary().add_rows(rows)


def finding_rows(rows: Iterable[Any]) -> list[dict[str, Any]]:
    """The rows that are findings (Mongo read path, Jira candidates, PDF catalogue), in order."""
    return [r for r in rows if isinstance(r, dict) and is_finding(display_row(r))]


__all__ = [
    "CodeRowSummary", "IMPACT_RISK", "INFORMATIONAL", "INFORMATIONAL_LABEL", "SEVERITIES", "average_risk",
    "code_row_quantum_vulnerable", "finding_rows", "finding_severity", "quantum_readiness_pct", "summarize_code_rows",
]
