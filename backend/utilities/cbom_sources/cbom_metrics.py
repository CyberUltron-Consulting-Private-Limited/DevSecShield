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

    ``quantum_safe`` is the stored tri-state (certificates, keys and protocols keep None). A row the rule base could
    not identify (``crypto_strength`` "unknown") is not judged, also when an older engine stored it as quantum-safe:
    the rule is read-time, so stored scans need no rewrite (CB-18 HF-1, ST-C)."""
    qs = row.get("quantum_safe") if isinstance(row, dict) else None
    if qs is True and str(row.get("crypto_strength") or "").strip().lower() == "unknown":
        return None
    if code_row_broken_today(row):
        return False  # judged, and not quantum-vulnerable: the caller counts it as broken today
    if qs is True:
        return False
    if qs is False:
        return True
    return None


def code_row_broken_today(row: dict[str, Any]) -> bool:
    """Not broken by a quantum computer but already broken without one (MD5, SHA-1, DES, RC4, ECB ...).

    The results table's Quantum column calls these rows "Broken today", never "Safe" (frontend quantumFilter.ts
    ``isBrokenToday``): an algorithm that is broken today is not quantum-ready."""
    if not isinstance(row, dict) or str(row.get("crypto_strength") or "").strip().lower() != "weak":
        return False
    qs = row.get("quantum_safe")
    # rows stored before G-D3-6 say quantum_safe true; newer ones say false with quantum_vulnerable false (MD5 is not
    # safe on any computer) - a weak quantum-vulnerable row (RSA-1024) stays quantum-vulnerable
    return qs is True or (qs is False and row.get("quantum_vulnerable") is False)


def finding_severity(row: dict[str, Any]) -> str | None:
    """Lower-case severity of a finding row, or None for clean inventory."""
    if not is_finding(row):
        return None
    impact = str(row.get("impact") or "").strip().lower()
    return impact if impact in IMPACT_RISK else "low"


def risk_posture(severity: dict[str, int], unverified: dict[str, int] | None = None) -> dict[str, Any]:
    """The D3 risk score of a code scan from its findings by severity (staging QA Q2-01, Rule P): the engine's one
    posture function (``aibom/src/aibom/score/posture.py``, worst-severity cap; loaded by ``aibom_posture``), the same
    number, grade and words the engine stores in ``cbom_scores`` for these rows. The PDF headline, the PDF summary
    page, the scan dashboard's KPI and the API (``cbom_scores``) all read this."""
    from backend.utilities.pdf.aibom_posture import posture_risk

    counts = {s: int(severity.get(s, 0) or 0) for s in SEVERITIES}
    guessed = {s: int((unverified or {}).get(s, 0) or 0) for s in SEVERITIES}
    n = sum(guessed.values())
    # #505's rule (re-review 6066152368): unconfirmed settings stay out of the confirmed score; when they are the only
    # weak crypto, the score is their worst case, status "unverified", never a clean A
    headline, status = (guessed, "unverified") if n and not sum(counts.values()) else (counts, "scored")
    score, grade, label = posture_risk(headline["critical"], headline["high"], headline["medium"], headline["low"])
    band = label.split(" ")[0].lower()
    return {"risk_score": score, "risk_grade": grade, "risk_label": label,
            "risk_band": band, "severity_counts": counts,
            # the same number in the shape of the app-wide ``risk_posture`` object (risk_scale.posture_field, #505)
            "risk_posture": {"score": score, "grade": grade, "label": label, "band": band},
            "risk_posture_status": status,
            "risk_unverified": _unverified(counts, guessed) if n else None}


def _unverified(sure: dict[str, int], guessed: dict[str, int]) -> dict[str, Any]:
    """#505's ``risk_unverified``: how many unconfirmed settings, the worst severity one would have if read, the worst
    case (the confirmed and unconfirmed findings together: the lists' risk filter and sort read it) and the note."""
    from backend.utilities.pdf.aibom_posture import posture_risk

    n = sum(guessed.values())
    worst = next((s for s in SEVERITIES if guessed[s]), None)
    both = {s: sure[s] + guessed[s] for s in SEVERITIES}
    score, grade, label = posture_risk(both["critical"], both["high"], both["medium"], both["low"])
    note = f"unverified: {n} unconfirmed setting{'s' if n != 1 else ''}" + (
        f" (worst: {worst.capitalize()})" if worst else "")
    return {"count": n, "worst": worst, "note": note,
            "worst_case": {"score": score, "grade": grade, "label": label, "band": label.split(" ")[0].lower()}}


RISK_FIELDS = ("risk_score", "risk_grade", "risk_label", "risk_posture")
UNVERIFIED_KEY = "risk_unverified"
# finished CBOM Sources runs (a partial run finished with what it collected)
RUN_SCORED_STATUSES = frozenset({"done", "partial"})


def risk_fields(risk: dict[str, Any], *, judged: bool = True, incomplete: bool = False) -> dict[str, Any]:
    """The risk fields a list row or a card spreads, with ``risk_posture_status`` (#505's
    ``risk_scale.posture_field``): "scored" with the posture numbers, or, for a scan or run that did not succeed
    (pending, running, failed, cancelled), "not_scored" with every number null, shown "—" and never matched by the
    "Low (A)" filter (re-review 6064703319, 5)."""
    if not judged:
        return {**dict.fromkeys(RISK_FIELDS), "risk_posture_status": "not_scored", UNVERIFIED_KEY: None}
    if incomplete:
        # a partial Sources run finished without everything a score needs: "incomplete", never a grade (#505)
        return {**dict.fromkeys(RISK_FIELDS), "risk_posture_status": "incomplete", UNVERIFIED_KEY: None}
    return {**{k: risk[k] for k in RISK_FIELDS}, "risk_posture_status": risk.get("risk_posture_status", "scored"),
            UNVERIFIED_KEY: risk.get(UNVERIFIED_KEY)}


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
        # the findings the risk score counts: test, fixture and example code is listed but not scored (PR #500
        # review 6061095673: six test files must not move the grade from B to D)
        self.scored = {s: 0 for s in SEVERITIES}
        self.findings_in_test_code = 0
        # settings no crypto call is proven to read (re-review 6063599094): listed, Low, not scored
        self.findings_unconfirmed = 0
        # their severity if a crypto call were proven to read them (the engine's ``unverified_severity``): #505's
        # worst case
        self.unverified = {s: 0 for s in SEVERITIES}
        self.algorithm_types: dict[str, int] = defaultdict(int)
        self.strengths = {"weak": 0, "moderate": 0, "strong": 0, "quantum_safe": 0}
        # the results table's Quantum column: Quantum-safe / Broken today / Quantum-vulnerable (one rule)
        self.quantum = {"quantum_safe": 0, "quantum_vulnerable": 0, "broken_today": 0}
        self.weak = 0
        self.certificates = 0
        self.keys = 0
        self.owasp: dict[str, int] = defaultdict(int)
        self.compliance: dict[str, int] = defaultdict(int)
        self.top_risks: list[dict[str, Any]] = []

    def add_rows(self, rows: Iterable[Any], origin: dict[str, Any] | None = None) -> "CodeRowSummary":
        """``origin`` says where rows without their own ``origin`` came from (a code scan); each top risk carries it."""
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
            if verdict is False and code_row_broken_today(row):
                self.quantum["broken_today"] += 1
            elif verdict is False:
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
            if row.get("code_context") == "test":
                self.findings_in_test_code += 1
            elif row.get("config_status") == "unconfirmed":
                self.findings_unconfirmed += 1
                worst = str(row.get("unverified_severity") or "").strip().lower()
                self.unverified[worst if worst in self.unverified else severity] += 1
            else:
                self.scored[severity] += 1
            for value in (row.get("owasp_top_10") or {}).values():
                self.owasp[value] += 1
            for value in (row.get("compliance_controls") or {}).values():
                self.compliance[value] += 1
            self.top_risks.append({
                "algorithm_name": row.get("algorithm_name", row.get("title", "Unknown")),
                "algorithm_type": algo_type,
                "crypto_strength": strength,
                "quantum_safe": row.get("quantum_safe", False),
                # the engine's verdict: MD5 stored as quantum_safe false + this false is "Broken today" (G-D3-6)
                "quantum_vulnerable": row.get("quantum_vulnerable"),
                "impact": row.get("impact") or severity.capitalize(),
                "risk_score": cbom_finding_risk_score(row),
                "origin": row.get("origin") or origin,
            })
        return self

    @property
    def informational(self) -> int:
        return self.rows - self.findings

    @property
    def crypto_assets(self) -> int:
        """The "Crypto assets" card of every CBOM view: the rows of the inventory table (findings + informational).

        Not ``len(cbom_json.components)``: the CycloneDX file also lists the crypto libraries every asset's file
        imports (clean ones too) and, for an uploaded CBOM, components that are not crypto at all, so that count
        disagreed with the severity totals beside it and with the scan list."""
        return self.rows

    @property
    def readiness_pct(self) -> float | None:
        """Quantum-safe rows over judged rows; a row that is broken today is judged and not ready."""
        not_ready = self.quantum["quantum_vulnerable"] + self.quantum["broken_today"]
        return quantum_readiness_pct(not_ready, self.quantum["quantum_safe"] + not_ready)

    @property
    def average_risk(self) -> float:
        return average_risk(self.severity)

    @property
    def risk(self) -> dict[str, Any]:
        """``risk_posture`` of these findings (test code excluded): the one D3 risk score."""
        return risk_posture(self.scored, self.unverified)

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
    "CodeRowSummary", "IMPACT_RISK", "INFORMATIONAL", "INFORMATIONAL_LABEL", "SEVERITIES", "average_risk", "risk_posture",
    "code_row_broken_today", "code_row_quantum_vulnerable", "finding_rows", "finding_severity", "quantum_readiness_pct", "summarize_code_rows",
]
