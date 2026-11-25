"""The AI BOM posture score and grade, from the engine's own module.

``aibom/src/aibom/score/posture.py`` holds the one formula, cap table and band words of the AI BOM risk score. It is
standard library only, so it is loaded here by file path (never imported as the ``aibom`` package, whose name a
repository folder may shadow): the engine's ``risk_band`` on the dashboard and the PDF grade say the same word for the
same score (review of #487 m2). The backend image carries the engine under ``/opt/aibom/src`` (backend/Dockerfile,
named build context ``aibom``); tests and local runs use the repository checkout.
"""
from __future__ import annotations

import importlib.util
import os
import threading
from pathlib import Path
from types import ModuleType
from typing import Any, Tuple

_LOCK = threading.Lock()
_MODULE: list[ModuleType] = []


def _candidates() -> list[Path]:
    roots = []
    if os.environ.get("CBOM_AIBOM_SRC"):
        roots.append(Path(os.environ["CBOM_AIBOM_SRC"]))
    roots.append(Path("/opt/aibom/src"))
    roots.append(Path(__file__).resolve().parents[3] / "aibom" / "src")
    return [r / "aibom" / "score" / "posture.py" for r in roots]


def engine_posture() -> ModuleType:
    """The engine's posture module, loaded once per process."""
    with _LOCK:
        if _MODULE:
            return _MODULE[0]
        for path in _candidates():
            if path.is_file():
                spec = importlib.util.spec_from_file_location("dss_aibom_posture", path)
                if spec is None or spec.loader is None:
                    continue
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                _MODULE.append(module)
                return module
        raise ImportError("aibom/src/aibom/score/posture.py not found (CBOM_AIBOM_SRC, /opt/aibom/src, repository)")


def posture_risk(critical: int, high: int, medium: int, low: int) -> Tuple[int, str, str]:
    """``(score, grade, label)``, e.g. ``(14, "A", "Low risk")`` for seven lows: the engine's function."""
    score, grade, label = engine_posture().posture_risk(critical, high, medium, low)
    return int(score), str(grade), str(label)


def current_scores(scores: Any, bom: Any = None) -> Any:
    """A stored AI BOM ``ai_bom_scores`` with its headline recomputed from its own ``severity_counts`` by the engine's
    posture function: a scan stored before a posture change shows on the page what the PDF and the API compute now
    (Rule P; review 6037909737 of #498, M5). Anything without four severity counts keeps its stored headline.

    A partial scan (the scores say so, or the stored BOM's metadata does) has its grade AND band withheld, so no
    surface reads "LOW" for a scan that did not finish (review 6063929550 of #498, R5-M2)."""
    if not isinstance(scores, dict):
        return scores
    out = dict(scores)
    counts = scores.get("severity_counts")
    keys = ("critical", "high", "medium", "low")
    if isinstance(counts, dict) and all(isinstance(counts.get(k), (int, float)) for k in keys):
        module = engine_posture()
        score = module.posture_score(*(int(counts[k]) for k in keys))
        grade, band = module.posture_grade(score)
        out.update(risk_normalized=float(score), risk_grade=grade, risk_band=band,
                   risk_label=module.posture_label(band))
    if is_partial(scores, bom):
        out.update(completeness="partial", risk_grade=GRADE_WITHHELD, risk_label=WITHHELD_LABEL,
                   risk_band=BAND_WITHHELD)
    return out


def is_partial(scores: Any = None, bom: Any = None) -> bool:
    """True when a scanner did not finish: the stored scores say ``completeness: partial`` or the BOM's metadata
    carries ``aibom:scan_completeness=partial`` / ``aibom:scanner_errors``."""
    if isinstance(scores, dict) and scores.get("completeness") == "partial":
        return True
    info = scan_completeness(bom)
    return bool(info and info.get("status") == "partial")


GRADE_WITHHELD = "—"
WITHHELD_LABEL = "Grade withheld: scan incomplete"
BAND_WITHHELD = "withheld"


def scan_completeness(bom: Any) -> dict | None:
    """``{status: "partial", scanner_errors, notebooks_unreadable}`` from an AI BOM's metadata properties when the
    scan did not read everything, else None (review 6063080163 of #498, R4-M2): the page, the PDF and the dashboard
    say so instead of presenting a complete inventory."""
    meta = bom.get("metadata") if isinstance(bom, dict) else None
    props = {str(p.get("name")): str(p.get("value")) for p in (meta or {}).get("properties") or []
             if isinstance(p, dict)}
    errors = props.get("aibom:scanner_errors")
    notebooks = props.get("aibom:notebooks_unreadable")
    partial = bool(errors) or props.get("aibom:scan_completeness") == "partial"
    if not partial and not notebooks:
        return None
    return {"status": "partial" if partial else "complete_with_warnings", "scanner_errors": errors,
            "notebooks_unreadable": notebooks}


#: customer-facing names of the engine's scanners (aibom/src/aibom/scan/scanners, ``name``): a report says "the
#: network/endpoint scanner did not finish", the exception class goes to a footnote (review 6063929550 of #498, nit)
SCANNER_LABELS = {
    "cloud-iac": "cloud infrastructure-as-code",
    "code-import": "AI library import",
    "docker": "container",
    "licence-coverage": "licence coverage",
    "live-cloud": "live cloud",
    "model-considerations": "model considerations",
    "model-file": "model file",
    "model-graph-link": "model linking",
    "model-ref": "model reference",
    "model-repo": "model repository",
    "net-env": "network/endpoint",
    "requirements": "dependency manifest",
    "secret": "secret",
    "unnamed-models": "unidentified model",
}


def scanners_not_finished(errors: Any) -> tuple[str, str]:
    """``("the network/endpoint scanner did not finish", "net-env: RuntimeError (unexpected)")`` from the BOM's
    ``aibom:scanner_errors``: a sentence for the customer and the technical detail for a footnote."""
    parts = [p.strip() for p in str(errors or "").split(";") if p.strip()]
    if not parts:
        return "", ""
    names = [SCANNER_LABELS.get(p.split(":", 1)[0].strip(), p.split(":", 1)[0].strip()) for p in parts]
    if len(names) == 1:
        sentence = f"the {names[0]} scanner did not finish"
    else:
        sentence = f"the {', '.join(names[:-1])} and {names[-1]} scanners did not finish"
    return sentence, "; ".join(parts)


def scan_data_partial(scan_data: Any) -> bool:
    """True when a stored AI BOM scan is partial, by its scores or its BOM's metadata: the scan list, the team
    dashboard and its tile mark it (review 6063929550 of #498, R5-M2)."""
    if not isinstance(scan_data, dict):
        return False
    return is_partial(scan_data.get("ai_bom_scores"), scan_data.get("ai_bom_json"))


def scan_succeeded(scan: Any) -> bool:
    """A stored scan row finished successfully, whatever the case of its ``scan_status`` (review 6065595627 of #498,
    m5: the team tile lowercased it, the list and the AI BOM dashboard compared it exactly)."""
    return str(getattr(scan, "scan_status", None) or "").lower() == "success"


def partial_ai_bom_scan(scan: Any) -> bool:
    """A successful AI BOM scan a scanner did not finish: the one rule the scan list, the team AI BOM dashboard and
    the team tile use."""
    return scan_succeeded(scan) and scan_data_partial(getattr(scan, "scan_data", None))


__all__ = ["current_scores", "engine_posture", "is_partial", "partial_ai_bom_scan", "posture_risk",
           "scan_completeness", "scan_data_partial", "scan_succeeded", "scanners_not_finished"]
