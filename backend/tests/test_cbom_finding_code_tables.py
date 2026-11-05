"""Every finding code the engine and the collectors emit has a label, a text and a severity in the backend tables.

The codes are enumerated from the sources that raise them, so a new code without its table entries fails here:

* the code-scan engine (aibom/src/aibom/cbom): ``NAME = "NAME"`` constants in every module (scanners included),
  ``add_flag("LITERAL", ...)`` calls and the posture catalogue ``POSTURE_CODES``;
* the server-side classifier that judges every collector's facts (classify.py and classify_ext/): literal
  ``out.add("CODE", ...)`` calls and the code tables it indexes (SSH, SCHANNEL, legacy TLS, PROTO_/MIN_ labels).

Tables checked: the knowledge base (title = label, description = text, default_impact = severity) for both
namespaces; the deliverable PDFs' labels and actions; the posture deliverables' code list, label, impact, anchor
and action; the team roll-up's posture severity map; the row-type and weakness tables of ``cbom_rows``.
"""
from __future__ import annotations

import ast
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend.utilities.cbom_sources import cbom_rows, classify  # noqa: E402
from backend.utilities.cbom_sources import crypto_kb as kb  # noqa: E402
from backend.utilities.dashboard import cbom_team_rollup as rollup  # noqa: E402
from backend.utilities.pdf import cbom_deliverable_text as deliverable  # noqa: E402
from backend.utilities.pdf import cbom_posture_text as posture  # noqa: E402

ENGINE = ROOT / "aibom/src/aibom/cbom"
ADAPTER = ROOT / "aibom/src/aibom/integrations/cbom_devsecshield.py"
CLASSIFIER = ROOT / "backend/utilities/cbom_sources"
IMPACTS = {"Critical", "High", "Medium", "Low"}
SARIF_TO_IMPACT = {"error": "High", "warning": "Medium", "note": "Low"}


def _literal(path: pathlib.Path, name: str):
    """A module-level literal (frozenset({...}), dict, tuple) read from the source without importing the engine."""
    for node in ast.parse(path.read_text(encoding="utf-8")).body:
        if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == name for t in node.targets):
            value = node.value
            if isinstance(value, ast.Call) and getattr(value.func, "id", "") == "frozenset":
                value = value.args[0]
            return ast.literal_eval(value)
    raise AssertionError(f"{name} not found in {path}")


def engine_codes() -> set[str]:
    codes: set[str] = set()
    for path in ENGINE.rglob("*.py"):
        src = path.read_text(encoding="utf-8")
        codes |= set(re.findall(r'^([A-Z][A-Z0-9_]{3,}) *= *"\1"', src, re.M))
        codes |= set(re.findall(r'add_flag\(\s*"([A-Z][A-Z0-9_]+)"', src))
    codes |= set(_literal(ENGINE / "posture/findings.py", "POSTURE_CODES"))
    return codes


def posture_codes() -> set[str]:
    return set(_literal(ENGINE / "posture/findings.py", "POSTURE_CODES"))


def collector_codes() -> set[str]:
    codes: set[str] = set()
    for path in [CLASSIFIER / "classify.py", *sorted((CLASSIFIER / "classify_ext").glob("*.py"))]:
        codes |= set(re.findall(r'out\.add\(\s*"([A-Z][A-Z0-9_]+)"', path.read_text(encoding="utf-8")))
    codes |= {code for _pattern, code, _impact, _label in classify._SSH_WEAK}
    codes |= {rule[0] for rule in classify._SCHANNEL.values()}
    codes |= {code for pair in classify._LEGACY_TLS.values() for code in pair}
    for label in ("SSLv2", "SSLv3", "TLS1.0", "TLS1.1"):  # _tls_rules: PROTO_<label> / MIN_<label>
        codes |= {f"PROTO_{label.replace('.', '')}", f"MIN_{label.replace('.', '')}"}
    return codes  # COVERAGE_<status> rows are "not collected" notes, not findings


def test_the_enumeration_finds_the_codes_it_must():
    assert {"WEAK_ALGORITHM", "LIBRARY_CVE_RANGE", "EOL_CRYPTO_LIBRARY", "CUSTOM_CRYPTO", "PROVIDER_MANAGED_KEY",
            "EOL_BASE_IMAGE", "QUANTUM_VULNERABLE"} <= engine_codes()
    assert {"LIB_EOL", "CERT_EXPIRED", "SSH_CBC_CIPHER", "PROTO_TLS10", "DB_EOL_VERSION", "KEY_WEAK_SYMMETRIC",
            "MESH_MTLS_OFF"} <= collector_codes()
    assert len(engine_codes()) > 30 and len(collector_codes()) > 100


def _kb_problems(namespace: str, codes: set[str]) -> list[str]:
    problems = []
    for code in sorted(codes):
        entry = kb.entry(namespace, code)
        if entry is None:
            problems.append(f"{namespace}:{code} has no knowledge-base entry")
            continue
        if not str(entry.get("title") or "").strip():
            problems.append(f"{namespace}:{code} has no label (title)")
        if len(str(entry.get("description") or "").strip()) < 20:
            problems.append(f"{namespace}:{code} has no text (description)")
        if entry.get("default_impact") not in IMPACTS:
            problems.append(f"{namespace}:{code} has no severity (default_impact {entry.get('default_impact')!r})")
    return problems


def test_every_engine_code_has_a_label_text_and_severity_in_the_knowledge_base():
    assert _kb_problems("code", engine_codes()) == []


def test_every_collector_code_has_a_label_text_and_severity_in_the_knowledge_base():
    assert _kb_problems("node", collector_codes()) == []


def test_every_engine_code_has_its_own_label_and_action_in_the_deliverables():
    labels = {**posture.FINDING_LABELS, **deliverable.FINDING_LABELS}
    actions = {**posture.FINDING_ACTIONS, **deliverable.FINDING_ACTIONS}
    assert sorted(engine_codes() - set(labels)) == [] and sorted(engine_codes() - set(actions)) == []
    for code in engine_codes():  # and the lookups the PDFs call return them, not the humanised fallback
        assert deliverable.finding_label(code) == labels[code] and deliverable.finding_action(code) == actions[code]


def test_every_posture_code_is_in_the_posture_tables_with_the_engines_severity():
    engine_severity = _literal(ENGINE / "posture/findings.py", "SEVERITY")
    problems = []
    for code in sorted(posture_codes()):
        expected = SARIF_TO_IMPACT[engine_severity[code]]
        if code not in posture.FINDING_CODES:
            problems.append(f"{code} missing from FINDING_CODES")
        for table in ("FINDING_LABELS", "FINDING_ANCHORS", "FINDING_ACTIONS"):
            if not str(getattr(posture, table).get(code) or "").strip():
                problems.append(f"{code} missing from {table}")
        if posture.FINDING_IMPACT.get(code) != expected:
            problems.append(f"FINDING_IMPACT[{code}] = {posture.FINDING_IMPACT.get(code)!r}, engine says {expected}")
        if rollup._POSTURE_CODE_SEVERITY.get(code) != expected:
            problems.append(f"roll-up severity[{code}] = {rollup._POSTURE_CODE_SEVERITY.get(code)!r}, engine says {expected}")
    assert problems == []


def test_the_roll_up_scores_a_provider_managed_key_fact_low_not_medium():
    assert rollup._fact_impact({}, ["PROVIDER_MANAGED_KEY"]) == "Low"
    assert rollup._fact_impact({}, ["EOL_BASE_IMAGE"]) == "Medium"


def test_row_types_and_weakness_mirror_the_engine():
    assert cbom_rows.LIBRARY_CODES == _literal(ADAPTER, "_LIBRARY_TYPE_CODES")
    assert cbom_rows.CONFIG_CODES == _literal(ADAPTER, "_CONFIG_TYPE_CODES")
    assert cbom_rows.WEAK_EXTRA_CODES == _literal(ENGINE / "normalize.py", "CONFIG_WEAKNESS_CODES") | {"CUSTOM_CRYPTO"}


def test_an_old_provider_managed_key_row_is_a_configuration_row_that_is_not_weak():
    old = {"algorithm_type": "other", "crypto_strength": "strong", "weak": False,
           "finding_codes": ["PROVIDER_MANAGED_KEY"], "impact": "Low"}
    shown = cbom_rows.display_row(old)
    assert (shown["algorithm_type"], shown["crypto_strength"], shown["weak"]) == ("configuration", "strong", False)
    old_tls = {**old, "finding_codes": ["TLS_VERIFICATION_DISABLED"]}
    assert cbom_rows.display_row(old_tls)["weak"] is True
