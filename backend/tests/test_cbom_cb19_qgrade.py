"""CB-19 PR-1: the quantum risk grade qg-1 as a pure function (no database).

* ``FORMULA_TEXT`` is the text the owner signs; its sha256 is pinned here and in ``qgrade.FORMULA_SHA256``, so editing
  the text without both constants fails CI.
* The decision-table property test grades 2,000 generated inputs with ``qgrade.grade`` and with a reference that
  reads the rule list (order, conditions, grades, reason codes) from ``FORMULA_TEXT`` itself: the code and the signed
  text cannot drift apart.
* The helpers that turn stored facts into grade inputs (coverage rows, classical fallback, trust anchors, exposure).

    cd backend && PYTHONPATH=.. python -m pytest tests/test_cbom_cb19_qgrade.py -q
"""
from __future__ import annotations

import hashlib
import random
import re
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from backend.utilities.cbom_sources import qgrade as QG  # noqa: E402

PINNED_TEXT_SHA256 = "9afdb44697907cc5a7e0369d38647564366234620d23b65569df41121b185e94"
CB = REPO / "backend" / "utilities" / "cbom_sources"


# ----------------------------------------------------------------------------- version identity
def test_formula_text_sha_is_pinned():
    digest = hashlib.sha256(QG.FORMULA_TEXT.encode("utf-8")).hexdigest()
    assert digest == QG.FORMULA_SHA256 == PINNED_TEXT_SHA256
    assert QG.GRADE_MODEL == "qg-1"
    assert QG.FORMULA_TEXT.startswith("ZeroShield quantum risk grade, model qg-1.\n")


def test_model_version_hashes_qgrade_and_posture():
    q, p = (CB / "qgrade.py").read_bytes(), (CB / "posture.py").read_bytes()
    assert QG.model_version(q, p) == QG.GRADE_MODEL_VERSION
    assert re.fullmatch(r"qg-1\+[0-9a-f]{12}", QG.GRADE_MODEL_VERSION) and len(QG.GRADE_MODEL_VERSION) <= 32
    assert QG.model_version(q, p + b"\n# a posture edit\n") != QG.GRADE_MODEL_VERSION  # class/exposure live there
    assert QG.model_version(q + b"\n# a grade edit\n", p) != QG.GRADE_MODEL_VERSION
    assert QG.model_version(q, p) == "qg-1+" + hashlib.sha256(q + p).hexdigest()[:12]


def test_grade_model_payload_lists_every_grade_and_reason():
    out = QG.model_payload()
    assert out["model"] == "qg-1" and out["model_version"] == QG.GRADE_MODEL_VERSION
    assert out["text"] == QG.FORMULA_TEXT and out["text_sha256"] == PINNED_TEXT_SHA256
    assert [g["grade"] for g in out["grades"]] == ["Q0", "Q1", "Q2", "Q3", "Q4"]
    assert [g["label"] for g in out["grades"]] == ["Unknown", "Critical", "High", "Medium", "Low"]
    codes = {r["code"]: r for r in out["reasons"]}
    # every reason the text names is served, with the grade the text gives it
    for rule in _rules():
        for reason in rule["reasons"]:
            assert codes[reason]["grade"] == rule["grade"], reason
    assert codes["not_an_item"]["grade"] is None and codes["not_an_item"]["kind"] == "not_an_item"
    # the two Q2 reasons are split (internal vs exposure unknown, cx4 OB19-6)
    assert codes["qv_exceeds"]["grade"] == codes["qv_exceeds_exposure_unknown"]["grade"] == "Q2"


# ----------------------------------------------------------------------------- reference read from the text
_E123 = ("E1", "E2", "E3")
_PQ = ("hybrid", "quantum-safe")


def _cls(i: QG.GradeInput) -> str | None:
    # Inputs, "fallback": an endpoint of class hybrid or quantum-safe that also completes a classical-only key exchange
    # is graded as class quantum-vulnerable (the weakest configuration it accepts)
    return "quantum-vulnerable" if i.cls in _PQ and i.fallback else i.cls


def _set(i: QG.GradeInput) -> bool:
    return all(isinstance(v, int) for v in (i.x, i.y, i.z))


ATOMS = {
    "unread scope": lambda i: i.item == "scope",
    "attested item at level E0": lambda i: i.provenance == "attested" and i.level == "E0",
    "attested item at E1..E3 whose answer carries no class":
        lambda i: i.provenance == "attested" and i.level in _E123 and i.cls is None,
    "class unknown": lambda i: _cls(i) == "unknown",
    "class not-applicable": lambda i: _cls(i) == "not-applicable",
    "correlation required and absent": lambda i: i.correlation_missing,
    "class quantum-vulnerable": lambda i: _cls(i) == "quantum-vulnerable",
    "X, Y or Z not set": lambda i: not _set(i),
    "X + Y > Z": lambda i: _set(i) and i.x + i.y > i.z,
    "X + Y <= Z": lambda i: _set(i) and i.x + i.y <= i.z,
    "exposure internet": lambda i: i.exposure == "internet",
    "exposure unknown": lambda i: i.exposure == "unknown",
    "anchor": lambda i: i.anchor,
    "class grover-weakened": lambda i: _cls(i) == "grover-weakened",
    "class hybrid or quantum-safe, attested at E1":
        lambda i: _cls(i) in _PQ and i.provenance == "attested" and i.level == "E1",
    "class hybrid or quantum-safe, observed": lambda i: _cls(i) in _PQ and i.provenance == "observed",
    "class hybrid or quantum-safe, code": lambda i: _cls(i) in _PQ and i.provenance == "code",
    "class hybrid or quantum-safe, attested at E2 or E3":
        lambda i: _cls(i) in _PQ and i.provenance == "attested" and i.level in ("E2", "E3"),
}


def _atoms(cond: str) -> list[str]:
    """Split "a and b and c" into known phrases, longest first (a phrase may itself contain " and ")."""
    words, out, i = cond.split(" and "), [], 0
    while i < len(words):
        for j in range(len(words), i, -1):
            phrase = " and ".join(words[i:j])
            if phrase in ATOMS:
                out.append(phrase)
                i = j
                break
        else:
            raise AssertionError(f"FORMULA_TEXT condition the reference cannot read: {words[i]!r} in {cond!r}")
    return out


def _rules() -> list[dict]:
    lines = QG.FORMULA_TEXT.splitlines()
    start = lines.index("Rules, first match wins:") + 1
    rules: list[dict] = []
    for line in lines[start:]:
        if not line.startswith(" "):
            break
        m = re.match(r"^\s*(\d+)\.\s+(.*)$", line)
        if m:
            rules.append({"n": int(m.group(1)), "body": m.group(2).strip()})
        else:
            rules[-1]["body"] += " " + line.strip()
    out = []
    for rule in rules:
        cond, arrow, result = rule["body"].partition("->")
        assert arrow, rule
        result = result.strip()
        grade = None if result.startswith("no grade") else re.match(r"(Q[0-4])\b", result).group(1)
        reasons = re.findall(r'"([a-z0-9_]+)"', result.split("(")[0])
        out.append({"n": rule["n"], "atoms": _atoms(re.sub(r"\s+", " ", cond).strip()), "grade": grade,
                    "reasons": reasons})
    assert [r["n"] for r in out] == list(range(1, len(out) + 1)), "rules are numbered 1..n in order"
    return out


def reference(i: QG.GradeInput) -> tuple[str | None, str, int]:
    for rule in _rules():
        if all(ATOMS[a](i) for a in rule["atoms"]):
            reasons = rule["reasons"]
            reason = reasons[0] if len(reasons) == 1 else i.scope_reason
            assert reason in reasons, (rule, i)
            return rule["grade"], reason, rule["n"]
    raise AssertionError(f"no rule of FORMULA_TEXT matches {i}")


def _gen(rng: random.Random) -> QG.GradeInput:
    def mosca():
        return rng.choice([None, 0, 1, 2, 4, 5, 10, 12, 15, 20, 50, 100, rng.randint(0, 100)])

    item = rng.choices(["asset", "scope", "evidence"], weights=[8, 1, 1])[0]
    provenance = "attested" if item == "evidence" else rng.choices(["observed", "code", "attested"], [6, 1, 1])[0]
    level = rng.choice(["E0", "E1", "E2", "E3"]) if provenance == "attested" else None
    classes = list(QG.CLASSES)
    if item == "scope":
        cls = None
    elif provenance == "attested":
        cls = rng.choice(classes + [None, None])
    else:
        cls = rng.choice(classes)
    return QG.GradeInput(
        item=item, scope_reason=rng.choice(QG.SCOPE_REASONS) if item == "scope" else None, cls=cls,
        fallback=rng.random() < 0.3, exposure=rng.choice(["internet", "internal", "unknown"]),
        anchor=rng.random() < 0.25, x=mosca(), y=mosca(), z=mosca(), provenance=provenance, level=level,
        correlation_missing=rng.random() < 0.05)


def test_decision_table_matches_the_signed_text_on_2000_inputs():
    rng = random.Random(19)
    hit: set[int] = set()
    for _ in range(2000):
        inp = _gen(rng)
        want_grade, want_reason, rule = reference(inp)
        got = QG.grade(inp)
        assert (got.q_grade, got.q_reason) == (want_grade, want_reason), (inp, rule)
        hit.add(rule)
    assert hit == {r["n"] for r in _rules()}, f"rules never exercised: {sorted({r['n'] for r in _rules()} - hit)}"


def test_every_reason_code_is_reachable():
    rng = random.Random(23)
    seen = {QG.grade(_gen(rng)).q_reason for _ in range(4000)}
    graded = {code for code, meta in QG.REASONS.items() if meta["kind"] != "not_an_item"}
    assert graded <= seen, sorted(graded - seen)


# ----------------------------------------------------------------------------- named cases (PLAN §4)
def _a(**kw) -> QG.GradeInput:
    base = {"item": "asset", "cls": "quantum-vulnerable", "exposure": "internal", "x": 10, "y": 5, "z": 12}
    return QG.GradeInput(**{**base, **kw})


@pytest.mark.parametrize("inp,grade,reason", [
    (_a(exposure="internet"), "Q1", "qv_exceeds_internet"),
    (_a(), "Q2", "qv_exceeds"),
    (_a(exposure="unknown"), "Q2", "qv_exceeds_exposure_unknown"),
    (_a(anchor=True), "Q1", "qv_exceeds_anchor"),
    (_a(z=15), "Q3", "qv_within"),  # boundary: X + Y == Z is not "exceeds"
    (_a(x=None), "Q0", "mosca_missing"),
    (_a(x=0, y=5, z=4), "Q2", "qv_exceeds"),  # X = 0 is a value, not "unset"
    (_a(cls="hybrid"), "Q4", "pq_observed"),
    (_a(cls="hybrid", fallback=True, exposure="internet"), "Q1", "qv_exceeds_internet"),  # weakest configuration
    (_a(cls="quantum-safe", fallback=True, x=None), "Q0", "mosca_missing"),
    (_a(cls="quantum-safe", provenance="code"), "Q4", "pq_code"),
    (_a(cls="grover-weakened"), "Q3", "grover_weakened"),
    (_a(cls="not-applicable", x=None), None, "not_applicable"),  # N/A never needs Mosca
    (_a(cls="unknown", x=None), "Q0", "unknown_verdict"),
    (QG.GradeInput(item="scope", scope_reason="source_truncated"), "Q0", "source_truncated"),
])
def test_named_cases(inp, grade, reason):
    out = QG.grade(inp)
    assert (out.q_grade, out.q_reason) == (grade, reason)
    assert out.q_label == (QG.LABELS[grade] if grade else None)


def test_invalid_inputs_are_refused():
    with pytest.raises(ValueError):
        QG.grade(QG.GradeInput(item="asset", cls=None))
    with pytest.raises(ValueError):
        QG.grade(QG.GradeInput(item="scope", scope_reason="something_else"))


# ----------------------------------------------------------------------------- inputs from stored facts
@pytest.mark.parametrize("facts,kind", [
    ({"check": "BitLocker", "status": "not_supported", "detail": "BitLocker is not installed on this server"},
     "not_present"),
    ({"check": "package list", "status": "not_supported", "detail": "no dpkg, apk or rpm package database was found"},
     "not_present"),
    ({"check": "linkerd policy", "status": "not_installed", "detail": ""}, "not_present"),
    # HF-4: "not_supported" that means "the product did not look" is an unread scope
    ({"check": "key and certificate files", "status": "not_supported",
      "detail": "Tier 1 does not search for key and certificate files; use Tier 2"}, "gap"),
    ({"check": "TLS secrets", "status": "not_supported", "detail": "Tier 1 does not read Secrets; use Tier 2"}, "gap"),
    ({"check": "Vault PKI and transit", "status": "not_supported",
      "detail": "no pki or transit mount is visible to this token"}, "gap"),
    ({"check": "BitLocker", "status": "denied", "detail": "Get-BitLockerVolume needs administrator rights"}, "gap"),
    ({"check": "package list", "status": "error", "detail": "neither dpkg-query nor rpm answered"}, "gap"),
    # FP-1: an address that answered on no probed port holds nothing the product could read
    ({"check": "no answer", "status": "unreachable", "detail": "10.0.0.9 did not answer on any listed port (443)"},
     "no_answer"),
    ({"check": "lambda environment", "status": "partial", "by_choice": True, "detail": "no CMK"}, "by_choice"),
])
def test_coverage_rows_are_read_by_what_was_not_read(facts, kind):
    assert QG.coverage_kind(facts) == kind


@pytest.mark.parametrize("asset_type,facts,codes,fallback", [
    ("tls_endpoint", {"protocols": ["TLSv1.3"], "pq_hybrid": True}, [], False),
    ("tls_endpoint", {"versions": {"TLSv1.2": True, "TLSv1.3": True}, "pq_hybrid": True}, [], True),
    ("tls_endpoint", {"versions": {"TLSv1.2": False, "TLSv1.3": True}, "pq_hybrid": True}, [], False),
    ("tls_endpoint", {"protocols": ["TLSv1.3"], "pq_hybrid": True}, ["STATIC_RSA_KEX"], True),
    ("tls_endpoint", {"protocols": ["TLSv1.3"], "pq_hybrid": True, "weak_ciphers_accepted": {"static_rsa": True}},
     [], True),
    ("tls_endpoint", {"protocols": ["TLSv1.3"], "pq_group_supported": True, "group": "x25519"}, [], True),
    ("ssh_endpoint", {"kex": ["mlkem768x25519-sha256", "curve25519-sha256"]}, [], True),
    ("ssh_endpoint", {"kex": ["mlkem768x25519-sha256"]}, [], False),
    ("kms_key", {"key_spec": "SYMMETRIC_DEFAULT", "protocols": ["TLSv1.2"]}, [], False),  # not an endpoint
])
def test_classical_fallback(asset_type, facts, codes, fallback):
    assert QG.classical_fallback(asset_type, facts, codes)[0] is fallback


@pytest.mark.parametrize("asset_type,facts,anchor,basis", [
    ("certificate", {"is_ca": True}, True, "is_ca"),
    ("certificate", {"is_ca": False, "self_signed": True}, False, None),
    ("cloud_ca", {}, True, "cloud_ca"),
    ("ca_authority", {}, True, "ca_authority"),
    ("signing_key", {"source": "idp"}, False, None),  # an IdP token-signing key is not a trust anchor (OQ-4)
])
def test_trust_anchor(asset_type, facts, anchor, basis):
    assert QG.trust_anchor(asset_type, facts) == (anchor, basis)


def test_collector_internet_facing_beats_a_team_internal_override():
    memo: dict = {}
    facing = {"internet_facing": True, "internet_facing_reason": "load balancer scheme internet-facing"}
    exposure, basis = QG.grade_exposure(facing, "10.0.0.5", "10.0.0.5:443", override="internal", segment=None, memo=memo)
    assert exposure == "internet" and "collector" in basis and "internal" in basis
    # an "internet" override still raises; an "internal" override still lowers when the collector says nothing
    assert QG.grade_exposure({}, "10.0.0.5", None, override="internet", segment=None, memo=memo)[0] == "internet"
    assert QG.grade_exposure({}, "52.95.110.1", None, override="internal", segment=None, memo=memo)[0] == "internal"
    assert QG.grade_exposure({}, "pay.bank.example", None, override=None, segment=None, memo=memo)[0] == "unknown"
    assert QG.grade_exposure({}, "52.95.110.1", None, override=None, segment=None, memo=memo)[0] == "internet"
    assert len(memo) == 5  # memoised per (override, segment, collector fact, target); location only when needed
