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

PINNED_TEXT_SHA256 = "e7778cae6c2b3d7468ff7874f532cde57db7d5d98804849623c70c35f17bc901"
CB = REPO / "backend" / "utilities" / "cbom_sources"


# ----------------------------------------------------------------------------- version identity
def test_formula_text_sha_is_pinned():
    digest = hashlib.sha256(QG.FORMULA_TEXT.encode("utf-8")).hexdigest()
    assert digest == QG.FORMULA_SHA256 == PINNED_TEXT_SHA256
    assert QG.GRADE_MODEL == "qg-1"
    assert QG.FORMULA_TEXT.startswith("ZeroShield quantum risk grade, model qg-1.\n")


def test_model_version_hashes_qgrade_posture_and_the_classifier():
    from backend.utilities.cbom_sources.classify import CLASSIFIER_VERSION

    q, p = (CB / "qgrade.py").read_bytes(), (CB / "posture.py").read_bytes()
    cv = CLASSIFIER_VERSION
    assert QG.model_version(q, p, cv) == QG.GRADE_MODEL_VERSION
    assert re.fullmatch(r"qg-1\+[0-9a-f]{12}", QG.GRADE_MODEL_VERSION) and len(QG.GRADE_MODEL_VERSION) <= 32
    assert QG.model_version(q, p + b"\n# a posture edit\n", cv) != QG.GRADE_MODEL_VERSION  # class/exposure live there
    assert QG.model_version(q + b"\n# a grade edit\n", p, cv) != QG.GRADE_MODEL_VERSION
    # the fallback test reads classify.quantum_vulnerable: a classifier change is a grade-model change (review B)
    assert QG.model_version(q, p, cv + "x") != QG.GRADE_MODEL_VERSION
    assert QG.model_version(q, p, cv) == "qg-1+" + hashlib.sha256(q + p + cv.encode()).hexdigest()[:12]


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
    # a classical fallback of a PQ endpoint has its own reasons (cx2 HF-1), same grades as the classical ones
    for code in ("exceeds_internet", "exceeds_anchor", "exceeds_exposure_unknown", "exceeds", "within"):
        assert codes[f"qv_fallback_{code}"]["grade"] == codes[f"qv_{code}"]["grade"]
        assert "fallback" in codes[f"qv_fallback_{code}"]["text"]
    assert "vendor no response" in codes["evidence_e0"]["text"]


# ----------------------------------------------------------------------------- reference read from the text
_E123 = ("E1", "E2", "E3")
_PQ = ("hybrid", "quantum-safe")


def _cls(i: QG.GradeInput) -> str | None:
    return i.cls


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
    # Inputs, "fallback": an endpoint of class hybrid or quantum-safe that also completes a classical-only exchange
    "fallback": lambda i: _cls(i) in _PQ and i.fallback,
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
    (_a(cls="hybrid", fallback=True, exposure="internet"), "Q1", "qv_fallback_exceeds_internet"),  # weakest config
    (_a(cls="hybrid", fallback=True), "Q2", "qv_fallback_exceeds"),
    (_a(cls="quantum-safe", fallback=True, exposure="unknown"), "Q2", "qv_fallback_exceeds_exposure_unknown"),
    (_a(cls="hybrid", fallback=True, z=20), "Q3", "qv_fallback_within"),
    (_a(cls="quantum-vulnerable", fallback=True), "Q2", "qv_exceeds"),  # fallback is only for PQ endpoints
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
    # review B: the container collector's distroless / scratch wording
    ({"check": "package list", "status": "not_supported",
      "detail": "no dpkg, apk or rpm (sqlite) package database in the image (distroless or scratch?)"}, "not_present"),
    # a by-choice row is by choice whatever its status
    ({"check": "lambda environment", "status": "not_supported", "by_choice": True, "detail": "option off"}, "by_choice"),
    ({"check": "linkerd policy", "status": "not_installed", "detail": ""}, "not_present"),
    # HF-4: "not_supported" that means "the product did not look" is an unread scope
    ({"check": "key and certificate files", "status": "not_supported",
      "detail": "Tier 1 does not search for key and certificate files; use Tier 2"}, "gap"),
    ({"check": "TLS secrets", "status": "not_supported", "detail": "Tier 1 does not read Secrets; use Tier 2"}, "gap"),
    ({"check": "Vault PKI and transit", "status": "not_supported",
      "detail": "no pki or transit mount is visible to this token"}, "gap"),
    ({"check": "BitLocker", "status": "denied", "detail": "Get-BitLockerVolume needs administrator rights"}, "gap"),
    ({"check": "AD CS template settings", "status": "not_supported",
      "detail": "no Active Directory Certificate Services CA is configured on this server"}, "not_present"),
    ({"check": "AD CS template settings", "status": "not_supported", "detail": "Web is published but not readable"},
     "gap"),
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
    # review A: classical SSH kex names come from algid (GSS family included), not a local table
    ("ssh_endpoint", {"kex": ["mlkem768x25519-sha256", "gss-curve25519-sha256-toWM5Slw5Ew8Mqkay+al2g=="]}, [], True),
    ("ssh_endpoint", {"kex": ["mlkem768x25519-sha256", "curve448-sha512"]}, [], True),
    # CB-12's prober reports whether a classical TLS 1.3 key share was accepted
    ("tls_endpoint", {"protocols": ["TLSv1.3"], "pq_hybrid": True, "classical_tls13_accepted": True}, [], True),
    ("tls_endpoint", {"protocols": ["TLSv1.3"], "pq_hybrid": True, "classical_tls13_accepted": False}, [], False),
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


@pytest.mark.parametrize("target,kind", [
    # review B: "not_supported" targets the node never read are unread scope (cx2 HF-4: not-read by default)
    ({"target": "reg.example/app:1", "status": "not_supported",
      "error": "a layer is zstd-compressed (not read: no decompressor in the scan node)"}, "gap"),
    ({"target": "db1:1521", "status": "not_supported",
      "error": "the server requires Oracle native network encryption (NNE) instead of TLS"}, "gap"),
    ({"target": "sql1:1433", "status": "not_supported", "error": "the server requires TDS 8.0 strict encryption"}, "gap"),
    ({"target": "10.0.0.9:5000", "status": "not_supported", "error": "foo is not supported by this node version"}, "gap"),
    ({"target": "aws/eu-south-2", "status": "not_supported", "error": "kms: not_enabled; acm: not_enabled",
      "services": {"kms": "not_enabled", "acm": "not_enabled"}}, "not_present"),
    ({"target": "ca01", "status": "not_supported",
      "error": "no Active Directory Certificate Services CA is configured on this server"}, "not_present"),
    ({"target": "10.0.0.9", "status": "timeout"}, "gap"),
    ({"target": "10.0.0.9", "status": "ok"}, "read"),
    ({"target": "10.0.0.9", "status": "partial"}, "read"),
    ({"target": "10.0.0.9", "status": "skipped_never_scan"}, "by_choice"),
    ({"target": "+1048 more", "status": "summary", "error": "{\"ok\": 1048}"}, "summary"),
])
def test_job_targets_are_read_by_what_was_not_read(target, kind):
    assert QG.target_kind(target) == kind


def test_collector_internet_facing_beats_a_team_internal_override():
    memo: dict = {}
    facing = {"internet_facing": True, "internet_facing_reason": "load balancer scheme internet-facing"}
    exposure, basis = QG.grade_exposure(facing, "10.0.0.5", "10.0.0.5:443", override="internal", segment=None, memo=memo)
    assert exposure == "internet" and "collector" in basis and "internal" in basis
    # an "internet" override still raises; an "internal" override still lowers when the collector says nothing
    assert QG.grade_exposure({}, "10.0.0.5", None, override="internet", segment=None, memo=memo)[0] == "internet"
    assert QG.grade_exposure({}, "52.95.110.1", None, override="internal", segment=None, memo=memo)[0] == "internal"
    # review B: a source set to "unknown" does not lower the collector's internet fact either
    assert QG.grade_exposure(facing, "10.0.0.5", None, override="unknown", segment=None, memo={})[0] == "internet"
    assert QG.grade_exposure({}, "pay.bank.example", None, override=None, segment=None, memo=memo)[0] == "unknown"
    assert QG.grade_exposure({}, "52.95.110.1", None, override=None, segment=None, memo=memo)[0] == "internet"
    assert len(memo) == 5  # memoised per (override, segment, collector fact, target); location only when needed


def test_the_fast_path_equals_the_explained_grade_on_random_rows():
    """The posture loop and list pages (explain=False, the score's exposure handed in) must give exactly the grade
    the asset detail (explain=True, the grade's own exposure) gives, row by row (review A: no second exposure
    computation in the loop, except where the grade's precedence differs)."""
    from types import SimpleNamespace as NS

    from backend.utilities.cbom_sources import posture as P

    rng = random.Random(1141)
    targets = ("52.95.110.1", "10.0.0.5", "web.example.org", "100.64.1.1", "52.95.110.1:443", None)
    locations = (None, "52.95.110.2:443", "192.168.1.1", "/etc/ssl/a.pem")
    seen = set()
    for _ in range(3000):
        job = QG._JobInfo(x=rng.choice((None, 0, 3, 30)), exposure=rng.choice((None, "internet", "internal", "unknown")),
                          segment=rng.choice((None, "DMZ", "core")), source_uid="s1", source_id=1, source_name=None,
                          network=False)
        ctx = QG.GradeContext(team_x=rng.choice((None, 2, 10)), y=rng.choice((None, 0, 5)), z=rng.choice((None, 4, 12)),
                              jobs={1: job}, run=None, job_rows=[], sources={})
        facts = {}
        if rng.random() < .5:
            facts["internet_facing"] = rng.choice((True, False))
        if rng.random() < .3:
            facts["is_ca"] = True
        qv = rng.choice((True, False, None))
        if qv is False and rng.random() < .6:
            facts["pq_hybrid"] = True
            facts["versions"] = {"TLSv1.3": True, "TLSv1.2": rng.choice((True, False))}
        row = NS(id=1, job_id=1, asset_type=rng.choice(("tls_endpoint", "ssh_endpoint", "certificate", "cloud_ca",
                                                        "kms_key", "disk_encryption", "database_config")),
                 quantum_vulnerable=qv, facts=facts, target=rng.choice(targets), location=rng.choice(locations),
                 asset_key="k", cdx_type="other")
        codes = ["DISK_XTS_128"] if row.asset_type == "disk_encryption" and rng.random() < .5 else []
        score = P.asset_exposure(facts, row.target, row.location, override=job.exposure, node_segment=job.segment)
        fast = ctx.grade_row(row, codes, explain=False, score_exposure=score)
        full = ctx.grade_row(row, codes, explain=True)
        assert (fast.q_grade, fast.q_reason, fast.q_item_key) == (full.q_grade, full.q_reason, full.q_item_key), row
        assert fast.explain["missing"] == full.explain["missing"]
        seen.add(full.q_reason)
    assert {"qv_exceeds_internet", "qv_fallback_exceeds", "mosca_missing", "pq_observed", "grover_weakened",
            "not_applicable", "qv_exceeds_anchor"} <= seen
