"""CB-16 (#294 follow-up): the code lane's CNSA 2.0 / FIPS 140-3 checks call the
shared standards module.

``aibom/src/aibom/cbom/standards.py`` is byte-identical to the Sources lane's copy
(the backend test ``test_cbom_cb16_standards`` compares them), and
``standards.framework_checks`` holds the CNSA-1, CNSA-2, FIPS-1, FIPS-2 and FIPS-3
predicates.  These tests show the checks really go through it: whenever the shared
module grades an asset, the check's verdict on that asset is the module's; only an
asset it cannot grade falls back to this lane's graph facts.
"""

from __future__ import annotations

import os

import pytest

from aibom.cbom import compliance as C
from aibom.cbom import standards as S
from aibom.cbom.pipeline import scan_crypto

_HERE = os.path.dirname(os.path.abspath(__file__))
_FIXTURES = [
    os.path.join(_HERE, "fixtures", name)
    for name in ("synthetic-crypto-app", "synthetic-crypto-pqc")
]
_HELPERS = {
    "CNSA-1": C.cnsa_symmetric_hash_noncompliant,
    "CNSA-2": C.cnsa_underparameterized_quantum_safe,
    "FIPS-1": lambda r: C.non_approved_algorithms(r, "fips_140_3"),
    "FIPS-2": C.fips_undersized_keys,
    "FIPS-3": C.fips_disallowed,
}


@pytest.mark.parametrize("fixture", _FIXTURES)
def test_every_asset_the_shared_module_grades_gets_its_verdict(fixture: str) -> None:
    r = scan_crypto(fixture)
    graded = 0
    for req, helper in _HELPERS.items():
        failing = {id(c) for c in helper(r)}
        candidates = (
            C.quantum_safe_mechanisms(r) if req == "CNSA-2" else C.algorithms(r)
        )
        for c in candidates:
            shared = C._std_checks(c)[req]
            if shared is None or (req == "FIPS-3" and c in C.ecb_modes(r)):
                continue
            graded += 1
            assert (id(c) in failing) == shared, (req, c.name)
    assert graded > 10


def test_the_checks_follow_the_shared_module(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make the shared module say "meets CNSA-1" for everything: the app fixture's
    CNSA-1 (SHA-256) then passes, which only happens if the check calls it."""
    app = scan_crypto(_FIXTURES[0])
    before = {
        x["id"]: x["verdict"]
        for x in C.run_cbom_compliance(app)["cnsa_2_0"]["requirements"]
    }
    assert before["CNSA-1"] == "fail"
    real = S.framework_checks

    def lenient(role, identifier, key_size=None):
        out = real(role, identifier, key_size)
        return {**out, "CNSA-1": False}

    monkeypatch.setattr(C._std, "framework_checks", lenient)
    after = {
        x["id"]: x["verdict"]
        for x in C.run_cbom_compliance(app)["cnsa_2_0"]["requirements"]
    }
    assert after["CNSA-1"] == "pass"
