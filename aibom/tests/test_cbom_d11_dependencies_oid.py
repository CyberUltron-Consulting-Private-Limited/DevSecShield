"""D11 / audit A-14 and C G-D3-3: the code-scan CBOM carries its crypto graph.

CycloneDX 1.6 ``dependencies``: a certificate, key or protocol ``dependsOn`` what it
references; a crypto library ``provides`` the algorithms its files use. Algorithms
the emitter's OID table missed get algid's OID.

Failing first on dev 214d3ca1e: ``cbom_json`` has no ``dependencies`` at all for
this fixture (KeyError), although ``cbom_graph`` draws library -> algorithm
"provides" links. (The RSA OID test is a guard: the emitter's own table already
covers RSA here.)
"""
from __future__ import annotations

import os

from aibom.cbom.normalize import normalize_crypto
from aibom.cbom.pipeline import scan_crypto
from aibom.emit.validate import validate_cyclonedx

_HERE = os.path.dirname(os.path.abspath(__file__))
_FX = os.path.join(_HERE, "fixtures", "synthetic-crypto-app")


def _bom() -> tuple[dict, dict]:
    run = normalize_crypto(scan_crypto(_FX), duration_of_scan=0.0)
    return run["cbom_json"], run["cbom_graph"]


def _asset_type(comp: dict) -> str | None:
    return comp.get("cryptoProperties", {}).get("assetType")


def test_dependencies_carry_the_graphs_uses_and_provides_links() -> None:
    bom, graph = _bom()
    assert validate_cyclonedx(bom) == []
    refs = {c["bom-ref"] for c in bom["components"]}
    deps = {d["ref"]: d for d in bom["dependencies"]}
    provides = [
        (e["source"], e["target"]) for e in graph["edges"] if e["rel"] == "provides"
    ]
    assert provides, "the fixture's crypto libraries provide algorithms"
    for src, dst in provides:
        assert dst in deps[src]["provides"]
    for dep in bom["dependencies"]:
        assert dep["ref"] in refs
        assert set(dep.get("dependsOn", [])) <= refs
        assert set(dep.get("provides", [])) <= refs
    for cert in (c for c in bom["components"] if _asset_type(c) == "certificate"):
        cp = cert["cryptoProperties"]["certificateProperties"]
        for key in ("signatureAlgorithmRef", "subjectPublicKeyRef"):
            if cp.get(key):
                assert cp[key] in deps[cert["bom-ref"]]["dependsOn"]


def test_rsa_algorithms_carry_an_oid_and_quantum_level() -> None:
    bom, _graph = _bom()
    rsa = [
        c for c in bom["components"]
        if _asset_type(c) == "algorithm" and c["name"].upper().startswith("RSA")
    ]
    assert rsa
    for comp in rsa:
        crypto = comp["cryptoProperties"]
        assert crypto["oid"].startswith("1.2.840.113549.1.1."), comp["name"]
        assert crypto["algorithmProperties"]["nistQuantumSecurityLevel"] == 0
