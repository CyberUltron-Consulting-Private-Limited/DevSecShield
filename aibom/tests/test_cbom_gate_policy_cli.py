"""S1: the offline ``aibom cbom`` gate honours a CBOM gate policy file in the
hosted gate's format.

Expected verdicts: NIST SP 800-131A Rev. 2 (RSA 1024 is disallowed; RSA 2048 and
P-256 are acceptable) and CNSA 2.0 (RSA 3072+ and P-384; quantum-vulnerable
public-key algorithms are phased out), never from a product view.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from aibom.cbom import gate_policy as GP
from aibom.cli import app

RSA_1024 = """from cryptography.hazmat.primitives.asymmetric import rsa


def make_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=1024)
"""
CLASSICAL = """from cryptography.hazmat.primitives.asymmetric import ec, rsa


def make_keys():
    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return rsa_key, ec.generate_private_key(ec.SECP256R1())
"""


def _tree(tmp_path: Path, source: str) -> Path:
    tree = tmp_path / "repo"
    tree.mkdir()
    (tree / "keys.py").write_text(source, encoding="utf-8")
    return tree


def _run(
    tmp_path: Path, tree: Path, policy: dict | None = None, raw: str | None = None
):
    args = ["cbom", str(tree), "-o", str(tmp_path / "bom.json")]
    if policy is not None or raw is not None:
        file = tmp_path / "policy.json"
        file.write_text(
            raw if raw is not None else GP.dump_policy_file(GP.validate_policy(policy)),
            encoding="utf-8",
        )
        args += ["--policy", str(file)]
    return CliRunner().invoke(app, args)


def test_default_policy_fails_rsa_1024_and_names_the_rules(tmp_path):
    out = _run(tmp_path, _tree(tmp_path, RSA_1024))
    assert out.exit_code == 1, out.output
    assert "FAIL min_key_size RSA-1024" in out.output
    assert "below the policy minimum of 2048 bits" in out.output
    assert json.loads((tmp_path / "bom.json").read_text())["bomFormat"] == "CycloneDX"


def test_default_policy_passes_classical_keys_and_warns_quantum_vulnerable(tmp_path):
    out = _run(tmp_path, _tree(tmp_path, CLASSICAL))
    assert out.exit_code == 0, out.output
    assert "WARN quantum_vulnerable" in out.output and "PASS policy=" in out.output


def test_cnsa_policy_file_fails_the_same_tree(tmp_path):
    out = _run(tmp_path, _tree(tmp_path, CLASSICAL), GP.PRESETS["cnsa-2.0"])
    assert out.exit_code == 1, out.output
    assert "(file, digest" in out.output
    assert "FAIL quantum_vulnerable" in out.output
    assert (
        "RSA key size 2048 bits is below the policy minimum of 3072 bits" in out.output
    )


def test_an_exception_in_the_file_waives_its_finding(tmp_path):
    policy = {
        **GP.DEFAULT_POLICY,
        "exceptions": [
            {
                "rule": "min_key_size",
                "algorithm": "RSA-1024",
                "location": "keys.py",
                "reason": "HSM vendor fix in Q1",
                "expires": "2099-12-31",
            }
        ],
        "block_codes": [],
    }
    out = _run(tmp_path, _tree(tmp_path, RSA_1024), policy)
    assert out.exit_code == 0, out.output
    assert "WAIVED min_key_size RSA-1024" in out.output


@pytest.mark.parametrize(
    "raw", ["{not json", json.dumps({"quantum_vulnerable": "sometimes"})]
)
def test_an_unusable_policy_file_exits_2(tmp_path, raw):
    out = _run(tmp_path, _tree(tmp_path, CLASSICAL), raw=raw)
    assert out.exit_code == 2, out.output
    assert "policy file cannot be used" in out.output
