"""The weight pin keeps the Base_Commit divisor at 112."""

from pathlib import Path

import yaml

from aibom.cbom.posture.findings import POSTURE_CODES, SEVERITY, WEIGHT

ROOT = Path(__file__).resolve().parents[1]
WEIGHTS = ROOT / "config" / "crypto-risk-weights.yaml"
BASE = {
    "WEAK_ALGORITHM": 8,
    "WEAK_CIPHER_MODE": 8,
    "WEAK_KEY_SIZE": 8,
    "WEAK_PROTOCOL": 8,
    "WEAK_CIPHER_SUITE": 8,
    "WEAK_PADDING": 8,
    "EXPIRED_CERTIFICATE": 8,
    "WEAK_CERTIFICATE_SIGNATURE": 8,
    "WEAK_CERTIFICATE_KEY": 8,
    "WEAK_RNG": 8,
    "STATIC_IV": 8,
    "REUSED_NONCE": 8,
    "HARDCODED_KEY": 8,
    "QUANTUM_VULNERABLE": 4,
    "SELF_SIGNED_LEAF": 4,
}


# Flags weighted after Base_Commit (emitted by crypto_advisory_scan and the custom-crypto detector). They do not
# change the pinned divisor: "max_raw: 112 # Base_Commit weight sum. Do not let new flags rescore old scans."
# A further flag must be added here on purpose.
ADDED_AFTER_BASE = {
    "VULNERABLE_CRYPTO_LIBRARY": 8,
    "CUSTOM_CRYPTO": 4,
    # container images, binaries and firmware (artifact_scan, scan option scan_binaries)
    "EOL_CRYPTO_LIBRARY": 4,
    "LIBRARY_CVE_RANGE": 1,
}


def test_base_weights_and_pin() -> None:
    loaded = yaml.safe_load(WEIGHTS.read_text(encoding="utf-8"))
    flags = loaded["flags"]
    for name, weight in {**BASE, **ADDED_AFTER_BASE}.items():
        assert flags[name] == weight
    assert set(flags) == set(BASE) | set(ADDED_AFTER_BASE) | POSTURE_CODES
    assert loaded["scale"]["max_raw"] == 112
    assert sum(BASE.values()) == 112
    assert loaded["severity"]["critical"] == 13
    assert loaded["scale"]["bands"]["low"] == 33
    for code in POSTURE_CODES:
        assert flags[code] == WEIGHT[SEVERITY[code]]
