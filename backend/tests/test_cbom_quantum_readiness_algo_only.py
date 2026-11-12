"""Hermetic: CBOM quantum_readiness is algorithm-only (no Unknown bucket).

Non-algorithm rows (certificate / protocol / key) carry ``quantum_safe=None``
from the adapter; the dashboard must exclude them from Safe/Vulnerable and
never increment ``unknown``. Score = safe / (safe + vulnerable).
"""

from __future__ import annotations

import os
import sys
import types

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from backend.utilities.dashboard.scan_list import generate_cbom_dashboard_data  # noqa: E402


def _scan(results: list[dict]) -> types.SimpleNamespace:
    return types.SimpleNamespace(
        scan_status="success",
        scan_data={"results": results},
        id=1,
    )


def test_quantum_readiness_excludes_na_never_unknown() -> None:
    rows = [
        {
            "algorithm_name": "AES-256-GCM",
            "algorithm_type": "block-cipher",
            "crypto_strength": "quantum_safe",
            "quantum_safe": True,
            "impact": "Low",
            "owasp_top_10": {},
            "compliance_controls": {},
        },
        {
            "algorithm_name": "RSA-2048",
            "algorithm_type": "pke",
            "crypto_strength": "strong",
            "quantum_safe": False,
            "impact": "Medium",
            "owasp_top_10": {},
            "compliance_controls": {},
        },
        {
            "algorithm_name": "cert.pem",
            "algorithm_type": "certificate",
            "crypto_strength": "strong",
            "quantum_safe": None,
            "impact": "Low",
            "owasp_top_10": {},
            "compliance_controls": {},
        },
        {
            "algorithm_name": "private-key",
            "algorithm_type": "key",
            "crypto_strength": "strong",
            "quantum_safe": None,
            "impact": "Low",
            "owasp_top_10": {},
            "compliance_controls": {},
        },
        {
            "algorithm_name": "TLS 1.2",
            "algorithm_type": "protocol",
            "crypto_strength": "strong",
            "quantum_safe": None,
            "impact": "Low",
            "owasp_top_10": {},
            "compliance_controls": {},
        },
    ]
    out = generate_cbom_dashboard_data([_scan(rows)])
    qr = out["quantum_readiness"]
    assert qr == {
        "quantum_safe": 1,
        "quantum_vulnerable": 1,
        "unknown": 0,
    }
    assert out["card_data"]["quantum_readiness_score"] == 50.0
    assert out["card_data"]["total_quantum_vulnerable"] == 1
