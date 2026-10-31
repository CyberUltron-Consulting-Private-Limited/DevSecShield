"""WP11b: Network, TLS and crypto protocol assessment PDF (#6)."""

from __future__ import annotations

import re
import sys
from datetime import date, datetime, timezone
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from backend.tests.support.pdf_text import pdf_text  # noqa: E402
from backend.utilities.dashboard.cbom_team_rollup import TeamCbomView  # noqa: E402
from backend.utilities.pdf import cbom_network_tls_pdf as network  # noqa: E402
from backend.utilities.pdf.report_branding import REPORT_META  # noqa: E402

SENTENCE = "The platform did not probe any endpoint."
_NOW = datetime(2026, 10, 26, 8, 0, tzinfo=timezone.utc)


def _bare() -> TeamCbomView:
    return TeamCbomView(
        team_id=7,
        team_name="Posture Team",
        generated_at=_NOW,
        as_of=date(2026, 10, 26),
        fingerprint="abcdef12",
    )


def _with_posture() -> TeamCbomView:
    view = _bare()
    view.included = 1
    view.eligible = 1
    view.fidelity_full = 1
    view.posture = {
        "sources": [{"label": "edge", "status": "assessed", "fact_count": 2}],
        "facts": [
            {
                "id": "static-1",
                "kind": "tls_endpoint",
                "provider": "aws",
                "address": "api.example:443",
                "native_type": "aws_lb_listener",
                "impact": "High",
                "location": "lb.tf:4",
                "paired_with": "edge|import-1",
                "discrepancy": True,
                "net": {
                    "endpoint": "api.example:443",
                    "evidence": "static server",
                    "min": "1.2",
                    "max": "1.3",
                    "protocols": {
                        "SSLv3": "not_offered",
                        "1.0": "not_offered",
                        "1.1": "not_offered",
                        "1.2": "offered",
                        "1.3": "offered",
                    },
                },
            },
            {
                "id": "import-1",
                "kind": "tls_endpoint",
                "provider": "other",
                "address": "api.example:443",
                "native_type": "testssl",
                "format": "import",
                "impact": "Medium",
                "location": "scan.json",
                "paired_with": "edge|static-1",
                "discrepancy": True,
                "net": {
                    "endpoint": "api.example:443",
                    "evidence": "imported:testssl",
                    "min": "1.0",
                    "max": "1.2",
                    "protocols": {
                        "SSLv3": "not_offered",
                        "1.0": "offered",
                        "1.1": "not_offered",
                        "1.2": "offered",
                        "1.3": "unknown",
                    },
                    "weak_suites": [{"suite": "TLS_RSA_WITH_RC4_128_SHA", "reasons": ["RC4"]}],
                    "certificate": {
                        "subject": "CN=api.example",
                        "issuer": "CN=Test",
                        "not_before": "2020-01-01",
                        "not_after": "2021-01-01",
                        "signature_algorithm": "sha1WithRSA",
                        "key_size": "1024",
                        "chain": "invalid",
                    },
                    "vulnerabilities": [{"item": "BEAST", "status": "vulnerable", "tool": "testssl"}],
                },
            },
        ],
        "imports": [
            {
                "file": "scan.json",
                "tool": "testssl",
                "tool_version": "3.2",
                "scan_start": "2026-10-01T00:00:00Z",
                "scan_end": "2026-10-01T00:05:00Z",
                "age_days": 25,
                "endpoint_count": 1,
            }
        ],
    }
    return view


def _visible(raw: bytes) -> str:
    """Text from the content-stream reader in ``backend/tests/support/pdf_text.py``."""
    return re.sub(r"\s+", " ", pdf_text(raw))


def test_report_key_is_registered():
    assert network.REPORT_KEY == "cbom_network_tls"
    assert network.REPORT_KEY in REPORT_META


def test_empty_view_pdf_states_that_no_endpoint_was_probed():
    raw = network.build_pdf(_bare())
    assert raw.startswith(b"%PDF-")
    assert len(raw) > 3000
    assert SENTENCE in _visible(raw)


def test_duck_typed_posture_block_marks_unscored_entries_and_keeps_rows_adjacent():
    raw = network.build_pdf(_with_posture())
    visible = _visible(raw)
    assert raw.startswith(b"%PDF-")
    assert len(raw) > 3000
    assert SENTENCE in visible
    assert "reported, not scored" in visible
    assert "api.example:443" in visible
    assert "discrepancy" in visible
    first = visible.index("static server")
    second = visible.index("imported:testssl")
    assert abs(first - second) < 400


def test_rollup_state_field_prints_counts_instead_of_not_assessed():
    """PostureSourceAgg stores ``state``, not ``status``. KPIs must stay numeric."""
    from types import SimpleNamespace

    view = _bare()
    view.included = 1
    view.eligible = 1
    view.posture = SimpleNamespace(
        sources=(
            SimpleNamespace(
                label="tls-protocol-assessment",
                state="assessed",
                reason=None,
                zero_facts=False,
                failed_lanes=(),
            ),
        ),
        facts=(
            {
                "kind": "tls_endpoint",
                "address": "example.com:443",
                "native_type": "tls_result",
                "provider": "testssl_pretty",
                "format": "tls_result",
                "path": "imports/testssl/legacy_protocols.json",
                "finding_codes": ["DOWNGRADE_PROTECTION_MISSING"],
                "net": {
                    "endpoint": "example.com:443",
                    "protocols": {"1.0": "offered"},
                    "downgrade": "missing",
                },
            },
        ),
        imports=(),
    )
    visible = _visible(network.build_pdf(view))
    assert "POSTURE NOT ASSESSED" not in visible
    assert "n/a" not in visible
    assert "imported:testssl_pretty" in visible
    assert "1 of 1 current sources assessed" in visible
