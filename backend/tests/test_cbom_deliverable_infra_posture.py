"""WP11a: Infrastructure & Cloud Encryption Posture PDF (#5)."""

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
from backend.utilities.pdf import cbom_infra_posture_pdf as infra  # noqa: E402
from backend.utilities.pdf import cbom_posture_text as authored  # noqa: E402
from backend.utilities.pdf.report_branding import REPORT_META  # noqa: E402

SENTENCE = "declared configuration is not proof of operation"
_NOW = datetime(2026, 10, 26, 8, 0, tzinfo=timezone.utc)
_TEXT_PATH = _REPO_ROOT / "backend" / "utilities" / "pdf" / "cbom_posture_text.py"
_BANNED = ("bedrock", "anthropic", "openai", "get_llm", "chatbedrock")


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
        "sources": [{"label": "payments", "status": "assessed", "fact_count": 1}],
        "facts": [
            {
                "id": "bucket-a",
                "kind": "object_store",
                "provider": "aws",
                "address": "bucket-a",
                "native_type": "aws_s3_bucket",
                "at_rest": "NOT_ENCRYPTED",
                "impact": "High",
                "finding_codes": ["UNENCRYPTED_AT_REST"],
                "location": "main.tf:10",
                "source": "payments",
            },
            {
                "id": "key-1",
                "kind": "kms_key",
                "provider": "aws",
                "address": "alias/app",
                "specification": "SYMMETRIC_DEFAULT",
                "usage": "ENCRYPT_DECRYPT",
                "protection": "hsm",
                "rotation": "disabled",
                "deletion_protection": "off",
                "exposure": "public",
                "location": "kms.tf:2",
                "source": "payments",
                "finding_codes": ["KMS_KEY_POLICY_PUBLIC"],
                "impact": "High",
            },
        ],
        "counts": {
            "facts": 2,
            "at_rest": {"NOT_ENCRYPTED": 1},
            "findings_by_code": {"UNENCRYPTED_AT_REST": 1, "KMS_KEY_POLICY_PUBLIC": 1},
            "findings_by_severity": {"High": 2, "Medium": 0, "Low": 0},
            "kms": {"keys": 1, "rotation_enabled": 0, "rotation_disabled": 1},
            "out_of_scope_resources": 0,
            "disabled_resources": 0,
        },
        "data_tables": [
            {"name": "defaults-registry", "data_version": "1", "valid_as_of": "2026-01-01"}
        ],
    }
    return view


def _visible(raw: bytes) -> str:
    """Text from the content-stream reader in ``backend/tests/support/pdf_text.py``."""
    return re.sub(r"\s+", " ", pdf_text(raw))


def test_report_key_and_ten_finding_actions():
    assert infra.REPORT_KEY == "cbom_infra_posture"
    assert infra.REPORT_KEY in REPORT_META
    assert list(authored.FINDING_LABELS) == list(authored.FINDING_CODES)
    assert set(authored.FINDING_ACTIONS) == set(authored.FINDING_CODES)
    assert len(authored.FINDING_CODES) == 10
    for action in authored.FINDING_ACTIONS.values():
        assert "\n" not in action
        assert action.endswith(".")
    source = _TEXT_PATH.read_text(encoding="utf-8").lower()
    for token in _BANNED:
        assert token not in source
    assert re.search(r"\bllm\b", source) is None
    assert re.search(r"\bnetwork\b", source) is None


def test_empty_view_pdf_contains_the_limits_sentence():
    raw = infra.build_pdf(_bare())
    assert raw.startswith(b"%PDF-")
    assert len(raw) > 3000
    assert SENTENCE in _visible(raw)


def test_duck_typed_posture_block_renders_the_same_sentence():
    raw = infra.build_pdf(_with_posture())
    assert raw.startswith(b"%PDF-")
    assert len(raw) > 3000
    visible = _visible(raw)
    assert SENTENCE in visible
    assert "bucket-a" in visible
    assert "alias/app" in visible
    assert "Posture coverage: 1 of 1 current sources assessed; 0 not assessed" in visible
