"""Scan the committed tree, render the three PDFs, and run the independent verifier."""

from __future__ import annotations

import json
import subprocess
import sys
from datetime import date, datetime, timezone
from pathlib import Path

_REPO = Path(__file__).resolve().parents[2]
if str(_REPO) not in sys.path:
    sys.path.insert(0, str(_REPO))

from backend.tests.support.pdf_text import pdf_text  # noqa: E402
from backend.utilities.dashboard.cbom_team_rollup import TeamCbomView  # noqa: E402
from backend.utilities.pdf.cbom_data_at_rest_pdf import build_pdf as data_pdf  # noqa: E402
from backend.utilities.pdf.cbom_infra_posture_pdf import build_pdf as infra_pdf  # noqa: E402
from backend.utilities.pdf.cbom_network_tls_pdf import build_pdf as net_pdf  # noqa: E402

_AIBOM = _REPO / "aibom"
TREE = _AIBOM / "tests" / "fixtures" / "synthetic-config-aws-tf"
_SCAN = _AIBOM / ".venv" / "bin" / "python"
VERIFIER = _REPO / "e2e" / "verify" / "verify_posture.py"
_NOW = datetime(2026, 10, 27, 6, 0, tzinfo=timezone.utc)


def _scanned_facts() -> list[dict[str, str]]:
    script = (
        "import json,sys\n"
        "from pathlib import Path\n"
        "from aibom.cbom.pipeline import scan_crypto\n"
        f"result = scan_crypto(Path({str(TREE)!r}))\n"
        "facts=[]\n"
        "for comp in result.components:\n"
        "    props = comp.properties or {}\n"
        "    if comp.kind != 'infra' or 'crypto:factId' not in props:\n"
        "        continue\n"
        "    facts.append({\n"
        "        'id': props.get('crypto:factId') or '',\n"
        "        'kind': props.get('crypto:factKind') or '',\n"
        "        'provider': props.get('crypto:factProvider') or 'aws',\n"
        "        'address': props.get('crypto:factAddress') or props.get('crypto:factNativeType') or '',\n"
        "        'native_type': props.get('crypto:factNativeType') or '',\n"
        "        'at_rest': props.get('crypto:factVerdict') or '',\n"
        "        'location': 'main.tf',\n"
        "        'source': 'fixture',\n"
        "    })\n"
        "json.dump(facts, sys.stdout)\n"
    )
    proc = subprocess.run([str(_SCAN), "-c", script], check=True, capture_output=True, text=True)
    return json.loads(proc.stdout)


def _view() -> TeamCbomView:
    facts = _scanned_facts()
    view = TeamCbomView(
        team_id=1,
        team_name="Fixture",
        generated_at=_NOW,
        as_of=date(2026, 10, 27),
        fingerprint="fixture01",
    )
    view.posture = {
        "facts": facts,
        "counts": {
            "facts": len(facts),
            "at_rest": {
                "NOT_ENCRYPTED": sum(1 for fact in facts if fact["at_rest"] == "NOT_ENCRYPTED"),
                "ENCRYPTED_PROVIDER_DEFAULT": sum(
                    1 for fact in facts if fact["at_rest"] == "ENCRYPTED_PROVIDER_DEFAULT"
                ),
            },
        },
        "sources": [{"label": "fixture", "status": "assessed", "fact_count": len(facts)}],
    }
    return view


def _pdf_text(tmp: Path) -> Path:
    view = _view()
    chunks = []
    for builder in (infra_pdf, net_pdf, data_pdf):
        raw = builder(view)
        assert raw.startswith(b"%PDF-")
        assert len(raw) > 3000
        path = tmp / f"{builder.__module__.rsplit('.', 1)[-1]}.pdf"
        path.write_bytes(raw)
        chunks.append(pdf_text(raw))
    text = tmp / "pdf.txt"
    text.write_text("\n".join(chunks), encoding="utf-8")
    return text


def _run(terraform: Path, pdf: Path, *, expect_fail: bool) -> subprocess.CompletedProcess[str]:
    command = [sys.executable, str(VERIFIER), str(terraform), str(pdf)]
    if expect_fail:
        command.append("--expect-fail")
    return subprocess.run(command, check=False, capture_output=True, text=True)


def test_fixture_scan_pdfs_pass_the_independent_verifier(tmp_path: Path) -> None:
    pdf = _pdf_text(tmp_path)
    result = _run(TREE / "main.tf", pdf, expect_fail=False)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "PASS" in result.stdout


def test_ten_negative_controls_fail(tmp_path: Path) -> None:
    original = _pdf_text(tmp_path).read_text(encoding="utf-8")
    mutations = (
        original.replace("Not encrypted", "Encrypted"),
        original.replace("aws_db_instance", "aws_instance"),
        original.replace("aws_s3_bucket", "aws_bucket"),
        original.replace("declared configuration is not proof of operation", ""),
        original.replace("The platform did not probe any endpoint", ""),
        original.replace("stored data was not inspected", ""),
        original.replace("Encrypted (provider default)", ""),
        original.replace("main.tf", "other.tf"),
        original + "\nCANARY_PRIVATE_KEY\n",
        "",
    )
    assert len(mutations) == 10
    for index, text in enumerate(mutations):
        path = tmp_path / f"bad-{index}.txt"
        path.write_text(text, encoding="utf-8")
        result = _run(TREE / "main.tf", path, expect_fail=True)
        assert result.returncode == 0, index
