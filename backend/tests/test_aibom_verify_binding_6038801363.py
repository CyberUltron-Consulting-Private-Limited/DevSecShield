"""Review 6038801363 (PR #495) m-1 and nit, through the HTTP routes.

* m-1  POST /{team}/ai_bom/scan/{id}/signature/verify with the scan's own SPDX 3.0 or SARIF 2.1.0 file and its
       X-ZS-Signature said "signed by this deployment but not this scan's file": the N1 binding reads the ``zs:``
       subject the server stamps in a BOM or VEX, and these files carry none. The binding is now the scan's own stored
       bytes: its own file is ``valid: true, bound: true``; another team's file, signed by the same deployment, stays
       ``valid: false``, and so does another scan's of the same team.
* nit  The pack's verify/README.txt lists bom.spdx.json.sig and bom.sarif.sig, with an openssl line.

Run (repo root): backend/.venv/bin/python -m pytest backend/tests/test_aibom_verify_binding_6038801363.py -q
"""
from __future__ import annotations

import copy
import io
import sys
import zipfile
from datetime import datetime, timezone
from pathlib import Path

import pytest
from sqlmodel import Session

sys.path.insert(0, str(Path(__file__).resolve().parent))

from backend.tests import test_aibom_served_files_6036875286 as SERVED  # noqa: E402
from backend.utilities.cbom_sources import bom_signing as SIGN  # noqa: E402

api, ai_api, _key = SERVED.api, SERVED.ai_api, SERVED._key  # the AI BOM scan with SPDX / SARIF, signing key
AUTH = SERVED.AUTH


@pytest.fixture()
def two_teams(ai_api):
    """Team 1's AI BOM scan (``ai_api``), a second AI BOM scan of team 1 and one of team 2, each with its own SPDX
    and SARIF (other bytes: another model name)."""
    from backend.new_models import Scan, Team

    http, base, engine, scan_id = ai_api
    with Session(engine) as session:
        mine = session.get(Scan, scan_id)
        team2 = Team(name="other bank", credit_balance=1.0)
        session.add(team2)
        session.commit()
        session.refresh(team2)
        others = {}
        for label, team_id in (("same-team", mine.team_id), ("other-team", team2.id)):
            data = copy.deepcopy(mine.scan_data)
            data["ai_bom_spdx"]["@graph"][1]["name"] = f"model-of-{label}"
            data["ai_bom_sarif"]["runs"][0]["tool"]["driver"]["name"] = f"DevSecShield AI BOM ({label})"
            now = datetime.now(timezone.utc)
            scan = Scan(team_id=team_id, owner_user_id=mine.owner_user_id, scan_type="ai_bom", title=label,
                        scan_status="success", created_at=now, last_updated=now, scan_data=data)
            session.add(scan)
            session.commit()
            session.refresh(scan)
            others[label] = f"/{team_id}/ai_bom/scan/{scan.id}"
    return http, base, others


def _download(http, route: str) -> tuple[bytes, str]:
    r = http.get(route, headers=AUTH)
    assert r.status_code == 200, r.text
    return r.content, r.headers["x-zs-signature"]


def _verify(http, base: str, body: bytes, signature: str) -> dict:
    r = http.post(f"{base}/signature/verify", content=body,
                  headers={**AUTH, "X-ZS-Signature-B64": signature, "Content-Type": "application/octet-stream"})
    assert r.status_code == 200, r.text
    return r.json()


@pytest.mark.parametrize("artifact", ["spdx", "sarif"])
def test_a_scans_own_spdx_or_sarif_verifies_and_is_bound(two_teams, artifact):
    http, base, _others = two_teams
    body, signature = _download(http, f"{base}/{artifact}")
    out = _verify(http, base, body, signature)
    assert out["valid"] is True and out["bound"] is True and out["signed_by_deployment"] is True, out
    assert out["method"] == "detached ES256"
    assert out["file_subject"]["kind"] == f"ai_bom-{artifact}"
    assert out["file_subject"]["scan_id"] == int(base.rsplit("/", 1)[1])


@pytest.mark.parametrize("artifact", ["spdx", "sarif"])
@pytest.mark.parametrize("whose", ["other-team", "same-team"])
def test_another_scans_file_signed_by_the_same_deployment_is_not_this_scans(two_teams, artifact, whose):
    http, base, others = two_teams
    body, signature = _download(http, f"{others[whose]}/{artifact}")
    out = _verify(http, base, body, signature)  # checked on team 1's first scan
    assert out["valid"] is False and out["signed_by_deployment"] is True and out["bound"] is False, out
    assert out["reason"].startswith("signed by this deployment but not this scan's file")
    # and on its own scan it verifies
    assert _verify(http, others[whose], body, signature)["valid"] is True


def test_an_altered_file_does_not_verify(two_teams):
    http, base, _others = two_teams
    body, signature = _download(http, f"{base}/spdx")
    out = _verify(http, base, body.replace(b"bert", b"BERT"), signature)
    assert out["valid"] is False and out["signed_by_deployment"] is False, out


def test_the_pack_readme_lists_the_spdx_and_sarif_signatures(two_teams):
    http, base, _others = two_teams
    readme = SIGN.readme_text(SIGN.keyring().active)
    assert "bom.spdx.json.sig, bom.sarif.sig" in readme
    assert "-signature bom.spdx.json.sig bom.spdx.json" in readme
    pack = zipfile.ZipFile(io.BytesIO(http.get(f"{base}/evidence-pack", headers=AUTH).content))
    text = pack.read("verify/README.txt").decode("utf-8")
    assert "bom.spdx.json.sig, bom.sarif.sig" in text
    assert {"bom.spdx.json.sig", "bom.sarif.sig"} <= set(pack.namelist())
