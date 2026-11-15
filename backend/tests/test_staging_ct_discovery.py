"""#369: Certificate Transparency discovery (``CBOM_CT_DISCOVERY``) was never on in a deployed environment, so saved
domains were never searched. Staging's compose file now turns it on for the two containers that read it (the API
says it is on and accepts a ct_logs source; the cloud worker runs the searches), switchable off from the host's .env.
Production keeps the code's default: off."""

from __future__ import annotations

from pathlib import Path

import yaml

from backend.utilities.cbom_sources.kinds import CT_FLAG, ct_discovery_enabled

ROOT = Path(__file__).resolve().parents[2]


def test_staging_turns_ct_discovery_on_for_the_api_and_the_cloud_worker():
    compose = yaml.safe_load((ROOT / "deploy/staging/docker-compose.yml").read_text())
    for service in ("backend", "cbom-cloud-worker"):
        assert compose["services"][service]["environment"].get(CT_FLAG) == "${CBOM_CT_DISCOVERY:-1}", service
    for service, spec in compose["services"].items():
        if service not in ("backend", "cbom-cloud-worker"):
            assert CT_FLAG not in ((spec or {}).get("environment") or {}), service


def test_production_default_stays_off(monkeypatch):
    monkeypatch.delenv(CT_FLAG, raising=False)
    assert ct_discovery_enabled() is False
    for path in ("backend/.env.example", "deploy/staging/backend.env.example", "deploy/local/.env.example"):
        p = ROOT / path
        if p.exists():
            assert f"{CT_FLAG}=1" not in p.read_text(), path


def test_staging_readme_documents_ct_discovery():
    readme = (ROOT / "deploy/staging/README.md").read_text()
    section = readme.split("## Certificate Transparency discovery on staging", 1)[1].split("\n## ", 1)[0]
    assert f"`{CT_FLAG}`" in section and "deploy/staging/.env" in section and "=0" in section
    assert "production" in section.lower() and "ct_discovery_enabled" in section
