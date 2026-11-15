"""#369: Certificate Transparency discovery (``CBOM_CT_DISCOVERY``) was never on in a deployed environment, so saved
domains were never searched. Staging turns it on the same way as ``CBOM_AI_PROVIDER``: the Deploy staging workflow
writes ``STAGING_SET_CBOM_CT_DISCOVERY`` into the host's ``backend.env`` (``BACKEND_ENV_KEYS``). Compose does not set
the variable under ``environment:`` (that entry hides ``env_file``, so the deploy write would never reach the
process). Production keeps the code's default: off. The flag is not a secret."""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from backend.utilities.cbom_sources.kinds import CT_FLAG, ct_discovery_enabled

ROOT = Path(__file__).resolve().parents[2]


def test_staging_writes_ct_discovery_like_the_ai_provider():
    """The workflow defaults the flag to 1 (on) and the deploy script is allowed to write that one key."""
    wf = (ROOT / ".github/workflows/deploy-staging.yml").read_text()
    step = wf.split("- name: Copy and deploy", 1)[1].split("\n      - name:", 1)[0]
    assert f"STAGING_SET_{CT_FLAG}: ${{{{ vars.{CT_FLAG} || '1' }}}}" in step
    assert f"secrets.{CT_FLAG}" not in wf  # not a secret, and not turned on by writing a secret
    script = (ROOT / "scripts/deploy/staging.sh").read_text()
    listed = re.search(r"BACKEND_ENV_KEYS=\(([^)]*)\)", script).group(1).split()
    assert CT_FLAG in listed
    example = (ROOT / "deploy/staging/backend.env.example").read_text()
    assert re.search(rf"(?m)^{CT_FLAG}=$", example)  # empty in the template: the workflow writes 1


def test_compose_does_not_hide_the_backend_env_value():
    """A compose ``environment`` value wins over ``env_file``. Leaving the flag out is what lets backend.env count."""
    compose = yaml.safe_load((ROOT / "deploy/staging/docker-compose.yml").read_text())
    for service, spec in compose["services"].items():
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
    assert f"`{CT_FLAG}`" in section and "BACKEND_ENV_KEYS" in section and "=0" in section
    assert "STAGING_SET_CBOM_CT_DISCOVERY" in section and "deploy-staging.yml" in section
    assert "production" in section.lower() and "ct_discovery_enabled" in section
    assert "secret" in section.lower()
