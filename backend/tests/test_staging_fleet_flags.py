"""#227: fleet onboarding (inventory, policies, managed sources, transports, SSH CA) was built but every flag was off on
staging, so it had never run on a deployed environment. Staging's compose file now turns the five flags on for the two
containers that read them (the API serves the routes; the cloud worker runs the fleet threads while inventory or
policies is on), each one switchable off from the host's .env. Production keeps the code's default: off."""

from __future__ import annotations

from pathlib import Path

import yaml

from backend.utilities.cbom_sources.fleet import flags as fleet_flags
from backend.utilities.cbom_sources.sshca import flags as sshca_flags
from backend.utilities.cbom_sources.transports import flags as transport_flags

ROOT = Path(__file__).resolve().parents[2]
FLAGS = ("CBOM_FLEET_INVENTORY", "CBOM_FLEET_POLICIES", "CBOM_FLEET_MATERIALIZE", "CBOM_FLEET_TRANSPORTS", "CBOM_SSH_CA")


def test_the_five_flags_are_every_fleet_flag_the_code_reads():
    read = set(fleet_flags.ENV.values()) | set(fleet_flags.STATUS_ENV.values()) | {transport_flags.ENV, sshca_flags.ENV}
    assert read == set(FLAGS)


def test_staging_turns_every_fleet_flag_on_for_the_api_and_the_cloud_worker():
    compose = yaml.safe_load((ROOT / "deploy/staging/docker-compose.yml").read_text())
    for service in ("backend", "cbom-cloud-worker"):
        env = compose["services"][service]["environment"]
        for flag in FLAGS:
            # on unless the host's .env says otherwise (CBOM_FLEET_POLICIES=0 in deploy/staging/.env turns it off)
            assert env.get(flag) == f"${{{flag}:-1}}", (service, flag)
    # no other container runs fleet code: the flags are not spread further than they need to be
    for service, spec in compose["services"].items():
        if service not in ("backend", "cbom-cloud-worker"):
            assert not set(FLAGS) & set((spec or {}).get("environment") or {}), service


def test_production_defaults_stay_off(monkeypatch):
    for flag in FLAGS:
        monkeypatch.delenv(flag, raising=False)
    assert fleet_flags.status() == {"inventory": False, "policies": False, "transports": False, "ssh_ca": False}
    assert not fleet_flags.materialize_enabled()
    assert not transport_flags.transports_enabled() and not sshca_flags.enabled()
    local = (ROOT / "deploy/local/.env.example").read_text().splitlines()
    for flag in FLAGS:  # the self-hosted example leaves them unset (off)
        assert f"{flag}=" in local, flag
    for path in ("backend/.env.example", "deploy/staging/backend.env.example"):
        p = ROOT / path
        if p.exists():
            text = p.read_text()
            for flag in FLAGS:
                assert f"{flag}=1" not in text, (path, flag)


def test_staging_readme_documents_the_flags_and_how_to_turn_one_off():
    readme = (ROOT / "deploy/staging/README.md").read_text()
    section = readme.split("## Fleet onboarding on staging", 1)[1].split("\n## ", 1)[0]
    for flag in FLAGS:
        assert f"`{flag}`" in section, flag
    assert "deploy/staging/.env" in section and "=0" in section  # how to turn one off
    assert "production" in section.lower()  # and that production stays off
    assert "GET /1/cbom/sources/fleet/status" in section  # how to check it on the host
