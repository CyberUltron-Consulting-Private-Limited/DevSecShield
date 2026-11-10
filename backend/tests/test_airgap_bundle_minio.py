"""`make airgap-bundle` (STAGING_INCLUDE_INFRA=1 staging.sh save) ships every image an air-gapped site starts.

Found on the local stack (round 5, L1): with the optional local S3 (COMPOSE_PROFILES=minio, the only S3 an air-gapped
site has unless it runs its own) the bundle carried postgres, mongo, rabbitmq and nginx but not MinIO, so
`docker compose up` on the site stopped at "No such image". docker is stubbed: it records what `save` was given.

Run: cd backend && python -m pytest tests/test_airgap_bundle_minio.py -q -p no:cacheprovider
"""
import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
pytestmark = pytest.mark.skipif(shutil.which("bash") is None or shutil.which("gzip") is None,
                                reason="needs bash and gzip")

FAKE_DOCKER = """#!/usr/bin/env bash
case "$1 $2" in
  "image inspect") exit 0 ;;
esac
if [ "$1" = save ]; then shift; printf '%s\\n' "$@" > "$FAKE_SAVE_LOG"; printf 'image-tar'; exit 0; fi
echo "unexpected docker $*" >&2; exit 2
"""


def run_save(tmp_path, env_lines):
    repo = tmp_path / "repo"
    (repo / "scripts" / "deploy").mkdir(parents=True)
    (repo / "deploy" / "staging").mkdir(parents=True)
    shutil.copy(ROOT / "scripts" / "deploy" / "staging.sh", repo / "scripts" / "deploy" / "staging.sh")
    (repo / "deploy" / "staging" / ".env").write_text("DSS_IMAGE_PREFIX=dss-staging\n" + "\n".join(env_lines) + "\n")
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    (bin_dir / "docker").write_text(FAKE_DOCKER)
    (bin_dir / "docker").chmod(0o755)
    log = tmp_path / "save.log"
    env = {"PATH": f"{bin_dir}:{os.environ['PATH']}", "HOME": str(tmp_path), "DSS_TAG": "t1",
           "STAGING_INCLUDE_INFRA": "1", "FAKE_SAVE_LOG": str(log), "LANG": "C"}
    out = subprocess.run(["bash", str(repo / "scripts" / "deploy" / "staging.sh"), "save"], env=env,
                         capture_output=True, text=True, timeout=60)
    assert out.returncode == 0, out.stderr
    assert (repo / "deploy" / "staging" / "images" / "dss-staging-t1.tar.gz.sha256").exists()
    return log.read_text().split()


def test_the_bundle_carries_minio_when_the_site_runs_the_minio_profile(tmp_path):
    saved = run_save(tmp_path, ["COMPOSE_PROFILES=minio", "MINIO_IMAGE=minio/minio:site-mirror"])
    assert "minio/minio:site-mirror" in saved
    assert {"postgres:15-alpine", "mongo:8.0.6", "rabbitmq:4.1-management-alpine", "nginx:1.27-alpine"} <= set(saved)
    assert "dss-staging/devsecshield-backend:t1" in saved


def test_the_default_minio_image_is_used_when_none_is_named(tmp_path):
    saved = run_save(tmp_path, ["COMPOSE_PROFILES=minio"])
    assert "minio/minio:RELEASE.2025-04-22T22-12-26Z" in saved


def test_no_minio_without_the_profile(tmp_path):
    saved = run_save(tmp_path, ["COMPOSE_PROFILES="])
    assert not any(s.startswith("minio/") for s in saved)
