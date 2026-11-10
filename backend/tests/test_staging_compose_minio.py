"""deploy/staging/docker-compose.yml with the optional MinIO profile, as `make up` / `staging.sh deploy` run it.

Found on the local production stack (round 5, L1):
* `make up` with COMPOSE_PROFILES=minio failed every time: `up --wait` treats the one-shot minio-init, which nothing
  depended on, as a failure ("container minio-init exited (0)"); staging.sh deploy uses the same `up --wait`;
* MinIO's root user came from Compose interpolation of ${AWS_ACCESS_KEY_ID}, which prefers the caller's shell
  environment over --env-file: with AWS credentials exported in the operator's shell, MinIO started with those and
  the backend (env_file .env) got InvalidAccessKeyId on every S3 call;
* the health check needed `mc`, which an image built from the MinIO source does not have (the default image can no
  longer be pulled from Docker Hub).

Run: cd backend && python -m pytest tests/test_staging_compose_minio.py -q -p no:cacheprovider
"""
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parents[2]
COMPOSE = REPO / "deploy" / "staging" / "docker-compose.yml"


@pytest.fixture(scope="module")
def services():
    return yaml.safe_load(COMPOSE.read_text())["services"]


def test_the_api_waits_for_the_bucket_so_up_wait_accepts_the_one_shot(services):
    dep = services["backend"]["depends_on"]["minio-init"]
    assert dep["condition"] == "service_completed_successfully"
    assert dep["required"] is False  # without the profile the dependency is ignored


def test_minio_root_credentials_come_from_the_env_file_not_interpolation(services):
    minio = services["minio"]
    assert ".env" in [e if isinstance(e, str) else e.get("path") for e in minio["env_file"]]
    env = minio.get("environment") or {}
    assert "MINIO_ROOT_USER" not in env and "MINIO_ROOT_PASSWORD" not in env
    entry = " ".join(minio["entrypoint"])
    assert 'MINIO_ROOT_USER="$$AWS_ACCESS_KEY_ID"' in entry and 'MINIO_ROOT_PASSWORD="$$AWS_SECRET_ACCESS_KEY"' in entry
    assert "minio server /data" in entry


def test_minio_health_check_does_not_need_mc(services):
    test = services["minio"]["healthcheck"]["test"]
    assert test[0] == "CMD-SHELL"
    assert "mc ready local" in test[1] and "/minio/health/live" in test[1] and "/dev/tcp/127.0.0.1/9000" in test[1]


@pytest.mark.skipif(shutil.which("docker") is None, reason="docker CLI not installed")
def test_an_exported_shell_aws_key_does_not_reach_minio(tmp_path):
    """`docker compose config` resolves interpolation without a daemon: the rendered MinIO service must not carry the
    shell's AWS key (it reads the .env pair inside the container)."""
    env_file = tmp_path / ".env"
    env_file.write_text("DSS_TAG=t\nPG_USER=u\nPG_USER_PASS=p\nPG_DB=d\nMONGO_INITDB_ROOT_USERNAME=m\n"
                        "MONGO_INITDB_ROOT_PASSWORD=m\nRABBIT_ADMIN_USERNAME=r\nRABBIT_ADMIN_PASSWORD=r\n"
                        "COMPOSE_PROFILES=minio\nAWS_ACCESS_KEY_ID=from-env-file\nAWS_SECRET_ACCESS_KEY=secret-from-file\n")
    (tmp_path / "backend.env").write_text("")
    staged = tmp_path / "docker-compose.yml"
    staged.write_text(COMPOSE.read_text())
    import os
    env = {**os.environ, "AWS_ACCESS_KEY_ID": "from-the-shell", "AWS_SECRET_ACCESS_KEY": "shell-secret"}
    out = subprocess.run(["docker", "compose", "--project-directory", str(tmp_path), "-f", str(staged),
                          "--env-file", str(env_file), "config", "--format", "json"],
                         capture_output=True, text=True, env=env, timeout=60)
    if out.returncode != 0:
        pytest.skip(f"docker compose config unavailable: {out.stderr.strip()[:200]}")
    import json
    minio = json.loads(out.stdout)["services"]["minio"]
    rendered = json.dumps(minio)
    assert "from-the-shell" not in rendered and "shell-secret" not in rendered
