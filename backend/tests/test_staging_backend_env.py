"""`staging.sh push` forwards the AWS collector identity and the lab switch (STAGING_SET_<KEY>, from the `staging`
environment's secrets in the Deploy staging workflow) to the host, where `staging.sh backend-env` sets exactly those
keys in backend.env before the deploy: only the keys provided, never a value in a log or on a command line,
idempotent, atomic, the file's mode kept. Staging's compose file says DSS_ENV=staging to the containers that decide
lab mode (lab_mode.py refuses it anywhere else).

docker, ssh and scp are stubs (test_deploy_staging_script.py, test_staging_deploy_disk.py)."""

from __future__ import annotations

import os
import re
import shutil
import stat
import subprocess
from pathlib import Path

import pytest
import yaml
from test_deploy_staging_script import BASH, ROOT, Host, failed, ok
from test_staging_deploy_disk import IMG, NEED, ShortHost, build_machine

pytestmark = pytest.mark.skipif(BASH is None or shutil.which("tar") is None, reason="needs bash and tar")

# Look like the real thing, are not: fixed test strings (the scripts must never print or pass them on a command line).
KEY_ID = "AKIATESTONLYNOTAKEY01"
SECRET = "testOnly/NotASecret+0123456789abcdefghijKL"
ARN = "arn:aws:iam::935951870001:user/devsecshield/devsecshield-developer"
KEYS = ("CBOM_AWS_ACCESS_KEY_ID", "CBOM_AWS_SECRET_ACCESS_KEY", "CBOM_AWS_PRINCIPAL_ARN", "CBOM_AWS_LAB_SAME_ACCOUNT")


def env_of(path: Path) -> list[str]:
    return path.read_text().splitlines()


def set_env(host: Host, text: str):
    return subprocess.run([BASH, str(host.root / "scripts/deploy/staging.sh"), "backend-env"], cwd=host.root,
                          input=text, capture_output=True, text=True, timeout=60,
                          env={"PATH": os.environ["PATH"], "HOME": str(host.root), "TMPDIR": str(host.root), "LANG": "C"})


@pytest.fixture
def host(tmp_path):
    h = Host(tmp_path, {"t1": ["r1"]})
    (h.root / "deploy/staging/backend.env").write_text(
        "JWT_SECRET_KEY=test-only-not-a-secret\n# AWS\nCBOM_AWS_ACCESS_KEY_ID=\nCBOM_AWS_SECRET_ACCESS_KEY=\n"
        "CBOM_AWS_PRINCIPAL_ARN=\nCBOM_AWS_PRINCIPAL_ARN=arn:aws:iam::000000000000:role/dup\nEMAIL_SENDER=x@zeroshield.test\n")
    (h.root / "deploy/staging/backend.env").chmod(0o640)
    return h


def test_sets_exactly_the_given_keys_in_place_and_keeps_everything_else(host):
    path = host.root / "deploy/staging/backend.env"
    proc = ok(set_env(host, f"CBOM_AWS_ACCESS_KEY_ID={KEY_ID}\nCBOM_AWS_SECRET_ACCESS_KEY={SECRET}\n"
                            f"CBOM_AWS_PRINCIPAL_ARN={ARN}\nCBOM_AWS_LAB_SAME_ACCOUNT=1\n"))
    assert env_of(path) == ["JWT_SECRET_KEY=test-only-not-a-secret", "# AWS", f"CBOM_AWS_ACCESS_KEY_ID={KEY_ID}",
                            f"CBOM_AWS_SECRET_ACCESS_KEY={SECRET}", f"CBOM_AWS_PRINCIPAL_ARN={ARN}",
                            "EMAIL_SENDER=x@zeroshield.test", "CBOM_AWS_LAB_SAME_ACCOUNT=1"]
    assert stat.S_IMODE(path.stat().st_mode) == 0o640  # the mode is kept
    out = proc.stdout + proc.stderr
    assert KEY_ID not in out and SECRET not in out and ARN not in out  # key names only
    assert "CBOM_AWS_SECRET_ACCESS_KEY" in out and "set in backend.env" in out
    assert not list(path.parent.glob(".backend.env.*"))  # no temporary file left


def test_is_idempotent_and_skips_keys_not_provided(host):
    path = host.root / "deploy/staging/backend.env"
    ok(set_env(host, f"CBOM_AWS_PRINCIPAL_ARN={ARN}\n"))
    before = path.read_text()
    inode = path.stat().st_ino
    proc = ok(set_env(host, f"CBOM_AWS_PRINCIPAL_ARN={ARN}\nCBOM_AWS_ACCESS_KEY_ID=\n"))
    assert path.read_text() == before and path.stat().st_ino == inode  # unchanged: not even rewritten
    assert "already set; backend.env unchanged" in proc.stdout
    assert "CBOM_AWS_ACCESS_KEY_ID=" in env_of(path)  # empty = not provided: the host's (empty) value stays
    ok(set_env(host, ""))
    assert path.read_text() == before


@pytest.mark.parametrize("text, message", [
    ("JWT_SECRET_KEY=evil\n", "is not one of"),
    ("CBOM_AWS_PRINCIPAL_ARN=arn with spaces\n", "characters an env file cannot hold"),
    ("CBOM_AWS_SECRET_ACCESS_KEY=a'b\n", "characters an env file cannot hold"),
    ("CBOM_AWS_SECRET_ACCESS_KEY=$(touch pwned)\n", "characters an env file cannot hold"),
    ("not a pair\n", "without KEY=VALUE"),
])
def test_refuses_other_keys_and_unsafe_values_without_changing_anything(host, text, message):
    path = host.root / "deploy/staging/backend.env"
    before = path.read_text()
    proc = failed(set_env(host, text))
    assert message in proc.stderr and path.read_text() == before
    assert "a'b" not in proc.stderr and "touch pwned" not in proc.stderr and not (host.root / "pwned").exists()


def test_push_forwards_only_provided_keys_over_stdin_and_never_logs_them(tmp_path):
    h = ShortHost(tmp_path, free=NEED + IMG)
    build = build_machine(tmp_path, h)
    env = {"PATH": f"{h.root / 'bin'}:{os.environ['PATH']}", "HOME": str(h.root), "TMPDIR": str(h.root),
           "LANG": "C", "FAKE_DOCKER_STATE": str(h.state_file), "STAGING_CONTAINERD_ROOT": str(h.store),
           "FAKE_SSH_LOG": str(h.root / "ssh.log"), "DSS_TAG": "t3", "SSH_OPTS": "-o BatchMode=yes",
           "STAGING_SET_CBOM_AWS_ACCESS_KEY_ID": KEY_ID, "STAGING_SET_CBOM_AWS_SECRET_ACCESS_KEY": SECRET,
           "STAGING_SET_CBOM_AWS_PRINCIPAL_ARN": ARN, "STAGING_SET_CBOM_AWS_LAB_SAME_ACCOUNT": "",  # not provided
           "CBOM_AWS_LAB_SAME_ACCOUNT": "1"}  # an operator's own shell variable is never forwarded
    proc = ok(subprocess.run([BASH, str(build / "scripts/deploy/staging.sh"), "push", "deploy@stage", str(h.root)],
                             cwd=build, env=env, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=180))
    lines = env_of(h.root / "deploy/staging/backend.env")
    assert f"CBOM_AWS_ACCESS_KEY_ID={KEY_ID}" in lines and f"CBOM_AWS_SECRET_ACCESS_KEY={SECRET}" in lines
    assert f"CBOM_AWS_PRINCIPAL_ARN={ARN}" in lines and not any(ln.startswith("CBOM_AWS_LAB_SAME_ACCOUNT") for ln in lines)
    calls = (h.root / "ssh.log").read_text()
    out = proc.stdout + proc.stderr + calls
    assert KEY_ID not in out and SECRET not in out and ARN not in out  # not in the log, not on any command line
    deploy = [c for c in calls.splitlines() if "staging.sh deploy" in c]
    assert len(deploy) == 1 and "staging.sh backend-env && " in deploy[0]  # set just before the deploy, same session
    assert "deployed t3" in proc.stdout


def test_push_without_keys_leaves_backend_env_alone(tmp_path):
    h = ShortHost(tmp_path, free=NEED + IMG)
    build = build_machine(tmp_path, h)
    before = (h.root / "deploy/staging/backend.env").read_text()
    env = {"PATH": f"{h.root / 'bin'}:{os.environ['PATH']}", "HOME": str(h.root), "TMPDIR": str(h.root),
           "LANG": "C", "FAKE_DOCKER_STATE": str(h.state_file), "STAGING_CONTAINERD_ROOT": str(h.store),
           "FAKE_SSH_LOG": str(h.root / "ssh.log"), "DSS_TAG": "t3", "SSH_OPTS": "-o BatchMode=yes"}
    ok(subprocess.run([BASH, str(build / "scripts/deploy/staging.sh"), "push", "deploy@stage", str(h.root)],
                      cwd=build, env=env, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=180))
    assert (h.root / "deploy/staging/backend.env").read_text() == before
    assert "backend-env" not in (h.root / "ssh.log").read_text()


def test_the_workflow_passes_the_staging_secrets_to_push_only():
    wf = (ROOT / ".github/workflows/deploy-staging.yml").read_text()
    step = wf.split("- name: Copy and deploy", 1)[1].split("\n      - name:", 1)[0]
    for key in KEYS[:3]:
        assert f"STAGING_SET_{key}: ${{{{ secrets.{key} }}}}" in step, key
    assert "STAGING_SET_CBOM_AWS_LAB_SAME_ACCOUNT: ${{ vars.CBOM_AWS_LAB_SAME_ACCOUNT || secrets.CBOM_AWS_LAB_SAME_ACCOUNT }}" in step
    assert len(re.findall(r"secrets\.CBOM_AWS_", wf)) == 4  # nowhere else (not in the build job)
    assert not re.search(r"(?m)^\s*(set -x|echo .*STAGING_SET_)", step)


def test_staging_compose_says_staging_to_the_containers_that_decide_lab_mode():
    compose = yaml.safe_load((ROOT / "deploy/staging/docker-compose.yml").read_text())
    for service in ("backend", "cbom-cloud-worker"):
        assert compose["services"][service]["environment"]["DSS_ENV"] == "staging", service


def test_backend_env_keys_are_the_documented_ones():
    script = (ROOT / "scripts/deploy/staging.sh").read_text()
    assert f"BACKEND_ENV_KEYS=({' '.join(KEYS)})" in script
    example = (ROOT / "deploy/staging/backend.env.example").read_text()
    for key in KEYS:
        assert re.search(rf"(?m)^{key}=$", example), key
