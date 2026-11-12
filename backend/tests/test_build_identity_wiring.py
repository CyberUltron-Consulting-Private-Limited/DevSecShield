"""CB-03: the commit an image was built from is baked into it (Dockerfile ARG -> ENV) by the build scripts every
deployment uses: scripts/deploy/build_images.sh (staging.sh, deploy-staging.yml and the local stack) and
scripts/release/scan_node_image.sh (the scan-node release).  docker is stubbed: the test reads the build arguments."""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
pytestmark = pytest.mark.skipif(shutil.which("bash") is None or shutil.which("git") is None, reason="needs bash, git")

FAKE_DOCKER = r"""#!/usr/bin/env python3
import json, os, sys
with open(os.environ["FAKE_DOCKER_LOG"], "a") as f:
    f.write(json.dumps(sys.argv[1:]) + "\n")
sys.exit(0)
"""


def _stages(dockerfile: str) -> list[list[str]]:
    """Instructions per build stage (continuation lines joined)."""
    text = re.sub(r"\\\n", " ", (ROOT / dockerfile).read_text())
    stages: list[list[str]] = [[]]
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.upper().startswith("FROM "):
            stages.append([])
        stages[-1].append(line)
    return stages


def _index(lines: list[str], pattern: str) -> int:
    for i, line in enumerate(lines):
        if re.search(pattern, line):
            return i
    raise AssertionError(f"{pattern!r} not found in {lines}")


def test_backend_image_bakes_the_build_after_the_source_layer():
    final = _stages("backend/Dockerfile")[-1]
    copy = _index(final, r"^COPY \. /backend$")
    assert _index(final, r"^ARG DSS_BUILD_SHA") > copy and _index(final, r"^ARG DSS_BUILD_VERSION") > copy
    env = final[_index(final, r"^ENV DSS_BUILD_SHA")]
    assert "DSS_BUILD_SHA=${DSS_BUILD_SHA}" in env and "DSS_BUILD_VERSION=${DSS_BUILD_VERSION}" in env
    # not in the deps stage: a new commit must not invalidate the virtualenv layer
    assert not any("DSS_BUILD" in line for stage in _stages("backend/Dockerfile")[:-1] for line in stage)


def test_frontend_bakes_the_build_before_next_build():
    builder = next(s for s in _stages("frontend/Dockerfile") if s and " AS builder" in s[0])
    arg = _index(builder, r"^ARG NEXT_PUBLIC_BUILD_SHA")
    assert arg < _index(builder, r"npm run build")
    assert any("NEXT_PUBLIC_BUILD_SHA=$NEXT_PUBLIC_BUILD_SHA" in line for line in builder if line.startswith("ENV "))
    layout = (ROOT / "frontend/app/layout.tsx").read_text()
    assert "buildMeta(process.env.NEXT_PUBLIC_BUILD_SHA)" in layout


def test_scan_node_image_bakes_the_build_after_the_code_layer():
    final = _stages("scan_node/Dockerfile")[-1]
    code = _index(final, r"^COPY zs_scan_node ")
    assert _index(final, r"^ARG ZS_NODE_BUILD") > code and _index(final, r"^ARG ZS_NODE_VERSION") > code
    env = final[_index(final, r"^ENV ZS_NODE_BUILD")]
    assert "ZS_NODE_BUILD=${ZS_NODE_BUILD}" in env and "ZS_NODE_VERSION=${ZS_NODE_VERSION}" in env


def _repo(tmp_path: Path, *rels: str) -> tuple[Path, str, dict]:
    repo = tmp_path / "repo"
    for rel in rels:
        (repo / rel).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / rel, repo / rel)
    (repo / "prod_database_migrations").mkdir(parents=True)
    (repo / "prod_database_migrations/alembic.ini").write_text("[alembic]\n")
    (repo / "scan_node").mkdir(exist_ok=True)
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    (bin_dir / "docker").write_text(FAKE_DOCKER)
    (bin_dir / "docker").chmod(0o755)
    env = {"PATH": f"{bin_dir}:{os.environ['PATH']}", "HOME": str(tmp_path), "FAKE_DOCKER_LOG": str(tmp_path / "log"),
           "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t", "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t",
           "GIT_CONFIG_GLOBAL": "/dev/null"}
    for cmd in (["init", "-q"], ["add", "-A"], ["commit", "-q", "-m", "x"]):
        subprocess.run(["git", "-C", str(repo), *cmd], check=True, env=env, capture_output=True)
    head = subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"], check=True, env=env, capture_output=True,
                          text=True).stdout.strip()
    return repo, head, env


def _builds(env: dict) -> list[list[str]]:
    lines = Path(env["FAKE_DOCKER_LOG"]).read_text().splitlines()
    return [a for a in map(json.loads, lines) if a[:2] == ["buildx", "build"]]


def _args(build: list[str], flag: str) -> list[str]:
    return [build[i + 1] for i, a in enumerate(build) if a == flag]


def test_build_images_passes_the_commit_and_version(tmp_path):
    repo, head, env = _repo(tmp_path, "scripts/deploy/build_images.sh")
    proc = subprocess.run([str(repo / "scripts/deploy/build_images.sh"), "--only", "backend,frontend"],
                          env={**env, "DSS_TAG": "k-ed70ff12e203", "NEXT_PUBLIC_BACKEND_URL": "https://api.dss.test",
                               "DSS_EXPOSE_BUILD": "1"},
                          capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    backend, frontend = _builds(env)
    assert f"DSS_BUILD_SHA={head}" in _args(backend, "--build-arg")
    assert "DSS_BUILD_VERSION=k-ed70ff12e203" in _args(backend, "--build-arg")
    assert f"NEXT_PUBLIC_BUILD_SHA={head}" in _args(frontend, "--build-arg")  # exposed: the page meta names it
    for build in (backend, frontend):  # the OCI label names the same commit
        assert f"org.opencontainers.image.revision={head}" in _args(build, "--label")
    assert f"build {head}" in proc.stdout


def test_build_images_version_override_and_bad_commit(tmp_path):
    repo, head, env = _repo(tmp_path, "scripts/deploy/build_images.sh")
    script = str(repo / "scripts/deploy/build_images.sh")
    ok = subprocess.run([script, "--only", "backend"], env={**env, "DSS_TAG": "t1", "DSS_BUILD_VERSION": "1.4.0"},
                        capture_output=True, text=True, timeout=60)
    assert ok.returncode == 0 and "DSS_BUILD_VERSION=1.4.0" in _args(_builds(env)[-1], "--build-arg")
    bad = subprocess.run([script, "--only", "backend"], env={**env, "DSS_TAG": "t1", "DSS_BUILD_SHA": "abc"},
                         capture_output=True, text=True, timeout=60)
    assert bad.returncode != 0 and "DSS_BUILD_SHA must be a full 40-character commit" in bad.stderr
    bad_version = subprocess.run([script, "--only", "backend"],
                                 env={**env, "DSS_TAG": "t1", "DSS_BUILD_VERSION": "1.4 beta"},
                                 capture_output=True, text=True, timeout=60)
    assert bad_version.returncode != 0 and "DSS_BUILD_VERSION" in bad_version.stderr


def test_frontend_meta_only_when_the_deployment_exposes_the_build(tmp_path):
    """Production default: the sign-in page must not name the commit (PR #72 security review); the backend image
    still carries it for signed-in users (/version), runs and exports."""
    repo, head, env = _repo(tmp_path, "scripts/deploy/build_images.sh")
    proc = subprocess.run([str(repo / "scripts/deploy/build_images.sh"), "--only", "backend,frontend"],
                          env={**env, "DSS_TAG": "t1", "NEXT_PUBLIC_BACKEND_URL": "https://api.example"},
                          capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    backend, frontend = _builds(env)
    assert f"DSS_BUILD_SHA={head}" in _args(backend, "--build-arg")
    assert "NEXT_PUBLIC_BUILD_SHA=" in _args(frontend, "--build-arg")  # empty: no <meta name="zs-build">


@pytest.mark.parametrize("change", ["modified", "untracked"])
def test_a_dirty_tree_never_reports_the_clean_commit(tmp_path, change):
    """PR #72 review: code that is not the commit must not claim it (G0 would pass, exports would lie)."""
    repo, head, env = _repo(tmp_path, "scripts/deploy/build_images.sh")
    if change == "modified":
        (repo / "prod_database_migrations/alembic.ini").write_text("[alembic]\n# edited\n")
    else:
        (repo / "backend").mkdir()
        (repo / "backend/new_file.py").write_text("x = 1\n")
    proc = subprocess.run([str(repo / "scripts/deploy/build_images.sh"), "--only", "backend,frontend"],
                          env={**env, "DSS_TAG": "t1", "NEXT_PUBLIC_BACKEND_URL": "https://api.example",
                               "DSS_EXPOSE_BUILD": "1"}, capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, proc.stderr
    for build in _builds(env):
        args = _args(build, "--build-arg") + _args(build, "--label")
        assert not any(head in a for a in args), args
        assert "org.opencontainers.image.revision=unknown" in _args(build, "--label")
    assert "DSS_BUILD_SHA=" in _args(_builds(env)[0], "--build-arg")
    assert "uncommitted changes" in proc.stdout + proc.stderr
    # an operator who names the commit explicitly takes responsibility for it
    explicit = subprocess.run([str(repo / "scripts/deploy/build_images.sh"), "--only", "backend"],
                              env={**env, "DSS_TAG": "t1", "DSS_BUILD_SHA": head}, capture_output=True, text=True,
                              timeout=60)
    assert explicit.returncode == 0 and f"DSS_BUILD_SHA={head}" in _args(_builds(env)[-1], "--build-arg")


def test_staging_backend_exposes_the_build_only_when_its_env_says_so():
    compose = (ROOT / "deploy/staging/docker-compose.yml").read_text()
    backend = compose[compose.index("\n  backend:\n"):compose.index("\n  cbom-cloud-worker:")]
    assert "DSS_EXPOSE_BUILD: ${DSS_EXPOSE_BUILD:-0}" in backend  # off unless .env says 1


@pytest.mark.parametrize("caller, env_file, exposed", [
    (None, None, False),  # production default: no meta
    ("1", None, True),    # deploy-staging.yml: a runner checkout has no deploy/staging/.env (PR #72 re-review)
    (None, "1", True),    # a build machine whose .env says so (the same .env the staging backend reads)
    ("0", "1", False),    # the caller's explicit choice wins over the file
])
def test_staging_build_takes_the_expose_switch_from_the_caller_then_its_env(tmp_path, caller, env_file, exposed):
    repo, head, env = _repo(tmp_path, "scripts/deploy/staging.sh", "scripts/deploy/build_images.sh", ".gitignore")
    if env_file is not None:  # gitignored (.gitignore: deploy/staging/*.env): the tree stays clean
        (repo / "deploy/staging").mkdir(parents=True)
        (repo / "deploy/staging/.env").write_text(f"DSS_EXPOSE_BUILD={env_file}\n")
    run_env = {**env, "STAGING_COMPONENTS": "frontend", "NEXT_PUBLIC_BACKEND_URL": "https://api.example"}
    if caller is not None:
        run_env["DSS_EXPOSE_BUILD"] = caller
    proc = subprocess.run([str(repo / "scripts/deploy/staging.sh"), "build"], env=run_env, capture_output=True,
                          text=True, timeout=60)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    (frontend,) = _builds(env)
    assert f"NEXT_PUBLIC_BUILD_SHA={head if exposed else ''}" in _args(frontend, "--build-arg")
    assert f"org.opencontainers.image.revision={head}" in _args(frontend, "--label")  # clean either way


def test_staging_workflow_builds_staging_with_the_build_exposed():
    """deploy-staging.yml builds the staging images: by default its frontend names the commit in its meta, so G0
    (meta == /health.build) can pass on workflow-built staging. The workflow's own self-test is
    .github/tests/test_deploy_staging.py; this one runs with the scripts it feeds."""
    wf = (ROOT / ".github/workflows/deploy-staging.yml").read_text()
    build = wf[wf.index("- name: Build images"):wf.index("- name: Save images")]
    assert "DSS_EXPOSE_BUILD: ${{ inputs.expose_build && '1' || '0' }}" in build
    assert "run: scripts/deploy/staging.sh build" in build


def _dirty(repo: Path, change: str) -> None:
    if change == "modified":
        (repo / "prod_database_migrations/alembic.ini").write_text("[alembic]\n# edited\n")
    else:
        (repo / "backend").mkdir(exist_ok=True)
        (repo / "backend/new_file.py").write_text("x = 1\n")


@pytest.mark.parametrize("change", ["modified", "untracked"])
@pytest.mark.parametrize("tag", ["default", "caller"])
def test_a_dirty_build_says_so_in_its_version(tmp_path, change, tag):
    """PR #72 re-review: a dirty image has no commit, so runs record its version (engine_version). That version must
    not look like a clean build's: it ends in "-dirty" whoever chose the tag (the default tag, or deploy-staging.yml's
    DSS_TAG=<sha12>), for modified and untracked files alike, and exactly once."""
    repo, head, env = _repo(tmp_path, "scripts/deploy/build_images.sh")
    _dirty(repo, change)
    extra = {"DSS_TAG": head[:12]} if tag == "caller" else {}
    proc = subprocess.run([str(repo / "scripts/deploy/build_images.sh"), "--only", "backend"], env={**env, **extra},
                          capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    build = _builds(env)[-1]
    assert f"DSS_BUILD_VERSION={head[:12]}-dirty" in _args(build, "--build-arg"), _args(build, "--build-arg")
    image = _args(build, "-t")[0]
    # the default tag is marked by the shared dirty rule; a caller's tag is the caller's
    assert image.endswith(f":{head[:12]}-dirty" if tag == "default" else f":{head[:12]}"), image


def test_dirty_version_marking_edges(tmp_path):
    repo, head, env = _repo(tmp_path, "scripts/deploy/build_images.sh")
    script = str(repo / "scripts/deploy/build_images.sh")
    _dirty(repo, "untracked")

    def version(**extra):
        proc = subprocess.run([script, "--only", "backend"], env={**env, **extra}, capture_output=True, text=True,
                              timeout=60)
        if proc.returncode:
            return proc
        return next(a for a in _args(_builds(env)[-1], "--build-arg") if a.startswith("DSS_BUILD_VERSION="))

    assert version(DSS_TAG="t1", DSS_BUILD_VERSION="1.4.0") == "DSS_BUILD_VERSION=1.4.0-dirty"
    assert version(DSS_TAG="t1", DSS_BUILD_VERSION="1.4.0-dirty") == "DSS_BUILD_VERSION=1.4.0-dirty"  # not twice
    # an operator who names the commit takes responsibility for it: no marker
    assert version(DSS_TAG="t1", DSS_BUILD_SHA=head) == "DSS_BUILD_VERSION=t1"
    # the marker counts toward the 64 characters the backend accepts (build_info._VERSION)
    assert version(DSS_TAG="t1", DSS_BUILD_VERSION="v" * 58) == f"DSS_BUILD_VERSION={'v' * 58}-dirty"
    too_long = version(DSS_TAG="t1", DSS_BUILD_VERSION="v" * 59)
    assert not isinstance(too_long, str) and too_long.returncode != 0 and "-dirty" in too_long.stderr


@pytest.mark.parametrize("case", ["clean", "commit named"])
def test_a_stray_DIRTY_SHA_in_the_environment_marks_nothing(tmp_path, case):
    """PR #72 r7: DIRTY_SHA is the script's own finding (uncommitted changes, no DSS_BUILD_SHA). A DIRTY_SHA that the
    caller's environment happens to export must not mark a clean build, or one whose commit the operator named."""
    repo, head, env = _repo(tmp_path, "scripts/deploy/build_images.sh")
    extra = {"DIRTY_SHA": "x"}
    if case == "commit named":
        _dirty(repo, "untracked")
        extra |= {"DSS_TAG": "t1", "DSS_BUILD_SHA": head}
    proc = subprocess.run([str(repo / "scripts/deploy/build_images.sh"), "--only", "backend"], env={**env, **extra},
                          capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    args = [a for a in _args(_builds(env)[-1], "--build-arg") if a.startswith("DSS_BUILD")]
    version = head[:12] if case == "clean" else "t1"
    assert args == [f"DSS_BUILD_SHA={head}", f"DSS_BUILD_VERSION={version}"], args


def test_staging_default_tag_uses_the_same_dirty_rule(tmp_path):
    """Both default_tag()s (build_images.sh, staging.sh) count untracked files, like the commit check."""
    repo, head, env = _repo(tmp_path, "scripts/deploy/staging.sh", "scripts/deploy/build_images.sh", ".gitignore")
    _dirty(repo, "untracked")
    proc = subprocess.run([str(repo / "scripts/deploy/staging.sh"), "build"],
                          env={**env, "STAGING_COMPONENTS": "backend"}, capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    (backend,) = _builds(env)
    assert _args(backend, "-t") == [f"dss-staging/devsecshield-backend:{head[:12]}-dirty"]
    assert f"DSS_BUILD_VERSION={head[:12]}-dirty" in _args(backend, "--build-arg")


def test_build_images_outside_git_builds_without_identity(tmp_path):
    repo, _head, env = _repo(tmp_path, "scripts/deploy/build_images.sh")
    shutil.rmtree(repo / ".git")
    proc = subprocess.run([str(repo / "scripts/deploy/build_images.sh"), "--only", "backend"],
                          env={**env, "DSS_TAG": "t1"}, capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, proc.stderr
    assert "DSS_BUILD_SHA=" in _args(_builds(env)[-1], "--build-arg")  # empty: the image reports "unknown"
    assert "no git commit" in proc.stdout + proc.stderr


def test_scan_node_release_bakes_the_commit_and_version(tmp_path):
    repo, head, env = _repo(tmp_path, "scripts/release/scan_node_image.sh")
    proc = subprocess.run([str(repo / "scripts/release/scan_node_image.sh"), "build", "1.1.0"],
                          env={**env, "OUT_DIR": str(tmp_path / "out")}, capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    (build,) = _builds(env)
    assert f"ZS_NODE_BUILD={head}" in _args(build, "--build-arg")
    assert "ZS_NODE_VERSION=1.1.0" in _args(build, "--build-arg")  # the node reports 1.1.0+<commit>
    assert f"org.opencontainers.image.revision={head}" in _args(build, "--label")
    # a dirty tree: no commit claimed
    (repo / "scan_node/x.py").write_text("x = 1\n")
    dirty = subprocess.run([str(repo / "scripts/release/scan_node_image.sh"), "build", "1.1.1"],
                           env={**env, "OUT_DIR": str(tmp_path / "out")}, capture_output=True, text=True, timeout=60)
    assert dirty.returncode == 0, dirty.stderr
    last = _builds(env)[-1]
    assert "ZS_NODE_BUILD=" in _args(last, "--build-arg") and not any(head in a for a in last)


@pytest.mark.parametrize("version, ok", [
    ("1.1.0", True), ("1.1", True), ("2.0.0-rc.1", True), ("1234567890123456789", True),  # the node's rule
    ("v1.2", False), ("1.2_rc1", False), ("1.2+meta", False), ("12345678901234567890", False), ("latest", False),
])
def test_scan_node_release_refuses_a_version_the_node_would_not_report(tmp_path, version, ok):
    """PR #72 re-review: the node keeps ZS_NODE_VERSION only when it matches zs_scan_node._VERSION and reports its
    built-in 1.0.0 otherwise, so `build v1.2` would publish an image that says 1.0.0+<commit>. Refused instead."""
    repo, head, env = _repo(tmp_path, "scripts/release/scan_node_image.sh")
    proc = subprocess.run([str(repo / "scripts/release/scan_node_image.sh"), "build", version],
                          env={**env, "OUT_DIR": str(tmp_path / "out")}, capture_output=True, text=True, timeout=60)
    if ok:
        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert f"ZS_NODE_VERSION={version}" in _args(_builds(env)[-1], "--build-arg")
    else:
        assert proc.returncode != 0 and "the scan node reports" in proc.stderr, proc.stdout + proc.stderr
        assert not (tmp_path / "log").exists() or not _builds(env)  # nothing was built


def test_scan_node_release_rule_is_the_nodes_rule():
    """The script's check and the node's regex are one rule written twice (bash and Python): keep them equal."""
    node = (ROOT / "scan_node/zs_scan_node/__init__.py").read_text()
    script = (ROOT / "scripts/release/scan_node_image.sh").read_text()
    rule = re.search(r'_VERSION = re\.compile\(r"(.+?)"\)', node).group(1)
    assert f'NODE_VERSION_RE="^{rule}$"' in script
