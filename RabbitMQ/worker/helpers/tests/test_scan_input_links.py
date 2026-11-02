"""Scan inputs never materialise a symbolic link on the worker.

A repository or an uploaded zip is attacker-controlled: a committed ``key.pem -> /proc/self/environ`` must reach
the engine as a plain file holding the target path, never as a link it could follow.
"""

import os
import shutil
import stat
import subprocess
import tempfile
import zipfile
from pathlib import Path

import pytest

from helpers.context.scan_context import CLONE_GIT_ENV, clone_repo, safe_extract_zip

_VCS = shutil.which("git")


def _vcs(*args: str, cwd: Path) -> None:
    subprocess.run([_VCS, *args], cwd=cwd, check=True, capture_output=True,
                   env={**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.invalid",
                        "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.invalid"})


@pytest.mark.skipif(_VCS is None, reason="git binary not installed")
def test_clone_checks_links_out_as_plain_files(tmp_path: Path) -> None:
    src = tmp_path / "src"
    src.mkdir()
    _vcs("init", "-q", "-b", "main", cwd=src)
    (src / "app.py").write_text("print('hi')\n")
    os.symlink("/proc/self/environ", src / "key.pem")
    _vcs("add", "-A", cwd=src)
    _vcs("commit", "-q", "-m", "seed", cwd=src)

    out = clone_repo(f"file://{src}", branch="main")
    try:
        checked_out = out / "key.pem"
        assert not checked_out.is_symlink()
        assert stat.S_ISREG(os.lstat(checked_out).st_mode)
        assert checked_out.read_text() == "/proc/self/environ"  # the link's target path, not the environment
    finally:
        shutil.rmtree(out, ignore_errors=True)


def test_clone_env_sets_core_symlinks_false() -> None:
    assert CLONE_GIT_ENV == {"GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "core.symlinks",
                             "GIT_CONFIG_VALUE_0": "false"}


def test_zip_symlink_entry_extracts_as_a_plain_file(tmp_path: Path) -> None:
    archive = tmp_path / "in.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        info = zipfile.ZipInfo("deploy/key.pem")
        info.create_system = 3  # unix
        info.external_attr = (stat.S_IFLNK | 0o777) << 16
        zf.writestr(info, "/proc/self/environ")
        zf.writestr("app.py", "print('hi')\n")
    dest = Path(tempfile.mkdtemp(dir=tmp_path))
    safe_extract_zip(str(archive), str(dest))
    extracted = dest / "deploy" / "key.pem"
    assert not extracted.is_symlink()
    assert stat.S_ISREG(os.lstat(extracted).st_mode)
    assert extracted.read_text() == "/proc/self/environ"
