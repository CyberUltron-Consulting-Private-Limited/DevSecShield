"""Nuclei must never leave Chrome behind after a DAST scan.

Prod 2026-08-26: dast-worker held 10.6GiB / 2268 Chrome PIDs (1598 orphaned
to PID 1) while Celery was idle. killpg ran only on Nuclei timeout.
"""

from __future__ import annotations

import signal
import subprocess
from pathlib import Path

from helpers.agent.context import AuthRequirements, StartDASTScanData
from helpers.agent.main import DASTAgent
from helpers.checks.nuclei import run_nuclei as nuclei_mod


REPO_ROOT = Path(__file__).resolve().parents[4]
DAST_DOCKERFILE = Path(__file__).resolve().parents[2] / "Dockerfile"
WORKER_COMPOSE = REPO_ROOT / "compose" / "worker-compose" / "docker-compose.yml"


def _template(tmp_path: Path) -> str:
    path = tmp_path / "t.yaml"
    path.write_text("id: t\ninfo:\n  name: t\nheadless: []\n")
    return str(path)


class _FakeProc:
    def __init__(self, returncode=0, *, on_communicate=None):
        self.returncode = returncode
        self.pid = 4242
        self._on_communicate = on_communicate
        self.killed = False

    def communicate(self, timeout=None):
        if self._on_communicate:
            return self._on_communicate()
        return b"", b""

    def wait(self, timeout=None):
        return self.returncode

    def kill(self):
        self.killed = True


def _scan_context() -> StartDASTScanData:
    return StartDASTScanData(
        target_url="https://example.com",
        auth=AuthRequirements(
            login_url="https://example.com/login",
            xpath_of_username_field="//user",
            xpath_of_password_field="//pass",
            username="u",
            password="p",
            xpath_of_submit_button="//go",
        ),
        scan_speed="fast",
        max_urls=1,
    )


def test_run_nuclei_kills_process_group_on_success(monkeypatch, tmp_path):
    killed = []
    monkeypatch.setattr(
        nuclei_mod.subprocess, "Popen", lambda *_a, **_k: _FakeProc(0)
    )
    monkeypatch.setattr(nuclei_mod, "load_dir_to_documents", lambda _p: [])
    monkeypatch.setattr(
        nuclei_mod, "_kill_process_group", lambda proc: killed.append(proc.pid)
    )
    monkeypatch.setattr(nuclei_mod, "_reap_new_browser_pids", lambda _before: 0)
    nuclei_mod.run_nuclei("https://example.com", _template(tmp_path), timeout_seconds=5)
    assert killed == [4242]


def test_run_nuclei_kills_process_group_on_nonzero_exit(monkeypatch, tmp_path):
    killed = []
    monkeypatch.setattr(
        nuclei_mod.subprocess, "Popen", lambda *_a, **_k: _FakeProc(1)
    )
    monkeypatch.setattr(
        nuclei_mod, "_kill_process_group", lambda proc: killed.append(proc.pid)
    )
    monkeypatch.setattr(nuclei_mod, "_reap_new_browser_pids", lambda _before: 0)
    nuclei_mod.run_nuclei("https://example.com", _template(tmp_path), timeout_seconds=5)
    assert killed == [4242]


def test_run_nuclei_kills_process_group_on_exception(monkeypatch, tmp_path):
    killed = []

    def _boom():
        raise RuntimeError("nuclei exploded")

    monkeypatch.setattr(
        nuclei_mod.subprocess, "Popen", lambda *_a, **_k: _FakeProc(0, on_communicate=_boom)
    )
    monkeypatch.setattr(
        nuclei_mod, "_kill_process_group", lambda proc: killed.append(proc.pid)
    )
    monkeypatch.setattr(nuclei_mod, "_reap_new_browser_pids", lambda _before: 0)
    result = nuclei_mod.run_nuclei(
        "https://example.com", _template(tmp_path), timeout_seconds=5
    )
    assert result == []
    assert killed == [4242]


def test_run_nuclei_kills_process_group_on_timeout(monkeypatch, tmp_path):
    killed = []

    def _timeout():
        raise subprocess.TimeoutExpired(cmd="nuclei", timeout=1)

    monkeypatch.setattr(
        nuclei_mod.subprocess,
        "Popen",
        lambda *_a, **_k: _FakeProc(0, on_communicate=_timeout),
    )
    monkeypatch.setattr(
        nuclei_mod, "_kill_process_group", lambda proc: killed.append(proc.pid)
    )
    monkeypatch.setattr(nuclei_mod, "_reap_new_browser_pids", lambda _before: 0)
    result = nuclei_mod.run_nuclei(
        "https://example.com", _template(tmp_path), timeout_seconds=5
    )
    assert result == []
    assert killed == [4242]


def test_reap_new_browser_pids_only_kills_new_chrome(monkeypatch):
    reaped = []
    monkeypatch.setattr(nuclei_mod, "_browser_pids", lambda: {100, 200, 201})
    monkeypatch.setattr(nuclei_mod, "_kill_pid", lambda pid: reaped.append(pid))
    monkeypatch.setattr(nuclei_mod, "_reap_enabled", lambda: True)
    n = nuclei_mod._reap_new_browser_pids({100})
    assert n == 2
    assert sorted(reaped) == [200, 201]


def test_reap_orphan_browsers_kills_ppid1_chrome_only_when_enabled():
    procs = [
        (10, 1, "chrome", "S"),
        (11, 99, "chrome", "S"),
        (12, 1, "celery", "S"),
        (13, 1, "chrome-headless", "Z"),
    ]
    killed = []
    n = nuclei_mod.reap_orphan_browsers(
        enabled=True,
        iter_procs=lambda: procs,
        kill_fn=lambda pid: killed.append(pid),
    )
    assert n == 2
    assert killed == [10, 13]


def test_reap_orphan_browsers_is_noop_outside_docker():
    killed = []
    n = nuclei_mod.reap_orphan_browsers(
        enabled=False,
        iter_procs=lambda: [(10, 1, "chrome", "S")],
        kill_fn=lambda pid: killed.append(pid),
    )
    assert n == 0
    assert killed == []


def test_dast_agent_run_reaps_orphan_browsers_on_success(monkeypatch):
    called = {"n": 0}

    class FakeCrawler:
        def __init__(self, **_kwargs):
            self.metadata = {"urls_included": ["https://example.com/"], "urls_excluded": []}

        def crawl(self):
            return ["https://example.com/"]

    monkeypatch.setattr("helpers.agent.main.Crawler", FakeCrawler)
    monkeypatch.setattr(
        "helpers.agent.main.reap_orphan_browsers", lambda: called.__setitem__("n", called["n"] + 1)
    )
    agent = DASTAgent(dast_context=_scan_context())
    monkeypatch.setattr(agent, "_scan_url", lambda _url: [])
    agent.run()
    assert called["n"] == 1


def test_dast_agent_run_reaps_orphan_browsers_on_failure(monkeypatch):
    called = {"n": 0}

    class FakeCrawler:
        def __init__(self, **_kwargs):
            self.metadata = {"urls_included": [], "urls_excluded": []}

        def crawl(self):
            return []

    monkeypatch.setattr("helpers.agent.main.Crawler", FakeCrawler)
    monkeypatch.setattr(
        "helpers.agent.main.reap_orphan_browsers", lambda: called.__setitem__("n", called["n"] + 1)
    )
    agent = DASTAgent(dast_context=_scan_context())
    try:
        agent.run()
    except Exception:
        pass
    assert called["n"] == 1


def test_kill_process_group_sends_sigkill_to_pgid(monkeypatch):
    sent = []
    proc = _FakeProc(0)
    monkeypatch.setattr(nuclei_mod.os, "killpg", lambda pgid, sig: sent.append((pgid, sig)))
    monkeypatch.setattr(nuclei_mod.os, "kill", lambda pid, sig: sent.append(("pid", pid, sig)))
    nuclei_mod._kill_process_group(proc)
    assert (4242, signal.SIGKILL) in sent


def test_dockerfile_uses_tini_as_entrypoint():
    text = DAST_DOCKERFILE.read_text()
    assert "tini" in text.lower()
    assert "ENTRYPOINT" in text
    assert "/usr/bin/tini" in text or "tini" in text


def test_dast_worker_compose_caps_memory_and_enables_init():
    text = WORKER_COMPOSE.read_text()
    block_start = text.index("dast_worker:")
    block = text[block_start : text.index("\n  dast_scheduler:")]
    assert "mem_limit:" in block
    assert "init: true" in block or "init:true" in block
    assert "pids_limit:" in block
