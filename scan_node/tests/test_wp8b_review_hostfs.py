"""Round-5 review (lens 6) of the agent's host file system access: the walk's memory does not grow with a directory,
it is capped per directory, in total and in depth and stops at the job's deadline (with coverage rows); a read cannot
leave the host root when a host user swaps a directory for a symlink; the host's /proc, /sys and /dev are not read;
and the process-library coverage row names the capability that is actually missing."""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import threading
import time
import tracemalloc
from pathlib import Path

import pytest

from test_wp8b_agent_registry import _ctx, _host_root

from zs_scan_node import hostfs
from zs_scan_node.collectors import host_agent, run_job
from zs_scan_node.hostfs import HostFS, WalkStats

PEM = re.compile(r".+\.(pem|key)")


def _files(directory, n: int, name: str = "f{:07d}.txt") -> None:
    os.makedirs(directory, exist_ok=True)
    for i in range(n):
        with open(os.path.join(directory, name.format(i)), "w"):
            pass


# ----------------------------------------------------------------------------- finding 5: the walk
def test_walk_memory_does_not_grow_with_a_directory(tmp_path, monkeypatch):
    monkeypatch.setattr(hostfs, "MAX_DIR_ENTRIES", 10 ** 9, raising=False)  # runs on the old walk too
    _files(tmp_path / "home/u/junk", 40000)
    (tmp_path / "home/u/junk/z.pem").write_text("x")
    stats = WalkStats()
    tracemalloc.start()
    try:
        found = list(HostFS(str(tmp_path)).walk("/home", PEM, 2000, 1 << 20, stats))
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    assert found == ["/home/u/junk/z.pem"]
    assert peak < 2 * 1024 * 1024, peak  # before: every entry of the directory was listed and sorted (~10 MB here)
    assert stats.entries == 40003


def test_walk_caps_entries_per_directory_in_total_and_in_depth(tmp_path, monkeypatch):
    monkeypatch.setattr(hostfs, "MAX_DIR_ENTRIES", 100)
    _files(tmp_path / "home/u/big", 300)
    deep = tmp_path / "home/d1/d2/d3/d4"
    deep.mkdir(parents=True)
    (deep / "deep.pem").write_text("x")
    stats = WalkStats()
    list(HostFS(str(tmp_path)).walk("/home", PEM, 2000, 1 << 20, stats))
    assert stats.big_dirs == 1 and stats.big_examples == ["/home/u/big"] and stats.entries < 120
    monkeypatch.setattr(hostfs, "MAX_DEPTH", 3)
    stats = WalkStats()
    assert list(HostFS(str(tmp_path)).walk("/home", PEM, 2000, 1 << 20, stats)) == []
    assert stats.too_deep == 1
    monkeypatch.setattr(hostfs, "MAX_WALK_ENTRIES", 50)
    stats = WalkStats()
    list(HostFS(str(tmp_path)).walk("/home", PEM, 2000, 1 << 20, stats))
    assert stats.entries_capped and stats.entries == 51
    assert list(HostFS(str(tmp_path)).walk("/etc", PEM, 2000, 1 << 20, stats)) == []  # the total spans every root


def test_walk_stops_at_the_job_deadline_and_the_agent_reports_it(tmp_path, monkeypatch):
    root = _host_root(tmp_path)
    _files(root / "home/u/many", 3000)
    stats = WalkStats()
    calls = []
    found = list(HostFS(str(root)).walk("/home", PEM, 2000, 1 << 20, stats,
                                        stop=lambda: calls.append(1) or "skipped_deadline"))
    assert stats.stopped == "skipped_deadline" and len(calls) == 1 and stats.entries == hostfs.STOP_EVERY
    assert found == [] or len(found) < 3

    monkeypatch.setenv("ZS_HOST_ROOT", str(root))
    monkeypatch.delenv("ZS_HOST_PROC", raising=False)
    monkeypatch.setattr(hostfs, "MAX_DIR_ENTRIES", 1000)
    ctx = _ctx(agent=True)
    run_job(ctx, {"id": 1, "kind": "collect"}, {}, {"kind": "host_agent", "config": {}, "secrets": {}})
    ctx.flush()
    notes = [r["facts"].get("detail", "") + " " + str(r["facts"]) for r in ctx.collected if r["type"] == "coverage"]
    assert any("searched in part" in n and "/home/u/many" in n for n in notes), notes
    ctx = _ctx(agent=True)
    ctx.deadline = time.monotonic() - 1  # the job's time is up: the walk stops at its first check
    run_job(ctx, {"id": 1, "kind": "collect"}, {}, {"kind": "host_agent", "config": {}, "secrets": {}})
    ctx.flush()
    notes = [str(r["facts"]) for r in ctx.collected if r["type"] == "coverage"]
    assert any("stopped early (skipped_deadline)" in n for n in notes), notes


# ----------------------------------------------------------------------------- finding 6: reads stay in the root
def _swap_tree(tmp_path):
    root = tmp_path / "host"
    outside = tmp_path / "container-state"  # stands for the node container's own /var/lib/zs-node
    (root / "home/u/d").mkdir(parents=True)
    outside.mkdir()
    (root / "home/u/d/id_ed25519").write_text("host user's file\n")
    (outside / "id_ed25519").write_text("OUTSIDE THE HOST ROOT\n")
    os.symlink(str(outside), root / "home/u/link")  # absolute: the agent maps it into the root, the kernel would not
    return root


def test_a_directory_swapped_for_a_symlink_while_reading_cannot_lead_outside_the_root(tmp_path, monkeypatch):
    root = _swap_tree(tmp_path)
    u = root / "home/u"
    real_open = os.open
    swapped = []

    def open_and_swap(path, flags, mode=0o777, *, dir_fd=None):
        # the moment the reader opens "d" (or a path through it), a host user swaps "d" for the symlink
        if not swapped and (path == "d" or str(path).endswith("/home/u/d/id_ed25519")):
            os.rename(u / "d", u / "real")
            os.rename(u / "link", u / "d")
            swapped.append(path)
        return real_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(hostfs.os, "open", open_and_swap)
    got = HostFS(str(root)).read("/home/u/d/id_ed25519", 4096)
    monkeypatch.setattr(hostfs.os, "open", real_open)
    assert swapped and b"OUTSIDE" not in got.data  # before: the kernel followed the link out of the root
    assert got.status == "missing"  # the link's target, taken inside the root, does not exist there


def test_reads_racing_a_directory_swap_never_leave_the_root(tmp_path):
    root = _swap_tree(tmp_path)
    u = root / "home/u"
    stop = threading.Event()

    def racer():
        while not stop.is_set():
            os.rename(u / "d", u / "real")
            os.rename(u / "link", u / "d")
            os.rename(u / "d", u / "link")
            os.rename(u / "real", u / "d")

    t = threading.Thread(target=racer, daemon=True)
    t.start()
    fs, escaped, reads, ok = HostFS(str(root)), 0, 0, 0
    end = time.monotonic() + 3
    try:
        while time.monotonic() < end:
            got = fs.read("/home/u/d/id_ed25519", 4096)
            reads += 1
            ok += got.ok
            escaped += b"OUTSIDE" in got.data
    finally:
        stop.set()
        t.join()
    assert reads > 1000 and ok and escaped == 0, (reads, ok, escaped)


def test_the_hosts_kernel_file_systems_are_never_read(tmp_path):
    root = tmp_path / "host"
    (root / "proc/self").mkdir(parents=True)
    (root / "proc/self/environ").write_text("ZS_REGISTRATION_TOKEN=zsp_secret\n")  # the node's own, via the host
    (root / "sys/kernel").mkdir(parents=True)
    (root / "sys/kernel/x").write_text("1")
    (root / "etc").mkdir()
    os.symlink("/proc/self/environ", root / "etc/cert.pem")
    os.symlink("../proc/self/environ", root / "etc/rel.pem")
    fs = HostFS(str(root))
    for path in ("/proc/self/environ", "/etc/cert.pem", "/etc/rel.pem", "/sys/kernel/x", "/etc/../proc/self/environ"):
        assert fs.read(path, 4096).status == "missing", path
    assert fs.listdir("/proc") is None and fs.resolve("/etc/cert.pem") is None
    assert list(fs.walk("/proc", re.compile(".*"), 10, 4096, WalkStats())) == []


def test_reads_still_follow_links_inside_the_root_and_report_denied_and_loops(tmp_path):
    root = tmp_path / "host"
    (root / "usr/share/ca").mkdir(parents=True)
    (root / "etc/ssl").mkdir(parents=True)
    (root / "usr/share/ca/a.crt").write_text("cert")
    os.symlink("/usr/share/ca", root / "etc/ssl/certs")  # absolute link to a directory, then a relative one
    os.symlink("../../usr/share/ca/a.crt", root / "etc/ssl/rel.crt")
    fs = HostFS(str(root))
    assert fs.read("/etc/ssl/certs/a.crt", 100).text() == "cert"
    assert fs.read("/etc/ssl/rel.crt", 100).text() == "cert"
    assert fs.listdir("/etc/ssl/certs") == ["a.crt"]
    assert fs.read("/etc/ssl", 100).status == "not_file" and fs.read("/", 100).status == "not_file"
    assert fs.read("/usr/share/ca/a.crt/x", 100).status == "missing"  # a file used as a directory


@pytest.mark.skipif(os.geteuid() != 0 or not shutil.which("setpriv"), reason="needs root and setpriv")
def test_a_search_only_directory_on_the_way_is_passed_like_a_path_lookup(tmp_path):
    """Descriptor-based resolution must not need READ permission on the directories it passes (O_PATH): a 0711 home
    directory still lets the agent read the world-readable files below it, as the kernel's own path lookup does."""
    root = tmp_path / "host"
    (root / "home/u/.ssh").mkdir(parents=True)
    (root / "home/u/.ssh/authorized_keys").write_text("ssh-ed25519 AAAA x\n")
    os.chmod(root / "home/u", 0o711)
    for p in (root / "home", root / "home/u", root / "home/u/.ssh", root / "home/u/.ssh/authorized_keys"):
        os.chown(p, 12345, 12345)  # another user's: root without capabilities gets the "other" permission bits
    script = ("import sys; sys.path.insert(0, sys.argv[1]); from zs_scan_node.hostfs import HostFS; fs = HostFS(sys.argv[2]); "
              "print(fs.read('/home/u/.ssh/authorized_keys', 100).status, fs.listdir('/home/u'), "
              "fs.listdir('/home/u/.ssh'))")
    out = subprocess.run(["setpriv", "--inh-caps=-all", "--bounding-set=-all", sys.executable, "-c", script,
                          str(Path(hostfs.__file__).parents[1]), str(root)], capture_output=True, text=True, check=True)
    assert out.stdout.split(None, 1) == ["ok", "None ['authorized_keys']\n"], out


# ----------------------------------------------------------------------------- finding 7: the ptrace text
def test_unreadable_process_maps_name_cap_sys_ptrace(tmp_path, monkeypatch):
    root = _host_root(tmp_path)
    proc = tmp_path / "proc"
    for pid in ("42", "43"):
        (proc / pid).mkdir(parents=True)
        (proc / pid / "comm").write_text("nginx\n")
        (proc / pid / "maps").write_text("7f00-7f01 r-xp 0 08:01 1 /usr/lib/x86_64-linux-gnu/libssl.so.3\n")
    real_open = open

    def open_maps(path, *a, **kw):
        if str(path).endswith("/43/maps"):  # another user's process: the kernel wants CAP_SYS_PTRACE
            raise PermissionError(13, "Permission denied", str(path))
        return real_open(path, *a, **kw)

    monkeypatch.setattr(host_agent, "open", open_maps, raising=False)
    monkeypatch.setenv("ZS_HOST_ROOT", str(root))
    monkeypatch.setenv("ZS_HOST_PROC", str(proc))
    ctx = _ctx(agent=True)
    run_job(ctx, {"id": 1, "kind": "collect"}, {}, {"kind": "host_agent", "config": {}, "secrets": {}})
    ctx.flush()
    rows = [str(r["facts"]) for r in ctx.collected if r["type"] == "coverage" and "process" in str(r["facts"])]
    assert any("1 of 2 processes" in r and "CAP_SYS_PTRACE" in r and "agent.sysPtrace" in r for r in rows), rows
    assert not any("run the agent as root to read them" in r for r in rows)


@pytest.mark.parametrize("name", ["proc", "sys", "dev"])
def test_kernel_dirs_are_refused_only_at_the_root(tmp_path, name):
    root = tmp_path / "host"
    (root / "opt" / name).mkdir(parents=True)
    (root / "opt" / name / "app.pem").write_text("x")
    assert HostFS(str(root)).read(f"/opt/{name}/app.pem", 10).ok  # /opt/proc is an ordinary directory
