"""staging.sh on a nearly full, shared host: disk preflight before copying and loading, bounded retention after a
deploy, clean-up of a partial `docker load`, and `staging.sh disk-plan`.

Deploy staging run 43572299641 (staging 5b5cb6da3bc9, promotion #128): the host ran out of disk while `docker load`
unpacked the 5.5 GB archive. With the containerd image store `docker load` still exited 0 ("Loaded image" followed by
"Error unpacking image ...: no space left on device" for scan-worker and dast-worker), `docker image inspect` found
every tag, and the deploy died at its first `docker run` with "cannot read the Alembic head". The host is shared with
other sites: only this deployment's images (`<prefix>/{devsecshield-backend,devsecshield-frontend,scan-worker,
dast-worker}:<tag>`) and archives (`deploy/staging/images/<prefix>-<tag>.tar.gz`) may ever be removed, and never the
running tag, its rollback target or the tag being deployed.

docker, df, du, ssh and scp are stubs (test_deploy_staging_script.py): the disk model gives every mount a size, the
archives use the mount of deploy/staging/images and every unpacked image uses IMG KiB on the image store's mount.
"""

from __future__ import annotations

import importlib.util
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest
from test_deploy_staging_script import BASH, ROOT, Host, failed, ok, running_tags

pytestmark = pytest.mark.skipif(BASH is None or shutil.which("tar") is None, reason="needs bash and tar")

IMG = 1_000_000  # KiB per unpacked image (4 per tag)
ARCH = 1_000_000  # KiB per archive
RESERVE = 1024 * 1024  # KiB, STAGING_DISK_RESERVE_MB default
FACTOR = 3.3  # STAGING_DISK_FACTOR default (measured 3.04 on run 43572299641's archive, + filesystem overhead)
NEED = int(ARCH * FACTOR) + RESERVE  # what loading one archive needs free on the image store's filesystem
REPOS = ("devsecshield-backend", "devsecshield-frontend", "scan-worker", "dast-worker")
FOREIGN = ["fireflies/web:latest", "redactor/api:2.4", "dss-staging/other-tool:1"]  # other sites' images, never ours


def refs(tag: str) -> set[str]:
    return {f"dss-staging/{r}:{tag}" for r in REPOS}


def present_tags(host: Host) -> set[str]:
    st = host.state
    return {t for t in st["tags"] for r in refs(t) if r not in st["missing"] and r not in st["gone"]}


def archives(host: Host) -> set[str]:
    return {p.name for p in host.images_dir.iterdir()}


def ours(host: Host) -> set[str]:
    return {a for a in archives(host) if a.startswith("dss-staging-")}


def archive_files(*tags: str) -> set[str]:
    return {f"dss-staging-{t}.tar.gz{s}" for t in tags for s in ("", ".sha256")}


class ShortHost(Host):
    """t1 then t2 deployed (t2 runs, t1 is its rollback target); leftovers (images and archives) from deploys before
    retention existed (`stale`); t3's archive is in place, about to be deployed; other sites' images and files share
    the host. The image store is its own filesystem with `free` KiB available."""

    def __init__(self, root: Path, free: int, *, stale: tuple[str, ...] = ("t0", "old")):
        super().__init__(root, {t: ["r1"] for t in ("t1", "t2", *stale, "t3")})
        self.update(gone=sorted(refs("t3").union(*(refs(t) for t in stale))))  # not on the host yet
        ok(self.ship("t1"))
        ok(self.ship("t2"))
        for t in stale:  # left behind by earlier deploys: their images loaded, their archives still there
            self.archive(t)
        (self.images_dir / "fireflies-backup.tar.gz").write_text("another site's file")
        (self.images_dir / "dss-prod-p1.tar.gz").write_text("another deployment's archive")
        self.archive("t3")
        st = self.state
        st.update(gone=sorted(refs("t3")), foreign=list(FOREIGN), removed=[])
        st["disk"]["file_kib"] = {f"dss-staging-{t}.tar.gz": ARCH for t in ("t0", "old", "t1", "t2", "t3")}
        st["disk"]["image_kib"] = IMG
        self.state_file.write_text(json.dumps(st))
        st["disk"]["mounts"][str(self.store)] = IMG * (len(self.dss_present()) + len(FOREIGN)) + free
        self.state_file.write_text(json.dumps(st))
        self.mark = len(st["log"])

    def free_on(self, mount: Path) -> int:
        """Available KiB on <mount>, as the df stub says."""
        spec = importlib.util.spec_from_file_location("fakedisk", self.root / "bin/fakedisk.py")
        fakedisk = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(fakedisk)
        return fakedisk.avail(self.state, str(mount))

    def dss_present(self) -> list[str]:
        st = self.state
        return [r for t in st["tags"] for r in refs(t) if r not in st["missing"] and r not in st["gone"]]

    def removed(self) -> set[str]:
        return set(self.state["removed"])

    def before_load(self) -> list[dict]:
        """The docker calls of the last deploy up to its `docker load` (all of them when it never loaded)."""
        log = self.log_since(self.mark)
        cmds = [e["cmd"] for e in log]
        return log[:cmds.index("load")] if "load" in cmds else log

    def removed_before_load(self) -> set[str]:
        return {e["ref"] for e in self.before_load() if e["cmd"] == "rmi"}


def assert_untouched(host: ShortHost, *keep: str) -> None:
    for tag in keep:
        assert not refs(tag) & host.removed(), f"{tag}'s images were removed"
        assert refs(tag) <= set(host.dss_present()) or tag == "t3"
    assert not set(FOREIGN) & host.removed() and host.state["foreign"] == FOREIGN
    assert {"fireflies-backup.tar.gz", "dss-prod-p1.tar.gz"} <= archives(host)


# ------------------------------------------------------------------------------------------------ preflight
def test_enough_space_loads_without_removing_anything_first(tmp_path):
    host = ShortHost(tmp_path, free=NEED + IMG)
    proc = ok(host.staging("deploy", "t3"))
    assert not [e for e in host.before_load() if e["cmd"] in ("rmi", "rmi-refused")]
    assert "disk: enough space to load t3" in proc.stdout
    assert host.env_tag() == "t3" and running_tags(host) == {"t3"}


def test_short_space_is_freed_by_removing_only_stale_tags_and_archives(tmp_path):
    host = ShortHost(tmp_path, free=NEED - IMG)  # short by one image; t0 and old free eight
    proc = ok(host.staging("deploy", "t3"))
    assert host.removed_before_load() == refs("t0") | refs("old")
    assert "disk: short" in proc.stdout and "removing" in proc.stdout
    assert not ours(host) & archive_files("t0", "old")
    assert_untouched(host, "t2", "t3")
    assert host.env_tag() == "t3" and running_tags(host) == {"t3"}


def test_still_short_fails_before_loading_or_switching_and_lists_sizes(tmp_path):
    host = ShortHost(tmp_path, free=NEED - 4 * IMG - 1, stale=("old",))  # removing old leaves it 1 KiB short
    proc = failed(host.staging("deploy", "t3"))
    assert "not enough disk space to load t3" in proc.stderr
    assert "nothing was switched" in proc.stderr and "still run t2" in proc.stderr
    assert "need" in proc.stderr and "free" in proc.stderr and "x3.3" in proc.stderr
    log = host.log_since(host.mark)
    assert not [e for e in log if e["cmd"] in ("load", "up", "run")]
    assert host.removed() == refs("old")
    assert_untouched(host, "t1", "t2")
    assert host.env_tag() == "t2" and running_tags(host) == {"t2"}
    assert ours(host) == archive_files("t3")  # the new archive stays for the next attempt; rollback needs no archive


def test_preflight_never_removes_running_rollback_new_or_foreign_images(tmp_path):
    host = ShortHost(tmp_path, free=0)  # as short as it gets: every candidate goes
    ok(host.staging("disk-check", "t3"))  # what `push` runs on the host before copying the archive
    assert host.removed() == refs("t0") | refs("old")
    assert_untouched(host, "t1", "t2", "t3")
    assert present_tags(host) == {"t1", "t2"}
    assert ours(host) == archive_files("t3")  # rollback uses images only: no archive but the new one is kept


def test_an_image_a_container_still_uses_is_kept(tmp_path):
    host = ShortHost(tmp_path, free=NEED - IMG)
    containers = host.state["containers"]
    containers["dast-worker"]["image"] = "dss-staging/dast-worker:old"  # e.g. a stopped container of an old release
    host.update(containers=containers)
    proc = ok(host.staging("deploy", "t3"))
    assert "dss-staging/dast-worker:old" not in host.removed_before_load()
    assert [e["ref"] for e in host.before_load() if e["cmd"] == "rmi-refused"] == ["dss-staging/dast-worker:old"]
    assert "kept dss-staging/dast-worker:old" in proc.stdout


def test_classic_image_store_checks_the_docker_root(tmp_path):
    host = ShortHost(tmp_path, free=NEED + IMG)
    st = host.state
    docker_root = tmp_path / "var/lib/docker"
    docker_root.mkdir(parents=True)
    st["docker_info"] = {"root": str(docker_root), "driver": "overlay2", "status": [["Backing Filesystem", "extfs"]]}
    st["disk"]["store"] = str(docker_root)
    st["disk"]["mounts"][str(docker_root)] = st["disk"]["mounts"].pop(str(host.store))
    host.update(**st)
    proc = ok(host.staging("disk-plan", "t3"))
    assert f"images {docker_root}" in proc.stdout and "enough space" in proc.stdout


# ------------------------------------------------------------------------------------------------ retention
def test_after_a_successful_deploy_only_the_running_and_previous_releases_are_kept(tmp_path):
    host = ShortHost(tmp_path, free=NEED + IMG)
    proc = ok(host.staging("deploy", "t3"))
    assert present_tags(host) == {"t3", "t2"}
    assert ours(host) == archive_files("t3")
    assert host.removed() == refs("t0") | refs("old") | refs("t1")
    assert_untouched(host, "t2", "t3")
    assert "retention: kept t3, t2 (rollback target);" in proc.stdout
    ok(host.staging("rollback"))  # the rollback target is intact
    assert host.env_tag() == "t2" and running_tags(host) == {"t2"}


def test_a_failed_deploy_keeps_everything_for_the_rollback(tmp_path):
    host = ShortHost(tmp_path, free=NEED + IMG)
    host.update(fail_up=True)
    failed(host.staging("deploy", "t3"))
    assert present_tags(host) == {"t0", "old", "t1", "t2", "t3"} and not host.removed()
    host.update(fail_up=False)
    ok(host.staging("rollback"))
    assert host.env_tag() == "t2"


# ------------------------------------------------------------------------------------------------ partial load
@pytest.mark.parametrize("driver, status", [
    ("overlayfs", [["driver-type", "io.containerd.snapshotter.v1"]]),  # docker load exits 0, "Error unpacking"
    ("overlay2", [["Backing Filesystem", "extfs"]]),  # docker load exits 1
])
def test_a_partial_load_removes_the_new_tags_only(tmp_path, driver, status):
    host = ShortHost(tmp_path, free=2 * IMG + IMG // 2, stale=())  # room for two of t3's four images
    st = host.state
    st["docker_info"].update(driver=driver, status=status)
    if driver == "overlay2":  # the classic store keeps its images under the Docker root
        st["docker_info"]["root"] = str(host.store)
    host.update(**st)
    # a factor too small for this archive: the preflight passes, the load still runs out of space
    proc = failed(host.staging("deploy", "t3", env={"STAGING_DISK_FACTOR": "0.1", "STAGING_DISK_RESERVE_MB": "0"}))
    assert "docker load of" in proc.stderr and "failed" in proc.stderr
    assert "removed the images of t3 it loaded" in proc.stderr
    assert "t3" not in present_tags(host)
    assert host.removed() and host.removed() <= refs("t3")
    assert_untouched(host, "t1", "t2")
    assert not [e for e in host.log_since(host.mark) if e["cmd"] in ("up", "run")]
    assert host.env_tag() == "t2" and running_tags(host) == {"t2"}


def test_a_partial_load_of_the_running_tag_removes_nothing(tmp_path):
    host = ShortHost(tmp_path, free=0, stale=())
    proc = failed(host.staging("deploy", "t2", env={"STAGING_DISK_FACTOR": "0", "STAGING_DISK_RESERVE_MB": "0"}))
    assert "docker load of" in proc.stderr and "t2 is running, the rollback target or the last release" in proc.stderr
    assert not host.removed()
    assert host.env_tag() == "t2" and present_tags(host) >= {"t1", "t2"}


# ------------------------------------------------------------------------------------------------ disk-plan
def test_disk_plan_prints_what_would_be_removed_and_changes_nothing(tmp_path):
    host = ShortHost(tmp_path, free=NEED - IMG)
    before = (host.state["gone"], archives(host))
    proc = ok(host.staging("disk-plan", "t3"))
    out = proc.stdout
    for ref in sorted(refs("t0") | refs("old")):
        assert f"preflight: would remove {ref}" in out
    for path in archive_files("t0", "old"):
        assert f"preflight: would remove {host.images_dir / path}" in out
    for keep in ("t1", "t2", "t3"):
        assert f"preflight: would remove dss-staging/devsecshield-backend:{keep}" not in out
    for ref in refs("t1"):  # what retention removes once t3 runs
        assert f"after the deploy: would remove {ref}" in out
    for ref in refs("t2") | refs("t3"):
        assert f"would remove {ref}" not in out
    assert not [f for f in FOREIGN if f"would remove {f}" in out] and "fireflies-backup" not in out
    assert (host.state["gone"], archives(host)) == before
    assert not [e for e in host.log_since(host.mark) if e["cmd"] in ("rmi", "load", "up")]


def test_disk_plan_before_the_copy_counts_the_archive(tmp_path):
    host = ShortHost(tmp_path, free=NEED + IMG)
    for name in archive_files("t3"):
        (host.images_dir / name).unlink()
    proc = ok(host.staging("disk-plan", "t3", "--archive-bytes", str(ARCH * 1024)))
    assert f"archive {host.images_dir} (976.6 MiB to copy)" in proc.stdout
    assert "disk: enough space to load t3" in proc.stdout


# ------------------------------------------------------------------------------------------------ review of #129
@pytest.mark.parametrize("env", [{"STAGING_DISK_FACTOR": "3,3"}, {"STAGING_DISK_FACTOR": "-1"},
                                 {"STAGING_DISK_RESERVE_MB": "1G"}, {"STAGING_DISK_RESERVE_MB": "-5"}])
def test_an_invalid_disk_setting_refuses_the_deploy(tmp_path, env):
    """[major] The settings were read inside `if disk_room`, where set -e is off: "3,3" printed an ERROR, became
    factor 0, reported enough space and loaded anyway (the run 43572299641 failure again)."""
    host = ShortHost(tmp_path, free=NEED // 4, stale=())  # far too little room for t3
    proc = failed(host.staging("deploy", "t3", env=env))
    assert "is not a" in proc.stderr and "enough space" not in proc.stdout
    assert not [e for e in host.log_since(host.mark) if e["cmd"] in ("load", "rmi", "up")]
    assert host.env_tag() == "t2"
    failed(host.staging("disk-check", "t3", env=env))
    failed(host.staging("disk-plan", "t3", env=env))


def test_an_invalid_setting_in_env_file_refuses_too(tmp_path):
    host = ShortHost(tmp_path, free=NEED // 4, stale=())
    with (host.root / "deploy/staging/.env").open("a") as f:
        f.write("STAGING_DISK_FACTOR=three\n")
    proc = failed(host.staging("deploy", "t3"))
    assert "STAGING_DISK_FACTOR=three is not a number" in proc.stderr
    assert not [e for e in host.log_since(host.mark) if e["cmd"] == "load"]


def test_lookalike_foreign_images_are_never_removed(tmp_path):
    """Reviewer's adversarial names: only exact <prefix>/<repo>:<tag> images of this deployment are candidates."""
    host = ShortHost(tmp_path, free=0)
    look = ["dss-staging/devsecshield-backend-old:t0", "dss-staging/scan-worker2:t0",
            "registry.example:5000/dss-staging/scan-worker:t0", "dss-staging-eu/scan-worker:t0",
            "xdss-staging/dast-worker:t0", "dss-staging/scan-worker:<none>", "dss-staging/Scan-Worker:t0"]
    st = host.state
    st["foreign"] += look
    st["disk"]["mounts"][str(host.store)] += IMG * len(look)  # they take their own space; still nothing free
    host.update(**st)
    ok(host.staging("disk-check", "t3"))
    assert not host.removed() & set(look)
    assert host.removed() == refs("t0") | refs("old")


def test_kept_tags_match_exactly(tmp_path):
    host = ShortHost(tmp_path, free=0, stale=("t2-dirty", "t2.x", "t."))
    ok(host.staging("disk-check", "t3"))
    assert host.removed() == refs("t2-dirty") | refs("t2.x") | refs("t.")


def test_one_filesystem_under_two_mount_points_is_counted_once(tmp_path):
    """[minor] A bind-mounted image store (/var/lib/containerd on the root filesystem) was checked as a second
    filesystem against the same free space: copy and load each fitted, together they did not."""
    host = ShortHost(tmp_path, free=10**9, stale=())
    for name in archive_files("t3"):
        (host.images_dir / name).unlink()
    st = host.state
    del st["disk"]["mounts"][str(host.store)]
    st["disk"]["alias"] = {str(host.store): str(tmp_path)}  # the store is a bind mount of the root filesystem
    host.update(**st)
    free = host.free_on(tmp_path)
    load = int(ARCH * FACTOR) + 1
    st["disk"]["mounts"][str(tmp_path)] += load + RESERVE + ARCH // 2 - free  # room for the load or the copy, not both
    host.update(**st)
    assert host.free_on(tmp_path) == load + RESERVE + ARCH // 2
    proc = ok(host.staging("disk-plan", "t3", "--archive-bytes", str(ARCH * 1024)))
    lines = [ln for ln in proc.stdout.splitlines() if ln.startswith("  ")]
    assert len(lines) == 1, lines  # one filesystem, named by both mount points
    assert lines[0].startswith(f"  {tmp_path}, {host.store}: archive ") and "+ images" in lines[0]
    assert "short by 488.3 MiB" in lines[0]  # copy and load together: half an archive more than is free


def test_another_deployments_archive_with_a_longer_prefix_is_never_removed(tmp_path):
    """[minor] dss-staging-eu-<tag>.tar.gz (prefix dss-staging-eu) matched dss-staging-*.tar.gz as tag eu-<tag>."""
    host = ShortHost(tmp_path, free=0, stale=())
    for name in ("dss-staging-eu-abc123.tar.gz", "dss-staging-eu-abc123.tar.gz.sha256", "dss-staging-t9.tar.gz"):
        (host.images_dir / name).write_text("not a release of this deployment that this host knows")
    proc = ok(host.staging("disk-plan", "t3"))
    assert "dss-staging-eu-abc123" not in proc.stdout and "dss-staging-t9" not in proc.stdout
    failed(host.staging("disk-check", "t3"))
    assert {"dss-staging-eu-abc123.tar.gz", "dss-staging-eu-abc123.tar.gz.sha256", "dss-staging-t9.tar.gz"} <= \
        archives(host)


def test_retention_after_a_failed_deploy_keeps_the_last_release_that_passed(tmp_path):
    """[minor] t3 FAILED at compose up (DSS_TAG=t3), t4 then deploys fine: retention kept t4 and the failed t3 and
    removed t2, the last release whose checks passed."""
    host = ShortHost(tmp_path, free=10**9, stale=())
    host.update(fail_up=True)
    failed(host.staging("deploy", "t3"))
    host.update(fail_up=False)
    st = host.state
    st["tags"]["t4"] = {"revs": ["r1"]}
    st["gone"] = sorted(set(st["gone"]) | refs("t4"))
    host.update(**st)
    host.archive("t4")
    proc = ok(host.staging("deploy", "t4"))
    assert present_tags(host) == {"t4", "t3", "t2"}  # new, rollback target (deploy-history), last passed
    assert host.removed() == refs("t1")
    assert "retention: kept t4, t3 (rollback target), t2 (last release that passed its checks)" in proc.stdout
    assert ours(host) == archive_files("t4")
    assert (host.root / "deploy/staging/releases/passed").read_text().split() == ["t1", "t2", "t4"]


def test_preflight_keeps_the_last_release_that_passed(tmp_path):
    host = ShortHost(tmp_path, free=10**9, stale=())
    host.update(fail_up=True)
    failed(host.staging("deploy", "t3"))  # runs t3 (failed); rollback target t2
    host.update(fail_up=False)
    st = host.state
    st["tags"]["t4"] = {"revs": ["r1"]}
    st["gone"] = sorted(set(st["gone"]) | refs("t4"))
    st["disk"]["mounts"][str(host.store)] = IMG * (len(host.dss_present()) + len(FOREIGN))  # nothing free
    st["disk"]["file_kib"]["dss-staging-t4.tar.gz"] = ARCH
    host.update(**st)
    host.archive("t4")
    host.mark = len(host.state["log"])
    failed(host.staging("deploy", "t4"))
    assert host.removed_before_load() == refs("t1")  # t3 runs, t2 is its rollback target and the last that passed


def test_a_measured_need_beside_the_archive_replaces_the_factor(tmp_path):
    """[minor] 3.3 holds for archives whose layers are gzip blobs (a containerd-store builder); `save` now writes
    what loading needs beside the archive (<archive>.need, bytes) and the check uses it."""
    host = ShortHost(tmp_path, free=NEED + IMG, stale=())  # enough for 3.3 x the archive ...
    (host.images_dir / "dss-staging-t3.tar.gz.need").write_text(f"{5 * ARCH * 1024}\n")  # ... not for 5x measured
    proc = failed(host.staging("deploy", "t3"))
    assert "measured" in proc.stderr and "not enough disk space to load t3" in proc.stderr
    assert not [e for e in host.log_since(host.mark) if e["cmd"] == "load"]
    (host.images_dir / "dss-staging-t3.tar.gz.need").write_text(f"{ARCH * 1024}\n")  # 1x (+10%) fits
    proc = ok(host.staging("deploy", "t3"))
    assert "measured" in proc.stdout and "x3.3" not in proc.stdout


def test_disk_check_takes_the_measured_need_from_push(tmp_path):
    host = ShortHost(tmp_path, free=NEED + IMG, stale=())
    for name in archive_files("t3"):
        (host.images_dir / name).unlink()
    failed(host.staging("disk-check", "t3", "--archive-bytes", str(ARCH * 1024), "--need-bytes", str(5 * ARCH * 1024)))
    ok(host.staging("disk-check", "t3", "--archive-bytes", str(ARCH * 1024), "--need-bytes", str(ARCH * 1024)))
    failed(host.staging("disk-check", "t3", "--archive-bytes", str(ARCH * 1024), "--need-bytes", "lots"))


def _gzip_layer(payload: bytes) -> bytes:
    import gzip
    import io
    import tarfile
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        info = tarfile.TarInfo("usr/bin/tool")
        info.size = len(payload)
        tf.addfile(info, io.BytesIO(payload))
    raw = buf.getvalue()
    return raw, gzip.compress(raw, compresslevel=1)


def test_save_measures_what_loading_needs(tmp_path):
    """`save` streams the archive once more and writes <archive>.need: every layer as stored (the containerd content
    store keeps it; the classic store extracts it to a temporary directory) plus every layer unpacked. A gzip layer
    counts its compressed and its unpacked size, an uncompressed layer (a classic-store builder) twice."""
    host = Host(tmp_path, {"t5": ["r1"]})
    raw, gz = _gzip_layer(os.urandom(64 * 1024))
    plain, _ = _gzip_layer(b"x" * 20000)
    host.update(save_layers=[gz.hex(), plain.hex()])
    proc = ok(host.staging("save", env={"DSS_TAG": "t5"}))
    need = int((host.images_dir / "dss-staging-t5.tar.gz.need").read_text())
    assert need == len(gz) + len(raw) + 2 * len(plain)
    assert "loading it needs" in proc.stdout


def test_the_workflow_ships_the_measured_need():
    text = (ROOT / ".github/workflows/deploy-staging.yml").read_text()
    assert "deploy/staging/images/*.need" in text


# ------------------------------------------------------------------------------------------------ push
FAKE_SSH = r'''#!/usr/bin/env bash
while (($#)); do case "$1" in -i|-o) shift 2;; -*) shift;; *) break;; esac; done
shift
printf 'ssh %s\n' "$*" >>"$FAKE_SSH_LOG"
exec bash -c "$*"
'''

FAKE_SCP = r'''#!/usr/bin/env bash
args=(); while (($#)); do case "$1" in -i|-o) shift 2;; -*) shift;; *) args+=("$1"); shift;; esac; done
dest=${args[-1]#*:}; unset 'args[-1]'
printf 'scp %s\n' "${args[*]##*/}" >>"$FAKE_SSH_LOG"
cp "${args[@]}" "$dest"
'''


def build_machine(tmp_path: Path, host: ShortHost) -> Path:
    build = tmp_path / "build"
    for rel in ("scripts/deploy/staging.sh", "scripts/deploy/staging_browser_check.py"):
        (build / rel).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / rel, build / rel)
    shutil.copytree(ROOT / "deploy/staging", build / "deploy/staging",
                    ignore=shutil.ignore_patterns(".env", "*.env", "certs", "images", "releases", "deploy-history"))
    shutil.copytree(ROOT / "compose/aibom-config-overlay", build / "compose/aibom-config-overlay")
    (build / "deploy/staging/images").mkdir()
    for name in ("dss-staging-t3.tar.gz", "dss-staging-t3.tar.gz.sha256"):  # what `save` left on the build machine
        shutil.move(host.images_dir / name, build / "deploy/staging/images" / name)
    (build / "deploy/staging/images/dss-staging-t3.tar.gz.need").write_text(f"{ARCH * 1024}\n")
    for name, text in (("ssh", FAKE_SSH), ("scp", FAKE_SCP)):
        (host.root / "bin" / name).write_text(text)
        (host.root / "bin" / name).chmod(0o755)
    return build


def push(host: ShortHost, build: Path):
    env = {"PATH": f"{host.root / 'bin'}:{os.environ['PATH']}", "HOME": str(host.root), "TMPDIR": str(host.root),
           "LANG": "C", "FAKE_DOCKER_STATE": str(host.state_file), "STAGING_CONTAINERD_ROOT": str(host.store),
           "FAKE_SSH_LOG": str(host.root / "ssh.log"), "DSS_TAG": "t3", "SSH_OPTS": "-o BatchMode=yes"}
    return subprocess.run([BASH, str(build / "scripts/deploy/staging.sh"), "push", "deploy@stage", str(host.root)],
                          cwd=build, env=env, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=120)


def test_push_checks_the_host_disk_before_copying_the_archive(tmp_path):
    host = ShortHost(tmp_path, free=0, stale=())
    build = build_machine(tmp_path, host)
    proc = failed(push(host, build))
    assert "not enough disk space" in proc.stderr
    calls = (host.root / "ssh.log").read_text().splitlines()
    assert not [c for c in calls if c.startswith("scp dss-staging-t3")], calls  # the archive was never copied
    assert "dss-staging-t3.tar.gz" not in archives(host)
    assert host.env_tag() == "t2" and running_tags(host) == {"t2"}


def test_push_with_room_copies_after_the_check_and_deploys(tmp_path):
    host = ShortHost(tmp_path, free=NEED + IMG)
    build = build_machine(tmp_path, host)
    proc = ok(push(host, build))
    calls = (host.root / "ssh.log").read_text().splitlines()
    check = next(i for i, c in enumerate(calls) if "disk-check" in c and "--archive-bytes" in c)
    copy = next(i for i, c in enumerate(calls) if c.startswith("scp dss-staging-t3.tar.gz"))
    deploy = next(i for i, c in enumerate(calls) if "staging.sh deploy" in c)
    assert check < copy < deploy, calls
    assert f"--need-bytes {ARCH * 1024}" in calls[check]
    assert "dss-staging-t3.tar.gz.need" in calls[copy]
    assert "deployed t3" in proc.stdout and host.env_tag() == "t3"
