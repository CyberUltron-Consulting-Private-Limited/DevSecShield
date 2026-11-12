"""Self-tests for reusable-image-build.yml: how the build job uses the runner disk (#50).

The scan-worker image (torch through garak) ran the hosted runner out of disk even after the free-disk clean-up:
the docker-container builder kept its own copy of the image and `load` streamed a tarball into Docker, which stored
and unpacked it again. These tests pin the fix and run the step scripts the way CI runs them.
Run: python3 -m unittest discover -s .github/tests -v
"""

import os
import re
import signal
import stat
import subprocess
import tempfile
import textwrap
import time
import unittest
from pathlib import Path

WF = (Path(__file__).resolve().parents[1] / "workflows" / "reusable-image-build.yml").read_text(encoding="utf-8")


def build_steps() -> list[tuple[str, str]]:
    """(name, text) of each step of the `build` job, in order."""
    m = re.search(r"\n  build:\n((?:(?:    .*|\s*)\n)+)", WF)
    assert m, "no build job"
    parts = re.split(r"\n      - name: ", m.group(1).split("\n    steps:\n", 1)[1])
    steps = []
    for part in parts:
        part = part.removeprefix("      - name: ")
        name, _, body = part.partition("\n")
        steps.append((name.strip(), body))
    return steps


STEPS = build_steps()
NAMES = [n for n, _ in STEPS]


def step(name: str) -> str:
    found = [body for n, body in STEPS if n == name]
    assert len(found) == 1, f"step {name!r}: {NAMES}"
    return found[0]


def step_script(name: str) -> str:
    m = re.search(r"\n?        run: \|\n((?:(?:\s{10}.*)?\n)+)", step(name))
    assert m, name
    return textwrap.dedent(m.group(1))


def fake_bin(d: Path, name: str, script: str) -> None:
    p = d / name
    p.write_text("#!/bin/bash\n" + script)
    p.chmod(p.stat().st_mode | stat.S_IEXEC)


def run(script: str, env: dict[str, str], path_dir: Path | None = None) -> subprocess.CompletedProcess:
    full = dict(os.environ, **env)
    if path_dir:
        full["PATH"] = f"{path_dir}:{full['PATH']}"
    return subprocess.run(["bash", "-e", "-c", script], env=full, capture_output=True, text=True, timeout=60)


class StepOrder(unittest.TestCase):
    def test_the_build_job_runs_the_disk_steps_in_order(self):
        order = ["Free disk space", "Start the disk monitor", "Docker uses the containerd image store",
                 "Set up Docker Buildx", "Build ${{ matrix.image.name }} (no push)", "Free the build cache",
                 "Image size", "Trivy image scan", "Disk headroom"]
        self.assertEqual([n for n in NAMES if n in order], order)
        self.assertEqual(NAMES[-1], "Disk headroom")


class BuildDriver(unittest.TestCase):
    def test_the_image_is_built_in_the_runners_docker(self):
        # No separate BuildKit container: its own store plus the tarball `load` doubled the image on disk (#50).
        self.assertRegex(step("Set up Docker Buildx"), r"\n          driver: docker\n")
        self.assertIn("load: true", step("Build ${{ matrix.image.name }} (no push)"))

    def test_the_cache_needs_the_containerd_image_store(self):
        self.assertIn("if: inputs.cache\n", step("Docker uses the containerd image store"))
        script = step_script("Docker uses the containerd image store")
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            fake_bin(d, "docker", 'echo "$STATUS"\n')
            ok = run(script, {"STATUS": '[["driver-type","io.containerd.snapshotter.v1"]]'}, d)
            self.assertEqual(ok.returncode, 0, ok.stdout + ok.stderr)
            classic = run(script, {"STATUS": '[["Backing Filesystem","extfs"],["Supports d_type","true"]]'}, d)
            self.assertNotEqual(classic.returncode, 0)
            self.assertIn("::error::", classic.stdout)


class FreeDiskSpace(unittest.TestCase):
    # Never delete these, or anything above them: the job uses them, or the runner does.
    KEEP = ["/", "/usr", "/usr/bin", "/usr/sbin", "/usr/lib", "/usr/lib/x86_64-linux-gnu", "/usr/local",
            "/usr/local/bin", "/usr/share", "/opt", "/etc", "/var", "/var/lib/docker", "/var/lib/containerd",
            "/tmp", "/home", "/home/runner", "/home/runner/work", "/home/runner/actions-runner"]

    def removed(self) -> tuple[list[str], subprocess.CompletedProcess]:
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            log = d / "calls"
            fake_bin(d, "sudo", f'echo "$*" >> "{log}"\n')
            fake_bin(d, "docker", f'echo "docker $*" >> "{log}"\n')
            res = run(step_script("Free disk space"), {}, d)
            calls = log.read_text().splitlines() if log.exists() else []
        paths = [p for c in calls if c.startswith("rm -rf ") for p in c.split()[2:]]
        return paths, res

    def test_it_deletes_the_preinstalled_toolchains(self):
        paths, res = self.removed()
        self.assertEqual(res.returncode, 0, res.stderr)
        for p in ("/usr/local/lib/android", "/usr/share/dotnet", "/opt/ghc", "/opt/hostedtoolcache", "/usr/lib/jvm",
                  "/usr/local/share/powershell", "/usr/local/share/chromium"):
            self.assertIn(p, paths)

    def test_it_never_deletes_what_the_job_or_runner_uses(self):
        paths, _ = self.removed()
        self.assertTrue(paths)
        for p in paths:
            self.assertTrue(p.startswith("/") and ".." not in p, p)
            for keep in self.KEEP:
                self.assertFalse(keep == p or keep.startswith(p.rstrip("/") + "/"), f"{p} would delete {keep}")

    def test_it_shows_the_free_space_before_and_after(self):
        _, res = self.removed()
        self.assertGreaterEqual(res.stdout.count("Filesystem"), 2, res.stdout)


class DiskMonitor(unittest.TestCase):
    def test_it_samples_the_free_space_in_the_background(self):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            env_file = d / "env"
            res = run(step_script("Start the disk monitor"), {"RUNNER_TEMP": str(d), "GITHUB_ENV": str(env_file)})
            self.assertEqual(res.returncode, 0, res.stderr)
            pid = int((d / "disk-monitor.pid").read_text())
            try:
                env = dict(line.split("=", 1) for line in env_file.read_text().splitlines())
                log = Path(env["DISK_LOG"])
                deadline = time.time() + 10
                while time.time() < deadline and not (log.exists() and log.read_text().strip()):
                    time.sleep(0.2)
                first = log.read_text().splitlines()[0]
                self.assertRegex(first, r"^\d\d:\d\d:\d\d\t\d+$")
            finally:
                os.kill(pid, signal.SIGTERM)

    def report(self, samples: str | None) -> tuple[subprocess.CompletedProcess, str]:
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            summary = d / "summary.md"
            env = {"GITHUB_STEP_SUMMARY": str(summary), "NAME": "scan-worker", "DISK_LOG": ""}
            if samples is not None:
                (d / "disk.tsv").write_text(samples)
                env["DISK_LOG"] = str(d / "disk.tsv")
            m = re.search(r"\n          WARN_BELOW_MB: (\d+)(?: #.*)?\n", step("Disk headroom"))
            env["WARN_BELOW_MB"] = m.group(1)
            res = run(step_script("Disk headroom"), env)
            return res, summary.read_text() if summary.exists() else ""

    def test_the_report_runs_even_when_the_build_failed(self):
        self.assertIn("if: always()\n", step("Disk headroom"))

    def test_a_low_water_mark_under_10_gb_warns(self):
        res, summary = self.report("12:10:55\t45000\n12:24:30\t2048\n12:24:35\t30000\n")
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertIn("lowest free space 2.0 GB at 12:24:30", res.stdout)
        self.assertIn("::warning", res.stdout)
        self.assertIn("lowest free space 2.0 GB", summary)

    def test_enough_headroom_passes_quietly(self):
        res, summary = self.report("12:10:55\t45056\n12:20:00\t20480\n12:25:00\t30000\n")
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertIn("lowest free space 20.0 GB at 12:20:00", res.stdout)
        self.assertIn("44.0 GB at the first sample, 29.3 GB at the end (3 samples", res.stdout)
        self.assertNotIn("::warning", res.stdout)

    def test_no_samples_is_not_a_failure(self):
        for samples in (None, "", "garbage\n"):
            res, _ = self.report(samples)
            self.assertEqual(res.returncode, 0, res.stderr)
            self.assertIn("No disk samples", res.stdout)


class BuildCache(unittest.TestCase):
    def test_the_build_cache_is_pruned_before_trivy_copies_the_image(self):
        self.assertIn("docker builder prune --all --force", step_script("Free the build cache"))


if __name__ == "__main__":
    unittest.main()
