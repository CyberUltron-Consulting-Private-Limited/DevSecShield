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
        # GitHub's runners only: the self-hosted runners keep a local layer cache and never use gha
        self.assertIn("if: inputs.cache && runner.environment == 'github-hosted'\n", step("Docker uses the containerd image store"))
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
    # ... and nothing inside these: Docker and its buildx plugin, system libraries, CA certificates, the runner.
    NOTHING_INSIDE = ["/usr/bin", "/usr/sbin", "/usr/libexec", "/usr/lib/x86_64-linux-gnu", "/usr/local/bin", "/etc",
                      "/usr/share/ca-certificates", "/var/lib/docker", "/var/lib/containerd", "/home/runner"]
    # Every deleted path is a preinstalled toolchain under one of these.
    TOOLCHAINS = ["/opt", "/usr/local/lib", "/usr/local/share", "/usr/share", "/usr/lib/jvm", "/usr/lib/google-cloud-sdk",
                  "/usr/local/.ghcup"]

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
            for t in self.NOTHING_INSIDE:
                self.assertFalse(p == t or p.startswith(t + "/"), f"{p} is inside {t}")
            self.assertTrue(any(p.startswith(t + "/") for t in self.TOOLCHAINS) or p in self.TOOLCHAINS[4:],
                            f"{p} is not under a known toolchain directory")

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

    def test_the_monitor_samples_the_root_disk_in_the_units_the_report_reads(self):
        # End to end: a real sample of this machine's / goes through the real report.
        self.assertIn("df --output=avail -BM / ", step_script("Start the disk monitor"))
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            env_file = d / "env"

            def df() -> float:  # free GB on /, as df reports it
                out = subprocess.run(["df", "--output=avail", "-BM", "/"], capture_output=True, text=True).stdout
                return int(out.splitlines()[-1].strip().rstrip("M")) / 1024

            before = df()
            res = run(step_script("Start the disk monitor"), {"RUNNER_TEMP": str(d), "GITHUB_ENV": str(env_file)})
            self.assertEqual(res.returncode, 0, res.stderr)
            pid = int((d / "disk-monitor.pid").read_text())
            try:
                log = Path(dict(line.split("=", 1) for line in env_file.read_text().splitlines())["DISK_LOG"])
                deadline = time.time() + 10
                while time.time() < deadline and not (log.exists() and log.read_text().strip()):
                    time.sleep(0.2)
            finally:
                os.kill(pid, signal.SIGTERM)
            after = df()
            out, _ = self.report(None, disk_log=str(log))
        m = re.search(r"lowest free space ([\d.]+) GB", out.stdout)
        self.assertTrue(m, out.stdout)
        self.assertGreaterEqual(float(m.group(1)), min(before, after) - 1, out.stdout)
        self.assertLessEqual(float(m.group(1)), max(before, after) + 1, out.stdout)

    def report(self, samples: str | None, disk_log: str = "", freed: str = "true"
               ) -> tuple[subprocess.CompletedProcess, str]:
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            summary = d / "summary.md"
            env = {"GITHUB_STEP_SUMMARY": str(summary), "NAME": "scan-worker", "DISK_LOG": disk_log, "FREED": freed}
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

    def test_the_warning_says_what_to_do(self):
        low = "12:10:55\t45056\n12:24:30\t2048\n"
        # no clean-up on this image yet: turn it on
        res, _ = self.report(low, freed="false")
        warning = [line for line in res.stdout.splitlines() if line.startswith("::warning")][0]
        self.assertIn('"free-disk-space": true', warning)
        self.assertIn("docs/ci/README.md#runner-disk", warning)
        # the clean-up already ran: the image itself must shrink
        res, _ = self.report(low, freed="true")
        warning = [line for line in res.stdout.splitlines() if line.startswith("::warning")][0]
        self.assertNotIn('"free-disk-space": true', warning)
        self.assertIn("smaller", warning)
        self.assertIn("docs/ci/README.md#runner-disk", warning)

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


class RequiredFiles(unittest.TestCase):
    """Second review of #487 (m-b): an image built without a named context (the backend without `aibom`) builds
    fine and fails later at run time (every AI BOM PDF: ImportError on aibom/score/posture.py). The image job fails
    instead, before Trivy, when a file the image needs is absent."""

    NAME = "Required files in the image"

    def check(self, present: set[str], files: str) -> subprocess.CompletedProcess:
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            # fake `docker run --rm --network none --entrypoint test <image> -f <path>`: exit 0 when <path> is present
            fake_bin(d, "docker", 'p="${@: -1}"; case " ' + " ".join(sorted(present)) + ' " in *" $p "*) exit 0;; esac; exit 1\n')
            return run(step_script(self.NAME), {"FILES": files, "IMAGE_REF": "ci.local/backend:x", "NAME": "backend"}, d)

    def test_it_runs_after_the_build_and_before_trivy(self):
        self.assertLess(NAMES.index("Image size"), NAMES.index(self.NAME))
        self.assertLess(NAMES.index(self.NAME), NAMES.index("Trivy image scan"))
        self.assertIn("if: matrix.image.require-files", step(self.NAME))

    def test_a_missing_file_fails_the_job_and_names_it(self):
        res = self.check({"/a"}, "/a /opt/aibom/src/aibom/score/posture.py")
        self.assertEqual(res.returncode, 1, res.stdout + res.stderr)
        self.assertIn("::error::backend image has no /opt/aibom/src/aibom/score/posture.py", res.stdout)

    def test_every_file_present_passes(self):
        res = self.check({"/a", "/b"}, "/a /b")
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)

    def test_the_backend_image_requires_the_engine_posture_module(self):
        ci = (Path(__file__).resolve().parents[1] / "workflows" / "ci.yml").read_text(encoding="utf-8")
        line = next(ln for ln in ci.splitlines() if '"name":"backend"' in ln and "add '" in ln)
        self.assertIn("aibom=aibom", line)
        self.assertRegex(line, r'"require-files":"[^"]*/opt/aibom/src/aibom/score/posture\.py')
        self.assertRegex(line, r'"require-files":"[^"]*/prod_database_migrations/alembic\.ini')

    def test_build_images_checks_the_backend_image_for_it(self):
        sh = (Path(__file__).resolve().parents[2] / "scripts" / "deploy" / "build_images.sh").read_text(encoding="utf-8")
        backend = sh.split("check_component() {", 1)[1].split(";;", 1)[0]
        self.assertIn("-f /opt/aibom/src/aibom/score/posture.py", backend)

    def test_the_e2e_backend_image_carries_and_checks_it(self):
        root = Path(__file__).resolve().parents[2]
        dockerfile = (root / "e2e" / "docker" / "backend.e2e.Dockerfile").read_text(encoding="utf-8")
        self.assertIn("COPY --from=aibom /src /opt/aibom/src", dockerfile)
        build = (root / "e2e" / "scripts" / "build.sh").read_text(encoding="utf-8")
        self.assertIn("--build-context \"aibom=${REPO_ROOT}/aibom\"", build)
        self.assertIn("/opt/aibom/src/aibom/score/posture.py", build.split("assert_backend() {", 1)[1].split("\n}\n", 1)[0])


if __name__ == "__main__":
    unittest.main()
