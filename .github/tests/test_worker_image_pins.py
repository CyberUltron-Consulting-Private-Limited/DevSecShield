"""#69: every third-party input of the scan-worker image is pinned and verified.

RabbitMQ/worker/Dockerfile used to build cbomkit-theia from upstream's default branch with go.sum deleted and the Go
checksum database off, and to pipe the rustup, grype and syft installers into sh.

Run: python3 -m unittest discover -s .github/tests -v
"""

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DOCKERFILE = ROOT / "RabbitMQ" / "worker" / "Dockerfile"


def instructions(text: str) -> list[str]:
    """The Dockerfile's instructions, continuation lines joined and comments dropped."""
    lines = [line for line in text.splitlines() if not line.lstrip().startswith("#")]
    return [i.strip() for i in re.sub(r"\\\n", " ", "\n".join(lines)).splitlines() if i.strip()]


class WorkerImagePins(unittest.TestCase):
    def setUp(self):
        self.text = DOCKERFILE.read_text(encoding="utf-8")
        self.steps = instructions(self.text)
        self.runs = [s for s in self.steps if s.startswith("RUN ")]
        self.args = dict(re.findall(r"(?m)^ARG (\w+)=(\S+)$", self.text))

    def test_no_installer_is_piped_into_a_shell(self):
        for run in self.runs:
            with self.subTest(run=run[:80]):
                self.assertNotRegex(run, r"\|\s*(ba|da)?sh\b")

    def test_go_checksums_stay_on(self):
        for bad in ("rm go.sum", "GONOSUMDB", "GONOSUMCHECK", "GOSUMDB=off", "GOFLAGS=-mod=mod",
                    "GOINSECURE", "GOPRIVATE", "go mod tidy"):
            with self.subTest(bad=bad):
                self.assertNotIn(bad, " ".join(self.steps))
        self.assertIn("GOFLAGS=-mod=readonly", " ".join(self.steps))
        self.assertIn("go mod verify", " ".join(self.runs))

    def test_cbomkit_theia_is_a_tag_held_to_its_commit(self):
        self.assertRegex(self.args.get("CBOMKIT_THEIA_REF", ""), r"^v\d+\.\d+\.\d+$")
        self.assertRegex(self.args.get("CBOMKIT_THEIA_SHA", ""), r"^[0-9a-f]{40}$")
        (clone,) = [r for r in self.runs if "cbomkit-theia.git" in r]
        self.assertIn('--branch "${CBOMKIT_THEIA_REF}"', clone)
        self.assertRegex(clone, r'rev-parse HEAD.*!= "\$\{CBOMKIT_THEIA_SHA\}".*exit 1')
        self.assertIn("-trimpath", clone)  # the same commit builds the same binary
        self.assertIn("-buildvcs=false", clone)

    def test_base_images_are_pinned_by_digest(self):
        for name in ("UV_BASE_IMAGE", "GO_BASE_IMAGE"):
            with self.subTest(name=name):
                self.assertRegex(self.args.get(name, ""), r"^[\w./-]+:[\w.-]+@sha256:[0-9a-f]{64}$")
        for step in self.steps:
            if step.startswith("FROM "):
                with self.subTest(step=step):
                    self.assertRegex(step, r"^FROM \$\{(UV|GO)_BASE_IMAGE\}( AS [\w-]+)?$")

    def test_every_download_is_a_pinned_version_checked_by_sha256(self):
        downloads = [r for r in self.runs if re.search(r"\bcurl -", r)]
        self.assertEqual(len(downloads), 2, "rustup-init, and grype + syft")
        for run in downloads:
            with self.subTest(run=run[:80]):
                self.assertIn("sha256sum -c", run)
                self.assertIn("set -eu", run)  # a failed check stops the build
                self.assertNotRegex(run, r"latest|get\.anchore\.io|sh\.rustup\.rs")
        for tool in ("RUSTUP", "GRYPE", "SYFT"):
            with self.subTest(tool=tool):
                self.assertRegex(self.args.get(f"{tool}_VERSION", ""), r"^\d+\.\d+\.\d+$")
                for arch in ("AMD64", "ARM64"):
                    self.assertRegex(self.args.get(f"{tool}_SHA256_{arch}", ""), r"^[0-9a-f]{64}$")
        self.assertRegex(self.args.get("RUST_TOOLCHAIN", ""), r"^\d+\.\d+\.\d+$")


if __name__ == "__main__":
    unittest.main()
