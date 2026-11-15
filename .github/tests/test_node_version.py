"""Issue #361: the scan node release version comes from the release branch's history (.github/ci/node_version.py),
so every promotion that ships node changes is a new, never-overwritten 1.0.N.

    python3 -m unittest discover -s .github/tests -p test_node_version.py -v
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / ".github" / "ci" / "node_version.py"
sys.path.insert(0, str(SCRIPT.parent))
import node_version as NV  # noqa: E402

ENV = {k: v for k, v in os.environ.items() if k in ("PATH", "HOME", "LANG")} | {
    "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.invalid", "GIT_COMMITTER_NAME": "t",
    "GIT_COMMITTER_EMAIL": "t@example.invalid", "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"}


class History:
    """A throwaway repository shaped like the real one: `staging` gets promotion merges from `dev`."""

    def __init__(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = self.tmp.name
        self.git("init", "-q", "-b", "staging")
        self.write("README.md", "x\n")
        self.write("scan_node/zs_scan_node/__init__.py", 'VERSION = "1.0.0"\n')
        self.commit("root")
        self.git("branch", "dev")

    def close(self):
        self.tmp.cleanup()

    def git(self, *args: str) -> str:
        return subprocess.run(["git", "-C", self.dir, *args], env=ENV, check=True, capture_output=True,
                              text=True).stdout.strip()

    def write(self, rel: str, text: str) -> None:
        path = Path(self.dir, rel)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)

    def commit(self, message: str) -> str:
        self.git("add", "-A")
        self.git("commit", "-q", "--allow-empty", "-m", message)
        return self.git("rev-parse", "HEAD")

    def anchor(self, after: str, first: str = "1.0.1") -> None:
        self.write("scan_node/release.json", json.dumps({"after": after, "first": first}))

    def promote(self, changes: dict[str, str], message: str = "promote") -> str:
        """A change on dev, merged into staging with a merge commit (the way promotions land)."""
        self.git("checkout", "-q", "dev")
        self.git("merge", "-q", "--ff-only", "staging") if self._behind() else None
        for rel, text in changes.items():
            self.write(rel, text)
        self.commit(f"dev: {message}")
        self.git("checkout", "-q", "staging")
        self.git("merge", "-q", "--no-ff", "-m", f"Merge: {message}", "dev")
        return self.git("rev-parse", "HEAD")

    def _behind(self) -> bool:
        return self.git("rev-list", "--count", "dev..staging") != "0"

    def version(self, rev: str = "HEAD") -> str:
        return NV.derive(self.dir, rev)["version"]


class Derive(unittest.TestCase):
    def setUp(self):
        self.h = History()
        # the anchor is the head of staging when the rule was introduced; the promotion that brings release.json is
        # itself the first node change after it
        self.a = self.h.git("rev-parse", "HEAD")
        self.h.git("checkout", "-q", "dev")
        self.h.anchor(self.a)
        self.h.commit("dev: release.json")
        self.h.git("checkout", "-q", "staging")
        self.h.git("merge", "-q", "--no-ff", "-m", "Merge: the rule", "dev")
        self.p1 = self.h.git("rev-parse", "HEAD")

    def tearDown(self):
        self.h.close()

    def test_the_first_node_promotion_after_the_anchor_is_first(self):
        self.assertEqual(self.h.version(), "1.0.1")

    def test_each_later_node_promotion_adds_one_and_others_keep_the_version(self):
        p2 = self.h.promote({"docs/notes.md": "docs only\n"}, "docs")
        p3 = self.h.promote({"deploy/helm/cbom-scan-node/values.yaml": "image: {}\n"}, "chart")
        p4 = self.h.promote({"backend/app.py": "x = 1\n"}, "backend only")
        p5 = self.h.promote({"scan_node/zs_scan_node/agent.py": "guard = True\n"}, "node fix")
        self.h.write("scripts/release/node_artifacts.py", "# packer\n")
        p6 = self.h.commit("a direct push to staging that changes the packer")  # also a first-parent commit
        got = {rev: self.h.version(rev) for rev in (self.p1, p2, p3, p4, p5, p6)}
        self.assertEqual(list(got.values()), ["1.0.1", "1.0.1", "1.0.2", "1.0.2", "1.0.3", "1.0.4"])

    def test_the_same_commit_always_gets_the_same_version(self):
        before = self.h.version(self.p1)
        self.h.promote({"scan_node/zs_scan_node/agent.py": "later\n"}, "later")
        self.assertEqual(self.h.version(self.p1), before)  # a re-run of an older promotion never moves
        self.assertEqual(self.h.version(), "1.0.2")

    def test_commits_inside_a_promotion_are_not_counted_separately(self):
        self.h.git("checkout", "-q", "dev")
        for i in range(3):
            self.h.write(f"scan_node/zs_scan_node/f{i}.py", f"{i}\n")
            self.h.commit(f"dev: node change {i}")
        self.h.git("checkout", "-q", "staging")
        self.h.git("merge", "-q", "--no-ff", "-m", "Merge: three node commits", "dev")
        self.assertEqual(self.h.version(), "1.0.2")  # one promotion, one version

    def test_promotions_that_land_before_the_rule_never_shift_the_first_version(self):
        # #361: staging moved on while this rule was in review; those promotions changed node files but carried no
        # release.json, so the promotion that brings the rule is still 1.0.1
        h = History()
        self.addCleanup(h.close)
        anchor = h.git("rev-parse", "HEAD")
        h.promote({"scan_node/zs_scan_node/agent.py": "before the rule\n"}, "node, no rule yet")
        h.promote({"deploy/helm/cbom-scan-node/values.yaml": "x\n"}, "chart, no rule yet")
        h.promote({"scan_node/release.json": json.dumps({"after": anchor, "first": "1.0.1"})}, "the rule")
        self.assertEqual(h.version(), "1.0.1")
        h.promote({"scan_node/zs_scan_node/agent.py": "after\n"}, "node")
        self.assertEqual(h.version(), "1.0.2")

    def test_a_minor_release_is_an_edit_of_release_json(self):
        head = self.h.promote({"scan_node/zs_scan_node/agent.py": "x\n"}, "node")
        self.assertEqual(self.h.version(), "1.0.2")
        self.h.promote({"scan_node/release.json": json.dumps({"after": head, "first": "1.1.0"})}, "cut 1.1")
        self.assertEqual(self.h.version(), "1.1.0")
        self.h.promote({"scan_node/zs_scan_node/agent.py": "y\n"}, "node")
        self.assertEqual(self.h.version(), "1.1.1")

    def test_an_anchor_off_the_first_parent_history_is_refused(self):
        dev = self.h.git("rev-parse", "dev")  # on staging's history, but only through a merge's second parent
        self.h.promote({"scan_node/release.json": json.dumps({"after": dev, "first": "1.0.1"})}, "bad anchor")
        with self.assertRaisesRegex(NV.VersionError, "not on the first-parent history"):
            self.h.version()

    def test_a_malformed_anchor_is_refused(self):
        for doc in ({"after": "abc", "first": "1.0.1"}, {"after": self.a, "first": "1.0"},
                    {"after": self.a, "first": "v1.0.1"}, [], "x"):
            self.h.promote({"scan_node/release.json": json.dumps(doc)}, f"bad {doc!r}")
            with self.assertRaises(NV.VersionError, msg=repr(doc)):
                self.h.version()

    def test_a_shallow_clone_says_so(self):
        self.h.promote({"scan_node/zs_scan_node/agent.py": "x\n"}, "node")
        with tempfile.TemporaryDirectory() as clone:
            subprocess.run(["git", "clone", "-q", "--depth", "1", "--branch", "staging", f"file://{self.h.dir}", clone],
                           env=ENV, check=True, capture_output=True)
            with self.assertRaisesRegex(NV.VersionError, "shallow"):
                NV.derive(clone, "HEAD")

    def test_a_blobless_clone_is_enough(self):
        self.h.promote({"scan_node/zs_scan_node/agent.py": "x\n"}, "node")
        with tempfile.TemporaryDirectory() as clone:
            subprocess.run(["git", "-c", "uploadpack.allowFilter=true", "clone", "-q", "--filter=blob:none",
                            "--no-checkout", "--branch", "staging", f"file://{self.h.dir}", clone],
                           env=ENV | {"GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "uploadpack.allowFilter",
                                      "GIT_CONFIG_VALUE_0": "true"}, check=True, capture_output=True)
            self.assertEqual(NV.derive(clone, "HEAD")["version"], "1.0.2")

    def test_the_cli_prints_the_version_or_fails_with_the_reason(self):
        p = subprocess.run([sys.executable, str(SCRIPT), "--repo", self.h.dir], capture_output=True, text=True)
        self.assertEqual((p.returncode, p.stdout), (0, "1.0.1\n"))
        p = subprocess.run([sys.executable, str(SCRIPT), "--repo", self.h.dir, "--explain"], capture_output=True,
                           text=True)
        self.assertEqual(json.loads(p.stdout)["releases"], [self.p1])
        p = subprocess.run([sys.executable, str(SCRIPT), "--repo", self.h.dir, "--rev", "no-such"],
                           capture_output=True, text=True)
        self.assertEqual(p.returncode, 1)
        self.assertIn("node_version:", p.stderr)


class TheRealAnchor(unittest.TestCase):
    def test_release_json_names_a_commit_and_the_next_patch(self):
        data = json.loads((ROOT / "scan_node" / "release.json").read_text())
        self.assertRegex(data["after"], r"^[0-9a-f]{40}$")
        # #361: 1.0.0 is the frozen GHCR release; the next promotion that ships node changes is 1.0.1
        self.assertEqual(data["first"], "1.0.1")

    def test_node_paths_cover_what_the_release_publishes(self):
        self.assertEqual(NV.NODE_PATHS, ("scan_node", "deploy/helm/cbom-scan-node", "scripts/release"))
        for rel in NV.NODE_PATHS:
            self.assertTrue((ROOT / rel).is_dir(), rel)


if __name__ == "__main__":
    unittest.main()
