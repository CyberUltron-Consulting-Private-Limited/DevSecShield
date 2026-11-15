"""Fetch the pinned benchmarks and build the trees the product scans.

`git fetch --depth 1 --filter=blob:none <repo> <commit>` + a sparse checkout of only the paths the lane needs: the
OWASP subset arrives in about 2 s (a path-by-path checkout fetched blob by blob and took about 5 min). Each checkout
is verified: HEAD == the pinned commit, a clean work tree, the label file's sha256, and the digest of every file the
product will scan. Scan trees are plain copies (no .git, no label files), so the product never reads the labels.
"""
from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
from pathlib import Path

from .labels import LaneError, owasp_cases


def _git(args: list[str], cwd: Path, timeout: int = 300) -> str:
    env = dict(os.environ, GIT_TERMINAL_PROMPT="0", GIT_ADVICE="0")
    res = subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True, timeout=timeout, env=env)
    if res.returncode != 0:
        raise LaneError(f"git {' '.join(args[:3])} failed ({res.returncode}): {res.stderr.strip()[-500:]}")
    return res.stdout


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def tree_digest(root: Path) -> tuple[str, int]:
    """sha256 over the sorted lines `<relative path>\\0<sha256 of the file>\\n` of every file under root."""
    files = sorted(p for p in root.rglob("*") if p.is_file())
    h = hashlib.sha256()
    for p in files:
        h.update(f"{p.relative_to(root).as_posix()}\0{sha256_file(p)}\n".encode())
    return h.hexdigest(), len(files)


def case_paths(name: str, spec: dict, checkout: Path) -> list[str]:
    if name == "owasp-benchmark":
        cases, _ = owasp_cases(checkout, spec)
        return sorted({f for c in cases for f in c["files"]})
    return []


def fetch(name: str, spec: dict, cache: Path) -> Path:
    dest = cache / f"{name}-{spec['commit'][:12]}"
    marker = dest / ".git" / "d1-verified"
    if marker.exists() and marker.read_text().strip() == spec["commit"]:
        verify(name, spec, dest)
        return dest
    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True)
    _git(["init", "-q", "."], dest)
    _git(["fetch", "-q", "--depth", "1", "--filter=blob:none", spec["repo"], spec["commit"]], dest, timeout=600)
    plain = [p for p in spec["fetch_paths"] if not p.startswith("@")]
    _git(["sparse-checkout", "set", "--no-cone", *plain], dest)
    _git(["checkout", "-q", "FETCH_HEAD"], dest, timeout=600)
    if "@cases" in spec["fetch_paths"]:
        extra = ["/" + p for p in case_paths(name, spec, dest)]
        res = subprocess.run(["git", "sparse-checkout", "set", "--no-cone", "--stdin"], cwd=dest, text=True,
                             input="\n".join(plain + extra) + "\n", capture_output=True, timeout=600,
                             env=dict(os.environ, GIT_TERMINAL_PROMPT="0"))
        if res.returncode != 0:
            raise LaneError(f"git sparse-checkout failed: {res.stderr.strip()[-500:]}")
    verify(name, spec, dest)
    marker.write_text(spec["commit"] + "\n")
    return dest


def verify(name: str, spec: dict, dest: Path) -> None:
    head = _git(["rev-parse", "HEAD"], dest).strip()
    if head != spec["commit"]:
        raise LaneError(f"{name}: checkout is at {head}, pinned {spec['commit']}")
    dirty = _git(["status", "--porcelain", "--untracked-files=no"], dest).strip()
    if dirty:
        raise LaneError(f"{name}: the checkout differs from the pinned commit: {dirty.splitlines()[:5]}")
    got = sha256_file(dest / spec["labels"]["path"])
    if got != spec["labels"]["sha256"]:
        raise LaneError(f"{name}: {spec['labels']['path']} sha256 {got}, pinned {spec['labels']['sha256'] or '(none)'}")


def scan_tree(name: str, spec: dict, checkout: Path, out: Path) -> dict:
    """Copy what the product scans into `out` and check its digest against the pin."""
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)
    rels: list[str] = []
    for p in spec["scan_paths"]:
        if p == "@cases":
            rels += case_paths(name, spec, checkout)
            continue
        src = checkout / p
        rels += [x.relative_to(checkout).as_posix() for x in sorted(src.rglob("*")) if x.is_file()] \
            if src.is_dir() else [p]
    for rel in sorted(set(rels)):
        dst = out / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(checkout / rel, dst)
    digest, count = tree_digest(out)
    if digest != spec.get("scan_tree_sha256"):
        raise LaneError(f"{name}: scan tree digest {digest} ({count} files), pinned "
                        f"{spec.get('scan_tree_sha256') or '(none)'}")
    return {"files": count, "sha256": digest}


def corpus_tree(corpus: Path, out: Path) -> dict:
    if out.exists():
        shutil.rmtree(out)
    shutil.copytree(corpus, out)
    digest, count = tree_digest(out)
    return {"files": count, "sha256": digest}
