"""Compare the pre-feature aibom suite with the committed baseline.

The environment of record is a checkout with no chroma clone. When the clone
is present this script prints ``not comparable: chroma clone present`` and
exits 0. ``--capture`` writes the baseline and refuses to run while the clone
is present.
"""

from __future__ import annotations

import json
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

AIBOM = Path(__file__).resolve().parents[2]
CHROMA = AIBOM / "tests" / "fixtures" / "chroma"
OUT = AIBOM / "tests" / "fixtures" / "frozen_goldens" / "baseline_counts.json"
NOT_COMPARABLE = "not comparable: chroma clone present"
BASE_COMMIT = "f7385517523212e50b20ec6f1947831a5ef19872"


def _tracked_test_files() -> list[str]:
    listed = subprocess.run(
        ["git", "ls-files", "--", "tests/test_*.py"],
        cwd=AIBOM,
        check=True,
        capture_output=True,
        text=True,
    )
    files = []
    for line in listed.stdout.splitlines():
        if not line or not (AIBOM / line).is_file():
            continue
        files.append(line)
    return sorted(files)


def _counts(files: list[str]) -> dict[str, dict[str, int]]:
    junit = AIBOM / "tests" / "fixtures" / "frozen_goldens" / "_baseline.junit.xml"
    junit.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            *files,
            "-q",
            "--tb=no",
            f"--junitxml={junit}",
        ],
        cwd=AIBOM,
        check=False,
    )
    tree = ET.parse(junit)
    tallies: dict[str, dict[str, int]] = {
        name: {"passed": 0, "skipped": 0, "failed": 0} for name in files
    }
    for case in tree.iter("testcase"):
        classname = case.get("classname") or ""
        parts = classname.split(".")
        file_name = f"{parts[0]}/{parts[1]}.py" if len(parts) >= 2 else ""
        if file_name not in tallies:
            continue
        if case.find("skipped") is not None:
            tallies[file_name]["skipped"] += 1
        elif case.find("failure") is not None or case.find("error") is not None:
            tallies[file_name]["failed"] += 1
        else:
            tallies[file_name]["passed"] += 1
    junit.unlink(missing_ok=True)
    return tallies


def capture() -> None:
    if CHROMA.exists():
        raise SystemExit("refusing to capture while the chroma clone is present")
    files = _tracked_test_files()
    payload = {
        "base_commit": BASE_COMMIT,
        "files": _counts(files),
    }
    text = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    OUT.write_text(text, encoding="ascii")
    print(f"wrote {OUT} ({len(files)} files)")


def compare() -> int:
    if CHROMA.exists():
        print(NOT_COMPARABLE)
        return 0
    expected = json.loads(OUT.read_text(encoding="ascii"))
    files = sorted(expected["files"])
    actual = _counts(files)
    mismatches = []
    for name in files:
        if actual.get(name) != expected["files"][name]:
            mismatches.append(name)
    if mismatches:
        print("baseline mismatch:")
        for name in mismatches:
            got = actual.get(name)
            print(f"  {name}: expected {expected['files'][name]} actual {got}")
        return 1
    print(f"baseline matches {len(files)} files")
    return 0


def main() -> None:
    if "--capture" in sys.argv:
        capture()
        return
    raise SystemExit(compare())


if __name__ == "__main__":
    main()
