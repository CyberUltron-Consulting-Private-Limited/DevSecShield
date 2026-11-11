"""docs/ci/README.md documents every input and secret of every reusable workflow (architecture review on PR #16).

Run: python3 -m unittest discover -s .github/tests -v
"""

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
README = (ROOT / "docs" / "ci" / "README.md").read_text(encoding="utf-8")
REUSABLE = sorted((ROOT / ".github" / "workflows").glob("reusable-*.yml")) + [ROOT / ".github/workflows/pr-labels.yml"]


def interface(path: Path) -> list[str]:
    """Names under `on: workflow_call: inputs:` and `secrets:` (6- and 8-space indentation, as these files use)."""
    text = path.read_text(encoding="utf-8")
    m = re.search(r"\n  workflow_call:\n((?:    .*\n|\s*\n)+)", text)
    assert m, path.name
    return re.findall(r"^      ([A-Za-z][\w-]*):\s*$", m.group(1), re.M)


class ReadmeCoversInterfaces(unittest.TestCase):
    def test_every_input_and_secret_is_documented(self):
        for wf in REUSABLE:
            names = interface(wf)
            self.assertTrue(names, wf.name)
            for name in names:
                with self.subTest(f"{wf.name}: {name}"):
                    self.assertIn(f"`{name}`", README, f"{wf.name} input/secret {name!r} is not in docs/ci/README.md")


if __name__ == "__main__":
    unittest.main()
