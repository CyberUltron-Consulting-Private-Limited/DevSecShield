"""Findings in test, fixture and example code (PR #500 takeover).

A key, a disabled TLS check or MD5 inside ``tests/`` is not what the application
ships, so the finding is downgraded to Low and labelled ``test code``, but never
hidden: the row, its code and its location stay in the inventory, the SARIF and
the VEX. The path rules follow the conventions code scanners use for test code
(Semgrep's default ``.semgrepignore`` test and fixture directories, CodeQL's
test-file classification): a ``test`` / ``tests`` / ``__tests__`` / ``spec`` /
``testdata`` / ``fixtures`` / ``mocks`` / ``examples`` / ``samples`` directory
(never under Maven / Gradle ``src/main/``: ``com/example`` is a package), or
a test file name (``test_*.py``, ``*_test.go``, ``*Test.java``, ``*.test.ts``,
``*.spec.js``, ``conftest.py``).
"""

from __future__ import annotations

import dataclasses
import re

from aibom.model.result import ScanResult

TEST_CODE_PROP = "crypto:codeContext"
TEST_CODE = "test"
TEST_CODE_LABEL = "test code"
_LOW = "note"  # SARIF note == Low
_PREFIX = "In test code (downgraded to Low): "

_TEST_DIR = re.compile(
    r"(?:^|/)(?:tests?|__tests__|testing|testdata|test[-_]?data|spec|specs"
    r"|__specs__|fixtures?|__fixtures__|mocks?|__mocks__|examples|samples)/",
    re.I,
)
_TEST_FILE = re.compile(
    r"(?:^|/)(?:test_[^/]+\.py|[^/]+_test\.(?:py|go|rb|rs|c|cc|cpp)|conftest\.py"
    r"|[^/]+(?:Tests?|IT|Spec)\.(?:java|kt|kts|scala|groovy|cs|swift)"
    r"|[^/]+\.(?:test|spec)\.(?:[cm]?[jt]sx?))$"
)


def is_test_path(path: str | None) -> bool:
    """Whether ``path`` (repository-relative) is test, fixture or example code."""
    if not path:
        return False
    p = path.replace("\\", "/")
    if _TEST_FILE.search(p):
        return True
    folder = p.rsplit("/", 1)[0] + "/" if "/" in p else ""
    # Maven / Gradle main sources are shipped code, whatever their package is named
    # (``src/main/java/com/example/...``, ``.../spec/...``)
    if "/src/main/" in "/" + folder:
        return False
    return bool(_TEST_DIR.search(folder))


def _path(props: dict[str, str]) -> str | None:
    """Where the scan found the component: a file asset's source, or a code fact's
    path (the TLS / database / server settings lane)."""
    return (
        props.get("discovery:source")
        or props.get("crypto:source")
        or props.get("crypto:factPath")
    )


def downgrade_test_code(result: ScanResult) -> None:
    """Every component found in test code: labelled; its flags Low (their messages
    say so); its stacked severity low."""
    refs: set[str] = set()
    for comp in result.components:
        props = comp.properties or {}
        if is_test_path(_path(props)):
            props[TEST_CODE_PROP] = TEST_CODE
            comp.properties = props
            refs.add(comp.bom_ref)
    if not refs:
        return
    flags = []
    for f in result.flags:
        if f.target in refs:
            msg = f.message if f.message.startswith(_PREFIX) else _PREFIX + f.message
            f = dataclasses.replace(f, severity=_LOW, message=msg)
        flags.append(f)
    result.flags = flags
    sev = (result.scores or {}).get("component_severity")
    if isinstance(sev, dict):
        for ref in refs & set(sev):
            sev[ref] = "low"


__all__ = [
    "TEST_CODE",
    "TEST_CODE_LABEL",
    "TEST_CODE_PROP",
    "downgrade_test_code",
    "is_test_path",
]
