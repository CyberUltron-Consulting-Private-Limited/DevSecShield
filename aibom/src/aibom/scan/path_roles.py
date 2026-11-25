"""What role a file plays in a repository: test code, an example / sample file,
documentation, an environment file or application code.

The AI BOM inventories what the application itself uses. A model name or an AI
endpoint that appears only in a test, an example data file or the docs is a
mention, not usage, so the scanners use these predicates to tell them apart
(audit-C G-D5-3, review of #487 M1 / m1 / m6 / m11).
"""

from __future__ import annotations

import re
from pathlib import Path

_TEST_DIRS = frozenset(
    {
        "test",
        "tests",
        "__tests__",
        "testing",
        "spec",
        "specs",
        "testdata",
        "fixtures",
        "e2e",
    }
)
_TEST_FILE = re.compile(
    r"^(?:test_.+\.py|.+_test\.(?:py|go)|conftest\.py|.+\.(?:test|spec)\.[cm]?[jt]sx?)$",
    re.IGNORECASE,
)
# ``.env``, ``.env.local``, ``.env.example``, ``prod.env``: the environment the
# application reads. A template of it (``.env.example``) documents the same
# settings, so it is configuration, not an example data file.
_ENV_FILE = re.compile(r"^(?:\.env(?:\.[\w.-]+)?|[\w.-]+\.env)$", re.IGNORECASE)
# ``models.example.yaml``, ``config.sample.json``, ``settings.yaml.template``
_EXAMPLE_FILE = re.compile(
    r"(?:^|[._-])(?:example|examples|sample|template)(?:[._-]|$)", re.IGNORECASE
)
_EXAMPLE_DIRS = frozenset({"example", "examples", "sample", "samples"})
DOC_SUFFIXES = frozenset({".md", ".mdx", ".markdown", ".rst", ".txt", ".adoc"})
# application code, ranked above configuration when choosing the file that best
# evidences a model (``discovery:source``)
CODE_SUFFIXES = frozenset(
    {
        ".py",
        ".pyi",
        ".ipynb",
        ".ts",
        ".tsx",
        ".js",
        ".jsx",
        ".mjs",
        ".cjs",
        ".go",
        ".java",
        ".kt",
        ".rs",
        ".rb",
        ".cs",
        ".php",
    }
)


def _parts(path: Path, root: Path) -> tuple[str, ...]:
    try:
        return path.relative_to(root).parts
    except ValueError:
        return path.parts


def is_env_file(path: Path) -> bool:
    """An environment file (``.env``, ``.env.*``, ``*.env``)."""
    return bool(_ENV_FILE.match(path.name))


# ``.env.example``, ``.env.sample``, ``env.template``, ``.env.dist``: documents the
# settings, never the deployment's values (review 6065595627 of #498, R6-M1)
_ENV_TEMPLATE = re.compile(
    r"(?:^|[._-])(?:example|sample|template|dist|tmpl)(?:[._-]|$)", re.IGNORECASE
)


def is_env_template(path: Path) -> bool:
    """An environment file that is a template of the real one (``.env.example``)."""
    return is_env_file(path) and bool(_ENV_TEMPLATE.search(path.name))


def is_test_path(path: Path, root: Path) -> bool:
    """A test file or a file under a test directory (relative to the scan root)."""
    return bool(_TEST_FILE.match(path.name)) or any(
        p.lower() in _TEST_DIRS for p in _parts(path, root)[:-1]
    )


def is_example_path(path: Path, root: Path) -> bool:
    """An example / sample / template data file (not an environment template)."""
    if is_env_file(path):
        return False
    return bool(_EXAMPLE_FILE.search(path.name)) or any(
        p.lower() in _EXAMPLE_DIRS for p in _parts(path, root)[:-1]
    )


def is_doc_path(path: Path) -> bool:
    """Documentation / prose (Markdown, reStructuredText, plain text)."""
    return path.suffix.lower() in DOC_SUFFIXES


def evidence_rank(path: Path) -> int:
    """How strongly a file evidences usage: application code 0, configuration 1."""
    return 0 if path.suffix.lower() in CODE_SUFFIXES else 1


__all__ = [
    "CODE_SUFFIXES",
    "DOC_SUFFIXES",
    "evidence_rank",
    "is_doc_path",
    "is_env_file",
    "is_env_template",
    "is_example_path",
    "is_test_path",
]
