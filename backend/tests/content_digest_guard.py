"""#352 guard: ``cbomcollectedasset.content_digest`` must follow the columns it digests.

The estate hooks skip a row whose digest equals the previous job's (``agility_store.changed_rows``,
``risk_register.write_keys``), so an UPDATE that changes a digested column (``new_models.CONTENT_DIGEST_COLUMNS``) and
leaves the old digest in place would make them serve a stale class or grade. Every such UPDATE must also set
``content_digest`` (recomputed, or NULL: an unknown digest is compared column by column).

* ``check_statement``: the SQL check, used by the test suite's engine listener (``conftest.py``), which sees every
  statement any test runs: ORM flushes, Core, raw SQL;
* ``scan_source``: the static check of the code and the data migrations (``test_cbom_content_digest_guard.py``).
"""
from __future__ import annotations

import ast
import re

from backend.new_models import CONTENT_DIGEST_COLUMNS

TABLE = "cbomcollectedasset"
DIGEST = "content_digest"
_UPDATE = re.compile(r"^\s*UPDATE\s+(?:ONLY\s+)?[\"`]?" + TABLE + r"[\"`]?(?:\s+(?:AS\s+)?\w+)?\s+SET\s+(.*?)"
                     r"(?:\s+FROM\s|\s+WHERE\s|\s+RETURNING\s|$)", re.IGNORECASE | re.DOTALL)
_SET_COLUMN = re.compile(r"(?:^|,)\s*(?:\w+\.)?[\"`]?(\w+)[\"`]?\s*=", re.DOTALL)


def set_columns(statement: str) -> set[str] | None:
    """The columns an ``UPDATE cbomcollectedasset SET ...`` statement sets, or None for any other statement."""
    m = _UPDATE.match(statement)
    if m is None:
        return None
    return {c.lower() for c in _SET_COLUMN.findall(m.group(1))}


def problem(columns: set[str]) -> str | None:
    touched = sorted(columns & set(CONTENT_DIGEST_COLUMNS))
    if touched and DIGEST not in columns:
        return (f"an UPDATE of {TABLE} sets {', '.join(touched)} but not {DIGEST}: recompute it "
                f"(new_models.content_digest) or set it to NULL (#352)")
    return None


def check_statement(statement: str) -> str | None:
    columns = set_columns(statement)
    return problem(columns) if columns is not None else None


def _strings(node: ast.AST) -> list[str]:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return [node.value]
    if isinstance(node, ast.JoinedStr):  # an f-string: its literal parts, joined
        return ["".join(v.value for v in node.values if isinstance(v, ast.Constant) and isinstance(v.value, str))]
    return []


def scan_source(source: str, filename: str = "<source>") -> list[str]:
    """Findings (``file:line: message``) for one Python file: SQL strings that UPDATE the table, and SQLAlchemy
    ``update(<the table>)....values(...)`` calls, that set a digested column without ``content_digest``. A
    ``.values(**mapping)`` it cannot read is a finding unless the call names ``content_digest``."""
    found: list[str] = []
    tree = ast.parse(source, filename)
    for node in ast.walk(tree):
        for text in _strings(node):
            if TABLE in text.lower() and (msg := check_statement(text)):
                found.append(f"{filename}:{node.lineno}: {msg}")
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "values"):
            continue
        receiver = ast.unparse(node.func.value)
        if "update(" not in receiver or not ("CbomCollectedAsset" in receiver or TABLE in receiver.lower()):
            continue
        names = {k.arg for k in node.keywords if k.arg}
        for arg in node.args:
            if isinstance(arg, ast.Dict):
                names |= {k.value for k in arg.keys if isinstance(k, ast.Constant) and isinstance(k.value, str)}
        unreadable = any(k.arg is None for k in node.keywords) or any(not isinstance(a, ast.Dict) for a in node.args)
        if unreadable and DIGEST not in names:
            found.append(f"{filename}:{node.lineno}: an UPDATE of {TABLE} with values this check cannot read: name "
                         f"{DIGEST} in it (#352)")
        elif msg := problem(names):
            found.append(f"{filename}:{node.lineno}: {msg}")
    return found
