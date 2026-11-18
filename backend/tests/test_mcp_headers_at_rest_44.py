"""Issue #44: an MCP scan's request headers (usually ``Authorization: Bearer ...``) are never kept in the clear.

``scan.scan_metadata`` kept the headers exactly as given, so a database dump or backup exposed the MCP server's
credential. Now:

* the row keeps the header NAMES, each value masked, and the values as one Fernet token made with the helper CBOM
  sources store their credentials with (``cbom_sources.crypto.encrypt_secrets``);
* migration d44mcphdr001 rewrites the rows stored before (batched, idempotent; downgrade keeps them sealed);
* no API returns a header value, for an old row or a new one;
* the printable copies of a task's kwargs in every Celery message the backend sends (``argsrepr`` / ``kwargsrepr``:
  worker log records, events, Flower) are redacted, while the worker still receives the real headers.

Credentials are generated at run time (never a real value). The PostgreSQL migration test runs when
``CBOM_TEST_PG_URL`` is set, as in CI, in a schema of its own (safe under pytest-xdist).
"""
from __future__ import annotations

import asyncio
import importlib.util
import json
import os
import secrets
import sys
import types
from pathlib import Path

import pytest
import sqlalchemy as sa

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))
os.environ.setdefault("JWT_SECRET_KEY", "mcp-headers-44-test-secret-not-for-production-use")

from backend.utilities.cbom_sources.crypto import decrypt_secrets  # noqa: E402
from backend.utilities.db.encryption import SECRET_PLACEHOLDER as MASK  # noqa: E402
from backend.utilities.db.metadata import get_scan_metadata_for_type  # noqa: E402
from backend.utilities.db.schemas import StartScanPayload  # noqa: E402

VERSIONS = _REPO_ROOT / "prod_database_migrations" / "migrations" / "versions"
PG = os.environ.get("CBOM_TEST_PG_URL")
URL = "https://mcp.example.test/mcp"


def _fresh() -> dict[str, str]:
    return {"bearer": secrets.token_urlsafe(24), "cookie": "sess=" + secrets.token_hex(12),
            "custom": "cust-" + secrets.token_hex(10)}


def _headers(s: dict[str, str]) -> dict[str, str]:
    return {"Authorization": f"Bearer {s['bearer']}", "Cookie": s["cookie"], "X-Custom": s["custom"]}


def _payload(headers) -> StartScanPayload:
    return StartScanPayload.model_validate({"mcp": {"server_url": URL, "server_mode": "httpstreamable",
                                                    "headers": headers}})


def _assert_no_value(text: str, s: dict[str, str]) -> None:
    for name, value in s.items():
        assert value not in text, name


# ============================================================================ what a started scan stores
def test_a_started_mcp_scan_stores_the_header_names_and_only_encrypted_values():
    s = _fresh()
    meta = get_scan_metadata_for_type("mcp", _payload(_headers(s)))
    _assert_no_value(json.dumps(meta), s)
    assert meta["headers"] == {"Authorization": MASK, "Cookie": MASK, "X-Custom": MASK}
    assert decrypt_secrets(meta["headers_encrypted"]) == _headers(s)
    # the rest of the row is what it was
    assert (meta["server_url"], meta["server_mode"], meta["environment"]) == (URL, "httpstreamable", "development")


@pytest.mark.parametrize("headers", [None, {}])
def test_an_mcp_scan_without_headers_stores_neither(headers):
    meta = get_scan_metadata_for_type("mcp", _payload(headers))
    assert meta["headers"] is None and meta["headers_encrypted"] is None


def test_each_store_is_a_fresh_token_of_the_same_headers():
    """Fernet: a random IV per token, so equal headers never give equal ciphertext (nothing to correlate in a dump)."""
    s = _fresh()
    one = get_scan_metadata_for_type("mcp", _payload(_headers(s)))
    two = get_scan_metadata_for_type("mcp", _payload(_headers(s)))
    assert one["headers_encrypted"] != two["headers_encrypted"]
    assert decrypt_secrets(one["headers_encrypted"]) == decrypt_secrets(two["headers_encrypted"]) == _headers(s)


# ============================================================================ what the API returns
def _scan(meta):
    owner = types.SimpleNamespace(email="a@example.test", first_name="Ada", last_name="Lovelace")
    return types.SimpleNamespace(
        id=7, title="mcp", created_at=None, last_updated=None, scan_status="success", credit_consumed=1.0,
        owner_user=owner, info=None, scan_metadata=meta,
        scan_data={"results": {"tools": [], "prompts": [], "resources": []}},
    )


def test_no_scan_api_returns_a_header_value_for_an_old_row_or_a_new_one():
    """GET /{team}/mcp/scan/{id} returns ``get_scan_metadata``; the scan list returns ``return_mcp_list_item``."""
    from backend.utilities.dashboard.scan_metadata import get_scan_metadata
    from backend.utilities.db.scan_list_item import return_mcp_list_item

    s = _fresh()
    legacy = {"server_url": URL, "server_mode": "sse", "headers": _headers(s), "environment": "production"}
    sealed = get_scan_metadata_for_type("mcp", _payload(_headers(s)))
    for meta in (legacy, sealed):
        scan = _scan(meta)
        returned = get_scan_metadata(scan_type="mcp", scan=scan)
        _assert_no_value(json.dumps([returned, return_mcp_list_item(scan)], default=str), s)
        assert returned["server_url"] == URL
        assert "headers_encrypted" not in returned  # the token is never handed out either


# ============================================================================ the task message
def test_the_published_task_message_has_redacted_reprs_and_the_worker_still_gets_the_headers(monkeypatch):
    """``kwargsrepr`` is what Celery prints for a task (worker log records, ``celery events``, Flower); the body is
    what the worker runs with."""
    # #53: the MCP server host must resolve to a public address; .test names never resolve (RFC 6761).
    import socket

    monkeypatch.setattr(socket, "getaddrinfo", lambda host, port, *a, **k: [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port))])

    from celery import Celery
    from celery.signals import after_task_publish

    import backend.utilities.celery.celery_connection  # noqa: F401  (every backend publisher imports it)
    from backend.utilities.scan.format_input import format_input_for_scan

    s = _fresh()
    kwargs = asyncio.run(format_input_for_scan("mcp", _payload(_headers(s))))
    published = []

    def grab(sender=None, headers=None, body=None, **_):
        published.append((dict(headers), body))

    after_task_publish.connect(grab, weak=False)
    try:
        app = Celery("test_mcp_headers_44", broker="memory://")
        app.send_task("scan_worker.mcp_scan", kwargs=kwargs, queue="test_mcp_headers_44")
    finally:
        after_task_publish.disconnect(grab)
    (headers, body), = published
    assert body[1]["mcp_dict_context"]["headers"] == _headers(s)
    _assert_no_value(headers["kwargsrepr"] + headers["argsrepr"], s)
    # still useful for debugging: the header names and the non-secret fields
    assert "Authorization" in headers["kwargsrepr"] and URL in headers["kwargsrepr"]


def test_the_repr_hook_never_raises_and_leaves_a_message_without_reprs_alone():
    from backend.utilities.celery.task_reprs import redact_task_reprs
    from backend.utilities.log_redaction import UNREDACTABLE

    headers = {"argsrepr": "()", "kwargsrepr": "{'x': 1}"}
    redact_task_reprs(headers=headers, body=None)  # not a protocol 2 body
    assert headers == {"argsrepr": UNREDACTABLE, "kwargsrepr": UNREDACTABLE}
    protocol_1 = {"id": "t"}
    redact_task_reprs(headers=protocol_1, body={"kwargs": {}})
    assert protocol_1 == {"id": "t"}


# ============================================================================ the migration
def _migration():
    path = next(VERSIONS.glob("d44mcphdr001_*.py"))
    spec = importlib.util.spec_from_file_location("m_d44mcphdr001", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    return mod


def test_the_migration_chains_onto_the_one_head():
    import re

    mod = _migration()
    assert mod.revision == "d44mcphdr001"
    revisions, parents = set(), set()
    for path in VERSIONS.glob("*.py"):
        text = path.read_text()
        rev = re.search(r"^revision(?::\s*str)?\s*=\s*['\"]([^'\"]+)['\"]", text, re.M)
        down = re.search(r"^down_revision[^=]*=\s*['\"]([^'\"]+)['\"]", text, re.M)
        if rev:
            revisions.add(rev.group(1))
        if down:
            parents.add(down.group(1))
    assert mod.down_revision in revisions
    assert len(revisions - parents) == 1 and (revisions - parents == {"d44mcphdr001"} or "d44mcphdr001" in parents)


def _rows(conn) -> dict[int, str | None]:
    return {r[0]: r[1] for r in conn.execute(sa.text("SELECT id, CAST(scan_metadata AS TEXT) FROM scan ORDER BY id"))}


def _seal_existing_rows(engine) -> None:
    from alembic.migration import MigrationContext
    from alembic.operations import Operations

    def step(name: str, batch: int = 2) -> dict[int, str | None]:
        with engine.begin() as conn:
            mod = _migration()
            mod.BATCH = batch  # several batches over the rows below
            with Operations.context(MigrationContext.configure(conn)):
                getattr(mod, name)()
            return _rows(conn)

    s, other = _fresh(), _fresh()
    legacy = {"server_url": URL, "server_mode": "sse", "headers": _headers(s), "environment": "production"}
    already = get_scan_metadata_for_type("mcp", _payload(_headers(other)))
    sast = {"repo_url": "https://github.com/acme/app", "headers": {"X-Not-Mcp": "kept"}}
    rows = {1: ("mcp", legacy), 2: ("mcp", {"server_url": URL, "server_mode": "sse", "headers": None}),
            3: ("mcp", already), 4: ("sast", sast), 5: ("mcp", None), 6: ("mcp", {}),
            7: ("mcp", {**legacy, "server_url": "https://two.example.test/mcp"}), 8: ("llm", {"model_type": "custom"})}
    with engine.begin() as conn:
        conn.execute(sa.text("CREATE TABLE scan (id integer PRIMARY KEY, scan_type varchar(32), scan_metadata json)"))
        for scan_id, (scan_type, meta) in rows.items():
            conn.execute(sa.text("INSERT INTO scan (id, scan_type, scan_metadata) VALUES (:i, :t, :m)"),
                         {"i": scan_id, "t": scan_type, "m": None if meta is None else json.dumps(meta)})
        before = _rows(conn)

    up = step("upgrade")
    for scan_id in (1, 7):  # the plaintext rows: sealed, everything else on them kept
        _assert_no_value(up[scan_id], s)
        sealed = json.loads(up[scan_id])
        assert sealed["headers"] == {"Authorization": MASK, "Cookie": MASK, "X-Custom": MASK}
        assert decrypt_secrets(sealed["headers_encrypted"]) == _headers(s)
        assert {k: v for k, v in sealed.items() if not k.startswith("headers")} == \
            {k: v for k, v in rows[scan_id][1].items() if k != "headers"}
    for scan_id in (2, 3, 4, 5, 6, 8):  # no headers, already sealed, not an MCP scan: untouched
        assert up[scan_id] == before[scan_id], scan_id
    assert step("upgrade", batch=500) == up  # a second run changes nothing (no re-encryption either)
    assert step("downgrade") == up  # the rows stay sealed
    assert step("upgrade") == up


def test_the_migration_seals_the_rows_stored_before_on_sqlite(tmp_path):
    engine = sa.create_engine(f"sqlite:///{tmp_path / 'm.db'}")
    try:
        _seal_existing_rows(engine)
    finally:
        engine.dispose()


@pytest.mark.skipif(not PG, reason="set CBOM_TEST_PG_URL to run against PostgreSQL")
def test_the_migration_seals_the_rows_stored_before_on_postgresql():
    schema = "t44_" + secrets.token_hex(4)
    admin = sa.create_engine(PG)
    with admin.begin() as conn:
        conn.execute(sa.text(f'CREATE SCHEMA "{schema}"'))
    engine = sa.create_engine(PG, connect_args={"options": f"-csearch_path={schema}"})
    try:
        _seal_existing_rows(engine)
    finally:
        engine.dispose()
        with admin.begin() as conn:
            conn.execute(sa.text(f'DROP SCHEMA "{schema}" CASCADE'))
        admin.dispose()
