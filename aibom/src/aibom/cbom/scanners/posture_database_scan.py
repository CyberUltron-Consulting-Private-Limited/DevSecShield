"""CBOM scanner: encryption facts in database, disk, and SQL files."""

from __future__ import annotations

from pathlib import PurePosixPath

from aibom.cbom.posture.assemble import add_facts, iter_class
from aibom.cbom.posture.certlink import link_certificates
from aibom.cbom.posture.ciphers import protocol_asset
from aibom.cbom.posture.context import posture_sink
from aibom.cbom.posture.curves import emit_curves
from aibom.cbom.posture.dhparam import emit_dh, resolve_dh
from aibom.cbom.posture.extract_databases import extract_databases
from aibom.cbom.posture.mssql_keys import key_use_assets
from aibom.cbom.registry import cbom_register
from aibom.scan.registry import ScanContext, Scanner

_CLASSES = frozenset({"database", "disk", "sql", "shell", "dockerfile"})
_PG_CONF = frozenset({"postgresql.conf", "postgresql.auto.conf"})


def _sibling(rel: str, name: str) -> str:
    parent = PurePosixPath(rel.replace("\\", "/")).parent
    if str(parent) in {".", ""}:
        return name
    return str(parent / name)


def _collect(ctx: ScanContext) -> None:
    sink = posture_sink(ctx)
    indexed = {item.rel.replace("\\", "/") for item in sink.index().files}
    sql: dict[str, str] = {}
    for decoded in iter_class(sink, _CLASSES):
        if decoded.cls == "sql":
            sql[decoded.rel] = decoded.text
        base = PurePosixPath(decoded.rel.replace("\\", "/")).name.casefold()
        hba: str | None = None
        hba_path: str | None = None
        if base in _PG_CONF:
            candidate = _sibling(decoded.rel, "pg_hba.conf")
            paired = sink.read_included(candidate, "database")
            if paired is not None:
                hba = paired.text
                hba_path = paired.rel
        elif base == "pg_hba.conf":
            # Design: a lone pg_hba is its own unit; a sibling postgresql.conf
            # owns the pair, so skip the duplicate fact here.
            conf = _sibling(decoded.rel, "postgresql.conf")
            auto = _sibling(decoded.rel, "postgresql.auto.conf")
            if conf in indexed or auto in indexed:
                continue
        facts = link_certificates(
            ctx,
            resolve_dh(
                sink,
                extract_databases(
                    decoded.text, decoded.rel, hba=hba, hba_path=hba_path
                ),
            ),
        )
        add_facts(ctx, facts)
        for fact in facts:
            asset = protocol_asset(fact)
            if asset is not None and not ctx.has_ref(asset.bom_ref):
                ctx.add_component(asset)
        emit_dh(ctx, facts)
        emit_curves(ctx, facts)
    # SQL Server EncryptByKey / DecryptByKey: the algorithm of the key, resolved across the scan's SQL files
    for asset in key_use_assets(sql):
        if not ctx.has_ref(asset.bom_ref):
            ctx.add_component(asset)


@cbom_register
class PostureDatabaseScanner(Scanner):
    """Database, cache, search, crypttab, cryptsetup, and SQL facts."""

    name = "posture_database"
    order = 33
    level = 1
    posture_role = "extractor"

    def scan(self, ctx: ScanContext) -> None:
        posture_sink(ctx).enter(self.name)
        with posture_sink(ctx).guard(self.name):
            _collect(ctx)
