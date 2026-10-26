"""Scan context for the posture lanes. One walk per scan."""

from __future__ import annotations

import os
import stat
from collections import Counter
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path

from aibom.cbom.posture.diagnostics import DiagnosticSink
from aibom.cbom.posture.limits import (
    BYTES_PER_SCAN,
    FILES_PER_SCAN,
    GlobBudget,
)
from aibom.cbom.posture.model import ConfigContext, DisabledResource, ImportRecord
from aibom.cbom.posture.safeio import (
    DecodedFile,
    IndexedFile,
    Skip,
    classify_name,
    decode_bytes,
    file_byte_limit,
    iter_entries,
    sanitize_path,
    sniff_cloudformation,
    sniff_compose,
    sniff_kubernetes,
    sniff_tls_result,
    sniff_traefik,
)
from aibom.model.result import ScanResult
from aibom.scan.registry import ScanContext

_CONFIG_FIRST = frozenset({"source", "shell"})
_TIME_LIMITS = frozenset({"SoftTimeLimitExceeded", "TimeLimitExceeded"})
_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)


@dataclass
class FileIndex:
    files: tuple[IndexedFile, ...]
    unread: int


@dataclass(frozen=True)
class PostureSidecar:
    lanes: tuple[str, ...]
    failed_lanes: tuple[str, ...]
    diagnostics: tuple
    diagnostic_totals: Mapping[str, int]
    imports: tuple[ImportRecord, ...]
    declared: tuple[tuple[tuple[str, str], int], ...]
    out_of_scope: int
    disabled: tuple[DisabledResource, ...]
    bytes_read: int
    files_parsed: int
    dropped_facts: int
    dropped_components: int
    assembly_failed: bool

    @staticmethod
    def empty() -> PostureSidecar:
        return PostureSidecar(
            lanes=(),
            failed_lanes=(),
            diagnostics=(),
            diagnostic_totals={},
            imports=(),
            declared=(),
            out_of_scope=0,
            disabled=(),
            bytes_read=0,
            files_parsed=0,
            dropped_facts=0,
            dropped_components=0,
            assembly_failed=False,
        )


@dataclass
class PostureSink:
    root: Path
    diagnostics: DiagnosticSink = field(default_factory=DiagnosticSink)
    imports: list[ImportRecord] = field(default_factory=list)
    declared: Counter[tuple[str, str]] = field(default_factory=Counter)
    out_of_scope: int = 0
    disabled: list[DisabledResource] = field(default_factory=list)
    bytes_read: int = 0
    files_parsed: int = 0
    sniff_bytes: int = 0
    lanes_run: set[str] = field(default_factory=set)
    failed_lanes: set[str] = field(default_factory=set)
    dropped_facts: int = 0
    dropped_components: int = 0
    file_order: Callable[[list[IndexedFile]], list[IndexedFile]] | None = None
    included: dict[str, DecodedFile | None] = field(default_factory=dict)
    included_files: int = 0
    glob_budget: GlobBudget = field(default_factory=GlobBudget)
    config_ctx: Mapping[str, ConfigContext] | None = None
    ciphers: object | None = None
    _index: FileIndex | None = None

    def enter(self, lane: str) -> None:
        self.lanes_run.add(lane)

    @contextmanager
    def guard(self, lane: str) -> Iterator[None]:
        try:
            yield
        except Exception as exc:
            if type(exc).__name__ in _TIME_LIMITS:
                raise
            self.failed_lanes.add(lane)
            self.diagnostics.add("internal_error", "", 0)

    def index(self) -> FileIndex:
        if self._index is not None:
            return self._index
        config: list[IndexedFile] = []
        later: list[IndexedFile] = []
        for rel, entry in iter_entries(self.root):
            kind = self._classify_entry(rel, entry)
            if kind is None:
                continue
            try:
                size = entry.stat(follow_symlinks=False).st_size
            except OSError:
                continue
            item = IndexedFile(sanitize_path(rel), kind, size)
            if kind in _CONFIG_FIRST:
                later.append(item)
            else:
                config.append(item)
        reserved: list[IndexedFile] = []
        unread = 0
        budget_bytes = 0
        stopped = False
        for item in config + later:
            over_budget = budget_bytes + item.size > BYTES_PER_SCAN
            too_many = self.files_parsed >= FILES_PER_SCAN
            if stopped or too_many or over_budget:
                unread += 1
                stopped = True
                continue
            if item.size > file_byte_limit(item.cls):
                self.diagnostics.add("size_cap", item.rel, 0)
                continue
            reserved.append(item)
            budget_bytes += item.size
            self.files_parsed += 1
        if unread:
            self.diagnostics.add("scan_budget_exhausted", "", unread)
        if self.file_order is not None:
            reserved = list(self.file_order(reserved))
        self.bytes_read = budget_bytes
        self._index = FileIndex(tuple(reserved), unread)
        return self._index

    def _classify_entry(self, rel: str, entry: os.DirEntry) -> str | None:
        try:
            mode = entry.stat(follow_symlinks=False).st_mode
        except OSError:
            return None
        special = (
            stat.S_ISLNK(mode)
            or stat.S_ISFIFO(mode)
            or stat.S_ISSOCK(mode)
            or stat.S_ISCHR(mode)
            or stat.S_ISBLK(mode)
        )
        if special:
            self.diagnostics.add("special_file_skipped", sanitize_path(rel), 0)
            return None
        if not stat.S_ISREG(mode):
            return None
        named = classify_name(rel)
        if named is not None:
            return named
        head = self._head(entry)
        if head is None:
            return None
        if sniff_tls_result(head):
            return "tls-result"
        if sniff_cloudformation(head):
            return "cloudformation"
        if sniff_kubernetes(head):
            return "kubernetes"
        if sniff_compose(head):
            return "compose"
        if sniff_traefik(head):
            return "web-server"
        return None

    def _head(self, entry: os.DirEntry) -> bytes | None:
        flags = os.O_RDONLY | _O_NOFOLLOW
        try:
            fd = os.open(entry.path, flags)
        except OSError:
            self.diagnostics.add("special_file_skipped", sanitize_path(entry.name), 0)
            return None
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode):
                rel_name = sanitize_path(entry.name)
                self.diagnostics.add("special_file_skipped", rel_name, 0)
                return None
            return os.read(fd, 65_536)
        finally:
            os.close(fd)

    def read(self, item: IndexedFile) -> DecodedFile | None:
        path = self.root / item.rel
        try:
            fd = os.open(path, os.O_RDONLY | _O_NOFOLLOW)
        except OSError:
            self.diagnostics.add("special_file_skipped", item.rel, 0)
            return None
        try:
            raw = os.read(fd, item.size + 1)
        finally:
            os.close(fd)
        decoded = decode_bytes(raw, item.rel, item.cls)
        if isinstance(decoded, Skip):
            self.diagnostics.add(decoded.code, item.rel, 0)
            return None
        if decoded.replaced:
            self.diagnostics.add("encoding_fallback", item.rel, 0)
        if decoded.capped_line:
            self.diagnostics.add("line_cap", item.rel, decoded.capped_line)
        return decoded

    def read_included(self, rel: str, cls: str) -> DecodedFile | None:
        key = sanitize_path(rel)
        if key in self.included:
            return self.included[key]
        path = (self.root / key).resolve()
        try:
            path.relative_to(self.root.resolve())
        except ValueError:
            self.diagnostics.add("special_file_skipped", key, 0)
            self.included[key] = None
            return None
        if self.bytes_read >= BYTES_PER_SCAN or self.files_parsed >= FILES_PER_SCAN:
            self.diagnostics.add("scan_budget_exhausted", key, 0)
            self.included[key] = None
            return None
        try:
            raw = path.read_bytes()
        except OSError:
            self.included[key] = None
            return None
        self.bytes_read += len(raw)
        self.files_parsed += 1
        self.included_files += 1
        decoded = decode_bytes(raw, key, cls)
        if isinstance(decoded, Skip):
            self.diagnostics.add(decoded.code, key, 0)
            self.included[key] = None
            return None
        self.included[key] = decoded
        return decoded

    def freeze(self, *, assembly_failed: bool = False) -> PostureSidecar:
        entered = tuple(sorted(self.lanes_run))
        failed = tuple(sorted(self.lanes_run if assembly_failed else self.failed_lanes))
        if assembly_failed:
            lanes: tuple[str, ...] = ()
        else:
            lanes = tuple(sorted(self.lanes_run - self.failed_lanes))
        return PostureSidecar(
            lanes=lanes,
            failed_lanes=failed or (entered if assembly_failed else ()),
            diagnostics=self.diagnostics.stored(),
            diagnostic_totals=dict(self.diagnostics.totals),
            imports=tuple(self.imports),
            declared=tuple(sorted(self.declared.items())),
            out_of_scope=self.out_of_scope,
            disabled=tuple(self.disabled),
            bytes_read=self.bytes_read,
            files_parsed=self.files_parsed,
            dropped_facts=self.dropped_facts,
            dropped_components=self.dropped_components,
            assembly_failed=assembly_failed,
        )


class CbomScanContext(ScanContext):
    def __init__(self, root: Path, *, file_order=None) -> None:
        super().__init__(root)
        self.posture = PostureSink(root=root, file_order=file_order)


def posture_sink(ctx: ScanContext) -> PostureSink:
    sink = getattr(ctx, "posture", None)
    if not isinstance(sink, PostureSink):
        raise TypeError("posture scanners require CbomScanContext")
    return sink


@dataclass
class CbomScanResult(ScanResult):
    posture: PostureSidecar = field(default_factory=PostureSidecar.empty)
