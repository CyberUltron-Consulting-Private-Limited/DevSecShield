"""zs-collect/1 documents: validation, chunked transport and relabelling.  Standard library only.

Canonical copy: ``scan_node/zs_scan_node/transports/zsdoc.py``.  A byte-identical copy lives at
``backend/utilities/cbom_sources/transports/zsdoc.py`` (the cloud worker checks SSM output with it); a backend test
compares the two files, so change both or neither.

* ``validate_document(doc, nonce, version)``: None when ``doc`` is a zs-collect/1 document for this job, else why not.
  It mirrors ``zs_scan_node/schemas/zs-collect-1.schema.json`` and the backend's ``AssetIn`` limits.
* ``encode_chunks`` / ``reassemble``: the document gzipped, base64'd and cut into lines
  ``ZSC1 <nonce> <i>/<n> <sha256 of the gzip> <data>`` of at most 512 KB (AWX keeps each job event under its size
  limit), and back, refusing a missing, foreign, duplicated-and-different or altered chunk.
* ``relabel(doc, label)``: the document's assets as the node posts them: ``target`` is the inventory address the
  job was given (zs-collect names the host by its own hostname), and a coverage row's location, which starts with
  the target, follows it.  Everything else is left exactly as zs-collect wrote it.
"""
from __future__ import annotations

import base64
import gzip
import hashlib
import io
import json
import re
from typing import Any

FORMAT = "zs-collect/1"
NONCE_RE = re.compile(r"^[A-Za-z0-9_-]{16,128}$")
STATUSES = ("success", "failure", "cancelled")
MAX_ASSETS = 50_000  # backend jobs.MAX_ASSETS_PER_ATTEMPT
MAX_CHUNK_BYTES = 512 * 1024
DEFAULT_CHUNK_BYTES = 384 * 1024  # base64 + the line header stay well under AWX's event size
CHUNK_PREFIX = "ZSC1"
MAX_DOCUMENT_BYTES = 64 * 1024 * 1024  # decompressed; 50,000 assets with 16 KB facts each would still fit
_ASSET_LIMITS = {"type": 32, "target": 255, "location": 512, "name": 255, "algorithm": 64, "protocol": 32}


class ChunkError(Exception):
    """Chunked output that is incomplete, out of place or altered."""


def validate_document(doc: Any, nonce: str, version: str | None = None) -> str | None:
    """None when ``doc`` is a zs-collect/1 document for this job (its nonce, and its version when given), else the
    reason it is refused.  Mirrors schemas/zs-collect-1.schema.json and the backend's AssetIn limits."""
    if not isinstance(doc, dict):
        return "not a JSON object"
    if doc.get("format") != FORMAT:
        return f"format is not {FORMAT}"
    if doc.get("run_nonce") != nonce:
        return "run nonce does not match this job"
    if version is not None and doc.get("collector_version") != version:
        return f"collector version {str(doc.get('collector_version'))[:20]} is not the expected {version}"
    for name in ("target_label", "started_at", "finished_at"):
        if not isinstance(doc.get(name), str):
            return f"{name} missing"
    if doc.get("tier") not in (1, 2):
        return "tier must be 1 or 2"
    if not isinstance(doc.get("host"), dict):
        return "host missing"
    if doc.get("status") not in STATUSES:
        return "status is not success, failure or cancelled"
    if doc.get("error") is not None and not isinstance(doc.get("error"), str):
        return "error must be text"
    result = doc.get("result")
    if not isinstance(result, dict) or not isinstance(result.get("counts"), dict) \
            or not isinstance(result.get("targets"), list):
        return "result missing"
    assets = doc.get("assets")
    if not isinstance(assets, list) or len(assets) > MAX_ASSETS:
        return "assets missing or more than 50,000"
    for i, a in enumerate(assets):
        if not isinstance(a, dict):
            return f"asset {i} is not an object"
        if not isinstance(a.get("location"), str) or not a["location"]:
            return f"asset {i} has no location"
        for key, limit in _ASSET_LIMITS.items():
            value = a.get(key)
            if key == "type" and not isinstance(value, str):
                return f"asset {i} has no type"
            if value is not None and (not isinstance(value, str) or len(value) > limit):
                return f"asset {i}: {key} longer than {limit}"
        ks = a.get("key_size")
        if ks is not None and (not isinstance(ks, int) or isinstance(ks, bool) or not 0 <= ks <= 1_000_000):
            return f"asset {i}: key_size out of range"
        facts = a.get("facts", {})
        if not isinstance(facts, dict) or len(json.dumps(facts, default=str)) > 16 * 1024:
            return f"asset {i}: facts missing or larger than 16 KB"
    return None


def encode_chunks(doc: dict, nonce: str, chunk_bytes: int = DEFAULT_CHUNK_BYTES) -> list[str]:
    """``ZSC1 <nonce> <i>/<n> <sha256 of the gzip> <base64 slice>`` lines, each at most ``chunk_bytes`` long."""
    if not 1024 <= chunk_bytes <= MAX_CHUNK_BYTES:
        raise ValueError(f"chunk size must be 1024..{MAX_CHUNK_BYTES} bytes")
    blob = gzip.compress(json.dumps(doc, separators=(",", ":"), default=str).encode(), mtime=0)
    digest = hashlib.sha256(blob).hexdigest()
    data = base64.b64encode(blob).decode()
    header = len(f"{CHUNK_PREFIX} {nonce} 999999/999999 {digest} ")
    room = chunk_bytes - header
    pieces = [data[i:i + room] for i in range(0, len(data), room)] or [""]
    n = len(pieces)
    return [f"{CHUNK_PREFIX} {nonce} {i + 1}/{n} {digest} {piece}" for i, piece in enumerate(pieces)]


def is_chunk(line: Any) -> bool:
    return isinstance(line, str) and line.lstrip().startswith(CHUNK_PREFIX + " ")


def reassemble(lines: list[str], nonce: str) -> dict:
    """The document from its chunk lines (any order).  Raises ChunkError if one is missing, foreign or altered."""
    parts: dict[int, str] = {}
    total, digest = None, None
    for raw in lines:
        fields = str(raw).strip().split(" ")
        if len(fields) != 5 or fields[0] != CHUNK_PREFIX:
            raise ChunkError("not a zs-collect chunk")
        _p, n_nonce, pos, n_digest, data = fields
        if n_nonce != nonce:
            raise ChunkError("chunk from another run (nonce)")
        try:
            i, n = (int(x) for x in pos.split("/", 1))
        except ValueError:
            raise ChunkError("bad chunk position") from None
        if not 1 <= i <= n or (total is not None and n != total) or (digest is not None and n_digest != digest):
            raise ChunkError("chunks of different documents")
        total, digest = n, n_digest
        if i in parts and parts[i] != data:
            raise ChunkError(f"chunk {i} arrived twice with different data")
        parts[i] = data
    if total is None or len(parts) != total:
        raise ChunkError(f"{len(parts)} of {total or '?'} chunks")
    try:
        blob = base64.b64decode("".join(parts[i] for i in range(1, total + 1)), validate=True)
    except ValueError:
        raise ChunkError("chunk data is not base64") from None
    if hashlib.sha256(blob).hexdigest() != digest:
        raise ChunkError("checksum mismatch")
    try:
        raw_json = gzip.GzipFile(fileobj=io.BytesIO(blob)).read(MAX_DOCUMENT_BYTES + 1)
    except (OSError, EOFError):
        raise ChunkError("chunk data does not decompress") from None
    if len(raw_json) > MAX_DOCUMENT_BYTES:
        raise ChunkError("document larger than 64 MB")
    try:
        doc = json.loads(raw_json)
    except ValueError:
        raise ChunkError("chunk data does not decompress to JSON") from None
    if not isinstance(doc, dict):
        raise ChunkError("not a document")
    return doc


def parse_output(text: str, nonce: str) -> dict:
    """The document from a launcher's stdout: one JSON line, or chunk lines (other lines are ignored).  Raises
    ChunkError for chunks that do not reassemble and ValueError when there is no document at all."""
    lines = [line for line in (text or "").splitlines() if line.strip()]
    chunks = [line for line in lines if is_chunk(line)]
    if chunks:
        return reassemble(chunks, nonce)
    for line in reversed(lines):
        line = line.strip()
        if line.startswith("{"):
            if len(line) > MAX_DOCUMENT_BYTES:
                raise ValueError("document larger than 64 MB")
            doc = json.loads(line)
            if isinstance(doc, dict):
                return doc
    raise ValueError("no zs-collect document in the output")


def relabel(doc: dict, label: str) -> list[dict]:
    """The document's assets with ``target`` set to ``label`` (and coverage locations that start with the document's
    own target moved to ``label``).  Assumes ``validate_document`` passed."""
    own = str(doc.get("target_label") or "")
    out = []
    for a in doc.get("assets") or []:
        b = dict(a)
        old = str(b.get("target") or own)
        b["target"] = label
        loc = str(b.get("location") or "")
        if b.get("type") == "coverage" and old and loc.startswith(old + "#"):
            b["location"] = label + loc[len(old):]
        out.append(b)
    return out


def target_outcome(doc: dict) -> tuple[str, str | None]:
    """(status, error) of the one host the document is about, as zs-collect recorded it."""
    rows = [t for t in ((doc.get("result") or {}).get("targets") or []) if isinstance(t, dict)]
    if rows:
        return str(rows[0].get("status") or "error"), rows[0].get("error")
    if doc.get("status") == "success":
        return "ok", None
    return "error", str(doc.get("error") or "zs-collect reported no outcome")[:256]
