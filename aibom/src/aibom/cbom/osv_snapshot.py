"""Offline OSV snapshot of crypto-library advisories (CB-29): versioned, checksummed
(and optionally signed) advisory
data for the maven, nuget, npm, pypi, go and cargo crypto libraries, so the code scan
matches library versions on
air-gapped and on-prem installs without calling OSV.

The file (``SCHEMA``)::

    {"schema": "zeroshield.osv-snapshot/1", "snapshot_version": "2026.11.14.1",
    "generated_at": "2026-11-14",
     "source": "https://api.osv.dev/v1/query", "packages": {"go":
     ["golang.org/x/crypto", ...], ...},
     "advisories": [{"id", "osv_id", "ecosystem", "name", "introduced", "fixed",
     "last_affected", "versions",
                     "summary", "source", "modified"}, ...],
     "sha256": "<hex of the canonical JSON of every other key>"}

* **Build** (online, once per release or per on-prem update): ``python -m
aibom.cbom.osv_snapshot build --out F``
  asks OSV (``/v1/query``, every page) for each package of ``data/osv_packages.json``
  and writes the file; ``--sign-key``
  writes ``F.sig`` (base64 Ed25519 over the file's bytes, the knowledge-base bundle's
  scheme); ``--from F`` builds from
  recorded OSV answers instead (tests, air-gapped rebuilds).
* **Load** (no network unless configured): the shipped ``data/osv_snapshot.json``;
``CBOM_OSV_SNAPSHOT`` (a file an
  operator copied in); ``CBOM_OSV_SNAPSHOT_URL`` (downloaded once per process). Every
  candidate must pass its checksum;
  when ``CBOM_OSV_PUBKEYS`` (else ``CBOM_KB_PUBKEYS``) is set, a file or download must
  also carry a valid signature.
  The newest valid one is used (a file wins a tie, then a download); a rejected one is
  reported, never used.
* **Match**: one OSV record becomes one row per affected range of the package
(``rows_from_record``); the same
  function reads the snapshot's build and the online fallback, and
  ``advisories.match_advisories`` matches both, so
  the same OSV data gives the same answer offline and online.
* **Fresh or stale**: older than ``CBOM_OSV_MAX_AGE_DAYS`` (default 30) is stale. A
stale snapshot is still used; with
  ``CBOM_OSV_ONLINE=1`` the packages a scan finds are asked of OSV live first (a package
  OSV does not answer keeps
  the snapshot's rows). The scan reports which data it used (``status``), shown in the
  UI and the CycloneDX export.
"""

from __future__ import annotations

import argparse
import base64
import datetime as _dt
import hashlib
import json
import logging
import os
import tempfile
import urllib.error
import urllib.request
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from functools import lru_cache
from importlib.resources import files
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

SCHEMA = "zeroshield.osv-snapshot/1"
OSV_QUERY = "https://api.osv.dev/v1/query"
# our ecosystem key -> OSV's ecosystem name
ECOSYSTEMS = {
    "maven": "Maven",
    "nuget": "NuGet",
    "npm": "npm",
    "pypi": "PyPI",
    "go": "Go",
    "cargo": "crates.io",
}
_FROM_OSV = {v: k for k, v in ECOSYSTEMS.items()}
DEFAULT_MAX_AGE_DAYS = 30
SUMMARY_MAX = 200
_TIMEOUT_S = 20.0
_MAX_PAGES = 50

Post = Callable[[str, dict[str, Any]], dict[str, Any] | None]


# --------------------------------------------------------------------------------------
# OSV record -> rows
def _cve(record: dict[str, Any]) -> str:
    """The id a row is shown under: the CVE alias when there is one (as the curated
    file and
    the SBOM lane do)."""
    for alias in [record.get("id"), *(record.get("aliases") or [])]:
        text = str(alias or "").strip()
        if text.upper().startswith("CVE-"):
            return text.upper()
    return str(record.get("id") or "").strip()


def _pairs(
    events: Sequence[dict[str, Any]],
) -> list[tuple[str | None, str | None, str | None]]:
    """(introduced, fixed, last_affected) intervals of one OSV range, in event order
    (OSV
    schema "Evaluation")."""
    out: list[tuple[str | None, str | None, str | None]] = []
    start: str | None = None
    open_ = False
    for event in events:
        if not isinstance(event, dict):
            continue
        if "introduced" in event:
            start, open_ = str(event["introduced"]), True
        elif "fixed" in event and open_:
            out.append((start, str(event["fixed"]), None))
            open_ = False
        elif "last_affected" in event and open_:
            out.append((start, None, str(event["last_affected"])))
            open_ = False
        elif "limit" in event and open_:
            out.append((start, str(event["limit"]), None))
            open_ = False
    if open_:
        out.append((start, None, None))
    return out


def rows_from_record(
    record: dict[str, Any], ecosystem: str, name: str
) -> list[dict[str, Any]]:
    """Every row one OSV record gives for one package (our ecosystem key, lower-case
    name): one per interval of each
    SEMVER / ECOSYSTEM range, plus one with the enumerated ``versions`` when the record
    lists them. A withdrawn
    record gives none; GIT ranges (commit hashes) are not version ranges and are
    skipped."""
    if not isinstance(record, dict) or record.get("withdrawn"):
        return []
    rid = _cve(record)
    osv_id = str(record.get("id") or "")
    summary = " ".join(
        str(record.get("summary") or record.get("details") or "").split()
    )[:SUMMARY_MAX]
    base = {
        "id": rid,
        "osv_id": osv_id,
        "ecosystem": ecosystem,
        "name": name,
        "summary": summary,
        "source": f"https://osv.dev/vulnerability/{osv_id}",
        "modified": str(record.get("modified") or ""),
    }
    rows: list[dict[str, Any]] = []
    for affected in record.get("affected") or []:
        pkg = affected.get("package") if isinstance(affected, dict) else None
        if (
            not isinstance(pkg, dict)
            or _FROM_OSV.get(str(pkg.get("ecosystem") or "")) != ecosystem
        ):
            continue
        if str(pkg.get("name") or "").strip().lower() != name:
            continue
        for rng in affected.get("ranges") or []:
            if not isinstance(rng, dict) or rng.get("type") not in (
                "SEMVER",
                "ECOSYSTEM",
            ):
                continue
            for introduced, fixed, last in _pairs(rng.get("events") or []):
                rows.append(
                    {
                        **base,
                        "introduced": None if introduced in (None, "0") else introduced,
                        "fixed": fixed,
                        "last_affected": last,
                        "versions": [],
                    }
                )
        versions = sorted({str(v) for v in affected.get("versions") or [] if v})
        if versions:
            rows.append(
                {
                    **base,
                    "introduced": None,
                    "fixed": None,
                    "last_affected": None,
                    "versions": versions,
                }
            )
    return rows


def _row_key(row: dict[str, Any]) -> tuple:
    return (
        row["ecosystem"],
        row["name"],
        row["id"],
        row.get("osv_id") or "",
        row.get("introduced") or "",
        row.get("fixed") or "",
        row.get("last_affected") or "",
        tuple(row.get("versions") or ()),
    )


def rows_from_records(
    records: Iterable[tuple[str, str, dict[str, Any]]],
) -> list[dict[str, Any]]:
    """Rows of (ecosystem, name, record) triples, de-duplicated and sorted (the same set
    in any order gives the same
    list, so the same OSV data gives the same snapshot bytes)."""
    seen: dict[tuple, dict[str, Any]] = {}
    for ecosystem, name, record in records:
        for row in rows_from_record(record, ecosystem, name):
            seen.setdefault(_row_key(row), row)
    return [seen[k] for k in sorted(seen)]


# --------------------------------------------------------------------------------------
# the document
def canonical(document: dict[str, Any]) -> bytes:
    body = {k: v for k, v in document.items() if k != "sha256"}
    return json.dumps(
        body, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")


def checksum(document: dict[str, Any]) -> str:
    return hashlib.sha256(canonical(document)).hexdigest()


def build_document(
    rows: list[dict[str, Any]],
    *,
    packages: dict[str, list[str]],
    generated_at: _dt.date,
    source: str,
    sequence: int = 1,
) -> dict[str, Any]:
    document = {
        "schema": SCHEMA,
        "snapshot_version": f"{generated_at:%Y.%m.%d}.{sequence}",
        "generated_at": generated_at.isoformat(),
        "source": source,
        "packages": {k: sorted(v) for k, v in sorted(packages.items())},
        "advisories": rows,
    }
    document["sha256"] = checksum(document)
    return document


def dumps(document: dict[str, Any]) -> bytes:
    return (
        json.dumps(document, sort_keys=True, indent=1, ensure_ascii=True) + "\n"
    ).encode("ascii")


def sign(data: bytes, private_key_pem: bytes) -> bytes:
    """Base64 Ed25519 signature over ``data`` (the knowledge-base bundle's scheme)."""
    # an optional dependency: only the build step signs (the check reuses crypto_kb's)
    from cryptography.hazmat.primitives import (  # type: ignore[import-not-found]
        serialization,
    )
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (  # type: ignore[import-not-found]
        Ed25519PrivateKey,
    )

    key = serialization.load_pem_private_key(private_key_pem, password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("the signing key is not an Ed25519 private key")
    return base64.b64encode(key.sign(data)) + b"\n"


def _trusted_keys() -> str:
    return os.environ.get("CBOM_OSV_PUBKEYS") or os.environ.get("CBOM_KB_PUBKEYS") or ""


def check(
    data: bytes, *, sig_path: str | None, keys: str, require_signature: bool
) -> tuple[dict[str, Any] | None, bool, str | None]:
    """(document, signed, problem): the document when its schema and checksum hold (and
    its signature, when one is
    required); ``signed`` is True when a trusted key verified it."""
    try:
        document = json.loads(data)
    except ValueError:
        return None, False, "not JSON"
    if not isinstance(document, dict) or document.get("schema") != SCHEMA:
        return None, False, f"schema is not {SCHEMA}"
    if document.get("sha256") != checksum(document):
        return None, False, "checksum does not match the content"
    try:
        _dt.date.fromisoformat(str(document.get("generated_at")))
    except ValueError:
        return None, False, "generated_at is not an ISO date"
    if not isinstance(document.get("advisories"), list):
        return None, False, "advisories is not a list"
    signed = False
    if keys:
        from aibom.cbom.crypto_kb import _verify_bundle

        reason = (
            _verify_bundle(data, sig_path or "", keys)
            if sig_path
            else "no signature file"
        )
        if reason is None:
            signed = True
        elif require_signature:
            return None, False, f"signature: {reason}"
    elif require_signature:
        return None, False, "signature required but no trusted key is configured"
    return document, signed, None


# --------------------------------------------------------------------------------------
# loading
@dataclass(frozen=True)
class Snapshot:
    document: dict[str, Any]
    origin: str  # builtin | file | download
    signed: bool
    problems: tuple[str, ...] = ()
    rows: tuple[dict[str, Any], ...] = field(default=())

    @property
    def version(self) -> str:
        return str(self.document.get("snapshot_version") or "")

    @property
    def generated_at(self) -> _dt.date:
        return _dt.date.fromisoformat(str(self.document["generated_at"]))

    def packages(self) -> set[tuple[str, str]]:
        return {
            (eco, str(n).lower())
            for eco, names in (self.document.get("packages") or {}).items()
            for n in names
        }

    def age_days(self, today: _dt.date | None = None) -> int:
        return ((today or _dt.date.today()) - self.generated_at).days

    def stale(self, today: _dt.date | None = None) -> bool:
        return self.age_days(today) > max_age_days()


def max_age_days() -> int:
    try:
        return max(
            1, int(os.environ.get("CBOM_OSV_MAX_AGE_DAYS") or DEFAULT_MAX_AGE_DAYS)
        )
    except ValueError:
        return DEFAULT_MAX_AGE_DAYS


def _builtin_bytes() -> bytes:
    return (
        files("aibom.cbom").joinpath("data").joinpath("osv_snapshot.json").read_bytes()
    )


def _download(url: str) -> tuple[bytes | None, str | None, str | None]:
    """(snapshot bytes, signature path, problem). Cached under CBOM_OSV_CACHE_DIR for
    the
    process's first ask."""
    cache = Path(
        os.environ.get("CBOM_OSV_CACHE_DIR")
        or Path(tempfile.gettempdir()) / "zeroshield-osv"
    )
    try:
        cache.mkdir(parents=True, exist_ok=True)
        req = urllib.request.Request(
            url, headers={"User-Agent": "zeroshield-cbom-osv-snapshot"}
        )
        with urllib.request.urlopen(req, timeout=_TIMEOUT_S) as resp:
            data = resp.read(64 * 1024 * 1024)
        (cache / "osv_snapshot.json").write_bytes(data)
        sig_path = None
        try:
            with urllib.request.urlopen(
                urllib.request.Request(url + ".sig", headers=req.headers),
                timeout=_TIMEOUT_S,
            ) as resp:
                (cache / "osv_snapshot.json.sig").write_bytes(resp.read(4096))
            sig_path = str(cache / "osv_snapshot.json.sig")
        except (urllib.error.URLError, OSError, ValueError):
            pass
        return data, sig_path, None
    except (urllib.error.URLError, OSError, ValueError) as exc:
        return None, None, f"download failed ({exc.__class__.__name__})"


@lru_cache(maxsize=1)
def load() -> Snapshot:
    """The snapshot in force (see the module docstring); never raises: the shipped one
    is
    always there."""
    keys = _trusted_keys()
    problems: list[str] = []
    candidates: list[tuple[int, Snapshot]] = []
    document, _signed, problem = check(
        _builtin_bytes(), sig_path=None, keys="", require_signature=False
    )
    if (
        document is None
    ):  # a broken build: an empty snapshot dated long ago (every scan says stale)
        problems.append(f"built-in snapshot rejected: {problem}")
        document = {
            "schema": SCHEMA,
            "snapshot_version": "0",
            "generated_at": "1970-01-01",
            "packages": {},
            "advisories": [],
            "source": "",
        }
    candidates.append((0, Snapshot(document, "builtin", False)))
    path = os.environ.get("CBOM_OSV_SNAPSHOT")
    if path:
        try:
            data = Path(path).read_bytes()
            doc, signed, problem = check(
                data,
                sig_path=os.environ.get("CBOM_OSV_SNAPSHOT_SIG") or path + ".sig",
                keys=keys,
                require_signature=bool(keys),
            )
        except OSError as exc:
            doc, signed, problem = None, False, f"unreadable ({exc.__class__.__name__})"
        if doc is None:
            problems.append(f"CBOM_OSV_SNAPSHOT rejected: {problem}")
        else:
            candidates.append((2, Snapshot(doc, "file", signed)))
    url = os.environ.get("CBOM_OSV_SNAPSHOT_URL")
    if url:
        blob, sig_path, problem = _download(url)
        doc, signed = None, False
        if blob is not None:
            doc, signed, problem = check(
                blob, sig_path=sig_path, keys=keys, require_signature=bool(keys)
            )
        if doc is None:
            problems.append(f"CBOM_OSV_SNAPSHOT_URL rejected: {problem}")
        else:
            candidates.append((1, Snapshot(doc, "download", signed)))
    _rank, best = max(candidates, key=lambda c: (c[1].document["generated_at"], c[0]))
    for problem in problems:
        log.warning("OSV snapshot: %s", problem)
    rows = tuple(
        r for r in best.document.get("advisories") or [] if isinstance(r, dict)
    )
    return Snapshot(best.document, best.origin, best.signed, tuple(problems), rows)


# --------------------------------------------------------------------------------------
# online (build, fallback)
def _post(url: str, body: dict[str, Any]) -> dict[str, Any] | None:
    req = urllib.request.Request(
        url,
        data=json.dumps(body).encode(),
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "zeroshield-cbom-osv-snapshot",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT_S) as resp:
            return json.loads(resp.read().decode("utf-8", errors="replace"))
    except (urllib.error.URLError, TimeoutError, OSError, ValueError):
        return None


def fetch_records(
    ecosystem: str, name: str, *, post: Post | None = None
) -> list[dict[str, Any]] | None:
    """Every OSV record of one package (all pages), or None when OSV did not answer."""
    post = post or _post
    records: list[dict[str, Any]] = []
    token = None
    for _ in range(_MAX_PAGES):
        body: dict[str, Any] = {
            "package": {"ecosystem": ECOSYSTEMS[ecosystem], "name": name}
        }
        if token:
            body["page_token"] = token
        answer = post(OSV_QUERY, body)
        if not isinstance(answer, dict):
            return None
        records.extend(v for v in answer.get("vulns") or [] if isinstance(v, dict))
        token = answer.get("next_page_token")
        if not token:
            return records
    return None  # more pages than any crypto library has: not trusted


def package_list() -> dict[str, list[str]]:
    """The crypto libraries the snapshot covers, per ecosystem
    (``data/osv_packages.json``).
    """
    data = json.loads(
        files("aibom.cbom").joinpath("data").joinpath("osv_packages.json").read_bytes()
    )
    return {
        eco: sorted({str(n) for n in names})
        for eco, names in (data.get("packages") or {}).items()
        if eco in ECOSYSTEMS
    }


def online_rows(
    packages: Iterable[tuple[str, str]], *, post: Post | None = None
) -> tuple[list[dict[str, Any]], set[tuple[str, str]]]:
    """Rows asked of OSV live for ``(ecosystem, name)`` packages, and the packages OSV
    answered."""
    triples: list[tuple[str, str, dict[str, Any]]] = []
    answered: set[tuple[str, str]] = set()
    for ecosystem, name in sorted(set(packages)):
        records = fetch_records(ecosystem, name, post=post)
        if records is None:
            continue
        answered.add((ecosystem, name))
        triples.extend((ecosystem, name.lower(), r) for r in records)
    return rows_from_records(triples), answered


# --------------------------------------------------------------------------------------
# what a scan reports
def status(
    snapshot: Snapshot | None = None,
    *,
    online: dict[str, Any] | None = None,
    today: _dt.date | None = None,
) -> dict[str, Any]:
    """The advisory data a scan used: shown on the results page and written into the
    CycloneDX metadata."""
    snap = snapshot or load()
    out = {
        "source": "osv-snapshot",
        "snapshot_version": snap.version,
        "generated_at": snap.document.get("generated_at"),
        "age_days": snap.age_days(today),
        "max_age_days": max_age_days(),
        "stale": snap.stale(today),
        "origin": snap.origin,
        "signed": snap.signed,
        "sha256": snap.document.get("sha256"),
        "advisories": len(snap.rows),
        "problems": list(snap.problems),
    }
    if online:
        out["online"] = online
    return out


def online_enabled() -> bool:
    return str(os.environ.get("CBOM_OSV_ONLINE") or "").strip().lower() in (
        "1",
        "true",
        "yes",
    )


# --------------------------------------------------------------------------------------
# CLI
def _cmd_build(args: argparse.Namespace) -> int:
    packages = package_list()
    triples: list[tuple[str, str, dict[str, Any]]] = []
    source = OSV_QUERY
    if args.from_file:
        recorded = json.loads(Path(args.from_file).read_text())
        source = str(recorded.get("source") or "recorded")
        for item in recorded.get("packages") or []:
            eco = _FROM_OSV.get(item["ecosystem"], item["ecosystem"])
            for page in item.get("pages") or []:
                triples.extend(
                    (eco, item["name"].lower(), r) for r in page.get("vulns") or []
                )
        packages = {}
        for item in recorded.get("packages") or []:
            packages.setdefault(
                _FROM_OSV.get(item["ecosystem"], item["ecosystem"]), []
            ).append(item["name"])
    else:
        missing = []
        for eco, names in packages.items():
            for name in names:
                records = fetch_records(eco, name)
                if records is None:
                    missing.append(f"{eco}:{name}")
                    continue
                triples.extend((eco, name.lower(), r) for r in records)
        if missing:
            print(
                f"OSV did not answer for {len(missing)} package(s): "
                f"{', '.join(missing)}; nothing written"
            )
            return 2
    generated = _dt.date.fromisoformat(args.date) if args.date else _dt.date.today()
    document = build_document(
        rows_from_records(triples),
        packages=packages,
        generated_at=generated,
        source=source,
        sequence=args.sequence,
    )
    data = dumps(document)
    Path(args.out).write_bytes(data)
    if args.sign_key:
        Path(args.out + ".sig").write_bytes(
            sign(data, Path(args.sign_key).read_bytes())
        )
    print(
        f"{args.out}: {document['snapshot_version']}, "
        f"{len(document['advisories'])} rows, "
        f"{sum(len(v) for v in packages.values())} packages, "
        f"sha256 {document['sha256']}" + (", signed" if args.sign_key else "")
    )
    return 0


def _cmd_verify(args: argparse.Namespace) -> int:
    data = Path(args.file).read_bytes()
    keys = args.keys or _trusted_keys()
    document, signed, problem = check(
        data, sig_path=args.file + ".sig", keys=keys, require_signature=bool(keys)
    )
    if document is None:
        print(f"{args.file}: REJECTED: {problem}")
        return 1
    snap = Snapshot(document, "file", signed, rows=tuple(document["advisories"]))
    print(json.dumps(status(snap), indent=1))
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m aibom.cbom.osv_snapshot")
    sub = parser.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser(
        "build",
        help="build a snapshot from OSV (online) or from recorded OSV answers (--from)",
    )
    b.add_argument("--out", required=True)
    b.add_argument("--from", dest="from_file", default=None)
    b.add_argument(
        "--date", default=None, help="generated_at (default today, UTC date)"
    )
    b.add_argument("--sequence", type=int, default=1)
    b.add_argument(
        "--sign-key", default=None, help="Ed25519 private key (PEM): writes <out>.sig"
    )
    v = sub.add_parser(
        "verify",
        help="check a snapshot's checksum (and signature: --keys / CBOM_OSV_PUBKEYS)",
    )
    v.add_argument("file")
    v.add_argument("--keys", default=None)
    args = parser.parse_args(argv)
    return _cmd_build(args) if args.cmd == "build" else _cmd_verify(args)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
