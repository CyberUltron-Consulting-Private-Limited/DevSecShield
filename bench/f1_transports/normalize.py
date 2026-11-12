"""Parity normaliser: the SSH path's assets and zs-collect's assets for the same host, made comparable.

CONTRACT section 4 ("Parity with SSH"): drop timings, ``host_key.first_use`` and the zs-collect/1 envelope; accept
``host_key.fingerprint`` when it equals one of the host's own host-key fingerprints (the ``ssh_host_key`` assets of the
same document); compare assets sorted by the backend's ``jobs._asset_key`` formula.  "Identical" means ``diff()``
returns an empty list.

Two more things are run-specific and dropped, on both sides alike:
* ``process_library.facts.pids``: process ids differ between any two runs, so ``diff()`` compares the group itself,
  its exe, library, ports and the ``deleted`` flag, not its pids.  ``pid_differences()`` reports them separately (every
  bench report carries it per host), so a transport's own processes joining a group, or a service's processes that
  zs-collect left out, stay visible: on a lab whose services keep their pids between runs the report should be empty.
* the per-target ``duration_ms`` and the run's ``duration_s`` / ``elapsed_s`` (timings).
* the thread id OpenSSL 3 puts in front of each error line (``80DB4734FD7E0000:error:1E08010C:DECODER routines...``)
  in a fact such as ``detail`` of a key file it could not read: it is the address of the openssl process's thread
  and differs between any two runs, SSH or not.  The rest of the line (code, library, reason) is compared.
"""
from __future__ import annotations

import copy
import hashlib
import json
import re
from typing import Any

LOCAL_HOST_KEY = "<this host's own host key>"
_OPENSSL_TID = re.compile(r"\b[0-9A-F]{8,16}(?=:error:)")


def _no_thread_ids(value: Any) -> Any:
    if isinstance(value, str):
        return _OPENSSL_TID.sub("<tid>", value)
    if isinstance(value, dict):
        return {k: _no_thread_ids(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_no_thread_ids(v) for v in value]
    return value


def asset_key(asset: dict) -> str:
    """backend/utilities/cbom_sources/jobs.py::_asset_key, unchanged."""
    facts = asset.get("facts") or {}
    identity = facts.get("fingerprint_sha256") or facts.get("identity") or asset.get("name") or ""
    raw = f"{asset.get('type')}|{asset.get('target') or ''}|{asset.get('location')}|{identity}"
    return hashlib.sha256(raw.encode("utf-8", "replace")).hexdigest()


def _host_fingerprints(assets: list[dict]) -> set[str]:
    return {str((a.get("facts") or {}).get("fingerprint")) for a in assets if a.get("type") == "ssh_host_key"}


def normalise_assets(assets: list[dict], target: str | None = None) -> list[dict]:
    rows = [copy.deepcopy(a) for a in assets if target is None or a.get("target") == target]
    own = _host_fingerprints(rows)
    out = []
    for a in rows:
        facts = a.get("facts") or {}
        hk = facts.get("host_key")
        if isinstance(hk, dict):
            hk.pop("first_use", None)
            if hk.get("fingerprint") in own:
                facts["host_key"] = LOCAL_HOST_KEY
        if a.get("type") == "process_library":
            facts.pop("pids", None)
        if facts:
            a["facts"] = _no_thread_ids(facts)
        out.append(a)
    return sorted(out, key=lambda a: (asset_key(a), json.dumps(a, sort_keys=True, default=str)))


def normalise_outcomes(result: dict, target: str | None = None) -> list[dict]:
    rows = []
    for t in (result or {}).get("targets") or []:
        if target is not None and t.get("target") != target:
            continue
        rows.append({k: v for k, v in t.items() if k not in ("duration_ms",)})
    return sorted(rows, key=lambda r: json.dumps(r, sort_keys=True, default=str))


def normalise(doc: dict, target: str | None = None) -> dict[str, Any]:
    """A collect.py document (SSH path) or a zs-collect/1 document, reduced to what must match."""
    return {"assets": normalise_assets(doc.get("assets") or [], target),
            "outcomes": normalise_outcomes(doc.get("result") or {}, target)}


def diff(a: dict, b: dict) -> list[str]:
    """Human-readable differences between two normalised documents (empty = identical)."""
    out: list[str] = []
    ka = {asset_key(x): x for x in a["assets"]}
    kb = {asset_key(x): x for x in b["assets"]}
    for k in sorted(set(ka) - set(kb)):
        out.append(f"only in A: {ka[k]['type']} {ka[k]['location']}")
    for k in sorted(set(kb) - set(ka)):
        out.append(f"only in B: {kb[k]['type']} {kb[k]['location']}")
    for k in sorted(set(ka) & set(kb)):
        if json.dumps(ka[k], sort_keys=True, default=str) != json.dumps(kb[k], sort_keys=True, default=str):
            out.append(f"differs: {ka[k]['type']} {ka[k]['location']}: "
                       f"A={json.dumps(ka[k], sort_keys=True, default=str)[:400]} "
                       f"B={json.dumps(kb[k], sort_keys=True, default=str)[:400]}")
    if a["outcomes"] != b["outcomes"]:
        out.append(f"outcomes differ: A={a['outcomes']} B={b['outcomes']}")
    if len(a["assets"]) != len(ka) or len(b["assets"]) != len(kb):
        out.append("duplicate asset keys in one document")
    return out


def pid_differences(a_doc: dict, b_doc: dict, target: str | None = None) -> list[str]:
    """``process_library`` groups present on both sides (same asset key) whose process ids differ, one line each:
    ``pids differ: <name> <location>: only A [..]; only B [..]``.  ``diff()`` ignores pids; this is the report that
    keeps them from hiding (review 5874466030: the salt-minion's own long-lived processes were left out, and the
    transport's SSH session added, on every host, with an empty normalised diff)."""
    def groups(doc: dict) -> dict[str, dict]:
        return {asset_key(x): x for x in doc.get("assets") or []
                if x.get("type") == "process_library" and (target is None or x.get("target") == target)}

    ga, gb = groups(a_doc), groups(b_doc)
    out = []
    for k in sorted(set(ga) & set(gb)):
        pa = set((ga[k].get("facts") or {}).get("pids") or [])
        pb = set((gb[k].get("facts") or {}).get("pids") or [])
        if pa != pb:
            out.append(f"pids differ: {ga[k].get('name')} {ga[k].get('location')}: only A {sorted(pa - pb)}; "
                       f"only B {sorted(pb - pa)}")
    return out
