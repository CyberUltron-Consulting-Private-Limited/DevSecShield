"""The library oracle: OSV.dev's answer at test time (O-2), recorded with the time it was asked.

No answer (offline, timeout, HTTP error) means the library rows are NOT-RUN, never "not vulnerable".
"""
from __future__ import annotations

import datetime as dt
import json
import urllib.error
import urllib.request

from . import SCHEMA_OSV


def query(libs: list[dict], url: str, timeout: float = 30.0) -> dict:
    asked = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    body = {"queries": [{"package": {"ecosystem": lib["ecosystem"], "name": lib["name"]}, "version": lib["version"]}
                        for lib in libs]}
    doc = {"schema": SCHEMA_OSV, "url": url, "asked_at": asked, "queries": body["queries"], "answers": {},
           "error": None}
    req = urllib.request.Request(url, data=json.dumps(body).encode(), method="POST",
                                 headers={"content-type": "application/json", "user-agent": "zs-cbom-d1-lane"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # the fixed OSV URL from sources.json
            data = json.loads(resp.read().decode())
    except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
        doc["error"] = f"{type(exc).__name__}: {exc}"
        return doc
    results = data.get("results") or []
    if len(results) != len(libs):
        doc["error"] = f"OSV answered {len(results)} results for {len(libs)} queries"
        return doc
    for lib, res in zip(libs, results):
        if res.get("next_page_token"):
            doc["error"] = f"OSV paged the answer for {lib['id']}; not judged"
            doc["answers"] = {}
            return doc
        doc["answers"][lib["id"]] = {"ids": sorted(v["id"] for v in res.get("vulns") or [])}
    return doc
