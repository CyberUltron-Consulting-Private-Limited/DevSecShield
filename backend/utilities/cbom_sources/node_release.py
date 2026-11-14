"""Is a scan node running this server's node build?  (staging QA B6-1)

A node reports ``<version>+<12-character commit>`` (``scan_node/zs_scan_node/__init__.py`` ``reported_version``; CB-03)
in its enrolment, every heartbeat and every job result, or only ``<version>`` when its image was built without a
commit (an image built by hand, or before build ids existed).  This server ships one node build with its scan-node
downloads (``CBOM_NODE_ARTIFACT_DIR/manifest.json``: ``version`` and ``build``, the 40-character commit the image was
built from; ``scripts/release/node_artifacts.py``).  ``node_update`` compares the two, so the Scan nodes tab can say
"Update available" and why, instead of every node showing the same "1.0.0" while running old code.

States:

* ``current``: the node runs the server's node build (same version and commit; or the same version when the server's
  build is unknown);
* ``update_available``: an older version, the same version from another commit, or the same version with no build id
  at all (every image this server ships carries one, so a node without one is not running it);
* ``newer``: the node reports a later version than the server ships (nothing to update to here);
* ``unknown``: nothing to compare (the node has not reported, or this server ships no node build).

Older nodes that send no build id keep working: nothing here is enforced, it is only reported.
"""
from __future__ import annotations

import os
import re
import threading
from typing import Any

_REPORTED = re.compile(r"(?P<version>[0-9][0-9A-Za-z.-]{0,18})(?:\+(?P<build>[0-9a-f]{12}))?")
_BUILD = re.compile(r"[0-9a-f]{40}")
_SEMVER = re.compile(r"(?P<core>[0-9]+(?:\.[0-9]+)*)(?:-(?P<pre>[0-9A-Za-z.-]+))?")


def parse_reported(value: str | None) -> tuple[str | None, str | None]:
    """(version, 12-character build or None) of what a node reported; (None, None) when it is not a node version."""
    match = _REPORTED.fullmatch((value or "").strip())
    if not match:
        return None, None
    return match.group("version"), match.group("build")


def _semver_key(version: str) -> tuple | None:
    """A sort key for ``1.2.3`` / ``2.0.0-rc.1`` (a pre-release sorts before its release); None when not semver-like."""
    match = _SEMVER.fullmatch(version)
    if not match:
        return None
    core = [int(part) for part in match.group("core").split(".")]
    core += [0] * (3 - len(core))
    pre = match.group("pre")
    pre_key: tuple = (1,) if pre is None else (0, *((0, int(p)) if p.isdigit() else (1, p) for p in pre.split(".")))
    return (*core, pre_key)


def _compare(a: str, b: str) -> int | None:
    """-1 / 0 / 1 for two versions, None when either is not semver-like and they differ."""
    if a == b:
        return 0
    ka, kb = _semver_key(a), _semver_key(b)
    if ka is None or kb is None:
        return None
    return (ka > kb) - (ka < kb)


def server_label(version: str | None, build: str | None) -> str | None:
    """How the server's node build is written: the same ``<version>+<12-character commit>`` a node reports."""
    if not version:
        return None
    return f"{version}+{build[:12]}" if build else version


def node_update(reported: str | None, server_version: str | None, server_build: str | None) -> dict[str, Any]:
    """{"state", "reason", "message", "server_build"} for one node (module docstring)."""
    server = server_label(server_version, server_build)
    out: dict[str, Any] = {"state": "unknown", "reason": None, "message": None, "server_build": server}
    version, build = parse_reported(reported)
    if not server_version:
        out["reason"] = "no_server_build"
        return out
    if version is None:
        out["reason"] = "not_reported"
        return out
    order = _compare(version, server_version)
    if order is not None and order < 0:
        out.update(state="update_available", reason="older_version",
                   message=f"Runs {reported}, older than the server's node build {server}.")
    elif order is not None and order > 0:
        out.update(state="newer", reason="newer_version",
                   message=f"Runs {reported}, newer than the server's node build {server}.")
    elif order is None:
        out.update(state="update_available", reason="different_version",
                   message=f"Runs {reported}, not the server's node build {server}.")
    elif not server_build:
        out.update(state="current", reason="same_version")
    elif build is None:
        out.update(state="update_available", reason="no_build_id",
                   message=f"Runs {reported} with no build id (an image built by hand or before build ids existed), "
                           f"so it is older than the server's node build {server}.")
    elif server_build.startswith(build):
        out.update(state="current", reason="same_build")
    else:
        out.update(state="update_available", reason="different_build",
                   message=f"Runs {reported}, not the server's node build {server}.")
    return out


# ------------------------------------------------------------------------------------------- the server's node build
_cache_lock = threading.Lock()
_cache: dict[str, Any] = {"key": None, "value": (None, None)}


def server_release() -> tuple[str | None, str | None]:
    """(version, 40-character build or None) of the node build this server ships (its downloads' manifest.json), read
    again only when the file changes; (None, None) without downloads."""
    from backend.routers import cbom_node_artifacts as artifacts

    directory = artifacts.artifact_dir()
    if not directory:
        return None, None
    path = os.path.join(directory, "manifest.json")
    try:
        st = os.stat(path)
    except OSError:
        return None, None
    key = (path, st.st_size, st.st_mtime_ns)
    with _cache_lock:
        if _cache["key"] == key:
            return _cache["value"]
    manifest = artifacts._manifest(directory)
    value = (artifacts._version(manifest), manifest_build(manifest))
    with _cache_lock:
        _cache.update(key=key, value=value)
    return value


def manifest_build(manifest: dict | None) -> str | None:
    value = manifest.get("build") if manifest else None
    return value if isinstance(value, str) and _BUILD.fullmatch(value) else None
