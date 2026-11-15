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


def _semver_key(version: str) -> tuple[list[int], tuple] | None:
    """(numeric core, pre-release key) of ``1.2.3`` / ``1.2.3.4`` / ``2.0.0-rc.1`` (a pre-release sorts before its
    release); None when not semver-like.  The core keeps its length: ``_compare`` pads both to the same width."""
    match = _SEMVER.fullmatch(version)
    if not match:
        return None
    core = [int(part) for part in match.group("core").split(".")]
    pre = match.group("pre")
    # numeric identifiers sort before alphanumeric ones; each part is (0, int) or (1, str), so they always compare
    pre_key: tuple = (1,) if pre is None else (0, *((0, int(p)) if p.isdigit() else (1, p) for p in pre.split(".")))
    return core, pre_key


def _compare(a: str, b: str) -> int | None:
    """-1 / 0 / 1 for two versions, None when either is not semver-like and they differ.  Cores of different lengths
    are zero-padded to the same width first (``1.2.3`` == ``1.2.3.0`` < ``1.2.3.4``), so an int is never compared with
    the pre-release tuple (review of PR #286: ``1.2.3.4`` vs ``1.2.3`` raised TypeError)."""
    if a == b:
        return 0
    ka, kb = _semver_key(a), _semver_key(b)
    if ka is None or kb is None:
        return None
    width = max(len(ka[0]), len(kb[0]), 3)
    full_a = (*ka[0], *[0] * (width - len(ka[0])), ka[1])
    full_b = (*kb[0], *[0] * (width - len(kb[0])), kb[1])
    return (full_a > full_b) - (full_a < full_b)


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


# ------------------------------------------------------------------------------------------- an image the wizard offers
# Issue #197: the wizard offered devsecshield-scan-node:1.0.0, a release tag written once (2 Nov) and never again
# while VERSION stayed 1.0.0, so every node installed from it lacked request signing, ZS_CA_FILE and the alive file.
# image_freshness says whether an image reference is this server's node build, from its tag alone (no registry call):
#   <prefix>-<sha12>[-<hash8>] (publish-ghcr.yml: dev-, staging-, pr-<n>-, manual-) or <version>-<sha12>: the commit;
#   <X.Y.Z>: a release tag, written once (it can hold an older build of the same version);
#   staging, dev, stable, latest, pr-<n>, <X.Y>, no tag: a moving tag (whatever was published last).
# The cases are a contract shared with the frontend: contracts/cbom/node_image_freshness.json.
STALE_IMAGE_STATES = ("outdated", "different", "unverified")
_SHA_TAG = re.compile(r"(?:(?:dev|staging|manual|pr-[1-9][0-9]{0,6})|(?P<version>[0-9][0-9A-Za-z.]{0,18}))"
                      r"-(?P<build>[0-9a-f]{12})(?:-[0-9a-f]{8})?")
_RELEASE_TAG = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?")
_MOVING_TAG = re.compile(r"(?:dev|staging|stable|latest|main|pr-[1-9][0-9]{0,6}|[0-9]+\.[0-9]+|[0-9]+)")


def image_tag(ref: str) -> str:
    """The tag of an image reference (``latest`` when it names none; a registry port is not a tag)."""
    ref = (ref or "").strip().split("@", 1)[0]
    cut = ref.rfind(":")
    return ref[cut + 1:] if cut > ref.rfind("/") else "latest"


def image_freshness(ref: str | None, server_version: str | None, server_build: str | None) -> dict[str, Any] | None:
    """{"state", "reason", "message", "server_build", "tag"} of the image ``ref`` against the server's node build, or
    None without a reference.  States: current, outdated (an older version), different (another commit, or a newer
    version), unverified (the server's version as a release tag: written once, it may predate this build), moving (a
    channel tag), unknown (nothing to compare, or a tag this server does not recognise)."""
    if not ref or not ref.strip():
        return None
    ref = ref.strip()
    tag = image_tag(ref)
    server = server_label(server_version, server_build)
    out: dict[str, Any] = {"state": "unknown", "reason": None, "message": None, "server_build": server, "tag": tag}

    def say(state: str, reason: str, message: str | None) -> dict[str, Any]:
        out.update(state=state, reason=reason, message=message)
        return out

    if not server_version:
        return say("unknown", "no_server_build", None)
    sha = _SHA_TAG.fullmatch(tag)
    if sha:
        version = sha.group("version")
        if version and (_compare(version, server_version) or 0) < 0:
            return say("outdated", "older_version", f"{ref} is scan node {version}, older than this server's node build {server}.")
        if not server_build:
            return say("unknown", "no_server_build_id", None)
        if server_build.startswith(sha.group("build")):
            return say("current", "same_build", None)
        return say("different", "different_build",
                   f"{ref} was built from commit {sha.group('build')}, not this server's node build {server}.")
    if _RELEASE_TAG.fullmatch(tag):
        order = _compare(tag, server_version)
        if order is not None and order < 0:
            return say("outdated", "older_version", f"{ref} is scan node {tag}, older than this server's node build {server}.")
        if order is not None and order > 0:
            return say("different", "newer_version", f"{ref} is scan node {tag}, newer than this server's node build {server}.")
        if not server_build:
            return say("current", "same_version", None)
        return say("unverified", "release_tag",
                   f"{ref} is a release tag, written once when {tag} was first published: it can hold an older build "
                   f"than this server's node build {server}.")
    if _MOVING_TAG.fullmatch(tag):
        return say("moving", "moving_tag",
                   f"{ref} is a moving tag: it names whatever was published last, which may not be this server's "
                   f"node build {server}.")
    return say("unknown", "unrecognised_tag", None)


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
