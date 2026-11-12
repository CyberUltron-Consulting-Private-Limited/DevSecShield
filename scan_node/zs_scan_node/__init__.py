"""ZeroShield CBOM scan node: runs inside the customer network, calls out to ZeroShield over HTTPS only."""
import os
import re

VERSION = "1.0.0"

_SHA = re.compile(r"[0-9a-f]{40}")


def node_build() -> str | None:
    """The commit this image was built from (ZS_NODE_BUILD, baked in by scan_node/Dockerfile), or None."""
    value = (os.environ.get("ZS_NODE_BUILD") or "").strip().lower()
    return value if _SHA.fullmatch(value) else None


def reported_version() -> str:
    """What the node tells ZeroShield (enrolment, heartbeat, results, User-Agent): ``1.0.0+<12-character commit>``
    (semver build metadata), or just the version for an image built without a commit. At most 32 characters, the
    width of ZeroShield's node_version column."""
    build = node_build()
    return f"{VERSION}+{build[:12]}" if build else VERSION
