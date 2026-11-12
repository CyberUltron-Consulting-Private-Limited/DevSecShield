"""ZeroShield CBOM scan node: runs inside the customer network, calls out to ZeroShield over HTTPS only."""
import os
import re

VERSION = "1.0.0"

_SHA = re.compile(r"[0-9a-f]{40}")
# a release version that keeps "<version>+<12-character commit>" within 32 characters
_VERSION = re.compile(r"[0-9][0-9A-Za-z.-]{0,18}")


def node_build() -> str | None:
    """The commit this image was built from (ZS_NODE_BUILD, baked in by scan_node/Dockerfile), or None."""
    value = (os.environ.get("ZS_NODE_BUILD") or "").strip().lower()
    return value if _SHA.fullmatch(value) else None


def node_version() -> str:
    """The release version baked into the image (ZS_NODE_VERSION, from ``scan_node_image.sh build <version>``), else
    the code's own VERSION."""
    value = (os.environ.get("ZS_NODE_VERSION") or "").strip()
    return value if _VERSION.fullmatch(value) else VERSION


def reported_version() -> str:
    """What the node tells ZeroShield (enrolment, heartbeat, results, User-Agent): ``<version>+<12-character
    commit>`` (semver build metadata), or just the version for an image built without a commit. At most 32
    characters, the width of ZeroShield's node_version column."""
    build = node_build()
    return f"{node_version()}+{build[:12]}" if build else node_version()
