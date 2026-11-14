"""Scan-node downloads: the files a customer needs to run a scan node without access to any registry or to the
DevSecShield repository, served by this deployment to members of the team.

* ``GET /{team_id}/cbom/node-artifacts``: what this server offers (version, file name, size, SHA-256 of each), and
  the image name the image file loads as.  A file this server does not hold is listed with ``available: false``.
* ``POST /{team_id}/cbom/node-artifacts/{kind}/link``: a download link for one file, valid for a few minutes, so the
  browser downloads it as a file (with progress, straight to disk) instead of holding it in memory.  The link names
  the member it was made for; it is checked again (still a member of the team) when it is used.
* ``GET /{team_id}/cbom/node-artifacts/{kind}``: the file itself, streamed from disk with its Content-Length
  (``Authorization: Bearer`` or ``?ticket=`` from the link route).  Every download is an audit event
  (``node_artifact.download``, the kind as the field).

Kinds: ``image`` (``scan-node-<version>.tar.gz``, a ``docker save`` archive), ``image-sha256`` (its
``sha256sum -c`` file), ``helm-chart`` (``cbom-scan-node-<version>.tgz``), ``ova-kit`` and ``ami-kit`` (zip files of
the Packer templates in deploy/node-images, with a README for customers).

The files live in ``CBOM_NODE_ARTIFACT_DIR`` with a ``manifest.json`` naming them; the deploy fills it
(``scripts/deploy/staging.sh node-artifacts``; deploy/staging/README.md, "Scan node downloads").  A server without
them answers 404 with ``NOT_AVAILABLE``, which the Add scan node wizard shows as it is.

``CBOM_NODE_IMAGE_REF`` (optional): the image in a registry customers can pull from.  Unset (the default), the wizard
offers no ``docker pull``: the image comes from the file.  ``CBOM_NODE_CHART_REF`` (optional, with it):
``oci://<registry>/<path>/cbom-scan-node:<chart version>``, the Helm chart in that registry (``helm upgrade --install
... oci://... --version <v>``).  The staging deploy sets both only when the GHCR packages are public
(``CBOM_NODE_REGISTRY_PUBLIC=1``; deploy/staging/README.md), so the wizard never offers a pull that needs a login.

Install links (terminal-only hosts): creating a node, or giving it a new registration token, returns
``install_links`` (``install_links()``): one link per file the node's way of running needs (Docker: the image; Helm:
the image and the chart; OVA/AMI: the build kit and the image), each with its SHA-256, for ``curl``/``wget`` in the
one-paste install command.  A link (``?node_ticket=<node id>.<HMAC>``) is bound to the team, the node, the file kind
and the node's current registration token (its hash): it works exactly as long as that token does, so it stops when
the node registers, when the token is regenerated or the node reset, and when the token expires (24 h).  It holds
nothing the registration token could be derived from.  Every use is an audit event (``node_artifact.download``, actor
the node).
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import threading
import time
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, Header, HTTPException, Query
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import FileResponse, JSONResponse, Response
from sqlmodel import Session

from backend.get_db import get_db
from backend.new_models import CbomScanNode
from backend.utilities.cbom_sources.common import audit, iso_z, log, utcnow
from backend.utilities.cbom_sources.http import PRIVATE, CbomRoute, TeamId, authorize, read_limiter, write_limiter
from backend.utilities.team import check_if_user_is_in_team

router = APIRouter(tags=["cbom-sources"], route_class=CbomRoute)
AuthHeader = Annotated[str | None, Header()]
BASE = "/{team_id}/cbom/node-artifacts"

Kind = Literal["image", "image-sha256", "helm-chart", "ova-kit", "ami-kit"]
# kind -> (label, the manifest key of its file, media type)
KINDS: dict[str, tuple[str, str, str]] = {
    "image": ("Scan node image", "image", "application/gzip"),
    "image-sha256": ("Scan node image SHA-256", "image", "text/plain; charset=utf-8"),
    "helm-chart": ("Helm chart", "helm-chart", "application/gzip"),
    "ova-kit": ("OVA build kit", "ova-kit", "application/zip"),
    "ami-kit": ("AMI build kit", "ami-kit", "application/zip"),
}
NOT_AVAILABLE = "{label} is not available on this server yet. Contact your administrator."
TICKET_SECONDS = 300
_FILE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
_VERSION = re.compile(r"[0-9][0-9A-Za-z.-]{0,18}")  # scripts/release/scan_node_image.sh NODE_VERSION_RE
# an image reference with an explicit tag: [registry[:port]/]path:tag (lower-case path, as Docker requires)
_IMAGE_REF = re.compile(r"(?:[A-Za-z0-9.-]+(?::[0-9]{1,5})?/)?[a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*"
                        r":[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}")


def artifact_dir() -> str | None:
    value = (os.environ.get("CBOM_NODE_ARTIFACT_DIR") or "").strip()
    return value or None


def pull_image_ref() -> str | None:
    """CBOM_NODE_IMAGE_REF when it is a tagged image reference; anything else is ignored (and logged)."""
    value = (os.environ.get("CBOM_NODE_IMAGE_REF") or "").strip()
    if not value:
        return None
    if not _IMAGE_REF.fullmatch(value):
        log("cbom node artifacts: CBOM_NODE_IMAGE_REF is not a tagged image reference; ignored")
        return None
    return value


_hash_lock = threading.Lock()
_hash_cache: dict[tuple[str, int, int], str] = {}


def file_sha256(path: str) -> str:
    """SHA-256 of a file, computed once per (path, size, mtime) and kept: the list shows the hash of exactly the bytes
    the download sends, without trusting a hash written next to the file."""
    st = os.stat(path)
    key = (path, st.st_size, st.st_mtime_ns)
    with _hash_lock:
        if key in _hash_cache:
            return _hash_cache[key]
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    value = digest.hexdigest()
    with _hash_lock:
        _hash_cache[key] = value
    return value


_CHART_REF = re.compile(r"oci://(" + _IMAGE_REF.pattern + r")")


def pull_chart() -> tuple[str, str] | None:
    """CBOM_NODE_CHART_REF (``oci://<registry>/<path>/<chart>:<version>``) as (``oci://...`` without the version, the
    version); anything else is ignored (and logged).  Only offered with CBOM_NODE_IMAGE_REF: the chart runs that image."""
    value = (os.environ.get("CBOM_NODE_CHART_REF") or "").strip()
    if not value or pull_image_ref() is None:
        return None
    if not _CHART_REF.fullmatch(value):
        log("cbom node artifacts: CBOM_NODE_CHART_REF is not oci://<registry>/<path>:<version>; ignored")
        return None
    ref, version = value.rsplit(":", 1)
    return ref, version


def _manifest(directory: str) -> dict | None:
    try:
        with open(os.path.join(directory, "manifest.json"), encoding="utf-8") as fh:
            data = json.load(fh)
    except FileNotFoundError:
        return None
    except (OSError, ValueError) as exc:
        log("cbom node artifacts: manifest.json unreadable", error=type(exc).__name__)
        return None
    return data if isinstance(data, dict) else None


def _resolve(directory: str, manifest: dict, kind: str) -> str | None:
    """The path of <kind>'s file: a plain file name from the manifest, a regular file inside the directory."""
    files = manifest.get("files")
    name = files.get(KINDS[kind][1]) if isinstance(files, dict) else None
    if not isinstance(name, str) or not _FILE_NAME.fullmatch(name):
        return None
    root = os.path.realpath(directory)
    path = os.path.realpath(os.path.join(root, name))
    if os.path.dirname(path) != root or not os.path.isfile(path):
        return None
    return path


def _state() -> tuple[str | None, dict | None]:
    directory = artifact_dir()
    return directory, (_manifest(directory) if directory else None)


def _version(manifest: dict | None) -> str | None:
    value = manifest.get("version") if manifest else None
    return value if isinstance(value, str) and _VERSION.fullmatch(value) else None


def _image_ref(manifest: dict | None) -> str | None:
    value = manifest.get("image_ref") if manifest else None
    return value if isinstance(value, str) and _IMAGE_REF.fullmatch(value) else None


def listing() -> dict:
    directory, manifest = _state()
    items = []
    for kind, (label, _key, _media) in KINDS.items():
        if kind == "image-sha256":
            continue  # offered with the image (its sha256 is the image's)
        path = _resolve(directory, manifest, kind) if directory and manifest else None
        if path is None:
            items.append({"kind": kind, "label": label, "available": False, "filename": None, "size": None,
                          "sha256": None, "message": NOT_AVAILABLE.format(label=label)})
            continue
        items.append({"kind": kind, "label": label, "available": True, "filename": os.path.basename(path),
                      "size": os.path.getsize(path), "sha256": file_sha256(path), "message": None})
    chart = pull_chart()
    return {
        "version": _version(manifest),
        "image_ref": _image_ref(manifest),
        "pull_image_ref": pull_image_ref(),
        "pull_chart_ref": chart[0] if chart else None,
        "pull_chart_version": chart[1] if chart else None,
        "artifacts": items,
    }


# ------------------------------------------------------------------------------------------------ download links
def _ticket_key() -> bytes:
    secret = os.environ.get("JWT_SECRET_KEY") or ""
    if not secret:
        raise HTTPException(status_code=503, detail="Download links are not configured on this server")
    return hmac.new(secret.encode("utf-8"), b"cbom-node-artifact-ticket/v1", hashlib.sha256).digest()


def _sign(team_id: int, kind: str, user_id: int, expires: int) -> str:
    msg = f"{team_id}:{kind}:{user_id}:{expires}".encode()
    return base64.urlsafe_b64encode(hmac.new(_ticket_key(), msg, hashlib.sha256).digest()).decode().rstrip("=")


def make_ticket(team_id: int, kind: str, user_id: int, now: float | None = None) -> str:
    expires = int((now if now is not None else time.time()) + TICKET_SECONDS)
    return f"{user_id}.{expires}.{_sign(team_id, kind, user_id, expires)}"


_LINK_REFUSED = HTTPException(status_code=401, detail="This download link is invalid or has expired. Start the download again.")


def ticket_user(ticket: str, team_id: int, kind: str, now: float | None = None) -> int:
    parts = ticket.split(".")
    if len(parts) != 3 or not parts[0].isdigit() or not parts[1].isdigit() or len(ticket) > 200:
        raise _LINK_REFUSED
    user_id, expires = int(parts[0]), int(parts[1])
    if not hmac.compare_digest(parts[2], _sign(team_id, kind, user_id, expires)):
        raise _LINK_REFUSED
    if expires < (now if now is not None else time.time()):
        raise _LINK_REFUSED
    return user_id


# ------------------------------------------------------------------------------------------------ node install links
# The files each way of running a node needs, main one first (the wizard's one-paste command fetches exactly these).
NODE_KINDS: dict[str, tuple[str, ...]] = {
    "docker": ("image",),
    "helm": ("image", "helm-chart"),
    "ova": ("ova-kit", "image"),
    "ami": ("ami-kit", "image"),
}
NODE_TICKET_MAX = 100
_NODE_LINK_REFUSED = HTTPException(
    status_code=401,
    detail="This install link no longer works: the node has registered, or its registration token was replaced or "
           "has expired. Generate a new registration token for the node and use its new install command.")


def _node_link_key() -> bytes | None:
    secret = os.environ.get("JWT_SECRET_KEY") or ""
    if not secret:
        return None
    return hmac.new(secret.encode("utf-8"), b"cbom-node-install-link/v1", hashlib.sha256).digest()


def _node_sig(key: bytes, team_id: int, node_id: int, kind: str, registration_hash: str) -> str:
    msg = f"{team_id}:{node_id}:{kind}:{registration_hash}".encode()
    return base64.urlsafe_b64encode(hmac.new(key, msg, hashlib.sha256).digest()).decode().rstrip("=")


def _awaiting_registration(node: CbomScanNode, now) -> bool:
    return bool(node.registration_token_hash and node.registration_expires_at and node.enrolled_at is None
                and node.node_token_hash is None and node.registration_expires_at > now)


def install_links(team_id: int, node: CbomScanNode) -> dict | None:
    """The install links of a node waiting to register (module docstring), or None: no registration token, no files
    on this server, or no signing key (the wizard then shows the command for files downloaded in the browser)."""
    if not _awaiting_registration(node, utcnow()):
        return None
    key = _node_link_key()
    directory, manifest = _state()
    if key is None or not directory or not manifest:
        return None
    files = []
    for kind in NODE_KINDS.get(node.deployment, NODE_KINDS["docker"]):
        path = _resolve(directory, manifest, kind)
        if path is None:
            continue
        sig = _node_sig(key, team_id, int(node.id), kind, node.registration_token_hash)
        files.append({"kind": kind, "filename": os.path.basename(path), "size": os.path.getsize(path),
                      "sha256": file_sha256(path), "url": f"/{team_id}/cbom/node-artifacts/{kind}?node_ticket={node.id}.{sig}"})
    if not files:
        return None
    return {"version": _version(manifest), "expires_at": iso_z(node.registration_expires_at), "files": files}


def node_ticket_node(engine, ticket: str, team_id: int, kind: str) -> int:
    """The node an install link was made for, while the link still works (module docstring); else 401."""
    node_id, _, sig = ticket.partition(".")
    key = _node_link_key()
    if not node_id.isdigit() or not sig or len(node_id) > 18 or key is None:
        raise _NODE_LINK_REFUSED
    with Session(engine) as session:
        node = session.get(CbomScanNode, int(node_id))
        ok = (node is not None and node.team_id == team_id and kind in NODE_KINDS.get(node.deployment, ())
              and _awaiting_registration(node, utcnow())
              and hmac.compare_digest(sig, _node_sig(key, team_id, int(node.id), kind, node.registration_token_hash)))
    if not ok:
        log("cbom node install link refused", team=team_id, node=node_id, kind=kind)
        raise _NODE_LINK_REFUSED
    return int(node_id)


# ------------------------------------------------------------------------------------------------ routes
@router.get(BASE, dependencies=[Depends(read_limiter)], summary="Scan node files this server offers")
async def list_artifacts(team_id: TeamId, Authorization: AuthHeader = None):
    await authorize(team_id, Authorization)
    return JSONResponse(await run_in_threadpool(listing), headers=PRIVATE)


@router.post(BASE + "/{kind}/link", dependencies=[Depends(write_limiter)], summary="A short-lived download link")
async def download_link(team_id: TeamId, kind: Kind, Authorization: AuthHeader = None):
    _engine, user = await authorize(team_id, Authorization)
    directory, manifest = await run_in_threadpool(_state)
    if not (directory and manifest and await run_in_threadpool(_resolve, directory, manifest, kind)):
        raise HTTPException(status_code=404, detail=NOT_AVAILABLE.format(label=KINDS[kind][0]))
    ticket = make_ticket(team_id, kind, int(user.id))
    return JSONResponse({"url": f"/{team_id}/cbom/node-artifacts/{kind}?ticket={ticket}", "expires_in": TICKET_SECONDS},
                        headers=PRIVATE)


def _record(engine, team_id: int, actor: tuple[str, int], kind: str, version: str | None, size: int) -> None:
    """A user's download (object: the file kind), or a node's install link (actor and object: the node)."""
    actor_type, actor_id = actor
    with Session(engine) as session:
        audit(session, team_id=team_id, actor_type=actor_type, actor_id=actor_id, action="node_artifact.download",
              object_type="node" if actor_type == "node" else "node_artifact",
              object_id=actor_id if actor_type == "node" else None, changed_fields=[kind])
        session.commit()
    log("cbom node artifact download", team=team_id, **{actor_type: actor_id}, kind=kind, version=version or "-",
        bytes=size)


@router.get(BASE + "/{kind}", dependencies=[Depends(read_limiter)], summary="Download a scan node file",
            response_class=Response)
async def download(team_id: TeamId, kind: Kind, Authorization: AuthHeader = None,
                   ticket: Annotated[str | None, Query(max_length=200)] = None,
                   node_ticket: Annotated[str | None, Query(max_length=NODE_TICKET_MAX)] = None):
    if Authorization or not (ticket or node_ticket):
        engine, user = await authorize(team_id, Authorization)
        actor = ("user", int(user.id))
    elif ticket:
        user_id = ticket_user(ticket, team_id, kind)
        engine = get_db()
        await run_in_threadpool(check_if_user_is_in_team, user_id, team_id, engine)
        actor = ("user", user_id)
    else:
        engine = get_db()
        actor = ("node", await run_in_threadpool(node_ticket_node, engine, node_ticket, team_id, kind))
    directory, manifest = await run_in_threadpool(_state)
    path = await run_in_threadpool(_resolve, directory, manifest, kind) if directory and manifest else None
    label, _key, media = KINDS[kind]
    if path is None:
        raise HTTPException(status_code=404, detail=NOT_AVAILABLE.format(label=label))
    name = os.path.basename(path)
    if kind == "image-sha256":
        body = f"{await run_in_threadpool(file_sha256, path)}  {name}\n".encode()
        await run_in_threadpool(_record, engine, team_id, actor, kind, _version(manifest), len(body))
        return Response(body, media_type=media, headers={
            **PRIVATE, "Content-Disposition": f'attachment; filename="{name}.sha256"'})
    size = os.path.getsize(path)
    await run_in_threadpool(_record, engine, team_id, actor, kind, _version(manifest), size)
    # FileResponse streams the file in chunks and sends its Content-Length (from stat), never reading it whole.
    return FileResponse(path, media_type=media, filename=name, headers=PRIVATE)
