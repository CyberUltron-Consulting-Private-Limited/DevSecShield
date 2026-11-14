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
offers no ``docker pull``: the image comes from the file.
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
from backend.utilities.cbom_sources.common import audit, log
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
    return {
        "version": _version(manifest),
        "image_ref": _image_ref(manifest),
        "pull_image_ref": pull_image_ref(),
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


def _record(engine, team_id: int, user_id: int, kind: str, version: str | None, size: int) -> None:
    with Session(engine) as session:
        audit(session, team_id=team_id, actor_type="user", actor_id=user_id, action="node_artifact.download",
              object_type="node_artifact", object_id=None, changed_fields=[kind])
        session.commit()
    log("cbom node artifact download", team=team_id, user=user_id, kind=kind, version=version or "-", bytes=size)


@router.get(BASE + "/{kind}", dependencies=[Depends(read_limiter)], summary="Download a scan node file",
            response_class=Response)
async def download(team_id: TeamId, kind: Kind, Authorization: AuthHeader = None,
                   ticket: Annotated[str | None, Query(max_length=200)] = None):
    if Authorization or not ticket:
        engine, user = await authorize(team_id, Authorization)
        user_id = int(user.id)
    else:
        user_id = ticket_user(ticket, team_id, kind)
        engine = get_db()
        await run_in_threadpool(check_if_user_is_in_team, user_id, team_id, engine)
    directory, manifest = await run_in_threadpool(_state)
    path = await run_in_threadpool(_resolve, directory, manifest, kind) if directory and manifest else None
    label, _key, media = KINDS[kind]
    if path is None:
        raise HTTPException(status_code=404, detail=NOT_AVAILABLE.format(label=label))
    name = os.path.basename(path)
    if kind == "image-sha256":
        body = f"{await run_in_threadpool(file_sha256, path)}  {name}\n".encode()
        await run_in_threadpool(_record, engine, team_id, user_id, kind, _version(manifest), len(body))
        return Response(body, media_type=media, headers={
            **PRIVATE, "Content-Disposition": f'attachment; filename="{name}.sha256"'})
    size = os.path.getsize(path)
    await run_in_threadpool(_record, engine, team_id, user_id, kind, _version(manifest), size)
    # FileResponse streams the file in chunks and sends its Content-Length (from stat), never reading it whole.
    return FileResponse(path, media_type=media, filename=name, headers=PRIVATE)
