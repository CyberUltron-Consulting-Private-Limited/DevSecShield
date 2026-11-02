"""Container images in a code-scan upload: ``docker save`` tarballs and OCI image layouts, read without a daemon.

Inputs (OCI Image Format Specification v1.1, "Image Layout" and "Image Manifest"; Docker's ``docker save``):

* a tar holding ``manifest.json`` (Docker's list of ``{Config, RepoTags, Layers}``; Docker >= 25 writes it next to
  an OCI layout, older versions with ``<id>/layer.tar`` layers), or holding only an OCI layout (``oci-layout``,
  ``index.json``, ``blobs/<alg>/<hex>``); the tar may itself be gzip/xz/bzip2-compressed;
* an OCI layout directory in the uploaded tree (``oci-layout`` + ``index.json`` + ``blobs/``).

``index.json`` is followed through image indexes / Docker manifest lists to one image manifest (``linux/amd64``
when listed, else the first one whose blob is present); descriptors must name ``sha256:<64 hex>`` digests, so a
crafted digest cannot point outside ``blobs/``.

Layers are applied in order into a virtual view (nothing is extracted): a file in a later layer replaces the same
path below it, and the OCI whiteouts remove what is below them (``.wh.<name>`` removes ``<name>`` and everything
under it; ``.wh..wh..opq`` empties its directory of everything from lower layers). Whiteouts apply only to lower
layers, as the specification requires. Only the files an inventory needs are read (see
:mod:`aibom.cbom.artifacts`); every other member is skipped, but still counted against the scan's one budget. Layer
compression (gzip, zstd, uncompressed) is detected from the bytes, not trusted from the media type; zstd layers are
reported as not covered (no decompressor in the standard library).
"""

from __future__ import annotations

import io
import json
import os
import re
import stat
import tempfile
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from aibom.cbom.archives import ArchiveBudget
from aibom.cbom.unpack import COMPRESSIONS, Inflate, Member, Refused, iter_tar, read_exact, safe_name, sniff

MAX_JSON = 4 * 1024 * 1024
MAX_IMAGES = 16
MAX_LAYERS = 256
MAX_SPOOL = 4 * 1024 * 1024 * 1024
_DIGEST = re.compile(r"^sha256:([0-9a-f]{64})$")
_INDEX_TYPES = ("application/vnd.oci.image.index.v1+json", "application/vnd.docker.distribution.manifest.list.v2+json")
_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)

# A layer visitor: (layer index, path, member) -> a result to keep for that path, or None (not an inventory file)
Visitor = Callable[[str, Member], object | None]


@dataclass
class ImageView:
    """The merged view of an image: path -> what the visitor kept for the file that is visible there."""

    label: str
    name: str
    layers: int = 0
    files: dict[str, object] = field(default_factory=dict)
    coverage: dict[str, int] = field(default_factory=dict)

    def count(self, key: str, n: int = 1) -> None:
        self.coverage[key] = self.coverage.get(key, 0) + n


# --------------------------------------------------------------------------------------------- blob sources
class _TarBlobs:
    """Members of an image tar on disk, read by offset (the tar is indexed once)."""

    def __init__(self, fh, budget: ArchiveBudget) -> None:
        self.fh = fh
        self.index: dict[str, tuple[int, int]] = {}
        for member in iter_tar(fh, budget):
            if member.kind == "file":
                self.index[member.name] = (fh.tell(), member.size)

    def has(self, name: str) -> bool:
        return name in self.index

    def open(self, name: str):
        offset, size = self.index[name]
        return _Section(self.fh, offset, size)


class _DirBlobs:
    """Blobs of an OCI layout directory; every file is opened without following links."""

    def __init__(self, root: Path) -> None:
        self.root = root

    def _path(self, name: str) -> Path:
        return self.root / safe_name(name)

    def has(self, name: str) -> bool:
        try:
            info = os.lstat(self._path(name))
        except (OSError, Refused):
            return False
        return stat.S_ISREG(info.st_mode)

    def open(self, name: str):
        fd = os.open(self._path(name), os.O_RDONLY | _O_NOFOLLOW)
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            os.close(fd)
            raise Refused("specialFile")
        return os.fdopen(fd, "rb")


class _Section(io.RawIOBase):
    def __init__(self, fh, offset: int, size: int) -> None:
        super().__init__()
        self.fh, self.offset, self.size, self.pos = fh, offset, size, 0

    def readable(self) -> bool:
        return True

    def readinto(self, buf) -> int:
        n = min(len(buf), self.size - self.pos)
        if n <= 0:
            return 0
        self.fh.seek(self.offset + self.pos)
        data = self.fh.read(n)
        buf[:len(data)] = data
        self.pos += len(data)
        return len(data)


def _read_json(blobs, name: str):
    with blobs.open(name) as fh:
        raw = read_exact(fh, MAX_JSON + 1)
    if len(raw) > MAX_JSON:
        raise Refused("manifestTooLarge")
    try:
        return json.loads(raw)
    except (ValueError, RecursionError):
        raise Refused("corruptManifest") from None


def _blob_name(descriptor: object) -> str | None:
    if not isinstance(descriptor, dict):
        return None
    m = _DIGEST.match(str(descriptor.get("digest") or ""))
    return f"blobs/sha256/{m.group(1)}" if m else None


# --------------------------------------------------------------------------------------------- manifests
def _images(blobs) -> list[tuple[str, list[str]]]:
    """(name, layer blob names in order) of each image in the archive / layout."""
    out: list[tuple[str, list[str]]] = []
    if blobs.has("manifest.json"):
        doc = _read_json(blobs, "manifest.json")
        for entry in doc if isinstance(doc, list) else []:
            if not isinstance(entry, dict) or not isinstance(entry.get("Layers"), list):
                continue
            tags = entry.get("RepoTags") or []
            name = str(tags[0]) if isinstance(tags, list) and tags else "image"
            layers = []
            for layer in entry["Layers"][:MAX_LAYERS]:
                try:
                    layers.append(safe_name(str(layer)))
                except Refused:
                    raise Refused("pathTraversal") from None
            out.append((name[:200], layers))
        if out:
            return out[:MAX_IMAGES]
    if not blobs.has("index.json"):
        return out
    index = _read_json(blobs, "index.json")
    queue = [(d, None) for d in (index.get("manifests") or [] if isinstance(index, dict) else [])]
    seen = 0
    while queue and len(out) < MAX_IMAGES and seen < 64:
        descriptor, parent_name = queue.pop(0)
        seen += 1
        name = _blob_name(descriptor)
        if name is None or not blobs.has(name):
            continue
        annotations = descriptor.get("annotations") or {}
        label = (annotations.get("io.containerd.image.name") or annotations.get("org.opencontainers.image.ref.name")
                 or parent_name or "image")
        doc = _read_json(blobs, name)
        media = str(descriptor.get("mediaType") or (doc.get("mediaType") if isinstance(doc, dict) else "") or "")
        if media in _INDEX_TYPES or (isinstance(doc, dict) and "manifests" in doc and "layers" not in doc):
            children = [d for d in doc.get("manifests") or [] if isinstance(d, dict)]
            present = [d for d in children if (n := _blob_name(d)) and blobs.has(n)]
            amd64 = [d for d in present if (d.get("platform") or {}).get("os") == "linux"
                     and (d.get("platform") or {}).get("architecture") == "amd64"]
            pick = (amd64 or present)[:1]
            queue[0:0] = [(d, str(label)) for d in pick]
            continue
        if isinstance(doc, dict) and isinstance(doc.get("layers"), list):
            layers = [n for n in (_blob_name(d) for d in doc["layers"][:MAX_LAYERS]) if n]
            out.append((str(label)[:200], layers))
    return out


# --------------------------------------------------------------------------------------------- layers
def _layer_members(raw, budget: ArchiveBudget, view: ImageView):
    head = raw.peek(512)[:512] if hasattr(raw, "peek") else b""
    kind = sniff(head)
    if kind in ("zstd", "lzo", "lz4"):
        view.count(f"unsupportedLayerCompression:{kind}")
        return iter(())
    if kind in COMPRESSIONS:
        raw = io.BufferedReader(Inflate(raw, kind, budget), buffer_size=1 << 16)
    elif kind not in ("tar", None):
        view.count("layerNotTar")
        return iter(())
    return iter_tar(raw, budget)


def _apply(view: ImageView, index: int, raw, budget: ArchiveBudget, visit: Visitor) -> None:
    results: dict[str, object] = {}
    replaced: set[str] = set()  # non-directory paths this layer writes (they hide what is below)
    whiteouts: list[str] = []
    opaque: list[str] = []
    for member in _layer_members(raw, budget, view):
        path = member.name
        base = path.rsplit("/", 1)[-1]
        parent = path.rsplit("/", 1)[0] if "/" in path else ""
        if base == ".wh..wh..opq":
            opaque.append(parent)
            continue
        if base.startswith(".wh."):
            whiteouts.append(f"{parent}/{base[4:]}" if parent else base[4:])
            continue
        if member.kind == "dir":
            replaced.add(path) if path in view.files else None
            continue
        replaced.add(path)
        if member.kind == "symlink":
            view.count("symlinksNotFollowed")
            continue
        if member.kind == "hardlink":
            target = path_of_link(member.linkname)
            if target is None:
                budget.refuse("linkEscape")
            elif target in results:
                results[path] = results[target]
            elif target in view.files:
                results[path] = view.files[target]
            continue
        kept = visit(path, member)
        if kept is not None:
            results[path] = kept
    # whiteouts and opaque directories remove only what lower layers put there
    for gone in whiteouts:
        prefix = gone + "/"
        for key in [k for k in view.files if k == gone or k.startswith(prefix)]:
            del view.files[key]
    for directory in opaque:
        prefix = directory + "/" if directory else ""
        for key in [k for k in view.files if k.startswith(prefix)]:
            del view.files[key]
    if replaced:
        for key in list(view.files):
            parts = key.split("/")
            if key in replaced or any("/".join(parts[:i]) in replaced for i in range(1, len(parts))):
                del view.files[key]
    view.files.update(results)
    view.layers = index + 1


def path_of_link(linkname: str | None) -> str | None:
    from aibom.cbom.unpack import resolve_link

    return resolve_link(linkname or "")


def _read_images(blobs, label: str, budget: ArchiveBudget, visit_factory) -> list[ImageView]:
    views: list[ImageView] = []
    for name, layers in _images(blobs):
        view = ImageView(label, name)
        visit = visit_factory(view)
        for i, layer in enumerate(layers):
            if not blobs.has(layer):
                view.count("layersMissing")
                continue
            try:
                with blobs.open(layer) as fh:
                    _apply(view, i, io.BufferedReader(fh, buffer_size=1 << 16), budget, visit)
            except Refused as exc:
                budget.refuse(exc.reason)
                view.count("layersNotRead")
        views.append(view)
    return views


def read_image_file(path: Path, label: str, budget: ArchiveBudget, visit_factory) -> list[ImageView] | None:
    """The images of a ``docker save`` / OCI archive file, or None when the file is not one."""
    fd = os.open(path, os.O_RDONLY | _O_NOFOLLOW)
    with os.fdopen(fd, "rb") as fh:
        if not stat.S_ISREG(os.fstat(fh.fileno()).st_mode):
            return None
        head = read_exact(fh, 512)
        fh.seek(0)
        kind = sniff(head)
        if kind == "tar":
            blobs = _TarBlobs(fh, budget)
            if not (blobs.has("manifest.json") or (blobs.has("index.json") and blobs.has("oci-layout"))):
                return None
            return _read_images(blobs, label, budget, visit_factory)
        if kind in ("gzip", "xz", "bzip2"):
            # a compressed image tar: decompress once to a private temporary file (counted), then read by offset
            stream = io.BufferedReader(Inflate(fh, kind, budget), buffer_size=1 << 16)
            if sniff(stream.peek(512)[:512]) != "tar":
                return None
            with tempfile.TemporaryFile(prefix="zs-image-") as spool:
                total = 0
                while True:
                    chunk = stream.read(1 << 20)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > MAX_SPOOL:
                        raise Refused("budgetExceeded")
                    spool.write(chunk)
                spool.seek(0)
                blobs = _TarBlobs(spool, budget)
                if not (blobs.has("manifest.json") or (blobs.has("index.json") and blobs.has("oci-layout"))):
                    return None
                return _read_images(blobs, label, budget, visit_factory)
    return None


def is_image_tar_name(name: str) -> bool:
    low = name.lower()
    return low.endswith((".tar", ".tar.gz", ".tgz", ".tar.xz", ".tar.bz2", ".oci", ".docker"))


def read_layout_dir(root: Path, label: str, budget: ArchiveBudget, visit_factory) -> list[ImageView]:
    """The images of an OCI image layout directory (``oci-layout`` + ``index.json`` + ``blobs/``)."""
    return _read_images(_DirBlobs(root), label, budget, visit_factory)


__all__ = ["ImageView", "is_image_tar_name", "read_image_file", "read_layout_dir"]
