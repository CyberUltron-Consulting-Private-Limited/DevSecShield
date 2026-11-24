"""Container images a repository names: Dockerfile ``FROM`` lines, Compose ``image:``.

SOW D3 lists container images among the inputs a CBOM covers (up to 50 per source). A
repository scan does not pull
images; it inventories the references, so the CBOM says which base images the code ships
on (``python:3.11-slim``)
and which images its deployment runs (``ghcr.io/org/app:latest``). With the scan
option "scan binaries" the
artifact lane also reads image tarballs found in the tree.

Pure parsing, offline: no registry lookup. ``scratch`` and build-stage aliases (``FROM
builder``) are not images. ``ARG`` defaults are resolved through each other
(``ARG BASE=python:${PY}-slim``). A reference whose variable has no value is kept, not
dropped: a tag that stays unresolved (``FROM node:${NODE_VERSION}-alpine``, no default)
is recorded as ``unresolved (${NODE_VERSION})`` on the repository, and a reference that
is only an unset variable (``FROM ${BASE}``) is listed as written, without a purl
(review of #491 m4). A reference keeps its tag and digest as written.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

import yaml

from aibom.cbom.files import FileWalk

MAX_IMAGES = 50  # per scanned source (SOW D3); the rest are counted, not listed

_FROM = re.compile(
    r"^\s*FROM\s+(?:--platform=\S+\s+)?(?P<ref>\S+)(?:\s+AS\s+(?P<alias>\S+))?\s*$",
    re.IGNORECASE,
)
_ARG = re.compile(
    r"^\s*ARG\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)(?:=(?P<value>\S*))?\s*$",
    re.IGNORECASE,
)
_VAR = re.compile(r"\$\{?([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}?")
_REFERENCE = re.compile(r"^[a-z0-9][a-z0-9._/:@-]{0,254}$", re.IGNORECASE)
_COMPOSE_NAMES = re.compile(
    r"^(?:docker-)?compose(?:[._-][\w.-]+)?\.ya?ml$", re.IGNORECASE
)
_MAX_COMPOSE_BYTES = 512 * 1024


@dataclass(frozen=True)
class ImageRef:
    reference: (
        str  # as written after variable substitution: registry/repo[:tag][@digest]
    )
    repository: str
    tag: str | None
    digest: str | None
    source: str  # repository-relative file
    line: int
    origin: str  # "dockerfile" | "compose"
    # the variables left without a value (``${NODE_VERSION}``), as written
    unresolved: tuple[str, ...] = ()

    @property
    def purl(self) -> str | None:
        """``pkg:oci`` package URL (the purl spec's type for container images); none
        when the repository itself is an unresolved variable."""
        if "${" in self.repository or "$" in self.repository:
            return None
        name = self.repository.rsplit("/", 1)[-1].lower()
        qualifiers = []
        if "/" in self.repository:
            qualifiers.append(f"repository_url={self.repository.lower()}")
        if self.tag:
            qualifiers.append(f"tag={self.tag}")
        version = f"@{self.digest.replace(':', '%3A')}" if self.digest else ""
        return f"pkg:oci/{name}{version}" + (
            f"?{'&'.join(qualifiers)}" if qualifiers else ""
        )


def split_reference(reference: str) -> tuple[str, str | None, str | None]:
    """``repo[:tag][@digest]`` -> (repository, tag, digest); a registry port: no tag."""
    ref, _, digest = reference.partition("@")
    last = ref.rsplit("/", 1)[-1]
    if ":" in last:
        repo, tag = ref.rsplit(":", 1)
    else:
        repo, tag = ref, None
    return repo, tag or None, digest or None


def _substitute(text: str, args: dict[str, str]) -> tuple[str, tuple[str, ...]]:
    """``text`` with every variable that has a value substituted; the variables
    without one are left as written and returned (``("${NODE_VERSION}",)``)."""
    unresolved: list[str] = []

    def repl(m: re.Match[str]) -> str:
        value = args.get(m.group(1)) or m.group(2)
        if not value:
            unresolved.append("${" + m.group(1) + "}")
            return m.group(0)
        return value

    return _VAR.sub(repl, text), tuple(unresolved)


def _unresolved_ref(
    written: str, unresolved: tuple[str, ...], rel: str, line: int, origin: str
) -> ImageRef | None:
    """An image whose reference keeps an unset variable: the repository if it is
    known (the tag is then ``unresolved``), else the reference as written."""
    if not _VAR.search(written):
        return None
    ref, _, digest = written.partition("@")
    head, sep, tag = ref.rpartition(":")
    if sep and "/" not in tag and not _VAR.search(head) and _REFERENCE.match(head):
        return ImageRef(
            written, head, None, digest or None, rel, line, origin, unresolved
        )
    return ImageRef(written, written, None, None, rel, line, origin, unresolved)


def _dockerfile_refs(text: str, rel: str) -> list[ImageRef]:
    refs: list[ImageRef] = []
    args: dict[str, str] = {}
    stages: set[str] = set()
    for number, raw in enumerate(text.splitlines(), start=1):
        arg = _ARG.match(raw)
        if arg:
            # a default may use earlier ARGs (``ARG BASE=python:${PY}-slim``)
            value = (arg.group("value") or "").strip("'\"")
            if value and arg.group("name") not in args:
                args[arg.group("name")] = _substitute(value, args)[0]
            continue
        m = _FROM.match(raw)
        if not m:
            continue
        alias = m.group("alias")
        ref, unresolved = _substitute(m.group("ref"), args)
        if alias:
            stages.add(alias.lower())
        if unresolved:
            kept = _unresolved_ref(ref, unresolved, rel, number, "dockerfile")
            if kept is not None:
                refs.append(kept)
            continue
        if (
            not ref
            or ref.lower() == "scratch"
            or ref.lower() in stages
            or not _REFERENCE.match(ref)
        ):
            continue
        repo, tag, digest = split_reference(ref)
        refs.append(ImageRef(ref, repo, tag, digest, rel, number, "dockerfile"))
    return refs


def _compose_refs(text: str, rel: str) -> list[ImageRef]:
    try:
        doc = yaml.safe_load(text)
    except yaml.YAMLError:
        return []
    services = doc.get("services") if isinstance(doc, dict) else None
    if not isinstance(services, dict):
        return []
    lines = text.splitlines()
    refs: list[ImageRef] = []
    for body in services.values():
        image = body.get("image") if isinstance(body, dict) else None
        if not isinstance(image, str):
            continue
        ref, unresolved = _substitute(image.strip(), {})
        if unresolved:
            line = next(
                (i for i, t in enumerate(lines, start=1) if image.strip() in t), 0
            )
            kept = _unresolved_ref(ref, unresolved, rel, line, "compose")
            if kept is not None:
                refs.append(kept)
            continue
        if not ref or not _REFERENCE.match(ref):
            continue
        line = next(
            (
                i
                for i, text_line in enumerate(lines, start=1)
                if re.match(
                    rf"^\s*image:\s*['\"]?{re.escape(image.strip())}", text_line
                )
            ),
            0,
        )
        repo, tag, digest = split_reference(ref)
        refs.append(ImageRef(ref, repo, tag, digest, rel, line, "compose"))
    return refs


def _is_dockerfile(path: Path) -> bool:
    name = path.name.lower()
    return (
        name == "dockerfile"
        or name.startswith("dockerfile.")
        or name.endswith(".dockerfile")
        or name == "containerfile"
    )


def image_references(walk: FileWalk) -> tuple[list[ImageRef], int]:
    """Every distinct image reference in the tree, first sighting kept, capped at
    :data:`MAX_IMAGES`.
    Returns (listed, total distinct)."""
    seen: dict[str, ImageRef] = {}
    paths = walk.files(
        lambda p: _is_dockerfile(p) or bool(_COMPOSE_NAMES.match(p.name)),
        max_bytes=_MAX_COMPOSE_BYTES,
    )
    for path in sorted(paths, key=lambda p: walk.rel(p)):
        text = walk.read_text(path)
        if text is None:
            continue
        rel = walk.rel(path)
        found = (
            _dockerfile_refs(text, rel)
            if _is_dockerfile(path)
            else _compose_refs(text, rel)
        )
        for ref in found:
            seen.setdefault(ref.reference, ref)
    refs = list(seen.values())
    return refs[:MAX_IMAGES], len(refs)


__all__ = ["MAX_IMAGES", "ImageRef", "image_references", "split_reference"]
