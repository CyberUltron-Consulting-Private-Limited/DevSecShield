"""Compose and Dockerfile posture. Unregistered: scan_crypto does not import this."""

from __future__ import annotations

import json
from collections.abc import Mapping
from functools import cache
from types import MappingProxyType

from aibom.cbom.posture.codec import make_fact_id
from aibom.cbom.posture.defaults import read_data_bytes
from aibom.cbom.posture.extract_common import listener_reader
from aibom.cbom.posture.jsonsafe import parse_json
from aibom.cbom.posture.model import BasisEntry, EncryptionFact, path_context
from aibom.cbom.posture.verdict import resource_verdict
from aibom.cbom.posture.yamlsafe import parse_yaml

# Design names the shipped catalog does not list yet. JSON rows win on clash.
_EXTRA_IMAGES: dict[str, str] = {
    "activemq": "message_queue",
    "cp-kafka": "data_stream",
    "redpanda": "data_stream",
}
OBSERVED_LAYERS: tuple[str, ...] = ("database", "volume", "transport")
READERS = MappingProxyType({"listener": listener_reader})


@cache
def _catalog() -> Mapping[str, tuple[str, str]]:
    raw = json.loads(read_data_bytes("datastore_images.json"))
    found: dict[str, tuple[str, str]] = {}
    rows = raw.get("rows") if isinstance(raw, Mapping) else None
    if isinstance(rows, list):
        for row in rows:
            if not isinstance(row, Mapping):
                continue
            image = row.get("image")
            kind = row.get("kind")
            ident = row.get("id")
            if not isinstance(image, str) or not isinstance(kind, str):
                continue
            image_id = ident if isinstance(ident, str) and ident else image
            found[image] = (image_id, kind)
    for image, kind in _EXTRA_IMAGES.items():
        found.setdefault(image, (image, kind))
    return found


def image_repository(reference: str) -> str:
    """Drop the registry host, tag, and digest. The repository path remains."""
    text = reference.strip()
    if not text:
        return ""
    digest = text.find("@")
    if digest >= 0:
        text = text[:digest]
    slash = text.rfind("/")
    colon = text.rfind(":")
    if colon > slash:
        text = text[:colon]
    parts = [part for part in text.split("/") if part]
    if len(parts) > 1 and _registry(parts[0]):
        parts = parts[1:]
    return "/".join(parts)


def match_datastore_image(reference: str) -> tuple[str, str] | None:
    """Return ``(image id, kind)`` when the repository is on the curated list."""
    repo = image_repository(reference)
    if not repo:
        return None
    parts = repo.split("/")
    candidates = [repo]
    if len(parts) >= 2:
        candidates.append("/".join(parts[-2:]))
    candidates.append(parts[-1])
    catalog = _catalog()
    for candidate in candidates:
        hit = catalog.get(candidate)
        if hit is not None:
            return hit
    return None


def unobserved_layers() -> dict[str, str]:
    return dict.fromkeys(OBSERVED_LAYERS, "UNKNOWN")


def unobserved_basis(image_id: str) -> tuple[BasisEntry, ...]:
    detail = [BasisEntry("image", image_id)]
    detail.extend(
        BasisEntry(name=layer, unknown_reason="layer_not_observable")
        for layer in OBSERVED_LAYERS
    )
    return tuple(detail)


def load_documents(text: str) -> list[object]:
    """YAML documents, or one JSON value when the text starts with ``{`` or ``[``."""
    stripped = text.lstrip()
    if not stripped:
        return []
    if stripped[0] in "{[":
        parsed = parse_json(text)
        if parsed is None:
            return []
        return [parsed.value]
    loaded = parse_yaml(text)
    if not loaded:
        return []
    return list(loaded)


def extract_compose(
    text: str, path: str = "compose.yaml"
) -> tuple[EncryptionFact, ...]:
    """One fact per service whose image is on the datastore list."""
    facts: list[EncryptionFact] = []
    for doc in load_documents(text):
        if not isinstance(doc, Mapping):
            continue
        services = doc.get("services")
        if not isinstance(services, Mapping):
            continue
        for name, body in services.items():
            if not isinstance(name, str) or not isinstance(body, Mapping):
                continue
            image = body.get("image")
            if not isinstance(image, str):
                continue
            matched = match_datastore_image(image)
            if matched is None:
                continue
            image_id, kind = matched
            layers = unobserved_layers()
            rolled = resource_verdict(layers, transport_only=False)
            facts.append(
                EncryptionFact(
                    id=make_fact_id(kind, "compose", image_id, name, path),
                    kind=kind,
                    provider="compose",
                    native_type=image_id,
                    address=name,
                    path=path,
                    line=_line(body),
                    format="compose",
                    layers=layers,
                    verdict=rolled or "UNKNOWN",
                    basis=unobserved_basis(image_id),
                    unknown_reason="layer_not_observable",
                    path_context=path_context(path),
                )
            )
    facts.sort(key=lambda item: (item.path, item.address, item.native_type))
    return tuple(facts)


def extract_dockerfile(
    text: str, path: str = "Dockerfile"
) -> tuple[EncryptionFact, ...]:
    """A fact per ``FROM`` whose base image release is past its end of life (:mod:`.dockerfile`)."""
    from aibom.cbom.posture.dockerfile import extract_dockerfile_images

    return extract_dockerfile_images(text, path)


def _registry(host: str) -> bool:
    return ":" in host or "." in host or host == "localhost"


def _line(body: object) -> int:
    line = getattr(body, "line", 1)
    if isinstance(line, int) and line > 0:
        return line
    return 1
