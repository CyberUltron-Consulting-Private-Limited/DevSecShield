"""Dockerfile posture: base images past their end of life, and crypto packages pinned in ``RUN`` installs.

The end-of-life dates are offline data (``data/base_image_eol.json``, each release citing its source). A base image
is matched when its repository is a distribution image (``ubuntu:16.04``, ``debian:buster-slim``, ``alpine:3.12``,
``centos:7``, ``amazonlinux:2``), or when another image names its distribution in the tag the way the official
images do (``python:3.8-slim-buster``, ``node:14-alpine3.12``). A tag that names no release (``latest``, a digest,
an ``ARG``) is not judged. Certificate-verification switches in ``RUN``/``ENV`` lines (``curl -k``,
``--trusted-host``, ``PYTHONHTTPSVERIFY=0`` …) are the verification lane's (``verification_patterns.json``).
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, date, datetime
from functools import cache

from aibom.cbom.posture.codec import make_fact_id
from aibom.cbom.posture.defaults import read_data_bytes
from aibom.cbom.posture.extract_compose import image_repository
from aibom.cbom.posture.model import BasisEntry, EncryptionFact, path_context

_FROM = re.compile(r"^\s*FROM\s+(.{1,512})$", re.IGNORECASE)
_RUN = re.compile(r"^\s*RUN\s", re.IGNORECASE)
_ALPINE_TAG = re.compile(r"^alpine(\d{1,2}\.\d{1,3})$")
_CENTOS_TAG = re.compile(r"^(?:centos)?(\d{1,2})(?:\.\d{1,4}){0,2}$")
_STREAM_TAG = re.compile(r"^stream(\d{1,2})$")
# Amazon Linux AMI (the first generation) is tagged ``1`` on Docker Hub; its last release is 2018.03.
_AMAZON_ALIASES = {"1": "2018.03"}
# Crypto libraries whose OS package a Dockerfile can pin (``apt-get install openssl=1.0.2g-1ubuntu4``,
# ``apk add openssl=1.1.1k-r0``).
_PACKAGE = re.compile(
    r"(?:^|[\s'\"])((?:openssl|libssl[0-9a-z.+]{0,12}|libcrypto[0-9a-z.+]{0,12}|gnutls[0-9a-z.+]{0,12}"
    r"|libgnutls[0-9a-z.+]{0,12}|libgcrypt[0-9a-z.+]{0,12}|libnss3|nss|libsodium[0-9a-z.+]{0,12}"
    r"|libmbedtls[0-9a-z.+]{0,12}|mbedtls|wolfssl)(?:-dev|-libs)?)=([0-9][0-9A-Za-z.+:~_-]{0,80})"
)
_INSTALLERS = (("apt-get", "deb"), ("apt ", "deb"), ("apk ", "apk"))


@dataclass(frozen=True, slots=True)
class PackagePin:
    """An OS crypto package pinned to a version in a ``RUN`` install line."""

    name: str
    version: str
    ecosystem: str
    path: str
    line: int


@dataclass(frozen=True, slots=True)
class _Release:
    distro: str
    release: str
    eol: str
    extended: str | None
    source: str


@cache
def _table() -> tuple[Mapping[str, str], Mapping[tuple[str, str], _Release], Mapping[tuple[str, str], _Release]]:
    raw = json.loads(read_data_bytes("base_image_eol.json"))
    images = {str(k): str(v) for k, v in (raw.get("images") or {}).items()}
    releases: dict[tuple[str, str], _Release] = {}
    codenames: dict[tuple[str, str], _Release] = {}
    for row in raw.get("rows") or ():
        if not isinstance(row, Mapping):
            continue
        item = _Release(
            distro=str(row["distro"]),
            release=str(row["release"]),
            eol=str(row["eol"]),
            extended=str(row["extended_support"]) if row.get("extended_support") else None,
            source=str(row.get("source_url") or ""),
        )
        releases[(item.distro, item.release)] = item
        if row.get("codename"):
            codenames[(item.distro, str(row["codename"]))] = item
    return images, releases, codenames


def _from_reference(rest: str) -> tuple[str, str | None]:
    """``[--platform=…] image[:tag|@digest] [AS name]`` -> (image reference, stage name)."""
    parts = [part for part in rest.split() if not part.startswith("--")]
    if not parts:
        return "", None
    stage = parts[2] if len(parts) >= 3 and parts[1].casefold() == "as" else None
    return parts[0], stage


def _tag(reference: str) -> str | None:
    if "@" in reference:
        return None
    slash = reference.rfind("/")
    colon = reference.rfind(":")
    return reference[colon + 1 :] if colon > slash else None


def match_release(reference: str) -> _Release | None:
    """The distribution release a base image reference names, or None."""
    if "$" in reference or reference.casefold() == "scratch":
        return None
    tag = _tag(reference)
    if not tag:
        return None
    images, releases, codenames = _table()
    distro = images.get(image_repository(reference).casefold())
    tokens = tag.casefold().split("-")
    if distro is not None:
        head = tokens[0]
        if distro == "amazonlinux":
            head = _AMAZON_ALIASES.get(head, head)
        if distro == "centos" and (stream := _STREAM_TAG.match(head)):
            return releases.get(("centos-stream", stream.group(1)))
        if distro == "centos" and (major := _CENTOS_TAG.match(head)):
            return releases.get(("centos", major.group(1)))
        found = releases.get((distro, head)) or codenames.get((distro, head))
        if found is None and distro in ("alpine", "debian", "ubuntu"):
            # a point release (``alpine:3.12.3``, ``debian:10.13``) belongs to its release line
            for (row_distro, release), item in releases.items():
                if row_distro == distro and head.startswith(release + "."):
                    return item
        return found
    # another image whose tag names its base the way the official images do
    for token in tokens:
        alpine = _ALPINE_TAG.match(token)
        if alpine:
            return releases.get(("alpine", alpine.group(1)))
        for distro_name in ("debian", "ubuntu"):
            hit = codenames.get((distro_name, token))
            if hit is not None:
                return hit
    return None


def _today() -> date:
    return datetime.now(UTC).date()


def extract_dockerfile_images(text: str, path: str, today: date | None = None) -> tuple[EncryptionFact, ...]:
    """One fact per ``FROM`` whose distribution release is past its end of life on ``today`` (the scan date)."""
    day = (today or _today()).isoformat()
    facts: list[EncryptionFact] = []
    seen: dict[str, int] = {}
    for number, line in enumerate(text.splitlines(), start=1):
        matched = _FROM.match(line)
        if not matched:
            continue
        reference, stage = _from_reference(matched.group(1))
        release = match_release(reference) if reference else None
        if release is None or release.eol > day:
            continue
        basis = [
            BasisEntry("image", reference[:200]),
            BasisEntry("distribution", f"{release.distro} {release.release}"),
            BasisEntry("end_of_life", release.eol),
        ]
        if release.extended:
            basis.append(BasisEntry("extended_support_until", release.extended))
        basis.append(BasisEntry("eol_source", release.source))
        basis.append(BasisEntry("signal", "EOL_BASE_IMAGE"))
        address = reference[:200] if stage is None else f"{reference[:200]} AS {stage[:64]}"
        # identity: the image and which of the file's FROMs of that image it is, never the line number, so an edit
        # above it is not a removed + added asset in a diff (the line stays in ``line`` for the location)
        seen[address] = seen.get(address, 0) + 1
        facts.append(
            EncryptionFact(
                id=make_fact_id("container_image", "dockerfile", "base_image", f"{address}#{seen[address]}", path),
                kind="container_image",
                provider="dockerfile",
                native_type="base_image",
                address=address,
                path=path,
                line=number,
                format="dockerfile",
                layers={"service": "UNKNOWN"},
                verdict="UNKNOWN",
                basis=tuple(basis),
                unknown_reason="layer_not_observable",
                path_context=path_context(path),
            )
        )
    return tuple(facts)


def crypto_package_pins(text: str, path: str) -> tuple[PackagePin, ...]:
    """Crypto OS packages pinned to a version in ``apt-get``/``apt``/``apk`` install lines of ``RUN`` instructions
    (continuation lines included)."""
    pins: list[PackagePin] = []
    ecosystem: str | None = None
    continuing = False
    for number, line in enumerate(text.splitlines(), start=1):
        starts = bool(_RUN.match(line))
        if not starts and not continuing:
            ecosystem = None
            continue
        if starts:
            ecosystem = None
        for token, eco in _INSTALLERS:
            if token in line:
                ecosystem = eco
        continuing = line.rstrip().endswith("\\")
        if ecosystem is None:
            continue
        for found in _PACKAGE.finditer(line):
            pins.append(PackagePin(found.group(1), found.group(2), ecosystem, path, number))
    return tuple(pins)


__all__ = ["PackagePin", "crypto_package_pins", "extract_dockerfile_images", "match_release"]
