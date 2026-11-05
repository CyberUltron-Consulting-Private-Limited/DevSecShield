"""IaC / Dockerfile fact ids never hash a line number (WP13).

The fact id is the asset's identity (bom-ref ``crypto-cfg_<id>``, diff and drift keys): an unrelated edit above a
``FROM`` or a ``cryptsetup`` command must not turn it into a removed + added asset. The line stays in ``line``.
"""

from __future__ import annotations

from datetime import date

from aibom.cbom.posture.dockerfile import extract_dockerfile_images
from aibom.cbom.posture.extract_databases import cryptsetup

DOCKERFILE = "FROM ubuntu:18.04 AS build\nRUN make\nFROM debian:9\nFROM ubuntu:18.04\nFROM ubuntu:18.04\n"
SCRIPT = (
    "#!/bin/sh\n"
    "cryptsetup luksFormat --cipher aes-xts-plain64 /dev/sdb1\n"
    "cryptsetup open /dev/sdb1 data\n"
    "cryptsetup luksFormat /dev/sdc1\n"
)
TODAY = date(2026, 11, 5)


def _shift(text: str) -> str:
    return "# a comment added above\n\n" + text


def test_dockerfile_base_image_ids_ignore_the_line_and_stay_unique() -> None:
    before = extract_dockerfile_images(DOCKERFILE, "Dockerfile", TODAY)
    after = extract_dockerfile_images(_shift(DOCKERFILE), "Dockerfile", TODAY)
    assert [f.address for f in before] == ["ubuntu:18.04 AS build", "debian:9", "ubuntu:18.04", "ubuntu:18.04"]
    assert [f.id for f in before] == [f.id for f in after]
    assert [f.line for f in after] == [f.line + 2 for f in before]  # the location still moves
    assert len({f.id for f in before}) == 4  # the same image twice is still two assets


def test_cryptsetup_ids_ignore_the_line_and_stay_unique() -> None:
    before = cryptsetup(SCRIPT, "deploy/disk.sh", form="shell")
    after = cryptsetup(_shift(SCRIPT), "deploy/disk.sh", form="shell")
    assert len(before) == 3
    assert [f.id for f in before] == [f.id for f in after]
    assert len({f.id for f in before}) == 3
    assert [f.address for f in before] == ["deploy/disk.sh:2", "deploy/disk.sh:3", "deploy/disk.sh:4"]  # display
