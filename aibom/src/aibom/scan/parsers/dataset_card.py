"""Parse a ``DATASET_CARD.md`` front-matter block into a dataset component.

Datasheet-style fields (type/size/provenance/sensitivity/known bias/license)
become a CycloneDX ``data`` component; the scanner routes the dataset_* fields
to ``dataset:`` namespaced properties at emit time.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from aibom.model.component import DatasetComponent
from aibom.scan.parsers.frontmatter import split_frontmatter
from aibom.scan.parsers.licenses import license_choice
from aibom.scan.safe_files import read_text


def _opt_str(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _str_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(v).strip() for v in value if str(v).strip()]
    text = _opt_str(value)
    return [text] if text else []


_PRESENCE = {"yes", "no", "noAssertion"}


def _presence(value: Any) -> str | None:
    text = _opt_str(value)
    return text if text in _PRESENCE else None


def parse_dataset_card(path: Path) -> DatasetComponent | None:
    """Parse a dataset card. Returns None if absent or missing a dataset name."""
    text = read_text(path)  # None: absent, a link or not a regular file
    if text is None:
        return None
    fm, _body = split_frontmatter(text)
    name = _opt_str(fm.get("name"))
    if not name:
        return None

    licenses = None
    lic = _opt_str(fm.get("license"))
    if lic:
        licenses = [license_choice(lic)]

    return DatasetComponent(
        bom_ref=_opt_str(fm.get("bom_ref")) or f"dataset-{name.lower()}",
        name=name,
        version=_opt_str(fm.get("version")),
        licenses=licenses,
        dataset_type=_opt_str(fm.get("dataset_type")),
        dataset_size=_opt_str(fm.get("dataset_size")),
        provenance=_opt_str(fm.get("provenance")),
        sensitivity=_opt_str(fm.get("sensitivity")),
        known_bias=_opt_str(fm.get("known_bias")),
        availability=_opt_str(fm.get("availability")),
        data_collection_process=_opt_str(fm.get("data_collection_process")),
        data_preprocessing=_str_list(fm.get("data_preprocessing")),
        anonymization_method=_str_list(fm.get("anonymization_method")),
        confidentiality_level=_opt_str(fm.get("confidentiality_level")),
        intended_use=_opt_str(fm.get("intended_use")),
        has_sensitive_personal_information=_presence(
            fm.get("has_sensitive_personal_information")
        ),
    )


__all__ = ["parse_dataset_card"]
