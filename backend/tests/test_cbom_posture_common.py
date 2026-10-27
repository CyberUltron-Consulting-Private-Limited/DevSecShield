"""Shared PDF shell. Omitted posture keywords keep the previous builder callable."""

from __future__ import annotations

import inspect
import sys
from pathlib import Path

_REPO = Path(__file__).resolve().parents[2]
if str(_REPO) not in sys.path:
    sys.path.insert(0, str(_REPO))

from backend.utilities.pdf.cbom_deliverable_common import build_document  # noqa: E402


def test_build_document_posture_keywords_default_to_none() -> None:
    params = inspect.signature(build_document).parameters
    for name in ("basis_extra", "disclaimer_paragraphs", "extra_banners"):
        assert params[name].default is None
