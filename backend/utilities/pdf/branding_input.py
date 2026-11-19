"""The team's report logo, as the PDF builders receive it.

Builders never read storage: each PDF route loads this once (``utilities.team.branding
.load_report_branding``) and passes it down, so every page of one report draws the same bytes and
the deliverable modules stay free of database and network imports.
"""

from __future__ import annotations

import hashlib
import io
import logging
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ReportBranding:
    png: bytes | None = None
    sha256: str | None = None
    width: int = 0
    height: int = 0
    tone: str = "dark"  # "dark" | "light": decides the chip the logo sits on
    status: str = "none"  # "applied" | "none" | "skipped"
    # Has transparent pixels: only then does a dark mark need a white chip on the navy header. An opaque logo
    # (a JPEG, a PNG with its own background) is drawn as it is everywhere, never framed.
    has_alpha: bool = False

    @property
    def applied(self) -> bool:
        return self.status == "applied" and bool(self.png)

    def reader(self):
        """A fresh ``ImageReader`` over the bytes (one per build), or None."""
        if not self.applied:
            return None
        from reportlab.lib.utils import ImageReader  # noqa: PLC0415

        return ImageReader(io.BytesIO(self.png))


NO_BRANDING = ReportBranding()


def branding_from_png(png: bytes | None, *, tone: str = "dark") -> ReportBranding:
    """Check that stored bytes still decode; on any failure the report is built without a logo."""
    if not png:
        return NO_BRANDING
    try:
        from reportlab.lib.utils import ImageReader  # noqa: PLC0415

        width, height = ImageReader(io.BytesIO(png)).getSize()
        if width <= 0 or height <= 0:
            raise ValueError("empty image")
    except Exception as exc:  # noqa: BLE001 - a broken logo never breaks a report
        logger.warning("report logo skipped: %s", type(exc).__name__)
        return ReportBranding(status="skipped")
    return ReportBranding(png=png, sha256=hashlib.sha256(png).hexdigest(), width=int(width),
                          height=int(height), tone=tone if tone in ("dark", "light") else "dark",
                          status="applied", has_alpha=png_has_alpha(png))


def png_has_alpha(png: bytes) -> bool:
    """From the PNG header: colour type 4 or 6 carries alpha; a tRNS chunk makes another type transparent.
    Logos are stored by ``logo_image`` as RGB (opaque) or RGBA, so this is exact for them."""
    if len(png) < 26 or not png.startswith(b"\x89PNG\r\n\x1a\n"):
        return True  # not a PNG we wrote: keep the chip, the safe choice on a navy bar
    if png[25] in (4, 6):
        return True
    data = png.find(b"IDAT")
    return b"tRNS" in png[: data if data > 0 else len(png)]
