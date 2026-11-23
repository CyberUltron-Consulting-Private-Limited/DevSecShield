"""PDF outline (bookmarks panel) entries for the long team deliverables (D7, D8).

``Bookmark`` is a zero-size flowable: where it lands in the story it marks the page and adds an outline entry. Level
0 entries are the document's sections; a level 1 entry folds under the level 0 entry before it (``closed=True``
shows it collapsed in the viewer). reportlab and the standard library only; titles are sanitised by ``pdf_plain``.
"""
from __future__ import annotations

from reportlab.platypus import Flowable

from backend.utilities.pdf.cbom_deliverable_common import pdf_plain


class Bookmark(Flowable):
    def __init__(self, title: str, key: str, level: int = 0, closed: bool = False) -> None:
        super().__init__()
        self.title, self.key, self.level, self.closed = title, key, level, closed

    def wrap(self, availWidth: float, availHeight: float) -> tuple[float, float]:
        return 0, 0

    def draw(self) -> None:
        self.canv.bookmarkPage(self.key)
        self.canv.addOutlineEntry(pdf_plain(self.title, limit=120), self.key, level=self.level, closed=self.closed)


__all__ = ["Bookmark"]
