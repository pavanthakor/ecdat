"""A small, deterministic PDF writer over reportlab's canvas.

**Determinism is the requirement that shapes this module.** A report that
changed bytes on every render could not be checksummed, attached to a ticket,
or compared against the copy somebody was sent. reportlab defaults fight that
in two specific ways, and both are pinned here:

* the document's ``CreationDate``/``ModDate`` default to ``now()`` -- set to the
  SCAN's timestamp instead, which is the date the report is actually about;
* the file identifier defaults to a random UUID -- derived from the scan id, so
  the same scan always produces the same identifier.

Deliberately a canvas rather than the platypus flowable machinery. The reports
are tabular and the page breaks are decided by content, not by a frame; a
hand-rolled cursor is fewer moving parts than a document template and keeps the
output byte-stable without fighting a layout engine.

The styling is FUNCTIONAL, not designed -- Helvetica, rules, and a two-column
grid. A designed template is later work (PUNCHLIST); this is an artefact you
can hand to an auditor, not a brochure.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any

from reportlab.lib.colors import Color, HexColor
from reportlab.lib.pagesizes import A4
from reportlab.lib.utils import simpleSplit
from reportlab.pdfgen.canvas import Canvas

__all__ = ["Page", "band_colour", "new_canvas"]

PAGE_WIDTH, PAGE_HEIGHT = A4
MARGIN = 42.0
CONTENT_WIDTH = PAGE_WIDTH - 2 * MARGIN

#: Severity, and nothing else, gets colour -- the same rule the console keeps,
#: so a printed report and the screen agree about what red means.
BAND_COLOURS: dict[str, Color] = {
    "Critical": HexColor("#B3261E"),
    "High": HexColor("#A05A00"),
    "Medium": HexColor("#7A6200"),
    "Low": HexColor("#5A6472"),
}
INK = HexColor("#111418")
MUTED = HexColor("#5A6472")
FAINT = HexColor("#8A93A0")
RULE = HexColor("#C9CED6")


def band_colour(band: str) -> Color:
    return BAND_COLOURS.get(band, MUTED)


def new_canvas(buffer: Any, *, title: str, scan_id: str, created: datetime) -> Canvas:
    """A canvas whose output depends only on its inputs.

    ``invariant=1`` stops reportlab writing a random document ID; the explicit
    dates stop it writing ``now()``.
    """
    canvas = Canvas(
        buffer,
        pagesize=A4,
        invariant=1,
        pageCompression=0,
    )
    canvas.setTitle(title)
    canvas.setSubject(f"ECDAT scan {scan_id}")
    canvas.setCreator("ECDAT")
    canvas.setAuthor("ECDAT")
    # Pin the document dates to the SCAN's timestamp. reportlab calls this
    # formatter with a varying signature across versions, so it takes anything
    # and answers the same thing -- the report is about the scan's moment, not
    # about when somebody happened to print it.
    stamp = created.strftime("D:%Y%m%d%H%M%S+00'00'")
    canvas._doc.setDateFormatter(lambda *_args: stamp)
    return canvas


@dataclass
class Page:
    """A cursor down the page, with the wrapping and paging a report needs."""

    canvas: Canvas
    footer: str
    y: float = PAGE_HEIGHT - MARGIN
    page: int = 1

    # -- primitives ------------------------------------------------------

    def space(self, amount: float = 8.0) -> None:
        self.y -= amount

    def room(self, needed: float) -> None:
        """Break the page when ``needed`` points will not fit."""
        if self.y - needed < MARGIN + 28:
            self.break_page()

    def break_page(self) -> None:
        self._footer()
        self.canvas.showPage()
        self.page += 1
        self.y = PAGE_HEIGHT - MARGIN

    def finish(self) -> None:
        self._footer()
        self.canvas.save()

    def _footer(self) -> None:
        self.canvas.setFont("Helvetica", 7)
        self.canvas.setFillColor(FAINT)
        self.canvas.drawString(MARGIN, MARGIN - 12, self.footer)
        self.canvas.drawRightString(
            PAGE_WIDTH - MARGIN, MARGIN - 12, f"page {self.page}"
        )

    # -- text ------------------------------------------------------------

    def title(self, text: str, subtitle: str = "") -> None:
        self.canvas.setFont("Helvetica-Bold", 18)
        self.canvas.setFillColor(INK)
        self.canvas.drawString(MARGIN, self.y, text)
        self.y -= 20
        if subtitle:
            self.canvas.setFont("Helvetica", 9.5)
            self.canvas.setFillColor(MUTED)
            self.canvas.drawString(MARGIN, self.y, subtitle)
            self.y -= 14
        self.rule()

    def heading(self, text: str) -> None:
        self.room(40)
        self.space(6)
        self.canvas.setFont("Helvetica-Bold", 10)
        self.canvas.setFillColor(INK)
        self.canvas.drawString(MARGIN, self.y, text.upper())
        self.y -= 11
        self.rule()
        self.space(4)

    def subheading(self, text: str, colour: Color | None = None) -> None:
        self.room(26)
        self.canvas.setFont("Helvetica-Bold", 9)
        self.canvas.setFillColor(colour or INK)
        self.canvas.drawString(MARGIN, self.y, text)
        self.y -= 12

    def body(
        self,
        text: str,
        *,
        size: float = 8.5,
        colour: Color | None = None,
        indent: float = 0.0,
        font: str = "Helvetica",
        leading: float = 10.5,
    ) -> None:
        width = CONTENT_WIDTH - indent
        for line in simpleSplit(text, font, size, width):
            self.room(leading + 2)
            self.canvas.setFont(font, size)
            self.canvas.setFillColor(colour or INK)
            self.canvas.drawString(MARGIN + indent, self.y, line)
            self.y -= leading

    def mono(
        self, text: str, *, indent: float = 0.0, colour: Color | None = None
    ) -> None:
        self.body(
            text,
            size=7.5,
            colour=colour or MUTED,
            indent=indent,
            font="Courier",
            leading=9.5,
        )

    def kv(self, label: str, value: str) -> None:
        self.room(13)
        self.canvas.setFont("Helvetica", 8)
        self.canvas.setFillColor(MUTED)
        self.canvas.drawString(MARGIN, self.y, label)
        self.canvas.setFont("Helvetica", 8.5)
        self.canvas.setFillColor(INK)
        self.canvas.drawString(MARGIN + 110, self.y, value)
        self.y -= 12

    def rule(self, colour: Color | None = None) -> None:
        self.canvas.setStrokeColor(colour or RULE)
        self.canvas.setLineWidth(0.5)
        self.canvas.line(MARGIN, self.y, PAGE_WIDTH - MARGIN, self.y)
        self.y -= 8

    # -- structured ------------------------------------------------------

    def metrics(self, pairs: list[tuple[str, str]]) -> None:
        """A row of headline figures, evenly spaced."""
        self.room(40)
        column = CONTENT_WIDTH / max(1, len(pairs))
        for index, (label, value) in enumerate(pairs):
            x = MARGIN + index * column
            self.canvas.setFont("Helvetica", 7.5)
            self.canvas.setFillColor(MUTED)
            self.canvas.drawString(x, self.y, label.upper())
            self.canvas.setFont("Helvetica-Bold", 16)
            self.canvas.setFillColor(INK)
            self.canvas.drawString(x, self.y - 18, value)
        self.y -= 32

    def band_bar(self, counts: dict[str, int]) -> None:
        """Band distribution, as a proportional bar plus explicit counts.

        The counts are written out beside it because a bar is not a number and
        a reader of a printed report cannot hover.
        """
        total = sum(counts.values())
        self.room(34)
        if total:
            x = MARGIN
            for band in ("Critical", "High", "Medium", "Low"):
                share = counts.get(band, 0) / total
                width = CONTENT_WIDTH * share
                if width > 0:
                    self.canvas.setFillColor(band_colour(band))
                    self.canvas.rect(x, self.y - 8, width, 8, stroke=0, fill=1)
                    x += width
            self.y -= 14
        legend = "   ".join(
            f"{band} {counts.get(band, 0)}"
            for band in ("Critical", "High", "Medium", "Low")
        )
        self.body(legend, size=8, colour=MUTED)
        self.space(2)

    def row(
        self,
        cells: list[tuple[str, float]],
        *,
        bold: bool = False,
        colour: Color | None = None,
    ) -> None:
        """One table row: ``(text, x-offset)`` pairs, clipped to the column."""
        self.room(13)
        self.canvas.setFont("Helvetica-Bold" if bold else "Helvetica", 8)
        self.canvas.setFillColor(colour or INK)
        for text, offset in cells:
            self.canvas.drawString(MARGIN + offset, self.y, text)
        self.y -= 11

    def note(self, text: str) -> None:
        """A caveat. Rendered in the text, never only as a colour."""
        self.body(text, size=7.5, colour=MUTED, indent=0)
