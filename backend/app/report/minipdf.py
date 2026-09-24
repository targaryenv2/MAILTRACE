"""A minimal PDF writer, used only when ReportLab is not installed.

Why this exists. The forensic report is the deliverable an analyst hands to
somebody else - a manager, a bank's fraud desk, a police cyber cell - so
"install ReportLab first" is not an acceptable answer on a machine where pip is
blocked or offline. This module writes a valid PDF 1.4 using nothing but the
standard library, so ``mailtrace report`` always produces a file.

It is deliberately small. Base-14 Helvetica only (no font embedding, no
Unicode - text is coerced to Latin-1), lines, rectangles, circles and text.
That is exactly the primitive set :mod:`app.report.pdf` draws with, so the
fallback report has the same content and structure as the ReportLab one; it is
plainer, not shorter.

Coordinates here are PDF-native: origin bottom-left, units are points. The
renderer in :mod:`app.report.pdf` works top-down and converts.
"""

from __future__ import annotations

import zlib
from pathlib import Path
from typing import List, Optional, Sequence, Tuple

A4: Tuple[float, float] = (595.28, 841.89)

Colour = Sequence[float]

# Helvetica advance widths, in ems, by character class. These are approximations,
# not the AFM table: they are used for line wrapping and column fitting, where
# being a few percent conservative costs a little whitespace and nothing else.
# The ReportLab path uses exact stringWidth, so precise layout is available
# whenever the optional dependency is.
_NARROW = set("ijltI.,:;'`!|()[]{}/\\-\" ")
_WIDE = set("mMWO@%&")


def _escape(text: str) -> bytes:
    out = text.replace("\\", r"\\").replace("(", r"\(").replace(")", r"\)")
    # cp1252, not latin-1: the fonts are declared /WinAnsiEncoding, and WinAnsi
    # *is* cp1252. Encoding as latin-1 would turn an ellipsis or a typographic
    # quote into "?" even though the font has the glyph.
    return out.encode("cp1252", "replace")


def string_width(text: str, size: float, bold: bool = False) -> float:
    """Approximate advance width of ``text`` in points."""
    em = 0.0
    for ch in text:
        if ch in _NARROW:
            em += 0.30
        elif ch in _WIDE:
            em += 0.84
        elif ch.isupper():
            em += 0.69
        else:
            em += 0.55
    return em * size * (1.045 if bold else 1.0)


def _fmt(value: float) -> str:
    return ("%.2f" % value).rstrip("0").rstrip(".") or "0"


class MiniPdf:
    """Accumulate drawing operators per page, then serialise."""

    def __init__(self, width: float = A4[0], height: float = A4[1]) -> None:
        self.width = width
        self.height = height
        self._pages: List[List[str]] = [[]]

    # --- page management ---------------------------------------------------
    @property
    def page_count(self) -> int:
        return len(self._pages)

    def new_page(self) -> None:
        self._pages.append([])

    def _op(self, op: str) -> None:
        self._pages[-1].append(op)

    # --- drawing ----------------------------------------------------------
    def _colour(self, colour: Colour, stroke: bool) -> str:
        r, g, b = (float(c) for c in colour)
        return "%s %s %s %s" % (_fmt(r), _fmt(
            g), _fmt(b), "RG" if stroke else "rg")

    def text(self, x: float, y: float, text: str, size: float = 9.0,
             bold: bool = False, colour: Colour = (0, 0, 0)) -> None:
        if not text:
            return
        self._op("BT %s /%s %s Tf 1 0 0 1 %s %s Tm (%s) Tj ET" % (
            self._colour(colour, False), "F2" if bold else "F1", _fmt(size),
            _fmt(x), _fmt(y), _escape(text).decode("latin-1")))

    def line(self, x1: float, y1: float, x2: float, y2: float,
             width: float = 0.6, colour: Colour = (0, 0, 0),
             dash: Optional[Tuple[float, float]] = None) -> None:
        dash_op = "[%s %s] 0 d " % (
            _fmt(dash[0]), _fmt(dash[1])) if dash else "[] 0 d "
        self._op("q %s%s %s w %s %s m %s %s l S Q" % (
            dash_op, self._colour(colour, True), _fmt(width),
            _fmt(x1), _fmt(y1), _fmt(x2), _fmt(y2)))

    def rect(self, x: float, y: float, w: float, h: float,
             fill: Optional[Colour] = None, stroke: Optional[Colour] = None,
             width: float = 0.6) -> None:
        ops = ["q"]
        if fill is not None:
            ops.append(self._colour(fill, False))
        if stroke is not None:
            ops.append("%s %s w" % (self._colour(stroke, True), _fmt(width)))
        ops.append("%s %s %s %s re" % (_fmt(x), _fmt(y), _fmt(w), _fmt(h)))
        ops.append("B" if (fill is not None and stroke is not None)
                   else ("f" if fill is not None else "S"))
        ops.append("Q")
        self._op(" ".join(ops))

    def circle(self, cx: float, cy: float, r: float,
               fill: Optional[Colour] = None, stroke: Optional[Colour] = None,
               width: float = 0.6) -> None:
        k = 0.5523 * r  # Bezier handle length for a quarter circle
        ops = ["q"]
        if fill is not None:
            ops.append(self._colour(fill, False))
        if stroke is not None:
            ops.append("%s %s w" % (self._colour(stroke, True), _fmt(width)))
        ops.append("%s %s m" % (_fmt(cx + r), _fmt(cy)))
        ops.append("%s %s %s %s %s %s c" % (_fmt(cx + r), _fmt(cy + k),
                                            _fmt(cx + k), _fmt(cy + r),
                                            _fmt(cx), _fmt(cy + r)))
        ops.append("%s %s %s %s %s %s c" % (_fmt(cx - k), _fmt(cy + r),
                                            _fmt(cx - r), _fmt(cy + k),
                                            _fmt(cx - r), _fmt(cy)))
        ops.append("%s %s %s %s %s %s c" % (_fmt(cx - r), _fmt(cy - k),
                                            _fmt(cx - k), _fmt(cy - r),
                                            _fmt(cx), _fmt(cy - r)))
        ops.append("%s %s %s %s %s %s c" % (_fmt(cx + k), _fmt(cy - r),
                                            _fmt(cx + r), _fmt(cy - k),
                                            _fmt(cx + r), _fmt(cy)))
        ops.append("B" if (fill is not None and stroke is not None)
                   else ("f" if fill is not None else "S"))
        ops.append("Q")
        self._op(" ".join(ops))

    # --- serialisation ----------------------------------------------------
    def save(self, path: str) -> str:
        objects: List[bytes] = []

        def add(body: bytes) -> int:
            objects.append(body)
            return len(objects)  # 1-based object number

        # Object numbers are laid out first because /Pages must reference its
        # children and each page must reference /Pages.
        n_pages = len(self._pages)
        catalog_no, pages_no = 1, 2
        font_regular, font_bold = 3, 4
        first_page_no = 5
        page_nos = [first_page_no + 2 * i for i in range(n_pages)]
        content_nos = [first_page_no + 2 * i + 1 for i in range(n_pages)]

        add(b"<< /Type /Catalog /Pages %d 0 R >>" % pages_no)
        add(b"<< /Type /Pages /Count %d /Kids [%s] >>" % (
            n_pages, b" ".join(b"%d 0 R" % p for p in page_nos)))
        add(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica "
            b"/Encoding /WinAnsiEncoding >>")
        add(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold "
            b"/Encoding /WinAnsiEncoding >>")
        for i, ops in enumerate(self._pages):
            add(
                b"<< /Type /Page /Parent %d 0 R /MediaBox [0 0 %s %s] "
                b"/Resources << /Font << /F1 %d 0 R /F2 %d 0 R >> >> "
                b"/Contents %d 0 R >>" %
                (pages_no, _fmt(
                    self.width).encode(), _fmt(
                    self.height).encode(), font_regular, font_bold, content_nos[i]))
            stream = zlib.compress("\n".join(ops).encode("latin-1", "replace"))
            add(b"<< /Length %d /Filter /FlateDecode >>\nstream\n%s\nendstream"
                % (len(stream), stream))

        out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
        offsets: List[int] = []
        for num, body in enumerate(objects, 1):
            offsets.append(len(out))
            out += b"%d 0 obj\n" % num + body + b"\nendobj\n"
        xref_at = len(out)
        out += b"xref\n0 %d\n" % (len(objects) + 1)
        out += b"0000000000 65535 f \n"
        for off in offsets:
            out += b"%010d 00000 n \n" % off
        out += (b"trailer\n<< /Size %d /Root %d 0 R >>\nstartxref\n%d\n%%%%EOF\n"
                % (len(objects) + 1, catalog_no, xref_at))
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(bytes(out))
        return str(target)
