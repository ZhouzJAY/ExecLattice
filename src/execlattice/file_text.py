"""Explicit text encodings and byte-preserving range decoding for file tools."""

from __future__ import annotations

import codecs

ENCODINGS = {"utf-8", "utf-16-le", "utf-16-be", "gb18030"}
BOMS = {"utf-8": b"\xef\xbb\xbf", "utf-16-le": b"\xff\xfe", "utf-16-be": b"\xfe\xff"}


def text_format(content: bytes, requested: str) -> tuple[str, int]:
    """Auto means Unicode BOM detection, then strict UTF-8; never guess a code page."""
    detected = next((encoding for encoding, bom in BOMS.items() if content.startswith(bom)), None)
    encoding = detected or "utf-8" if requested == "auto" else requested
    if encoding not in ENCODINGS or detected is not None and detected != encoding:
        raise UnicodeError("The requested encoding disagrees with the file BOM")
    return encoding, len(BOMS[detected]) if detected is not None else 0


def decode_range(data: bytes, encoding: str, bom_bytes: int, offset: int, *, final=True) -> tuple[str, int]:
    """Decode complete characters, returning text and the number of consumed bytes.

    The leading BOM remains part of the receipt and file hash, but is omitted
    from displayed text. Only the first range may contain that BOM.
    """
    if encoding not in ENCODINGS or bom_bytes not in {0, len(BOMS.get(encoding, b""))}:
        raise UnicodeError("Invalid text format")
    prefix = bom_bytes if offset == 0 else 0
    if bom_bytes and offset == 0 and not data.startswith(BOMS[encoding]):
        raise UnicodeError("Missing file BOM")
    if offset and offset < bom_bytes or encoding.startswith("utf-16") and (offset - prefix) % 2:
        raise UnicodeError("Range begins inside a text character")
    decoder = codecs.getincrementaldecoder(encoding)(errors="strict")
    text = decoder.decode(data[prefix:], final=final)
    if "\x00" in text:
        raise UnicodeError("Text contains NUL")
    buffered, _ = decoder.getstate()
    return text, len(data) - len(buffered)
