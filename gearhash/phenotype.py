"""
Phenotype detection: a file's type from its magic bytes, never its name.
A small explicit signature table; extending it is a one-line add.
"""

from typing import NamedTuple


class Phenotype(NamedTuple):
    mask: int
    name: str


UNKNOWN = Phenotype(0x0000, "Unknown Binary")
TEXT = Phenotype(0x00FF, "Plain Text")

# (magic bytes, offset, mask, name) -- checked in order, first match wins.
_SIGNATURES = [
    (b"%PDF-", 0, 0x0001, "PDF Document"),
    (b"\x89PNG\r\n\x1a\n", 0, 0x0002, "PNG Image"),
    (b"\xff\xd8\xff", 0, 0x0003, "JPEG Image"),
    (b"GIF87a", 0, 0x0004, "GIF Image"),
    (b"GIF89a", 0, 0x0004, "GIF Image"),
    (b"PK\x03\x04", 0, 0x0005, "ZIP Archive (or ZIP-based format: docx/xlsx/jar/apk...)"),
    (b"\x7fELF", 0, 0x0006, "ELF Binary"),
    (b"ID3", 0, 0x0007, "MP3 Audio"),
    (b"ftyp", 4, 0x0008, "MP4/MOV Media"),
    (b"RIFF", 0, 0x0009, "RIFF Container (WAV/AVI/...)"),
    (b"SQLite format 3\x00", 0, 0x000A, "SQLite Database"),
    (b"\x1f\x8b", 0, 0x000B, "GZIP Compressed"),
    (b"BM", 0, 0x000C, "BMP Image"),
]


def detect(data: bytes) -> Phenotype:
    """`data`: the first ~64 bytes. Falls back to a printable-text heuristic,
    then UNKNOWN. Never raises.
    """
    for magic, offset, mask, name in _SIGNATURES:
        end = offset + len(magic)
        if len(data) >= end and data[offset:end] == magic:
            return Phenotype(mask, name)

    sample = data[:512]
    if sample and _looks_like_text(sample):
        return TEXT
    return UNKNOWN


def _looks_like_text(sample: bytes) -> bool:
    try:
        sample.decode("utf-8")
    except UnicodeDecodeError:
        return False
    # Mostly control bytes (other than tab/newline/CR) means not text.
    printable = sum(1 for b in sample if b >= 0x20 or b in (0x09, 0x0A, 0x0D))
    return printable / len(sample) > 0.95


def detect_from_file(file_path: str) -> Phenotype:
    with open(file_path, "rb") as f:
        return detect(f.read(64))
