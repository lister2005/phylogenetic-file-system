"""
Phenotype detection: identifies a file's true format from its own
content -- magic bytes / file signature -- instead of trusting a
filename extension. Per the design doc: "a user can name a file
absolutely anything, or give it no name at all, and the kernel will
always know exactly what it is." This is the mapping from raw bytes to
a Phenotype_Mask, used instead of '.pdf'/'.png'/etc: a Node's identity
is defined by its Expressed Genes (magic numbers / structural headers),
not a three-letter tag someone could rename away.

Deliberately a small, explicit signature table rather than pulling in a
general "file type sniffing" library (like python-magic/libmagic) --
keeping this dependency-free and matching the small set of concrete
magic-byte examples the design doc itself calls out (PDF's %PDF, PNG's
8-byte signature, and so on), rather than a large opaque database this
project doesn't need yet. Extending the table is a one-line add.
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
    """`data` should be the first ~64 bytes of the file -- every
    signature above fits well within that. Falls back to a simple
    printable-text heuristic, then to UNKNOWN. Never raises -- an
    unrecognized or empty sample is a legitimate, expected outcome
    (UNKNOWN), not an error."""
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
    # Reject control-byte-heavy samples a real text file wouldn't have
    # (allow common whitespace: tab, newline, carriage return).
    printable = sum(1 for b in sample if b >= 0x20 or b in (0x09, 0x0A, 0x0D))
    return printable / len(sample) > 0.95


def detect_from_file(file_path: str) -> Phenotype:
    with open(file_path, "rb") as f:
        return detect(f.read(64))
