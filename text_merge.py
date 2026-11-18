"""
Line-by-line three-way merge for text files.

Merging two branches of a text file compares each with the version they last
had in common (the base). Lines changed on only one side are taken from that
side; lines changed the same way on both are taken once; lines changed
differently on both are a conflict, which the user settles by choosing one
side, or both in order. This is the classic "merge3" method used by version
control systems: the base is lined up with each side, and the stretches of
base lines that both sides kept unchanged anchor the comparison.

Works on lines, so an insertion near the top of a file doesn't disturb
anything below it, unlike the chunk-position merge used for other files.
"""

import difflib
from typing import List, Optional

# Line merging reads all three versions into memory, so it is used only for
# versions of at most this many chunks (at most 16 MB each, chunks being at
# most 16 KB); larger files use the chunk-position merge.
MAX_TEXT_MERGE_CHUNKS = 1024


class LineConflict:
    """One stretch of lines both branches changed differently."""

    def __init__(self, index: int, base_start: int, base: list, a: list, b: list):
        """index: its number among the file's conflicts; base_start: its first
        base line (0-based); base/a/b: the lines of each version there."""
        self.index = index
        self.base_start = base_start
        self.base = base
        self.a = a
        self.b = b

    def lines_description(self) -> str:
        """Where the conflict is, for people: 'line 12', 'lines 12-14', or 'after line 11'."""
        first = self.base_start + 1
        if not self.base:
            return f"after line {self.base_start}" if self.base_start else "at the start"
        last = self.base_start + len(self.base)
        return f"line {first}" if first == last else f"lines {first}-{last}"


class MergeResult:
    """A three-way merge: its parts in order, and the conflicts among them."""

    def __init__(self, parts: list):
        """parts: lists of lines (settled) and LineConflict objects, in file order."""
        self.parts = parts
        self.conflicts = [p for p in parts if isinstance(p, LineConflict)]

    def text(self, choices: Optional[dict] = None) -> str:
        """The merged text. choices maps each conflict's index to 'a', 'b' or
        'both' (a's lines, then b's). ValueError if a conflict has no choice."""
        choices = choices or {}
        out = []
        for part in self.parts:
            if not isinstance(part, LineConflict):
                out.extend(part)
                continue
            side = choices.get(part.index)
            if side == "a":
                out.extend(part.a)
            elif side == "b":
                out.extend(part.b)
            elif side == "both":
                out.extend(part.a)
                out.extend(part.b)
            else:
                raise ValueError(f"Conflict {part.index + 1} ({part.lines_description()}) has no choice: "
                                 f"choose 'a', 'b' or 'both'.")
        return "".join(out)


def _sync_regions(base: list, a: list, b: list) -> list:
    """Stretches of base lines both sides kept unchanged, as
    (base_start, base_end, a_start, a_end, b_start, b_end), ending with an
    empty sentinel at the end of all three."""
    a_blocks = difflib.SequenceMatcher(None, base, a, autojunk=False).get_matching_blocks()
    b_blocks = difflib.SequenceMatcher(None, base, b, autojunk=False).get_matching_blocks()
    regions = []
    ia = ib = 0
    while ia < len(a_blocks) and ib < len(b_blocks):
        abase, amatch, alen = a_blocks[ia]
        bbase, bmatch, blen = b_blocks[ib]
        start = max(abase, bbase)
        end = min(abase + alen, bbase + blen)
        if start < end:
            a_start = amatch + (start - abase)
            b_start = bmatch + (start - bbase)
            regions.append((start, end, a_start, a_start + (end - start), b_start, b_start + (end - start)))
        if abase + alen < bbase + blen:
            ia += 1
        else:
            ib += 1
    regions.append((len(base), len(base), len(a), len(a), len(b), len(b)))
    return regions


def merge_lines(base: list, a: list, b: list) -> MergeResult:
    """Three-way merges lists of lines (each keeping its line ending)."""
    parts: List[object] = []
    conflicts = 0
    iz = ia = ib = 0
    for zmatch, zend, amatch, aend, bmatch, bend in _sync_regions(base, a, b):
        base_part, a_part, b_part = base[iz:zmatch], a[ia:amatch], b[ib:bmatch]
        if base_part or a_part or b_part:
            if a_part == b_part:
                parts.append(a_part)  # unchanged, or changed the same way on both
            elif a_part == base_part:
                parts.append(b_part)  # only b changed it
            elif b_part == base_part:
                parts.append(a_part)  # only a changed it
            else:
                parts.append(LineConflict(conflicts, iz, base_part, a_part, b_part))
                conflicts += 1
        if zend > zmatch:
            parts.append(base[zmatch:zend])
        iz, ia, ib = zend, aend, bend
    return MergeResult([p for p in parts if isinstance(p, LineConflict) or p])


def merge_bytes(base: bytes, a: bytes, b: bytes) -> Optional[MergeResult]:
    """Three-way merges three versions of a file line by line, or returns
    None if any of them isn't UTF-8 text (use the chunk merge instead)."""
    try:
        texts = [data.decode("utf-8") for data in (base, a, b)]
    except UnicodeDecodeError:
        return None
    if any("\x00" in text for text in texts):
        return None
    return merge_lines(*(text.splitlines(keepends=True) for text in texts))
