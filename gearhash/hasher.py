"""Gear hasher and mask helper, ported from ``src/lib.rs`` in rust-gearhash
(https://github.com/srijs/rust-gearhash), Copyright (c) 2019 Sam Rijs and contributors,
MIT license (notice in LICENSE)."""

from __future__ import annotations
from typing import Optional, Sequence
from .chunk import Iter, StreamingIter
from .table import GEAR_TABLE, Table

#: All arithmetic on ``hash`` must wrap at 64 bits, the same as Rust's `u64`.
_U64_MASK = 0xFFFFFFFFFFFFFFFF

#: Size (in bits) of the masks used by the Gear hash.
MASK_SIZE = 64


class Hasher:
    """Gear hasher."""

    __slots__ = ("table", "hash")

    def __init__(self, table: Optional[Table] = None) -> None:
        """Create a new hasher.

        If ``table`` is omitted, :data:`GEAR_TABLE` is used.
        """
        self.table: Table = table if table is not None else GEAR_TABLE
        self.hash: int = 0

    def consume(self, byte: int) -> None:
        """Consume a single message byte."""
        # Hashing stage of the Gear-based CDC, as defined in the Ddelta and FastCDC papers.
        self.hash = ((self.hash << 1) + self.table[byte]) & _U64_MASK

    def consume_slice(self, data: Sequence[int]) -> None:
        """Consume a sequence (e.g. ``bytes``) of message bytes."""
        for byte in data:
            self.consume(byte)

    def digest(self) -> int:
        """Return the digest value."""
        return self.hash

    def chunks(self, mask: int, data: bytes, min_size: int = None, max_size: int = None,
               anchored: bool = False) -> Iter:
        """Return an iterator over the chunks determined by chunk boundaries
        (anchored: see chunk.Iter)."""
        return Iter(self, mask, data, min_size=min_size, max_size=max_size, anchored=anchored)

    def stream_chunks(self, mask: int, file_obj, min_size: int = None, max_size: int = None,
                       read_ahead: int = 8 * 1024 * 1024, anchored: bool = False) -> StreamingIter:
        """Like chunks(), but reads from an open file object in bounded
        increments instead of requiring the whole file as an in-memory
        bytes object. Use this for large files."""
        return StreamingIter(self, mask, file_obj, min_size=min_size, max_size=max_size, read_ahead=read_ahead,
                             anchored=anchored)

    def is_chunk_boundary(self, mask: int) -> bool:
        """True if the current digest is a chunk boundary for `mask` (see :func:`mask`)."""
        return (self.hash & mask) == 0

    def __repr__(self) -> str:
        """Shows the current hash value in hex."""
        return f"Hasher(hash={self.hash:#018x})"


def mask(n: int) -> int:
    """A mask with the `n` most-significant bits set.

    Raises ValueError if `n` is outside ``1..=64``.
    """
    if not (1 <= n <= MASK_SIZE):
        raise ValueError(f"n must be in range 1..={MASK_SIZE}, got {n}")
    
    return _U64_MASK ^ ((1 << (64 - n)) - 1)