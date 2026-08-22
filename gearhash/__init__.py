"""Gear-hash based content-defined chunking (FastCDC-style).

Python port of a small Rust crate consisting of ``table.rs``, ``lib.rs``, and
``chunk.rs``. Package layout mirrors the original crate:

- ``table.py``  -> Gear hash lookup table   (was ``table.rs``)
- ``hasher.py`` -> ``Hasher`` + ``mask()``  (was ``lib.rs``)
- ``chunk.py``  -> ``Chunk`` + ``Iter``     (was ``chunk.rs``)
"""

from .chunk import Chunk
from .hasher import Hasher, mask
from .table import GEAR_TABLE, Table

__all__ = ["Chunk", "Hasher", "mask", "GEAR_TABLE", "Table"]
