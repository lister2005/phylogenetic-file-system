"""Chunk type and accelerated chunking iterator with native zero-copy C integration."""

from __future__ import annotations
import os
import ctypes
from dataclasses import dataclass
from typing import Iterator, TYPE_CHECKING
from .table import GEAR_TABLE

if TYPE_CHECKING:
    from .hasher import Hasher

MIN_SIZE = 4096
MAX_SIZE = 16384

@dataclass(eq=True)
class Chunk:
    hash: int
    offset: int
    len: int

@dataclass(eq=True)
class StreamedChunk:
    """Like Chunk, but carries its own bytes -- needed because streaming
    mode has no full in-memory buffer left to slice offset/len out of."""
    hash: int
    offset: int
    len: int
    data: bytes

USING_C_EXTENSION = False
C_LOAD_ERROR = None
_c_table_ptr = None

_dir = os.path.dirname(os.path.abspath(__file__))
_so_path = os.path.join(_dir, "libgearhash.so")

if os.path.exists(_so_path):
    try:
        _c_lib = ctypes.CDLL(_so_path)
        _c_lib.scan_chunk_c.argtypes = [
            ctypes.c_char_p,                 # const uint8_t* data
            ctypes.c_size_t,                 # size_t data_len
            ctypes.c_size_t,                 # size_t cursor
            ctypes.POINTER(ctypes.c_uint64), # uint64_t* current_hash
            ctypes.c_uint64,                 # uint64_t mask
            ctypes.c_size_t,                 # size_t min_size
            ctypes.c_size_t,                 # size_t max_size
            ctypes.POINTER(ctypes.c_uint64)  # const uint64_t* gear_table
        ]
        _c_lib.scan_chunk_c.restype = ctypes.c_size_t
        
        _c_table_ptr = (ctypes.c_uint64 * len(GEAR_TABLE))(*GEAR_TABLE)
        USING_C_EXTENSION = True
    except Exception as e:
        C_LOAD_ERROR = str(e)
else:
    C_LOAD_ERROR = f"Shared library binary missing at target path: {_so_path}"


class Iter(Iterator[Chunk]):
    def __init__(self, hasher: "Hasher", mask: int, data: bytes, min_size: int = None, max_size: int = None) -> None:
        self.hasher = hasher
        self.mask = mask
        self.data = data
        self.cursor = 0
        self.min_size = min_size if min_size is not None else MIN_SIZE
        self.max_size = max_size if max_size is not None else MAX_SIZE

    def __iter__(self) -> "Iter":
        return self

    def __next__(self) -> Chunk:
        if self.cursor >= len(self.data):
            raise StopIteration

        offset = self.cursor
        
        if USING_C_EXTENSION:
            c_hash = ctypes.c_uint64(self.hasher.hash)
            chunk_len = _c_lib.scan_chunk_c(
                self.data,
                len(self.data),
                self.cursor,
                ctypes.byref(c_hash),
                self.mask,
                self.min_size,
                self.max_size,
                _c_table_ptr
            )
            self.hasher.hash = c_hash.value
            self.cursor += chunk_len
        else:
            # Fallback Path
            max_limit = min(offset + self.max_size, len(self.data))
            min_limit = min(offset + self.min_size, len(self.data))
            
            while self.cursor < min_limit:
                byte = self.data[self.cursor]
                self.hasher.hash = ((self.hasher.hash << 1) + self.hasher.table[byte]) & 0xFFFFFFFFFFFFFFFF
                self.cursor += 1
                
            while self.cursor < max_limit:
                byte = self.data[self.cursor]
                self.hasher.hash = ((self.hasher.hash << 1) + self.hasher.table[byte]) & 0xFFFFFFFFFFFFFFFF
                self.cursor += 1
                if (self.hasher.hash & self.mask) == 0:
                    break

        return Chunk(hash=self.hasher.digest(), offset=offset, len=self.cursor - offset)


class StreamingIter(Iterator[StreamedChunk]):
    """Same chunk-boundary semantics as Iter, but reads from a file object
    in bounded increments instead of requiring the whole file in memory.

    Peak memory is O(read_ahead + max_size), independent of file size --
    this is what makes it safe to run against multi-GB files, unlike Iter
    which needs the entire file loaded as `data: bytes` up front.
    """

    def __init__(
        self,
        hasher: "Hasher",
        mask: int,
        file_obj,
        min_size: int = None,
        max_size: int = None,
        read_ahead: int = 8 * 1024 * 1024,
    ) -> None:
        self.hasher = hasher
        self.mask = mask
        self.file_obj = file_obj
        self.min_size = min_size if min_size is not None else MIN_SIZE
        self.max_size = max_size if max_size is not None else MAX_SIZE
        # Always keep enough buffered ahead to satisfy one full max_size scan.
        self.read_ahead = max(read_ahead, self.max_size)
        self.buffer = bytearray()
        self.buffer_offset = 0  # absolute file position of buffer[0]
        self.eof = False

    def __iter__(self) -> "StreamingIter":
        return self

    def _fill_buffer(self) -> None:
        while len(self.buffer) < self.max_size and not self.eof:
            block = self.file_obj.read(self.read_ahead)
            if not block:
                self.eof = True
                break
            self.buffer.extend(block)

    def __next__(self) -> StreamedChunk:
        self._fill_buffer()

        if not self.buffer:
            raise StopIteration

        offset = self.buffer_offset
        data_len = len(self.buffer)

        if USING_C_EXTENSION:
            # scan_chunk_c(data, data_len, cursor=0, ...) never looks past
            # min(cursor + max_size, data_len) -- so it never needs more
            # than max_size bytes from the front of the buffer, regardless
            # of how much read-ahead is currently sitting behind it. Slicing
            # first bounds BOTH the bytearray copy and the bytes() copy to
            # max_size (<=16KB); the previous bytes(self.buffer) converted
            # the FULL buffer (up to read_ahead, 8MB) on every single call,
            # which dominated the entire write path's cost (measured: 77%
            # of total time on a 300MB file, cProfile-confirmed 2026-07-23)
            # for something the C code was going to ignore past 16KB anyway.
            window = bytes(self.buffer[:self.max_size])
            c_hash = ctypes.c_uint64(self.hasher.hash)
            chunk_len = _c_lib.scan_chunk_c(
                window,
                len(window),
                0,
                ctypes.byref(c_hash),
                self.mask,
                self.min_size,
                self.max_size,
                _c_table_ptr,
            )
            self.hasher.hash = c_hash.value
        else:
            cursor = 0
            min_limit = min(self.min_size, data_len)
            max_limit = min(self.max_size, data_len)

            while cursor < min_limit:
                byte = self.buffer[cursor]
                self.hasher.hash = ((self.hasher.hash << 1) + self.hasher.table[byte]) & 0xFFFFFFFFFFFFFFFF
                cursor += 1

            while cursor < max_limit:
                byte = self.buffer[cursor]
                self.hasher.hash = ((self.hasher.hash << 1) + self.hasher.table[byte]) & 0xFFFFFFFFFFFFFFFF
                cursor += 1
                if (self.hasher.hash & self.mask) == 0:
                    break

            chunk_len = cursor

        chunk_bytes = bytes(self.buffer[:chunk_len])
        del self.buffer[:chunk_len]  # drop consumed prefix -- bounds memory
        self.buffer_offset += chunk_len

        return StreamedChunk(hash=self.hasher.digest(), offset=offset, len=chunk_len, data=chunk_bytes)