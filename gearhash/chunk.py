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
    """One chunk found in an in-memory buffer: its rolling hash, offset and length."""
    hash: int
    offset: int
    len: int

@dataclass(eq=True)
class StreamedChunk:
    """A Chunk that carries its own bytes (streaming mode has no buffer to slice)."""
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
        _c_lib.scan_chunk_anchored_c.argtypes = _c_lib.scan_chunk_c.argtypes
        _c_lib.scan_chunk_anchored_c.restype = ctypes.c_size_t
        
        _c_table_ptr = (ctypes.c_uint64 * len(GEAR_TABLE))(*GEAR_TABLE)
        USING_C_EXTENSION = True
    except Exception as e:
        C_LOAD_ERROR = str(e)
else:
    C_LOAD_ERROR = f"Shared library binary missing at target path: {_so_path}"



_U64 = 0xFFFFFFFFFFFFFFFF


def _scan_python(data, start: int, hash_value: int, table, mask: int, min_size: int, max_size: int,
                 anchored: bool):
    """Pure-Python scan_chunk_c / scan_chunk_anchored_c: (chunk length, hash
    at the cut). See gearhash_core.c for the rules."""
    data_len = len(data)
    anchored = anchored and start + max_size <= data_len
    max_limit = min(start + max_size, data_len)
    min_limit = min(start + min_size, data_len)
    cursor = start
    while cursor < min_limit:
        hash_value = ((hash_value << 1) + table[data[cursor]]) & _U64
        cursor += 1
    best_hash, best_end = _U64 + 1, max_limit
    while cursor < max_limit:
        hash_value = ((hash_value << 1) + table[data[cursor]]) & _U64
        cursor += 1
        if (hash_value & mask) == 0:
            return cursor - start, hash_value
        if anchored and hash_value < best_hash:
            best_hash, best_end = hash_value, cursor
    if anchored:
        return best_end - start, best_hash
    return cursor - start, hash_value


class Iter(Iterator[Chunk]):
    """Iterates over the chunks of an in-memory buffer using the Gear rolling hash."""
    def __init__(self, hasher: "Hasher", mask: int, data: bytes, min_size: int = None, max_size: int = None,
                 anchored: bool = False) -> None:
        """Prepares to chunk data; min_size/max_size default to the module's 4 KB / 16 KB.
        anchored: cut at the lowest-hash position when no natural cut comes
        before max_size (storage chunking; see scan_chunk_anchored_c)."""
        self.anchored = anchored
        self.hasher = hasher
        self.mask = mask
        self.data = data
        self.cursor = 0
        self.min_size = min_size if min_size is not None else MIN_SIZE
        self.max_size = max_size if max_size is not None else MAX_SIZE

    def __iter__(self) -> "Iter":
        """Returns itself, so the object can be used in a for loop."""
        return self

    def __next__(self) -> Chunk:
        """Finds the next cut point (in C if available, else Python) and returns the chunk."""
        if self.cursor >= len(self.data):
            raise StopIteration

        offset = self.cursor
        
        if USING_C_EXTENSION:
            c_hash = ctypes.c_uint64(self.hasher.hash)
            scan = _c_lib.scan_chunk_anchored_c if self.anchored else _c_lib.scan_chunk_c
            chunk_len = scan(
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
            chunk_len, self.hasher.hash = _scan_python(self.data, offset, self.hasher.hash, self.hasher.table,
                                                       self.mask, self.min_size, self.max_size, self.anchored)
            self.cursor += chunk_len

        return Chunk(hash=self.hasher.digest(), offset=offset, len=self.cursor - offset)


class StreamingIter(Iterator[StreamedChunk]):
    """Same boundaries as Iter, reading a file in bounded increments.
    Peak memory is O(read_ahead + max_size), independent of file size.
    """

    def __init__(
        self,
        hasher: "Hasher",
        mask: int,
        file_obj,
        min_size: int = None,
        max_size: int = None,
        read_ahead: int = 8 * 1024 * 1024,
        anchored: bool = False,
    ) -> None:
        """Prepares to chunk a file object while reading it in read_ahead-sized
        blocks. anchored: as for Iter."""
        self.anchored = anchored
        self.hasher = hasher
        self.mask = mask
        self.file_obj = file_obj
        self.min_size = min_size if min_size is not None else MIN_SIZE
        self.max_size = max_size if max_size is not None else MAX_SIZE
        # Keep at least one full max_size scan buffered.
        self.read_ahead = max(read_ahead, self.max_size)
        self.buffer = bytearray()
        self.buffer_offset = 0  # absolute file position of buffer[0]
        self.eof = False

    def __iter__(self) -> "StreamingIter":
        """Returns itself, so the object can be used in a for loop."""
        return self

    def _fill_buffer(self) -> None:
        """Reads more of the file until the buffer holds at least one maximum-size chunk, or the file ends."""
        while len(self.buffer) < self.max_size and not self.eof:
            block = self.file_obj.read(self.read_ahead)
            if not block:
                self.eof = True
                break
            self.buffer.extend(block)

    def __next__(self) -> StreamedChunk:
        """Finds the next cut point in the buffer and returns that chunk's bytes, removing them from the buffer."""
        self._fill_buffer()

        if not self.buffer:
            raise StopIteration

        offset = self.buffer_offset
        data_len = len(self.buffer)

        if USING_C_EXTENSION:
            # scan_chunk_c never looks past cursor + max_size, so pass only that
            # prefix: converting the whole read-ahead buffer on every call dominated
            # write time.
            window = bytes(self.buffer[:self.max_size])
            c_hash = ctypes.c_uint64(self.hasher.hash)
            scan = _c_lib.scan_chunk_anchored_c if self.anchored else _c_lib.scan_chunk_c
            chunk_len = scan(
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
            window = bytes(self.buffer[:self.max_size])
            chunk_len, self.hasher.hash = _scan_python(window, 0, self.hasher.hash, self.hasher.table, self.mask,
                                                       self.min_size, self.max_size, self.anchored)

        chunk_bytes = bytes(self.buffer[:chunk_len])
        del self.buffer[:chunk_len]  # drop the consumed prefix
        self.buffer_offset += chunk_len

        return StreamedChunk(hash=self.hasher.digest(), offset=offset, len=chunk_len, data=chunk_bytes)