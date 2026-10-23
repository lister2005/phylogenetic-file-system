"""
How a file's similarity fingerprint (its SIMILARITY_PROFILE trait set)
is stored inside a Python-engine manifest's metadata.

Manifests written since 2026-10-23 store it PACKED: the 32-byte trait
hashes, sorted, concatenated into one bytes object -- the same layout as
the C++ manifest's fingerprint_hashes array. Older manifests store a
pickled set of bytes objects. Decrypting a manifest unpickles whatever
it holds, and the old form builds one Python object per trait on EVERY
manifest read (FUSE open/stat, clustering, 'info'), even when the
fingerprint isn't used. Measured on a 16 MB file (~50,000 traits):
reading the old form peaks at 9.4 MB and keeps 5.1 MB; the packed form
peaks at 5.1 MB and keeps 1.5 MB. The peak can't drop further while the
fingerprint lives inside the manifest: the encrypted file, the
decrypted pickle stream and the unpickled value all exist at once.

Both forms are read; only the packed form is written. Nothing is
migrated: an old manifest keeps its set until something rewrites it.
Code that needs the traits calls unpack(); code that only needs how
many there are calls count(), which never builds the set.
"""
from typing import Iterable, Optional, Set

TRAIT_BYTES = 32


def pack(traits: Iterable[bytes]) -> bytes:
    """Sorted, concatenated 32-byte traits -- what a manifest stores."""
    ordered = sorted(traits)
    for trait in ordered:
        if len(trait) != TRAIT_BYTES:
            raise ValueError(f"a fingerprint trait must be {TRAIT_BYTES} bytes, got {len(trait)}")
    return b"".join(ordered)


def _is_packed(stored) -> bool:
    return isinstance(stored, (bytes, bytearray, memoryview))


def unpack(stored) -> Optional[Set[bytes]]:
    """The trait set from a manifest's stored value (packed or the older
    pickled set), or None if the manifest has no fingerprint."""
    if stored is None:
        return None
    if _is_packed(stored):
        data = bytes(stored)
        if len(data) % TRAIT_BYTES:
            raise ValueError("packed fingerprint length isn't a multiple of 32 bytes")
        return {data[i:i + TRAIT_BYTES] for i in range(0, len(data), TRAIT_BYTES)}
    return set(stored)


def count(stored) -> int:
    """Number of traits in a stored fingerprint, without unpacking it.
    0 if there's none."""
    if stored is None:
        return 0
    if _is_packed(stored):
        return len(stored) // TRAIT_BYTES
    return len(stored)
