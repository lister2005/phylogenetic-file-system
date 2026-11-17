"""
The stored form of a Python-engine similarity fingerprint: the sorted
32-byte traits concatenated, as in the C++ manifest. It is written to a
separate encrypted file per manifest (gearhash/pipeline.py, TRAITS_SUFFIX).
Older manifests hold it inside, packed or as a pickled set; unpack()
accepts both. unpack() builds the set; count() doesn't.
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
    """True if the fingerprints are stored as one packed byte string rather than a set."""
    return isinstance(stored, (bytes, bytearray, memoryview))


def unpack(stored) -> Optional[Set[bytes]]:
    """The trait set from a stored value (packed or old set), or None."""
    if stored is None:
        return None
    if _is_packed(stored):
        data = bytes(stored)
        if len(data) % TRAIT_BYTES:
            raise ValueError("packed fingerprint length isn't a multiple of 32 bytes")
        return {data[i:i + TRAIT_BYTES] for i in range(0, len(data), TRAIT_BYTES)}
    return set(stored)


def count(stored) -> int:
    """Number of traits, without unpacking. 0 if none."""
    if stored is None:
        return 0
    if _is_packed(stored):
        return len(stored) // TRAIT_BYTES
    return len(stored)
