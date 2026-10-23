"""
How a Python-engine manifest stores a similarity fingerprint.

New manifests store it packed: the sorted 32-byte traits concatenated,
as in the C++ manifest. Older ones hold a pickled set, which costs one
Python object per trait on every manifest read. Measured at 16 MB
(~50,000 traits): reading peaks at 9.4 MB and keeps 5.1 MB for the old
form, 5.1 MB and 1.5 MB packed. Both forms are read; only packed is
written; nothing is migrated. unpack() builds the set; count() doesn't.
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
