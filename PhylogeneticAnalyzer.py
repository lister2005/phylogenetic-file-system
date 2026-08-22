import os
import hashlib
from gearhash.hasher import Hasher

# --- Chunking Profiles --------------------------------------------------
# These serve two unrelated purposes and do NOT need to share a granularity:
#
# STORAGE_PROFILE drives the actual PFS delta/dedup engine. Non-negotiable --
# tuned for the metadata-overhead-vs-storage-efficiency tradeoff (4KB-16KB,
# mask paired per min=avg/2, max=avg*2, avg=8KB -> 0x1FFF).
#
# SIMILARITY_PROFILE drives ONLY the Jaccard distance calculation that feeds
# UPGMA / Neighbor-Joining clade clustering to build the phylogenetic tree.
# It never touches physical storage, so it's tuned purely for sensitivity.
# Same min=avg/2, max=avg*2 pairing, avg=256B -> mask 0xFF (8 bits).
STORAGE_PROFILE = {"chunk_mask": 0x1FFF, "min_size": 4096, "max_size": 16384}
SIMILARITY_PROFILE = {"chunk_mask": 0xFF, "min_size": 128, "max_size": 512}

# Below this many chunks, a Jaccard distance is noise, not signal: with
# SIMILARITY_PROFILE's 128-512B chunks, a handful of chunks means the whole
# file is only a few hundred bytes to ~1-2KB, so ONE differing chunk can by
# itself swing the distance to a misleading 1.0 ("nothing shared") even
# between two otherwise near-identical files. 8 is a defensible floor: it's
# small enough not to blind the tool on genuinely small-but-real files, but
# big enough that a single-chunk difference no longer dominates the ratio.
MIN_RELIABLE_TRAIT_COUNT = 8


class PhylogeneticAnalyzer:
    def __init__(self, profile: dict = None):
        # Defaults to the similarity profile since that's this class's job --
        # building the Jaccard distance matrix for tree construction.
        self.profile = profile or SIMILARITY_PROFILE

    def extract_traits(self, file_path: str) -> set:
        """Returns the set of SHA-256 content fingerprints for a file's
        chunks, using whichever chunking profile this analyzer was
        configured with.

        Streams the file in bounded increments instead of reading it
        whole into memory -- peak memory is O(read_ahead + max_size),
        independent of file size, matching the guarantee the storage
        pipeline already makes on its own (STORAGE_PROFILE) pass. This
        matters most here: SIMILARITY_PROFILE's much smaller average
        chunk size means this pass produces far more chunks per byte
        than the storage pass, so it's the one most likely to be run
        against very large files without ever holding the whole thing
        in RAM."""
        trait_matrix = set()
        hasher = Hasher()

        with open(file_path, "rb") as f:
            for chunk in hasher.stream_chunks(
                self.profile["chunk_mask"],
                f,
                min_size=self.profile["min_size"],
                max_size=self.profile["max_size"],
            ):
                # chunk.hash is the internal Gear rolling-hash STATE at the
                # cut point, not a content hash -- it only reflects the last
                # ~64 bytes of the chunk. Fingerprint the actual chunk bytes.
                trait_matrix.add(hashlib.sha256(chunk.data).digest())

        return trait_matrix

    def trait_set_is_reliable(self, traits: set) -> bool:
        """True if `traits` (as returned by extract_traits, or read back
        from a stored similarity_fingerprint) has enough chunks for a
        Jaccard distance computed from it to be statistically meaningful
        -- see MIN_RELIABLE_TRAIT_COUNT's comment. Purely additive: does
        NOT change extract_traits's signature/return type, just gives
        callers (CLI/GUI) a way to check before trusting/displaying a
        distance built from it."""
        return len(traits) >= MIN_RELIABLE_TRAIT_COUNT

    def calculate_distance(self, traits_a: set, traits_b: set) -> float:
        """Jaccard Distance: 1 - (|A ∩ B| / |A ∪ B|)"""
        intersection = traits_a.intersection(traits_b)
        union = traits_a.union(traits_b)
        if not union:
            return 1.0
        return 1.0 - (len(intersection) / len(union))

    # ... rest of your analyzer code ...