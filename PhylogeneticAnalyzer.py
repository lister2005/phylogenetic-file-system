import os
import hashlib
from gearhash.hasher import Hasher

# Chunking profiles. STORAGE_PROFILE drives storage and dedup (8 KiB
# average, mask 0x1FFF). SIMILARITY_PROFILE only feeds Jaccard distances
# for clade clustering, so it's finer for sensitivity (256 B, mask 0xFF).
STORAGE_PROFILE = {"chunk_mask": 0x1FFF, "min_size": 4096, "max_size": 16384}
SIMILARITY_PROFILE = {"chunk_mask": 0xFF, "min_size": 128, "max_size": 512}

# Below this many chunks, one differing chunk can swing the distance to
# 1.0, so the distance is noise and callers warn about it.
MIN_RELIABLE_TRAIT_COUNT = 8


class PhylogeneticAnalyzer:
    def __init__(self, profile: dict = None):
        # Defaults to the similarity profile.
        self.profile = profile or SIMILARITY_PROFILE

    def extract_traits(self, file_path: str) -> set:
        """SHA-256 fingerprints of the file's chunks under this profile. Streams
        the file: peak memory O(read_ahead + max_size).
        """
        trait_matrix = set()
        hasher = Hasher()

        with open(file_path, "rb") as f:
            for chunk in hasher.stream_chunks(
                self.profile["chunk_mask"],
                f,
                min_size=self.profile["min_size"],
                max_size=self.profile["max_size"],
            ):
                # chunk.hash is the rolling-hash state, not a content hash: hash the bytes.
                trait_matrix.add(hashlib.sha256(chunk.data).digest())

        return trait_matrix

    def trait_set_is_reliable(self, traits: set) -> bool:
        """True if `traits` has at least MIN_RELIABLE_TRAIT_COUNT chunks."""
        return len(traits) >= MIN_RELIABLE_TRAIT_COUNT

    def calculate_distance(self, traits_a: set, traits_b: set) -> float:
        """Jaccard Distance: 1 - (|A ∩ B| / |A ∪ B|)"""
        intersection = traits_a.intersection(traits_b)
        union = traits_a.union(traits_b)
        if not union:
            return 1.0
        return 1.0 - (len(intersection) / len(union))

