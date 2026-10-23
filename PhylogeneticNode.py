import time
import uuid
import struct
from typing import List, Optional, Set

# Serialized form: the C struct's fixed fields
#   node_uuid[16] + parent_uuid[16] + generation_index(u64) +
#   branch_signature(u32) + birth_timestamp(u64) + delta_size(u64)
# followed by the variable-length sections its pointers referred to:
# the trait count and hashes, then delta_size bytes of mutation_delta.
_HEADER_FORMAT = "16s16sQIQQ"
_HEADER_SIZE = struct.calcsize(_HEADER_FORMAT)
_TRAIT_HASH_SIZE = 32  # SHA-256 digest


class PhylogeneticNode:
    def __init__(self, parent_uuid: Optional[bytes] = None):
        self.node_uuid: bytes = uuid.uuid4().bytes  # 16 raw bytes, matches uint8_t[16]
        self.parent_uuid: Optional[bytes] = parent_uuid
        self.generation_index = 0
        self.branch_signature = 0  # bitmask, see TreeConstructor
        self.birth_timestamp = int(time.time())

        # Chunk content hashes (32-byte SHA-256 digests).
        self.trait_matrix: Set[bytes] = set()

        # Lineage-only; left at the defaults on clustering nodes, which have no content.
        self.delta_size = 0
        self.mutation_delta: bytes = b""

        # Clustering diagnostic: traits that differ between the two children. Not a storage delta.
        self.trait_divergence_count = 0

        # Cluster size, for UPGMA's weighted average.
        self.leaf_count = 1
        # UPGMA only: ultrametric height above the leaves (0 for NJ).
        self.height = 0.0
        # Edge length to the parent, for either algorithm.
        self.branch_length = 0.0
        # Set for leaves.
        self.metadata_name: Optional[str] = None

    def uuid_hex(self) -> str:
        """Human-readable form of node_uuid, e.g. for printing/lookup."""
        return uuid.UUID(bytes=self.node_uuid).hex

    def to_dict(self):
        """Serialize for JSON / human inspection."""
        return {
            "node_uuid": self.uuid_hex(),
            "parent_uuid": uuid.UUID(bytes=self.parent_uuid).hex if self.parent_uuid else None,
            "generation_index": self.generation_index,
            "branch_signature": self.branch_signature,
            "birth_timestamp": self.birth_timestamp,
            "trait_matrix_len": len(self.trait_matrix),
            "delta_size": self.delta_size,
            "trait_divergence_count": self.trait_divergence_count,
            "leaf_count": self.leaf_count,
            "height": self.height,
            "branch_length": self.branch_length,
            "metadata_name": self.metadata_name,
        }

    def to_bytes(self) -> bytes:
        """The fixed header, then the trait count and sorted hashes, then mutation_delta."""
        parent = self.parent_uuid or b"\x00" * 16
        header = struct.pack(
            _HEADER_FORMAT,
            self.node_uuid,
            parent,
            self.generation_index,
            self.branch_signature,
            self.birth_timestamp,
            self.delta_size,
        )
        sorted_traits = sorted(self.trait_matrix)  # deterministic order
        trait_section = struct.pack("Q", len(sorted_traits)) + b"".join(sorted_traits)
        return header + trait_section + self.mutation_delta

    @classmethod
    def from_bytes(cls, data: bytes) -> "PhylogeneticNode":
        node_uuid, parent_uuid, generation_index, branch_signature, birth_timestamp, delta_size = \
            struct.unpack(_HEADER_FORMAT, data[:_HEADER_SIZE])

        node = cls()
        node.node_uuid = node_uuid
        node.parent_uuid = None if parent_uuid == b"\x00" * 16 else parent_uuid
        node.generation_index = generation_index
        node.branch_signature = branch_signature
        node.birth_timestamp = birth_timestamp
        node.delta_size = delta_size

        offset = _HEADER_SIZE
        (trait_count,) = struct.unpack("Q", data[offset:offset + 8])
        offset += 8
        node.trait_matrix = set()
        for _ in range(trait_count):
            node.trait_matrix.add(data[offset:offset + _TRAIT_HASH_SIZE])
            offset += _TRAIT_HASH_SIZE

        node.mutation_delta = data[offset:offset + delta_size]
        return node
