import time
import uuid
import struct
from typing import List, Optional, Set

# Fixed-size header layout, matching the C struct's fixed fields:
#   node_uuid[16] + parent_uuid[16] + generation_index(u64) +
#   branch_signature(u32) + birth_timestamp(u64) + delta_size(u64)
# The struct's two pointer fields (trait_matrix_ptr, mutation_delta) can't
# serialize literally -- pointers aren't meaningful outside one process's
# memory. The standard way to serialize "a struct with pointers" is what's
# used here: a fixed header (with size fields) followed by the variable-
# length payload sections it points to, in order. delta_size (already in
# the header) tells a reader how many mutation_delta bytes follow; the
# trait matrix entry count is written just before its own section.
_HEADER_FORMAT = "16s16sQIQQ"
_HEADER_SIZE = struct.calcsize(_HEADER_FORMAT)
_TRAIT_HASH_SIZE = 32  # SHA-256 digest


class PhylogeneticNode:
    def __init__(self, parent_uuid: Optional[bytes] = None):
        self.node_uuid: bytes = uuid.uuid4().bytes  # 16 raw bytes, matches uint8_t[16]
        self.parent_uuid: Optional[bytes] = parent_uuid
        self.generation_index = 0
        self.branch_signature = 0  # bitmask -- see note in TreeConstructor
        self.birth_timestamp = int(time.time())

        # The Genetic Material: chunk content hashes (32-byte SHA-256
        # digests from PhylogeneticAnalyzer), NOT ints -- this was
        # mistyped before.
        self.trait_matrix: Set[bytes] = set()

        # delta_size / mutation_delta are for the LINEAGE DAG only (real
        # per-edit deltas between actual file versions -- see
        # TreeConstructor.py's module docstring for the distinction).
        # They stay at these defaults on clade-clustering-tree nodes,
        # since internal cluster nodes have no real byte content to
        # take a delta of.
        self.delta_size = 0
        self.mutation_delta: bytes = b""

        # Clustering-tree-only diagnostic: count of traits that differ
        # between this node's two children at a merge. This is a
        # similarity STATISTIC for clustering visualization, NOT a real
        # storage delta -- do not confuse with delta_size above.
        self.trait_divergence_count = 0

        # Needed for real UPGMA (the arithmetic-mean update formula is
        # weighted by cluster size) and useful for NJ/visualization too.
        self.leaf_count = 1
        # UPGMA-specific: ultrametric height above this node's descendant
        # leaves (cumulative). Meaningless for NJ, which isn't ultrametric
        # -- NJ nodes leave this at 0 and use branch_length instead.
        self.height = 0.0
        # Universal: edge length from this node up to its own parent.
        # Set by whichever algorithm builds the tree. This is the field
        # to use for rendering/measuring branches regardless of which
        # algorithm produced the tree.
        self.branch_length = 0.0
        # Set by TreeConstructor for leaves; convenient for visualization.
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
        """Binary layout matching the C struct's fixed fields, followed
        by the trait matrix (count + sorted 32-byte hashes) and the
        mutation_delta payload."""
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
