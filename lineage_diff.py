"""
Lineage diff: what changed between two generations of the same label,
by chunk position (each manifest is an ordered list of chunk hashes).

Not the clade comparison in pfs_gui.py's _show_diff_between, which
compares different labels' similarity; the two stay separate.
"""
from dataclasses import dataclass, field
from typing import List, Optional

UNCHANGED = "unchanged"  # same chunk hash at this position in both generations
NEW = "new"              # position exists in the newer generation only (file grew)
CHANGED = "changed"      # position exists in both, but the chunk hash differs (mutated)
DELETED = "deleted"      # position existed in the older generation only (file shrank)


@dataclass
class ChunkDiffPosition:
    index: int
    status: str  # UNCHANGED / NEW / CHANGED / DELETED
    old_hash: Optional[bytes]
    new_hash: Optional[bytes]


@dataclass
class LineageDiffResult:
    label: str
    generation_old: int
    generation_new: int
    positions: List[ChunkDiffPosition] = field(default_factory=list)
    total_old: int = 0
    total_new: int = 0

    def _count(self, status: str) -> int:
        return sum(1 for p in self.positions if p.status == status)

    @property
    def unchanged_count(self) -> int:
        return self._count(UNCHANGED)

    @property
    def changed_count(self) -> int:
        return self._count(CHANGED)

    @property
    def new_count(self) -> int:
        return self._count(NEW)

    @property
    def deleted_count(self) -> int:
        return self._count(DELETED)

    @property
    def identical(self) -> bool:
        return self.changed_count == 0 and self.new_count == 0 and self.deleted_count == 0


def diff_generations(adapter, label: str, generation_old: int, generation_new: int) -> LineageDiffResult:
    """Chunk-position diff between two generations of `label`. Pass the older
    generation first: NEW means past its end, DELETED means only it had that
    position.

    `adapter`: anything with get_chunk_hashes(label, generation_index).
    """
    chunks_old = adapter.get_chunk_hashes(label, generation_old)
    chunks_new = adapter.get_chunk_hashes(label, generation_new)

    positions = []
    max_len = max(len(chunks_old), len(chunks_new))
    for i in range(max_len):
        old = chunks_old[i] if i < len(chunks_old) else None
        new = chunks_new[i] if i < len(chunks_new) else None
        if old is not None and new is not None:
            status = UNCHANGED if old == new else CHANGED
        elif new is not None:  # only the newer generation reaches this position
            status = NEW
        else:  # only the older generation reaches this position
            status = DELETED
        positions.append(ChunkDiffPosition(i, status, old, new))

    return LineageDiffResult(label, generation_old, generation_new, positions, len(chunks_old), len(chunks_new))
