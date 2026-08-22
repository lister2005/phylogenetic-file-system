"""
Real lineage diff: computes what actually mutated between two
GENERATIONS of the SAME label's real edit history (lineage.py /
cpp_engine's LineageStore) -- e.g. a node and its parent, or any two
generations a Tree-view user picks.

This is deliberately NOT the same thing as pfs_gui.py's existing
_show_diff_between, which compares two DIFFERENT LABELS' clade
similarity fingerprints (a Jaccard-style % + shared/unique trait counts
via PhylogeneticAnalyzer) -- that's clade-clustering machinery
(unrelated-file similarity, see PORTFOLIO.md SS2.3), not lineage. This
project has a hard-won rule against conflating the two (PORTFOLIO.md
SS3.1): a clade comparison and a lineage diff must stay separate code
paths. This module is the lineage one.

Core primitive: a chunk-POSITION diff between two generations' ordered
chunk-hash lists. Every manifest is already a flat array of block
hashes (both engines' pfs_engine_adapter.get_chunk_hashes exposes it
identically) -- no separate delta storage is needed to compute this.
Same technique merge_branches() uses for its 3-way diff against a
common ancestor (cpp_engine/src/merge.cpp, vault_session.py's
merge_branches), just a simpler 2-way version: no common ancestor, no
conflict detection, no merge -- just "what differs between exactly
these two generations."
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
    status: str  # one of UNCHANGED / NEW / CHANGED / DELETED
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
    """Real chunk-position diff between two generations of `label`'s own
    lineage. `generation_old` is conventionally the earlier/ancestor
    generation (e.g. a node's parent) and `generation_new` the later
    one -- the math itself is symmetric, but the NEW/DELETED labeling
    ("grew past old's length" / "old had a chunk old doesn't reach")
    assumes this direction, so callers picking two arbitrary tree nodes
    should order them by generation_index before calling this (which
    is what pfs_gui.py's caller does).

    `adapter` is a PythonEngineAdapter or CppEngineAdapter (or anything
    exposing the same .get_chunk_hashes(label, generation_index)
    method) -- this function is engine-agnostic by construction.
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
        elif new is not None:  # old is None -- position only reached by the newer generation
            status = NEW
        else:  # new is None, old is not -- position only reached by the older generation
            status = DELETED
        positions.append(ChunkDiffPosition(i, status, old, new))

    return LineageDiffResult(label, generation_old, generation_new, positions, len(chunks_old), len(chunks_new))
