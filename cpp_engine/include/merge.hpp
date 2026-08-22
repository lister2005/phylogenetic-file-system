#pragma once
// Ports vault_session.py's merge_branches() -- the design doc's
// Mutation Conflict resolution. Deliberately a free function taking
// BOTH a StoragePipeline and a LineageStore by reference, rather than
// a method on either: merging two branches of one label is inherently
// a cross-cutting operation over storage (reading already-committed
// chunks, persisting the merge result) AND lineage (finding the common
// ancestor, recording the merge as a new generation) -- it doesn't
// belong to just one of them, same as Python's version lives in
// vault_session.py (the orchestration layer over both pipeline.py and
// lineage.py), not inside either module itself.
//
// Algorithm (unchanged from Python, see vault_session.py's own
// extensive docstring for the full reasoning): find the lowest common
// ancestor of two divergent generations of the same label by walking
// PRIMARY parent pointers from both; then a chunk-POSITION 3-way diff
// against the ancestor, using each generation's own already-stored
// ordered chunk-hash list (no separate delta storage needed) --
// a position changed by only one branch (or identically by both)
// merges automatically, a position changed DIFFERENTLY by both raises
// MutationConflictError and commits nothing. On success, the merge
// result's primary parent is generation_a, with generation_b recorded
// as a lateral parent -- the same mechanism a graft uses, just within
// one label instead of across two.
#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

#include "lineage_store.hpp"
#include "pipeline.hpp"

namespace pfs_engine {

// The design doc's EvolutionaryDivergenceException. Lists the
// conflicting chunk positions (0-indexed, matching each generation's
// own manifest block order) so the caller can resolve manually --
// mirrors MutationConflictError in vault_session.py exactly, no
// automated resolution is ever attempted.
class MutationConflictError : public std::runtime_error {
public:
    explicit MutationConflictError(std::vector<uint64_t> positions)
        : std::runtime_error(build_message(positions)), conflicting_positions(std::move(positions)) {}

    std::vector<uint64_t> conflicting_positions;

private:
    static std::string build_message(const std::vector<uint64_t>& positions) {
        std::string msg = std::to_string(positions.size()) +
                           " chunk position(s) were changed differently on both branches since their "
                           "common ancestor: ";
        for (size_t i = 0; i < positions.size() && i < 10; i++) {
            if (i > 0) msg += ", ";
            msg += std::to_string(positions[i]);
        }
        if (positions.size() > 10) msg += "...";
        return msg;
    }
};

struct MergeResult {
    std::string manifest_path;
    uint64_t total_blocks = 0;
    uint64_t new_chunks_written = 0;
    uint64_t duplicate_chunks_found = 0;
};

// Throws std::invalid_argument for all the "this request doesn't make
// sense" cases (unknown generation, pruned generation, same generation
// twice, no common ancestor, one generation is a direct ancestor of
// the other -- i.e. linear history, not a real divergent branch), and
// MutationConflictError specifically for a genuine, unresolvable
// content conflict.
MergeResult merge_branches(StoragePipeline& pipeline, LineageStore& lineage,
                            const std::string& label, uint64_t generation_a, uint64_t generation_b);

}  // namespace pfs_engine
