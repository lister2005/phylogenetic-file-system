#pragma once
// Port of vault_session.py's merge_branches(): a free function, since it
// spans storage and lineage.
//
// Finds the lowest common ancestor along primary parents, then a 3-way
// diff of chunk positions against it: changed by one branch (or the same
// way by both) merges; changed differently by both is a conflict. A
// resolution ('a' or 'b' for a position) settles a conflict by taking that
// branch's chunk, or its end if that branch ends there; an unresolved
// conflict throws MutationConflictError and commits nothing. The result's
// primary parent is generation_a, with generation_b as a lateral parent.
#include <cstdint>
#include <map>
#include <stdexcept>
#include <string>
#include <vector>

#include "lineage_store.hpp"
#include "pipeline.hpp"

namespace pfs_engine {

// Conflicting chunk positions (0-indexed manifest block order); nothing was committed.
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

// position -> 'a' or 'b'
using MergeResolutions = std::map<uint64_t, char>;

// Throws std::invalid_argument for invalid requests (unknown, pruned or
// identical generations, no common ancestor, linear history, a resolution
// other than 'a'/'b') and MutationConflictError for an unresolved conflict.
MergeResult merge_branches(StoragePipeline& pipeline, LineageStore& lineage,
                            const std::string& label, uint64_t generation_a, uint64_t generation_b,
                            const MergeResolutions& resolutions = {});

// The two branch tips and their common ancestor, after the checks
// merge_branches() makes (same std::invalid_argument errors).
struct MergeNodes {
    LineageNode node_a;
    LineageNode node_b;
    LineageNode ancestor;
};
MergeNodes merge_nodes(const LineageStore& lineage, const std::string& label, uint64_t generation_a,
                       uint64_t generation_b);

// Commits source_path (content merged by the caller, e.g. line by line) as
// the merge of two branches: generation_a is the primary parent and
// generation_b a lateral parent, as with merge_branches().
MergeResult commit_merged_file(StoragePipeline& pipeline, LineageStore& lineage, const std::string& label,
                               uint64_t generation_a, uint64_t generation_b, const std::string& source_path);

}  // namespace pfs_engine
