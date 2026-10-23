#pragma once
// C++ counterpart of vault_session.py's VaultSession: ties StoragePipeline,
// LineageStore and Catalog together so no caller has to update all three.
#include <optional>
#include <string>
#include <vector>

#include "catalog.hpp"
#include "lineage_store.hpp"
#include "merge.hpp"
#include "pipeline.hpp"
#include "vault_lock.hpp"

namespace pfs_engine {

struct DeleteLabelResult {
    uint64_t manifests_freed = 0;
    uint64_t manifests_kept_shared = 0;
};

struct PruneResult {
    bool freed = false;
};

class VaultSession {
public:
    VaultSession(std::string storage_root, const Bytes32& kek);

    // First member, so it's constructed first and destroyed last: the vault
    // lock (vault_lock.hpp) is held for the session's whole lifetime.
    VaultLock lock_;

    // Stores a file as `label`: writes it, records a generation (not for a
    // byte-identical resave of the tip; always for a fork) and moves the
    // catalog pointer. Returns the manifest path.
    std::string commit_write(const std::string& label, const std::string& source_path,
                              const std::vector<std::string>& lateral_parent_labels = {},
                              std::optional<uint64_t> fork_from_generation = std::nullopt);

    // Removes a label's whole history and catalog entry. Refuses a
    // "protected" tip unless force. A manifest is deleted only once nothing
    // else references it.
    DeleteLabelResult delete_label(const std::string& label, bool force = false);

    // Frees one past generation, keeping the rest. Refuses the current tip,
    // and a "protected" generation unless force.
    PruneResult prune_generation(const std::string& label, uint64_t generation_index, bool force = false);

    // Grafts label_a and label_b into new_label (a's content then b's) with
    // both tips as parents, through the normal commit path (so it gets a
    // fingerprint). Refuses a "no_graft_source" source. Returns the manifest path.
    std::string graft(const std::string& label_a, const std::string& label_b, const std::string& new_label);

    // merge_branches() (merge.hpp) plus the catalog update on success.
    // Throws MutationConflictError on a conflict, committing nothing.
    MergeResult merge(const std::string& label, uint64_t generation_a, uint64_t generation_b);

    // Vacuums with the live-manifest set from this session's catalog and lineage.
    VacuumReport vacuum();

    // Verify and repair from mirrors.
    FsckReport fsck() { return pipeline.verify_and_repair(); }

    StoragePipeline pipeline;
    LineageStore lineage;
    Catalog catalog;

private:
    // References to a manifest from catalog tips and every lineage generation.
    uint64_t manifest_reference_count(const std::string& manifest_filename) const;

    // Every manifest filename referenced by a catalog tip or a generation.
    std::vector<std::string> live_manifest_filenames() const;
};

}  // namespace pfs_engine
