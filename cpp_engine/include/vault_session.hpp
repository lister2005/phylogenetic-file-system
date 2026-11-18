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

struct ShredResult {
    uint64_t versions_shredded = 0;
    uint64_t manifests_freed = 0;
    uint64_t manifests_kept_shared = 0;  // identical content still used elsewhere
    uint64_t chunks_destroyed = 0;
    uint64_t chunks_kept_shared = 0;     // still used by another live file or version
};

class VaultSession {
public:
    // Opens a vault. Several programs may have one vault open at once
    // (vault_lock.hpp): every change below runs under the vault's write lock
    // and first reloads whatever another program changed.
    VaultSession(std::string storage_root, const Bytes32& kek);

    // One change: holds the write lock, reloads others' changes first, and
    // afterwards records the files' new state. Re-entrant.
    class Change {
    public:
        explicit Change(VaultSession& session);
        ~Change();
        Change(const Change&) = delete;
        Change& operator=(const Change&) = delete;

    private:
        VaultSession& session_;
        VaultLock::WriteGuard guard_;
    };

    // Picks up changes other programs made (catalog, history, keys,
    // settings). Returns true if anything changed.
    bool refresh();

    // Renames a file; throws if old_label is missing or new_label exists.
    void rename_label(const std::string& old_label, const std::string& new_label);
    void set_tag(const std::string& label, const std::string& key, const TagValue& value);
    bool remove_tag(const std::string& label, const std::string& key);
    // Starts a new key epoch for new chunks; returns its number.
    uint32_t rotate_key();
    // 'spares all' on or off (StoragePipeline::set_mirror_all); returns how
    // many existing chunks got a spare.
    uint64_t set_mirror_all(bool enabled);

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

    // Securely erases a file's whole history (no generation) or one old
    // version, like vault_session.py's shred(): chunks used only by what is
    // shredded are overwritten in both containers and securely removed from
    // the index; recipes are overwritten before deletion; the catalog and
    // history files are rewritten with their old copies overwritten. A
    // shredded version stays in the history, pruned and tagged "shredded".
    // Refuses the current version and "protected" files unless force.
    // delete_label() and prune_generation() shred files tagged "secret".
    ShredResult shred(const std::string& label, std::optional<uint64_t> generation_index, bool force = false);

    // Grafts label_a and label_b into new_label (a's content then b's) with
    // both tips as parents, through the normal commit path (so it gets a
    // fingerprint). Refuses a "no_graft_source" source. Returns the manifest path.
    std::string graft(const std::string& label_a, const std::string& label_b, const std::string& new_label);

    // merge_branches() (merge.hpp) plus the catalog update on success.
    // Throws MutationConflictError on a conflict, committing nothing.
    MergeResult merge(const std::string& label, uint64_t generation_a, uint64_t generation_b,
                      const MergeResolutions& resolutions = {});

    // The generation two branches last had in common (for a line-by-line
    // merge done by the caller). Same checks as merge().
    uint64_t merge_base(const std::string& label, uint64_t generation_a, uint64_t generation_b);

    // Commits content the caller merged (commit_merged_file(), merge.hpp)
    // plus the catalog update.
    MergeResult commit_merged(const std::string& label, uint64_t generation_a, uint64_t generation_b,
                              const std::string& source_path);

    // Vacuums with the live-manifest set from this session's catalog and
    // lineage. Needs the vault to itself (VaultBusyError otherwise).
    VacuumReport vacuum();

    // Verify and repair from mirrors. Needs the vault to itself.
    FsckReport fsck();

    StoragePipeline pipeline;
    LineageStore lineage;
    Catalog catalog;

    // True if the tags mark a file as secret.
    static bool is_secret(const Tags& tags);

private:
    // References to a manifest from catalog tips and every lineage generation.
    uint64_t manifest_reference_count(const std::string& manifest_filename) const;

    // Every manifest filename referenced by a catalog tip or a generation.
    std::vector<std::string> live_manifest_filenames() const;

    // Size, modification time and inode of the files other programs may
    // change; -1 for a missing file.
    std::vector<long long> state_signature() const;
    // Reloads catalog, history, keys and settings if their files changed.
    bool reload_if_changed();
    std::vector<long long> seen_state_;

    // shred() after its checks.
    ShredResult shred_unchecked(const std::string& label, std::optional<uint64_t> generation_index);
};

}  // namespace pfs_engine
