#include "vault_session.hpp"

#include <ctime>
#include <sys/stat.h>

#include <cstdio>
#include <fstream>
#include <set>
#include <stdexcept>

namespace pfs_engine {

// Opens a vault: takes its lock, then loads the pipeline, history and catalog.
VaultSession::VaultSession(std::string storage_root, const Bytes32& kek)
    : lock_(storage_root), pipeline(storage_root, kek), lineage(storage_root, kek), catalog(storage_root, kek) {
    // The members loaded without the write lock; load again under it, so a
    // half-written change from another program can't have been read.
    VaultLock::WriteGuard guard(lock_);
    catalog.reload();
    lineage.reload();
    pipeline.keyring().reload();
    pipeline.reload_settings();
    seen_state_ = state_signature();
}

// Takes the write lock and reloads others' changes before a change runs.
VaultSession::Change::Change(VaultSession& session) : session_(session), guard_(session.lock_) {
    session_.reload_if_changed();
}

// Records the files' state after the change, so this program's own change isn't mistaken for another's.
VaultSession::Change::~Change() { session_.seen_state_ = session_.state_signature(); }

// Returns size/time/inode of each file other programs may change.
std::vector<long long> VaultSession::state_signature() const {
    static const char* kFiles[] = {"catalog.pfsc", "lineage.pfsl", "keyring.pfsk", "settings.pfss"};
    std::vector<long long> sig;
    for (const char* name : kFiles) {
        struct stat st{};
        std::string path = pipeline.storage_root() + "/" + name;
        if (stat(path.c_str(), &st) != 0) {
            sig.insert(sig.end(), {-1, -1, -1});
            continue;
        }
        long long mtime_ns = static_cast<long long>(st.st_mtim.tv_sec) * 1000000000LL + st.st_mtim.tv_nsec;
        sig.insert(sig.end(), {static_cast<long long>(st.st_size), mtime_ns, static_cast<long long>(st.st_ino)});
    }
    return sig;
}

// Reloads everything if another program changed any of the shared files.
bool VaultSession::reload_if_changed() {
    std::vector<long long> now = state_signature();
    if (now == seen_state_) return false;
    catalog.reload();
    lineage.reload();
    pipeline.keyring().reload();
    pipeline.reload_settings();
    seen_state_ = now;
    return true;
}

// Picks up other programs' changes, under the write lock so none is half-written.
bool VaultSession::refresh() {
    VaultLock::WriteGuard guard(lock_);
    return reload_if_changed();
}

// Renames a file; content and history are unchanged.
void VaultSession::rename_label(const std::string& old_label, const std::string& new_label) {
    Change change(*this);
    if (!catalog.contains(old_label)) throw std::out_of_range("no such label: '" + old_label + "'");
    if (catalog.contains(new_label)) throw std::invalid_argument("label '" + new_label + "' already exists");
    auto manifest_filename = catalog.get(old_label);
    catalog.set(new_label, *manifest_filename);
    catalog.remove(old_label);
    lineage.rename_label(old_label, new_label);
}

// Sets a tag on a file's latest version.
void VaultSession::set_tag(const std::string& label, const std::string& key, const TagValue& value) {
    Change change(*this);
    lineage.set_tag(label, key, value);
}

// Removes a tag from a file's latest version; returns whether it was there.
bool VaultSession::remove_tag(const std::string& label, const std::string& key) {
    Change change(*this);
    return lineage.remove_tag(label, key);
}

// Starts a new key epoch for new chunks.
uint32_t VaultSession::rotate_key() {
    Change change(*this);
    return pipeline.keyring().rotate();
}

// The generation two branches last had in common.
uint64_t VaultSession::merge_base(const std::string& label, uint64_t generation_a, uint64_t generation_b) {
    return merge_nodes(lineage, label, generation_a, generation_b).ancestor.generation_index;
}

// Commits caller-merged content as the merge of two branches, and moves the catalog to it.
MergeResult VaultSession::commit_merged(const std::string& label, uint64_t generation_a, uint64_t generation_b,
                                        const std::string& source_path) {
    Change change(*this);
    if (!catalog.contains(label)) throw std::out_of_range("No such label: '" + label + "'");
    MergeResult result = commit_merged_file(pipeline, lineage, label, generation_a, generation_b, source_path);
    catalog.set(label, result.manifest_path.substr(result.manifest_path.find_last_of('/') + 1));
    return result;
}

// Turns 'spares all' on or off.
uint64_t VaultSession::set_mirror_all(bool enabled) {
    Change change(*this);
    return pipeline.set_mirror_all(enabled);
}

// Checks every chunk and repairs from spares; needs the vault to itself.
FsckReport VaultSession::fsck() {
    VaultLock::ExclusiveGuard sole(lock_);
    reload_if_changed();
    FsckReport report = pipeline.verify_and_repair();
    seen_state_ = state_signature();
    return report;
}

// Stores a file as the next version of label (or a branch), recording any extra parents.
std::string VaultSession::commit_write(const std::string& label, const std::string& source_path,
                                        const std::vector<std::string>& lateral_parent_labels,
                                        std::optional<uint64_t> fork_from_generation) {
    Change change(*this);
    std::vector<NodeUuid> lateral_parent_uuids;
    for (const auto& other_label : lateral_parent_labels) {
        auto tip = lineage.get_tip(other_label);
        if (!tip) throw std::invalid_argument("'" + other_label + "' has no recorded lineage tip to graft from.");
        lateral_parent_uuids.push_back(tip->node_uuid);
    }

    std::optional<LineageNode> fork_from_node;
    if (fork_from_generation) {
        fork_from_node = lineage.get_generation(label, *fork_from_generation);
        if (!fork_from_node) {
            throw std::invalid_argument("No generation " + std::to_string(*fork_from_generation) +
                                         " recorded for '" + label + "' to fork from.");
        }
        if (fork_from_node->pruned) {
            throw std::invalid_argument("Generation " + std::to_string(*fork_from_generation) + " of '" + label +
                                         "' was pruned -- its content is gone, so there's nothing to fork from.");
        }
    }

    WriteResult write_result = pipeline.secure_and_persist_file(source_path, label);
    std::string manifest_filename =
        write_result.manifest_path.substr(write_result.manifest_path.find_last_of('/') + 1);

    auto existing_history = lineage.get_history(label);
    bool should_record;
    if (fork_from_node) {
        should_record = true;  // a fork always records a generation
    } else if (existing_history.empty()) {
        should_record = true;
    } else {
        const LineageNode& tip = existing_history.back();
        should_record = !tip.has_manifest || tip.manifest_filename != manifest_filename;
    }

    if (should_record) {
        lineage.record_version(label, manifest_filename, write_result.new_chunks_written, write_result.total_blocks,
                                lateral_parent_uuids, fork_from_node ? &(*fork_from_node) : nullptr);
    }

    catalog.set(label, manifest_filename);
    return write_result.manifest_path;
}

// Merges two branches of a file and points the catalog at the result.
MergeResult VaultSession::merge(const std::string& label, uint64_t generation_a, uint64_t generation_b,
                                const MergeResolutions& resolutions) {
    Change change(*this);
    MergeResult result = merge_branches(pipeline, lineage, label, generation_a, generation_b, resolutions);
    std::string manifest_filename = result.manifest_path.substr(result.manifest_path.find_last_of('/') + 1);
    catalog.set(label, manifest_filename);
    return result;
}

// Returns every recipe filename still used by the catalog or the history.
std::vector<std::string> VaultSession::live_manifest_filenames() const {
    std::set<std::string> names;
    for (const auto& label : catalog.labels()) {
        auto m = catalog.get(label);
        if (m) names.insert(*m);
    }
    for (const auto& label : lineage.all_labels()) {
        for (const auto& node : lineage.get_history(label)) {
            if (node.has_manifest) names.insert(node.manifest_filename);
        }
    }
    return std::vector<std::string>(names.begin(), names.end());
}

VacuumReport VaultSession::vacuum() {
    VaultLock::ExclusiveGuard sole(lock_);
    reload_if_changed();
    VacuumReport report = pipeline.vacuum(live_manifest_filenames());
    seen_state_ = state_signature();
    return report;
}

// Counts how many files and versions use a recipe.
uint64_t VaultSession::manifest_reference_count(const std::string& manifest_filename) const {
    uint64_t count = 0;
    for (const auto& other_label : catalog.labels()) {
        if (catalog.get(other_label) == manifest_filename) count++;
    }
    for (const auto& other_label : lineage.all_labels()) {
        for (const auto& node : lineage.get_history(other_label)) {
            if (node.has_manifest && node.manifest_filename == manifest_filename) count++;
        }
    }
    return count;
}

// Deletes a file and its history, freeing a recipe only when nothing else uses it.
DeleteLabelResult VaultSession::delete_label(const std::string& label, bool force) {
    Change change(*this);
    if (!catalog.contains(label)) throw std::out_of_range("No such label: '" + label + "'");

    auto tags = lineage.get_tags(label);
    auto protected_it = tags.find("protected");
    if (!force && protected_it != tags.end() && protected_it->second.is_bool && protected_it->second.bool_value) {
        throw std::domain_error("'" + label + "' is tagged 'protected' -- won't delete without an explicit override.");
    }

    if (is_secret(tags)) {
        ShredResult shredded = shred_unchecked(label, std::nullopt);
        DeleteLabelResult result;
        result.manifests_freed = shredded.manifests_freed;
        result.manifests_kept_shared = shredded.manifests_kept_shared;
        return result;
    }

    std::set<std::string> manifest_filenames;
    auto current = catalog.get(label);
    if (current) manifest_filenames.insert(*current);
    for (const auto& node : lineage.get_history(label)) {
        if (node.has_manifest) manifest_filenames.insert(node.manifest_filename);
    }

    catalog.remove(label);
    lineage.delete_label(label);

    DeleteLabelResult result;
    for (const auto& manifest_filename : manifest_filenames) {
        if (manifest_reference_count(manifest_filename) > 0) {
            result.manifests_kept_shared++;
            continue;
        }
        std::string manifest_path = pipeline.storage_root() + "/" + manifest_filename;
        try {
            pipeline.delete_file(manifest_path);
            result.manifests_freed++;
        } catch (const std::exception&) {
            // Already gone (or pruned): nothing to free.
        }
    }
    return result;
}

// Frees one old generation's storage, keeping its history record.
PruneResult VaultSession::prune_generation(const std::string& label, uint64_t generation_index, bool force) {
    Change change(*this);
    if (!catalog.contains(label)) throw std::out_of_range("No such label: '" + label + "'");

    auto history = lineage.get_history(label);
    if (history.empty()) throw std::invalid_argument("'" + label + "' has no recorded lineage history to prune.");

    const LineageNode& tip = history.back();
    if (tip.generation_index == generation_index) {
        throw std::domain_error("Generation " + std::to_string(generation_index) + " is '" + label +
                                 "'s current tip -- can't prune the live version. Use delete_label instead.");
    }

    auto node = lineage.get_generation(label, generation_index);
    if (!node) throw std::invalid_argument("No generation " + std::to_string(generation_index) + " recorded for '" + label + "'.");
    if (node->pruned) throw std::domain_error("Generation " + std::to_string(generation_index) + " of '" + label + "' was already pruned.");

    auto protected_it = node->epigenetic_tags.find("protected");
    if (!force && protected_it != node->epigenetic_tags.end() && protected_it->second.is_bool && protected_it->second.bool_value) {
        throw std::domain_error("Generation " + std::to_string(generation_index) + " of '" + label +
                                 "' is tagged 'protected' -- won't prune without an explicit override.");
    }

    if (is_secret(node->epigenetic_tags) || is_secret(lineage.get_tags(label))) {
        PruneResult result;
        result.freed = shred_unchecked(label, generation_index).manifests_freed > 0;
        return result;
    }

    auto freed_manifest_filename = lineage.mark_pruned(label, generation_index);

    PruneResult result;
    if (freed_manifest_filename && manifest_reference_count(*freed_manifest_filename) == 0) {
        std::string manifest_path = pipeline.storage_root() + "/" + *freed_manifest_filename;
        try {
            pipeline.delete_file(manifest_path);
            result.freed = true;
        } catch (const std::exception&) {
        }
    }
    return result;
}

// Makes a new file combining two files, recorded as descended from both.
std::string VaultSession::graft(const std::string& label_a, const std::string& label_b, const std::string& new_label) {
    Change change(*this);
    if (label_a == label_b) throw std::invalid_argument("Can't graft a label onto itself.");
    if (!catalog.contains(label_a)) throw std::out_of_range("No such label: '" + label_a + "'");
    if (!catalog.contains(label_b)) throw std::out_of_range("No such label: '" + label_b + "'");
    for (const auto& source_label : {label_a, label_b}) {
        auto tags = lineage.get_tags(source_label);
        auto it = tags.find("no_graft_source");
        if (it != tags.end() && it->second.is_bool && it->second.bool_value) {
            throw std::domain_error("'" + source_label + "' is tagged 'no_graft_source' -- won't use it as a graft "
                                     "source. Remove the tag first if this graft is really intended.");
        }
    }

    std::string tmp_a = pipeline.storage_root() + "/__graft_a__.tmp";
    std::string tmp_b = pipeline.storage_root() + "/__graft_b__.tmp";
    std::string tmp_combined = pipeline.storage_root() + "/__graft_combined__.tmp";
    auto cleanup = [&]() {
        std::remove(tmp_a.c_str());
        std::remove(tmp_b.c_str());
        std::remove(tmp_combined.c_str());
    };

    try {
        std::string manifest_path_a = pipeline.storage_root() + "/" + *catalog.get(label_a);
        std::string manifest_path_b = pipeline.storage_root() + "/" + *catalog.get(label_b);
        pipeline.reconstruct(manifest_path_a, tmp_a);
        pipeline.reconstruct(manifest_path_b, tmp_b);

        {
            std::ofstream out(tmp_combined, std::ios::binary | std::ios::trunc);
            std::ifstream fa(tmp_a, std::ios::binary);
            std::ifstream fb(tmp_b, std::ios::binary);
            out << fa.rdbuf() << fb.rdbuf();
        }

        std::string result = commit_write(new_label, tmp_combined, {label_a, label_b});
        cleanup();
        return result;
    } catch (...) {
        cleanup();
        throw;
    }
}

// True if the tags mark a file as secret.
bool VaultSession::is_secret(const Tags& tags) {
    auto it = tags.find("secret");
    return it != tags.end() && it->second.is_bool && it->second.bool_value;
}

// Securely erases a file, or one old version of it, after checking the request.
ShredResult VaultSession::shred(const std::string& label, std::optional<uint64_t> generation_index, bool force) {
    Change change(*this);
    if (!catalog.contains(label)) throw std::out_of_range("No such label: '" + label + "'");
    auto is_protected = [](const Tags& tags) {
        auto it = tags.find("protected");
        return it != tags.end() && it->second.is_bool && it->second.bool_value;
    };
    if (!generation_index) {
        if (!force && is_protected(lineage.get_tags(label))) {
            throw std::domain_error("'" + label + "' is tagged 'protected' -- won't shred without an explicit override.");
        }
    } else {
        auto history = lineage.get_history(label);
        if (!history.empty() && history.back().generation_index == *generation_index) {
            throw std::domain_error("Generation " + std::to_string(*generation_index) + " is '" + label +
                                     "'s current version -- save a new version first, or shred the whole file.");
        }
        auto node = lineage.get_generation(label, *generation_index);
        if (!node) {
            throw std::invalid_argument("No generation " + std::to_string(*generation_index) + " recorded for '" +
                                        label + "'.");
        }
        if (node->pruned) {
            throw std::domain_error("Generation " + std::to_string(*generation_index) + " of '" + label +
                                     "' was already pruned or shredded.");
        }
        if (!force && is_protected(node->epigenetic_tags)) {
            throw std::domain_error("Generation " + std::to_string(*generation_index) + " of '" + label +
                                     "' is tagged 'protected' -- won't shred without an explicit override.");
        }
    }
    return shred_unchecked(label, generation_index);
}

// The work of shred(): removes the records, then overwrites what only they used.
ShredResult VaultSession::shred_unchecked(const std::string& label, std::optional<uint64_t> generation_index) {
    char when[32];
    std::time_t now = std::time(nullptr);
    std::strftime(when, sizeof(when), "%Y-%m-%d %H:%M:%S", std::localtime(&now));

    ShredResult result;
    std::set<std::string> candidates;
    if (!generation_index) {
        auto history = lineage.get_history(label);
        auto current = catalog.get(label);
        if (current) candidates.insert(*current);
        for (const auto& node : history) {
            if (node.has_manifest) candidates.insert(node.manifest_filename);
        }
        result.versions_shredded = history.empty() ? 1 : history.size();
        catalog.remove_scrubbed(label);
        lineage.delete_label(label, true);
    } else {
        auto manifest_filename = lineage.mark_shredded(label, *generation_index, when);
        if (manifest_filename && !manifest_filename->empty()) candidates.insert(*manifest_filename);
        result.versions_shredded = 1;
    }

    std::vector<std::string> doomed;
    for (const auto& m : candidates) {
        struct stat st{};
        std::string path = pipeline.storage_root() + "/" + m;
        if (manifest_reference_count(m) == 0 && stat(path.c_str(), &st) == 0) {
            doomed.push_back(m);
        } else {
            result.manifests_kept_shared++;
        }
    }

    // Chunks still used by any live recipe must survive.
    std::set<Bytes32> live_chunks;
    for (const auto& m : live_manifest_filenames()) {
        struct stat st{};
        std::string path = pipeline.storage_root() + "/" + m;
        if (stat(path.c_str(), &st) != 0) continue;
        for (const auto& h : pipeline.manifest_chunk_hashes(path)) live_chunks.insert(h);
    }
    for (const auto& m : doomed) {
        std::string path = pipeline.storage_root() + "/" + m;
        std::set<Bytes32> own;
        for (const auto& h : pipeline.manifest_chunk_hashes(path)) {
            if (!live_chunks.count(h)) own.insert(h);
        }
        ShredReport report = pipeline.shred_manifest(path, own);
        result.manifests_freed++;
        result.chunks_destroyed += report.chunks_destroyed;
        result.chunks_kept_shared += report.chunks_kept_shared;
    }
    return result;
}

}  // namespace pfs_engine
