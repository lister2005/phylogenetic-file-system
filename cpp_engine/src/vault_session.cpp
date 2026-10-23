#include "vault_session.hpp"

#include <cstdio>
#include <fstream>
#include <set>
#include <stdexcept>

namespace pfs_engine {

VaultSession::VaultSession(std::string storage_root, const Bytes32& kek)
    : lock_(storage_root), pipeline(storage_root, kek), lineage(storage_root, kek), catalog(storage_root, kek) {}

std::string VaultSession::commit_write(const std::string& label, const std::string& source_path,
                                        const std::vector<std::string>& lateral_parent_labels,
                                        std::optional<uint64_t> fork_from_generation) {
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

MergeResult VaultSession::merge(const std::string& label, uint64_t generation_a, uint64_t generation_b) {
    MergeResult result = merge_branches(pipeline, lineage, label, generation_a, generation_b);
    std::string manifest_filename = result.manifest_path.substr(result.manifest_path.find_last_of('/') + 1);
    catalog.set(label, manifest_filename);
    return result;
}

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

VacuumReport VaultSession::vacuum() { return pipeline.vacuum(live_manifest_filenames()); }

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

DeleteLabelResult VaultSession::delete_label(const std::string& label, bool force) {
    if (!catalog.contains(label)) throw std::out_of_range("No such label: '" + label + "'");

    auto tags = lineage.get_tags(label);
    auto protected_it = tags.find("protected");
    if (!force && protected_it != tags.end() && protected_it->second.is_bool && protected_it->second.bool_value) {
        throw std::domain_error("'" + label + "' is tagged 'protected' -- won't delete without an explicit override.");
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

PruneResult VaultSession::prune_generation(const std::string& label, uint64_t generation_index, bool force) {
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

std::string VaultSession::graft(const std::string& label_a, const std::string& label_b, const std::string& new_label) {
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

}  // namespace pfs_engine
