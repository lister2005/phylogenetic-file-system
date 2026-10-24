#include "c_api.h"

#include <cstring>
#include <string>

#include "manifest.hpp"
#include "phylo.hpp"
#include "vault_session.hpp"

#include <algorithm>
#include <filesystem>
#include <map>

using namespace pfs_engine;

struct pfs_session {
    VaultSession session;
    pfs_session(std::string storage_root, const Bytes32& kek) : session(std::move(storage_root), kek) {}
};

namespace {
thread_local std::string g_last_error;

void set_error(const std::exception& e) { g_last_error = e.what(); }
void set_error(const std::string& msg) { g_last_error = msg; }

void copy_out(const std::string& value, char* out_buf, size_t out_buf_len) {
    if (out_buf && out_buf_len > 0) {
        strncpy(out_buf, value.c_str(), out_buf_len - 1);
        out_buf[out_buf_len - 1] = '\0';
    }
}

pfs_generation_info_t to_c_info(const LineageNode& node) {
    pfs_generation_info_t info{};
    info.generation_index = node.generation_index;
    info.birth_timestamp = node.birth_timestamp;
    info.new_chunks = node.new_chunks;
    info.total_chunks = node.total_chunks;
    info.pruned = node.pruned ? 1 : 0;
    info.has_parent = node.has_parent ? 1 : 0;
    std::string uuid_hex = node_uuid_to_hex(node.node_uuid);
    strncpy(info.node_uuid_hex, uuid_hex.c_str(), sizeof(info.node_uuid_hex) - 1);
    if (node.has_parent) {
        std::string parent_hex = node_uuid_to_hex(node.parent_uuid);
        strncpy(info.parent_uuid_hex, parent_hex.c_str(), sizeof(info.parent_uuid_hex) - 1);
    }
    info.lateral_parent_count = node.lateral_parent_uuids.size();
    return info;
}
}  // namespace

extern "C" {

pfs_session_t* pfs_open(const char* storage_root, const uint8_t* kek32) {
    try {
        Bytes32 kek{};
        memcpy(kek.data(), kek32, 32);
        return reinterpret_cast<pfs_session_t*>(new pfs_session(storage_root, kek));
    } catch (const std::exception& e) {
        set_error(e);
        return nullptr;
    }
}

void pfs_close(pfs_session_t* session) { delete reinterpret_cast<pfs_session*>(session); }

int pfs_commit_write(pfs_session_t* session_h, const char* label, const char* source_path,
                      char* out_manifest_filename, size_t out_buf_len) {
    auto* s = reinterpret_cast<pfs_session*>(session_h);
    try {
        std::string manifest_path = s->session.commit_write(label, source_path);
        std::string manifest_filename = manifest_path.substr(manifest_path.find_last_of('/') + 1);
        if (out_manifest_filename && out_buf_len > 0) {
            strncpy(out_manifest_filename, manifest_filename.c_str(), out_buf_len - 1);
            out_manifest_filename[out_buf_len - 1] = '\0';
        }
        return 0;
    } catch (const std::exception& e) {
        set_error(e);
        return -1;
    }
}

int pfs_reconstruct_label(pfs_session_t* session_h, const char* label, const char* output_path) {
    auto* s = reinterpret_cast<pfs_session*>(session_h);
    try {
        auto manifest_filename = s->session.catalog.get(label);
        if (!manifest_filename) {
            set_error(std::string("no such label: '") + label + "'");
            return -1;
        }
        std::string manifest_path = s->session.pipeline.storage_root() + "/" + *manifest_filename;
        s->session.pipeline.reconstruct(manifest_path, output_path);
        return 0;
    } catch (const std::exception& e) {
        set_error(e);
        return -1;
    }
}

int pfs_delete_label(pfs_session_t* session_h, const char* label) {
    auto* s = reinterpret_cast<pfs_session*>(session_h);
    try {
        s->session.delete_label(label);
        return 0;
    } catch (const std::exception& e) {
        set_error(e);
        return -1;
    }
}

int pfs_list_labels(pfs_session_t* session_h, pfs_label_callback cb, void* user_data) {
    auto* s = reinterpret_cast<pfs_session*>(session_h);
    try {
        auto labels = s->session.catalog.labels();
        for (const auto& label : labels) cb(label.c_str(), user_data);
        return static_cast<int>(labels.size());
    } catch (const std::exception& e) {
        set_error(e);
        return -1;
    }
}

int pfs_get_history(pfs_session_t* session_h, const char* label, pfs_generation_callback cb, void* user_data) {
    auto* s = reinterpret_cast<pfs_session*>(session_h);
    try {
        auto history = s->session.lineage.get_history(label);
        for (const auto& node : history) {
            pfs_generation_info_t info = to_c_info(node);
            cb(&info, user_data);
        }
        return static_cast<int>(history.size());
    } catch (const std::exception& e) {
        set_error(e);
        return -1;
    }
}

int pfs_get_manifest_info(pfs_session_t* session_h, const char* label, pfs_manifest_info_t* out_info) {
    auto* s = reinterpret_cast<pfs_session*>(session_h);
    try {
        auto manifest_filename = s->session.catalog.get(label);
        if (!manifest_filename) {
            set_error(std::string("no such label: '") + label + "'");
            return -1;
        }
        std::string manifest_path = s->session.pipeline.storage_root() + "/" + *manifest_filename;
        Manifest m = read_manifest_file(manifest_path, *manifest_filename, s->session.pipeline.kek());
        out_info->total_blocks = m.metadata().total_blocks;
        out_info->original_size = m.metadata().original_size;
        out_info->new_chunks_written = m.metadata().new_chunks_written;
        out_info->duplicate_chunks_found = m.metadata().duplicate_chunks_found;
        out_info->has_similarity_fingerprint = m.metadata().similarity_fingerprint ? 1 : 0;
        out_info->similarity_fingerprint_count =
            m.metadata().similarity_fingerprint ? m.metadata().similarity_fingerprint->size() : 0;
        out_info->phenotype_mask = m.metadata().phenotype_mask;
        strncpy(out_info->phenotype_name, m.metadata().phenotype_name.c_str(), sizeof(out_info->phenotype_name) - 1);
        out_info->phenotype_name[sizeof(out_info->phenotype_name) - 1] = '\0';
        strncpy(out_info->manifest_filename, manifest_filename->c_str(), sizeof(out_info->manifest_filename) - 1);
        out_info->manifest_filename[sizeof(out_info->manifest_filename) - 1] = '\0';
        return 0;
    } catch (const std::exception& e) {
        set_error(e);
        return -1;
    }
}

int pfs_get_manifest_fingerprint(pfs_session_t* session_h, const char* label,
                                  pfs_raw_hash_callback cb, void* user_data) {
    auto* s = reinterpret_cast<pfs_session*>(session_h);
    try {
        auto manifest_filename = s->session.catalog.get(label);
        if (!manifest_filename) {
            set_error(std::string("no such label: '") + label + "'");
            return -1;
        }
        std::string manifest_path = s->session.pipeline.storage_root() + "/" + *manifest_filename;
        Manifest m = read_manifest_file(manifest_path, *manifest_filename, s->session.pipeline.kek());
        if (!m.metadata().similarity_fingerprint) return 0;
        for (const auto& hash : *m.metadata().similarity_fingerprint) cb(hash.data(), user_data);
        return static_cast<int>(m.metadata().similarity_fingerprint->size());
    } catch (const std::exception& e) {
        set_error(e);
        return -1;
    }
}

int pfs_find_node_by_uuid(pfs_session_t* session_h, const char* uuid_hex,
                           char* out_label_buf, size_t out_label_buf_len,
                           pfs_generation_info_t* out_info) {
    auto* s = reinterpret_cast<pfs_session*>(session_h);
    try {
        NodeUuid id = node_uuid_from_hex(uuid_hex);
        auto node = s->session.lineage.find_node_by_uuid(id);
        if (!node) {
            set_error("no node with that uuid");
            return -1;
        }
        copy_out(node->label, out_label_buf, out_label_buf_len);
        if (out_info) *out_info = to_c_info(*node);
        return 0;
    } catch (const std::exception& e) {
        set_error(e);
        return -1;
    }
}

int pfs_get_generation_chunk_hashes(pfs_session_t* session_h, const char* label, uint64_t generation_index,
                                     pfs_raw_hash_callback cb, void* user_data) {
    auto* s = reinterpret_cast<pfs_session*>(session_h);
    try {
        auto node = s->session.lineage.get_generation(label, generation_index);
        if (!node) {
            set_error("no generation " + std::to_string(generation_index) + " recorded for '" +
                       std::string(label) + "'");
            return -1;
        }
        if (!node->has_manifest) {
            set_error("generation " + std::to_string(generation_index) + " of '" + std::string(label) +
                       "' is pruned -- its content is no longer available");
            return -1;
        }
        std::string manifest_path = s->session.pipeline.storage_root() + "/" + node->manifest_filename;
        Manifest m = read_manifest_file(manifest_path, node->manifest_filename, s->session.pipeline.kek());
        uint64_t total = m.metadata().total_blocks;
        for (uint64_t i = 0; i < total; i++) {
            auto hash = m.lookup(i);
            if (!hash) {
                set_error("block " + std::to_string(i) + " missing from generation " +
                           std::to_string(generation_index) + "'s manifest");
                return -1;
            }
            cb(hash->data(), user_data);
        }
        return static_cast<int>(total);
    } catch (const std::exception& e) {
        set_error(e);
        return -1;
    }
}

int pfs_fork_write(pfs_session_t* session_h, const char* label, const char* source_path,
                    uint64_t fork_from_generation, char* out_manifest_filename, size_t out_buf_len) {
    auto* s = reinterpret_cast<pfs_session*>(session_h);
    try {
        std::string manifest_path = s->session.commit_write(label, source_path, {}, fork_from_generation);
        copy_out(manifest_path.substr(manifest_path.find_last_of('/') + 1), out_manifest_filename, out_buf_len);
        return 0;
    } catch (const std::exception& e) {
        set_error(e);
        return -1;
    }
}

int pfs_graft(pfs_session_t* session_h, const char* label_a, const char* label_b, const char* new_label,
              char* out_manifest_filename, size_t out_buf_len) {
    auto* s = reinterpret_cast<pfs_session*>(session_h);
    try {
        std::string manifest_path = s->session.graft(label_a, label_b, new_label);
        copy_out(manifest_path.substr(manifest_path.find_last_of('/') + 1), out_manifest_filename, out_buf_len);
        return 0;
    } catch (const std::exception& e) {
        set_error(e);
        return -1;
    }
}

int pfs_commit_write_lateral(pfs_session_t* session_h, const char* label, const char* source_path,
                              const char* lateral_parent_label,
                              char* out_manifest_filename, size_t out_buf_len) {
    auto* s = reinterpret_cast<pfs_session*>(session_h);
    try {
        std::string manifest_path = s->session.commit_write(label, source_path, {lateral_parent_label});
        copy_out(manifest_path.substr(manifest_path.find_last_of('/') + 1), out_manifest_filename, out_buf_len);
        return 0;
    } catch (const std::exception& e) {
        set_error(e);
        return -1;
    }
}

int pfs_merge_branches(pfs_session_t* session_h, const char* label, uint64_t generation_a, uint64_t generation_b,
                       char* out_manifest_filename, size_t out_buf_len) {
    auto* s = reinterpret_cast<pfs_session*>(session_h);
    try {
        MergeResult result = s->session.merge(label, generation_a, generation_b);
        copy_out(result.manifest_path.substr(result.manifest_path.find_last_of('/') + 1), out_manifest_filename, out_buf_len);
        return 0;
    } catch (const std::exception& e) {
        set_error(e);  // what() lists the conflicting positions
        return -1;
    }
}

int pfs_merge_branches_resolved(pfs_session_t* session_h, const char* label, uint64_t generation_a,
                                uint64_t generation_b, const uint64_t* positions, const char* sides,
                                size_t resolution_count, char* out_manifest_filename, size_t out_buf_len,
                                uint64_t* out_conflicts, size_t conflicts_cap, size_t* out_conflict_count) {
    auto* s = reinterpret_cast<pfs_session*>(session_h);
    if (out_conflict_count) *out_conflict_count = 0;
    try {
        MergeResolutions resolutions;
        for (size_t i = 0; i < resolution_count; i++) resolutions[positions[i]] = sides[i];
        MergeResult result = s->session.merge(label, generation_a, generation_b, resolutions);
        copy_out(result.manifest_path.substr(result.manifest_path.find_last_of('/') + 1), out_manifest_filename, out_buf_len);
        return 0;
    } catch (const MutationConflictError& e) {
        set_error(e);
        const auto& found = e.conflicting_positions;
        for (size_t i = 0; i < found.size() && i < conflicts_cap; i++) out_conflicts[i] = found[i];
        if (out_conflict_count) *out_conflict_count = found.size();
        return 1;
    } catch (const std::exception& e) {
        set_error(e);
        return -1;
    }
}

int pfs_checkout(pfs_session_t* session_h, const char* label, uint64_t generation_index, const char* output_path) {
    auto* s = reinterpret_cast<pfs_session*>(session_h);
    try {
        auto node = s->session.lineage.get_generation(label, generation_index);
        if (!node) {
            set_error("no generation " + std::to_string(generation_index) + " recorded for '" + label + "'");
            return -1;
        }
        if (!node->has_manifest) {
            set_error("generation " + std::to_string(generation_index) + " of '" + label +
                       "' was pruned -- its content is gone");
            return -1;
        }
        std::string manifest_path = s->session.pipeline.storage_root() + "/" + node->manifest_filename;
        s->session.pipeline.reconstruct(manifest_path, output_path);
        return 0;
    } catch (const std::exception& e) {
        set_error(e);
        return -1;
    }
}

int pfs_rename_label(pfs_session_t* session_h, const char* old_label, const char* new_label) {
    auto* s = reinterpret_cast<pfs_session*>(session_h);
    try {
        if (!s->session.catalog.contains(old_label)) {
            set_error(std::string("no such label: '") + old_label + "'");
            return -1;
        }
        if (s->session.catalog.contains(new_label)) {
            set_error(std::string("label '") + new_label + "' already exists");
            return -1;
        }
        auto manifest_filename = s->session.catalog.get(old_label);
        s->session.catalog.set(new_label, *manifest_filename);
        s->session.catalog.remove(old_label);
        s->session.lineage.rename_label(old_label, new_label);
        return 0;
    } catch (const std::exception& e) {
        set_error(e);
        return -1;
    }
}

int pfs_delete_label_ex(pfs_session_t* session_h, const char* label, int force,
                         uint64_t* out_freed, uint64_t* out_kept_shared) {
    auto* s = reinterpret_cast<pfs_session*>(session_h);
    try {
        DeleteLabelResult r = s->session.delete_label(label, force != 0);
        if (out_freed) *out_freed = r.manifests_freed;
        if (out_kept_shared) *out_kept_shared = r.manifests_kept_shared;
        return 0;
    } catch (const std::exception& e) {
        set_error(e);
        return -1;
    }
}

int pfs_prune_generation(pfs_session_t* session_h, const char* label, uint64_t generation_index, int force,
                          int* out_freed) {
    auto* s = reinterpret_cast<pfs_session*>(session_h);
    try {
        PruneResult r = s->session.prune_generation(label, generation_index, force != 0);
        if (out_freed) *out_freed = r.freed ? 1 : 0;
        return 0;
    } catch (const std::exception& e) {
        set_error(e);
        return -1;
    }
}

int pfs_vacuum(pfs_session_t* session_h, pfs_vacuum_report_t* out_report) {
    auto* s = reinterpret_cast<pfs_session*>(session_h);
    try {
        VacuumReport r = s->session.vacuum();
        if (out_report) {
            out_report->old_size = r.old_size;
            out_report->new_size = r.new_size;
            out_report->bytes_reclaimed = r.bytes_reclaimed;
            out_report->live_chunks = r.live_chunks;
            out_report->chunks_corrected = r.chunks_corrected;
            out_report->orphaned_manifests_removed = r.orphaned_manifests_removed;
            out_report->orphaned_tmp_files_removed = r.orphaned_tmp_files_removed;
            out_report->mirror_old_size = r.mirror_old_size;
            out_report->mirror_new_size = r.mirror_new_size;
            out_report->mirror_bytes_reclaimed = r.mirror_bytes_reclaimed;
            out_report->live_mirrors = r.live_mirrors;
        }
        return 0;
    } catch (const std::exception& e) {
        set_error(e);
        return -1;
    }
}

int pfs_fsck(pfs_session_t* session_h, pfs_fsck_report_t* out_report, pfs_hash_callback cb, void* user_data) {
    auto* s = reinterpret_cast<pfs_session*>(session_h);
    try {
        FsckReport r = s->session.fsck();
        if (out_report) {
            out_report->scanned = r.scanned;
            out_report->healthy = r.healthy;
            out_report->healed = r.healed;
        }
        if (cb) {
            for (const auto& hex : r.unrecoverable) cb(hex.c_str(), user_data);
        }
        return 0;
    } catch (const std::exception& e) {
        set_error(e);
        return -1;
    }
}

int pfs_set_tag_bool(pfs_session_t* session_h, const char* label, const char* key, int value) {
    auto* s = reinterpret_cast<pfs_session*>(session_h);
    try {
        s->session.lineage.set_tag(label, key, TagValue::from_bool(value != 0));
        return 0;
    } catch (const std::exception& e) {
        set_error(e);
        return -1;
    }
}

int pfs_set_tag_string(pfs_session_t* session_h, const char* label, const char* key, const char* value) {
    auto* s = reinterpret_cast<pfs_session*>(session_h);
    try {
        s->session.lineage.set_tag(label, key, TagValue::from_string(value));
        return 0;
    } catch (const std::exception& e) {
        set_error(e);
        return -1;
    }
}

int pfs_remove_tag(pfs_session_t* session_h, const char* label, const char* key) {
    auto* s = reinterpret_cast<pfs_session*>(session_h);
    try {
        return s->session.lineage.remove_tag(label, key) ? 1 : 0;
    } catch (const std::exception& e) {
        set_error(e);
        return -1;
    }
}

int pfs_get_tags(pfs_session_t* session_h, const char* label, pfs_tag_callback cb, void* user_data) {
    auto* s = reinterpret_cast<pfs_session*>(session_h);
    try {
        auto tags = s->session.lineage.get_tags(label);
        for (const auto& kv : tags) {
            const auto& key = kv.first;
            const auto& value = kv.second;
            cb(key.c_str(), value.is_bool ? 1 : 0, value.bool_value ? 1 : 0, value.string_value.c_str(), user_data);
        }
        return static_cast<int>(tags.size());
    } catch (const std::exception& e) {
        set_error(e);
        return -1;
    }
}

int pfs_get_node_tags_by_uuid(pfs_session_t* session_h, const char* uuid_hex, pfs_tag_callback cb, void* user_data) {
    auto* s = reinterpret_cast<pfs_session*>(session_h);
    try {
        NodeUuid id = node_uuid_from_hex(uuid_hex);
        auto node = s->session.lineage.find_node_by_uuid(id);
        if (!node) {
            set_error("no node with that uuid");
            return -1;
        }
        for (const auto& kv : node->epigenetic_tags) {
            const auto& key = kv.first;
            const auto& value = kv.second;
            cb(key.c_str(), value.is_bool ? 1 : 0, value.bool_value ? 1 : 0, value.string_value.c_str(), user_data);
        }
        return static_cast<int>(node->epigenetic_tags.size());
    } catch (const std::exception& e) {
        set_error(e);
        return -1;
    }
}

int pfs_get_lateral_parents_by_uuid(pfs_session_t* session_h, const char* uuid_hex,
                                     pfs_uuid_callback cb, void* user_data) {
    auto* s = reinterpret_cast<pfs_session*>(session_h);
    try {
        NodeUuid id = node_uuid_from_hex(uuid_hex);
        auto node = s->session.lineage.find_node_by_uuid(id);
        if (!node) {
            set_error("no node with that uuid");
            return -1;
        }
        for (const auto& lateral : node->lateral_parent_uuids) {
            std::string hex = node_uuid_to_hex(lateral);
            cb(hex.c_str(), user_data);
        }
        return static_cast<int>(node->lateral_parent_uuids.size());
    } catch (const std::exception& e) {
        set_error(e);
        return -1;
    }
}

int pfs_get_heads(pfs_session_t* session_h, const char* label, pfs_generation_callback cb, void* user_data) {
    auto* s = reinterpret_cast<pfs_session*>(session_h);
    try {
        auto heads = s->session.lineage.get_heads(label);
        for (const auto& node : heads) {
            pfs_generation_info_t info = to_c_info(node);
            cb(&info, user_data);
        }
        return static_cast<int>(heads.size());
    } catch (const std::exception& e) {
        set_error(e);
        return -1;
    }
}

uint32_t pfs_rotate_key(pfs_session_t* session_h) {
    auto* s = reinterpret_cast<pfs_session*>(session_h);
    try {
        return s->session.pipeline.keyring().rotate();
    } catch (const std::exception& e) {
        set_error(e);
        return UINT32_MAX;
    }
}

namespace {
std::map<std::string, TraitSet> gather_named_traits(pfs_session* s) {
    std::map<std::string, TraitSet> named_traits;
    for (const auto& label : s->session.catalog.labels()) {
        auto manifest_filename = s->session.catalog.get(label);
        if (!manifest_filename) continue;
        std::string manifest_path = s->session.pipeline.storage_root() + "/" + *manifest_filename;
        Manifest m = read_manifest_file(manifest_path, *manifest_filename, s->session.pipeline.kek());
        if (m.metadata().similarity_fingerprint) {
            const auto& fp = *m.metadata().similarity_fingerprint;
            named_traits[label] = TraitSet(fp.begin(), fp.end());
        }
    }
    return named_traits;
}
}  // namespace

int pfs_build_tree(pfs_session_t* session_h, const char* algorithm, pfs_text_callback cb, void* user_data) {
    auto* s = reinterpret_cast<pfs_session*>(session_h);
    try {
        auto named_traits = gather_named_traits(s);
        if (named_traits.size() < 2) {
            set_error("need at least 2 files with a stored fingerprint to build a tree");
            return -1;
        }
        std::string algo(algorithm ? algorithm : "upgma");
        PhyloTree nodes = (algo == "nj") ? build_tree_nj_from_traits(named_traits)
                                          : build_tree_upgma_from_traits(named_traits);
        std::string rendering = visualize_tree(nodes);
        cb(rendering.c_str(), user_data);
        return static_cast<int>(named_traits.size());
    } catch (const std::exception& e) {
        set_error(e);
        return -1;
    }
}

int pfs_similar(pfs_session_t* session_h, const char* label, pfs_similar_callback cb, void* user_data) {
    auto* s = reinterpret_cast<pfs_session*>(session_h);
    try {
        auto named_traits = gather_named_traits(s);
        auto it = named_traits.find(label);
        if (it == named_traits.end()) {
            set_error(std::string("'") + label + "' has no stored fingerprint");
            return -1;
        }
        TraitSet target = it->second;
        named_traits.erase(it);

        std::vector<std::pair<std::string, double>> ranked;
        for (const auto& kv : named_traits) ranked.emplace_back(kv.first, jaccard_distance(target, kv.second));
        std::sort(ranked.begin(), ranked.end(), [](const auto& a, const auto& b) { return a.second < b.second; });
        for (const auto& pr : ranked) cb(pr.first.c_str(), pr.second, user_data);
        return static_cast<int>(ranked.size());
    } catch (const std::exception& e) {
        set_error(e);
        return -1;
    }
}

int pfs_compute_clades(pfs_session_t* session_h, const char* label, double threshold,
                        pfs_text_callback cb, void* user_data,
                        char* out_representative, size_t out_buf_len) {
    auto* s = reinterpret_cast<pfs_session*>(session_h);
    try {
        auto named_traits = gather_named_traits(s);
        if (named_traits.find(label) == named_traits.end()) {
            set_error(std::string("'") + label + "' has no stored fingerprint");
            return -1;
        }
        double thr = threshold > 0.0 ? threshold : kDefaultCladeThreshold;
        auto clades = compute_clades(named_traits, thr);
        for (const auto& kv : clades) {
            const auto& members = kv.second;
            if (std::find(members.begin(), members.end(), std::string(label)) == members.end()) continue;
            if (out_representative && out_buf_len > 0) {
                std::strncpy(out_representative, kv.first.c_str(), out_buf_len - 1);
                out_representative[out_buf_len - 1] = '\0';
            }
            for (const auto& m : members) cb(m.c_str(), user_data);
            return static_cast<int>(members.size());
        }
        set_error("internal error: label not found in any computed clade");
        return -1;
    } catch (const std::exception& e) {
        set_error(e);
        return -1;
    }
}

int pfs_get_unreliable_fingerprint_labels(pfs_session_t* session_h, pfs_label_count_callback cb, void* user_data) {
    auto* s = reinterpret_cast<pfs_session*>(session_h);
    try {
        auto named_traits = gather_named_traits(s);
        int count = 0;
        for (const auto& kv : named_traits) {
            if (!trait_set_is_reliable(kv.second)) {
                cb(kv.first.c_str(), static_cast<uint64_t>(kv.second.size()), user_data);
                count++;
            }
        }
        return count;
    } catch (const std::exception& e) {
        set_error(e);
        return -1;
    }
}

int pfs_debug_get_block_hash(pfs_session_t* session_h, const char* label, uint64_t block_index,
                              uint8_t* out_hash32) {
    auto* s = reinterpret_cast<pfs_session*>(session_h);
    try {
        auto manifest_filename = s->session.catalog.get(label);
        if (!manifest_filename) {
            set_error(std::string("no such label: '") + label + "'");
            return -1;
        }
        std::string manifest_path = s->session.pipeline.storage_root() + "/" + *manifest_filename;
        Manifest m = read_manifest_file(manifest_path, *manifest_filename, s->session.pipeline.kek());
        auto hash = m.lookup(block_index);
        if (!hash) {
            set_error("block " + std::to_string(block_index) + " out of range for '" + label + "'");
            return -1;
        }
        memcpy(out_hash32, hash->data(), 32);
        return 0;
    } catch (const std::exception& e) {
        set_error(e);
        return -1;
    }
}

int pfs_debug_lookup_chunk(pfs_session_t* session_h, const uint8_t* content_hash32,
                            uint64_t* out_offset, uint64_t* out_length, uint32_t* out_epoch_id) {
    auto* s = reinterpret_cast<pfs_session*>(session_h);
    try {
        Bytes32 hash{};
        memcpy(hash.data(), content_hash32, 32);
        auto entry = s->session.pipeline.dedup_index().lookup(hash);
        if (!entry) {
            set_error("no index entry for this content hash");
            return -1;
        }
        if (out_offset) *out_offset = entry->offset;
        if (out_length) *out_length = entry->length;
        if (out_epoch_id) *out_epoch_id = entry->epoch_id;
        return 0;
    } catch (const std::exception& e) {
        set_error(e);
        return -1;
    }
}

int pfs_debug_get_mirror(pfs_session_t* session_h, const uint8_t* content_hash32,
                          uint64_t* out_offset, uint64_t* out_length) {
    auto* s = reinterpret_cast<pfs_session*>(session_h);
    try {
        Bytes32 hash{};
        memcpy(hash.data(), content_hash32, 32);
        auto entry = s->session.pipeline.dedup_index().get_mirror(hash);
        if (!entry) {
            set_error("no Ancestral Hardening mirror for this content hash");
            return -1;
        }
        if (out_offset) *out_offset = entry->offset;
        if (out_length) *out_length = entry->length;
        return 0;
    } catch (const std::exception& e) {
        set_error(e);
        return -1;
    }
}

int pfs_get_container_path(pfs_session_t* session_h, char* out_path, size_t out_buf_len) {
    auto* s = reinterpret_cast<pfs_session*>(session_h);
    copy_out(s->session.pipeline.container_path(), out_path, out_buf_len);
    return 0;
}

int pfs_get_mirror_container_path(pfs_session_t* session_h, char* out_path, size_t out_buf_len) {
    auto* s = reinterpret_cast<pfs_session*>(session_h);
    copy_out(s->session.pipeline.mirror_container_path(), out_path, out_buf_len);
    return 0;
}

int pfs_get_stats(pfs_session_t* session_h, pfs_vault_stats_t* out_stats) {
    auto* s = reinterpret_cast<pfs_session*>(session_h);
    if (!out_stats) {
        set_error("out_stats must not be NULL");
        return -1;
    }
    try {
        pfs_vault_stats_t stats{};

        std::error_code ec;
        uint64_t sz = std::filesystem::file_size(s->session.pipeline.container_path(), ec);
        stats.container_size = ec ? 0 : sz;

        auto entries = s->session.pipeline.dedup_index().iter_all();
        stats.total_chunks = entries.size();
        for (const auto& e : entries) {
            stats.total_refs += e.ref_count;
            if (e.ref_count == 0) stats.dead_chunks++;
        }

        stats.files_tracked = s->session.catalog.labels().size();
        stats.key_epochs = static_cast<uint32_t>(s->session.pipeline.keyring().current_epoch() + 1);

        *out_stats = stats;
        return 0;
    } catch (const std::exception& e) {
        set_error(e);
        return -1;
    }
}

const char* pfs_last_error(void) { return g_last_error.c_str(); }

} /* extern "C" */
