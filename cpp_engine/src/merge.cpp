#include "merge.hpp"

#include <algorithm>
#include <cstdio>
#include <fstream>
#include <optional>
#include <set>

#include <fcntl.h>
#include <unistd.h>

#include "manifest.hpp"

namespace pfs_engine {

namespace {

// Finds the last version the two branches have in common, following primary parents.
std::optional<LineageNode> find_common_ancestor(const LineageStore& lineage, const LineageNode& node_a,
                                                  const LineageNode& node_b) {
    // Lowest common ancestor along primary parents (a linear walk: one label's history is small).
    std::set<NodeUuid> ancestors_a;
    std::optional<LineageNode> node = node_a;
    while (node) {
        ancestors_a.insert(node->node_uuid);
        node = node->has_parent ? lineage.find_node_by_uuid(node->parent_uuid) : std::nullopt;
    }
    node = node_b;
    while (node) {
        if (ancestors_a.count(node->node_uuid)) return node;
        node = node->has_parent ? lineage.find_node_by_uuid(node->parent_uuid) : std::nullopt;
    }
    return std::nullopt;
}

// A generation's ordered chunk hashes.
std::vector<Bytes32> manifest_chunk_list(const std::string& storage_root, const std::string& manifest_filename,
                                          const Bytes32& kek) {
    std::string manifest_path = storage_root + "/" + manifest_filename;
    Manifest m = read_manifest_file(manifest_path, manifest_filename, kek);
    std::vector<Bytes32> out;
    out.reserve(m.metadata().total_blocks);
    for (uint64_t i = 0; i < m.metadata().total_blocks; i++) out.push_back(*m.lookup(i));
    return out;
}

}  // namespace

// Merges two branches chunk by chunk against their common ancestor; clashes use the given choices.
MergeResult merge_branches(StoragePipeline& pipeline, LineageStore& lineage, const std::string& label,
                            uint64_t generation_a, uint64_t generation_b, const MergeResolutions& resolutions) {
    for (const auto& kv : resolutions) {
        if (kv.second != 'a' && kv.second != 'b') {
            throw std::invalid_argument("A resolution must be 'a' or 'b'.");
        }
    }
    auto node_a_opt = lineage.get_generation(label, generation_a);
    auto node_b_opt = lineage.get_generation(label, generation_b);
    if (!node_a_opt) throw std::invalid_argument("No generation " + std::to_string(generation_a) +
                                                  " recorded for '" + label + "'.");
    if (!node_b_opt) throw std::invalid_argument("No generation " + std::to_string(generation_b) +
                                                  " recorded for '" + label + "'.");
    LineageNode node_a = *node_a_opt, node_b = *node_b_opt;

    if (node_a.pruned || node_b.pruned) {
        throw std::invalid_argument("Can't merge a pruned generation -- its content is no longer available.");
    }
    if (node_a.node_uuid == node_b.node_uuid) {
        throw std::invalid_argument("Can't merge a generation with itself.");
    }

    auto ancestor_opt = find_common_ancestor(lineage, node_a, node_b);
    if (!ancestor_opt) {
        throw std::invalid_argument("Generations " + std::to_string(generation_a) + " and " +
                                     std::to_string(generation_b) + " of '" + label +
                                     "' share no common ancestor -- can't 3-way merge them.");
    }
    LineageNode ancestor = *ancestor_opt;
    if (ancestor.node_uuid == node_a.node_uuid || ancestor.node_uuid == node_b.node_uuid) {
        throw std::invalid_argument(
            "One of these generations is a direct ancestor of the other -- that's just linear "
            "history, not a divergent branch. Nothing to merge.");
    }

    const Bytes32& kek = pipeline.kek();
    const std::string& storage_root = pipeline.storage_root();
    std::vector<Bytes32> chunks_ancestor = manifest_chunk_list(storage_root, ancestor.manifest_filename, kek);
    std::vector<Bytes32> chunks_a = manifest_chunk_list(storage_root, node_a.manifest_filename, kek);
    std::vector<Bytes32> chunks_b = manifest_chunk_list(storage_root, node_b.manifest_filename, kek);

    // nullopt means "this branch has no chunk at this position": unequal to any hash.
    auto at = [](const std::vector<Bytes32>& v, size_t i) -> std::optional<Bytes32> {
        if (i < v.size()) return v[i];
        return std::nullopt;
    };

    size_t max_len = std::max({chunks_ancestor.size(), chunks_a.size(), chunks_b.size()});
    std::vector<Bytes32> merged;
    std::vector<uint64_t> conflicts;

    for (size_t i = 0; i < max_len; i++) {
        std::optional<Bytes32> base = at(chunks_ancestor, i);
        std::optional<Bytes32> a = at(chunks_a, i);
        std::optional<Bytes32> b = at(chunks_b, i);
        bool a_changed = (a != base);
        bool b_changed = (b != base);

        std::optional<Bytes32> winner;
        if (!a_changed && !b_changed) {
            winner = base;
        } else if (a_changed && !b_changed) {
            winner = a;
        } else if (b_changed && !a_changed) {
            winner = b;
        } else if (a == b) {
            winner = a;  // both changed the same way (including both truncating)
        } else if (auto r = resolutions.find(i); r != resolutions.end()) {
            winner = r->second == 'a' ? a : b;
        } else {
            // Changed differently by both, including truncation vs. edit.
            conflicts.push_back(static_cast<uint64_t>(i));
            continue;
        }

        if (!winner) {
            // Truncated here: end the merged sequence.
            break;
        }
        merged.push_back(*winner);
    }

    if (!conflicts.empty()) throw MutationConflictError(conflicts);

    std::string tmp_path = storage_root + "/__merge_result__.tmp";
    {
        std::ofstream out(tmp_path, std::ios::binary | std::ios::trunc);
        if (!out) throw std::runtime_error("failed to open merge temp file: " + tmp_path);
        int container_fd = open(pipeline.container_path().c_str(), O_RDONLY);
        if (container_fd < 0) throw std::runtime_error("failed to open container for merge reconstruction");
        for (const auto& content_hash : merged) {
            auto location = pipeline.dedup_index().lookup(content_hash);
            if (!location) {
                close(container_fd);
                throw std::runtime_error(
                    "Merge chunk missing from the global index -- this should be impossible given it "
                    "came from an already-committed manifest.");
            }
            Bytes32 dek = pipeline.keyring().get_dek(location->epoch_id);
            std::vector<uint8_t> payload(location->length);
            if (pread(container_fd, payload.data(), location->length, static_cast<off_t>(location->offset)) !=
                static_cast<ssize_t>(location->length)) {
                close(container_fd);
                throw std::runtime_error("failed reading a merge chunk from the container");
            }
            std::vector<uint8_t> plaintext =
                aead_decrypt(dek, payload.data(), payload.size(), content_hash.data(), content_hash.size());
            if (sha256(plaintext.data(), plaintext.size()) != content_hash) {
                close(container_fd);
                throw std::runtime_error(
                    "Merge chunk failed integrity verification -- check for corruption, then try again.");
            }
            out.write(reinterpret_cast<const char*>(plaintext.data()), static_cast<std::streamsize>(plaintext.size()));
        }
        close(container_fd);
    }

    WriteResult write_result;
    try {
        write_result = pipeline.secure_and_persist_file(tmp_path, label);
    } catch (...) {
        remove(tmp_path.c_str());
        throw;
    }
    remove(tmp_path.c_str());

    std::string manifest_filename =
        write_result.manifest_path.substr(write_result.manifest_path.find_last_of('/') + 1);
    lineage.record_version(label, manifest_filename, write_result.new_chunks_written, write_result.total_blocks,
                            {node_b.node_uuid}, &node_a);

    MergeResult result;
    result.manifest_path = write_result.manifest_path;
    result.total_blocks = write_result.total_blocks;
    result.new_chunks_written = write_result.new_chunks_written;
    result.duplicate_chunks_found = write_result.duplicate_chunks_found;
    return result;
}

}  // namespace pfs_engine
