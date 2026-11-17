#pragma once
// C++ port of lineage.py's LineageStore: each label's edit-history DAG
// (branches via fork_from, cross-label parents, inherited tags).
//
// Same append-only framing as Python (magic header, then length-framed
// encrypted SNAPSHOT or NODE records), with a portable binary node
// encoding instead of pickle. record_version() appends
// one record (O(1)); the rare mutating methods rewrite a snapshot (O(N)).
#include <array>
#include <cstdint>
#include <deque>
#include <map>
#include <optional>
#include <string>
#include <vector>

#include "crypto_utils.hpp"

namespace pfs_engine {

using NodeUuid = std::array<uint8_t, 16>;

NodeUuid generate_node_uuid();
std::string node_uuid_to_hex(const NodeUuid& id);
NodeUuid node_uuid_from_hex(const std::string& hex);

// A tag value: bool (true/false/yes/no/1/0) or string.
struct TagValue {
    bool is_bool = false;
    bool bool_value = false;
    std::string string_value;

    static TagValue from_bool(bool v) { return TagValue{true, v, ""}; }
    static TagValue from_string(std::string v) { return TagValue{false, false, std::move(v)}; }
    bool operator==(const TagValue& other) const {
        return is_bool == other.is_bool && bool_value == other.bool_value && string_value == other.string_value;
    }
};
using Tags = std::map<std::string, TagValue>;  // sorted, for deterministic serialization

struct LineageNode {
    NodeUuid node_uuid{};
    bool has_parent = false;
    NodeUuid parent_uuid{};
    std::vector<NodeUuid> lateral_parent_uuids;
    std::string label;
    bool has_manifest = false;  // false once pruned (one-way)
    std::string manifest_filename;
    uint64_t generation_index = 0;
    double birth_timestamp = 0.0;
    uint64_t new_chunks = 0;
    uint64_t total_chunks = 0;
    bool pruned = false;
    Tags epigenetic_tags;
};

class LineageStore {
public:
    LineageStore(std::string storage_root, const Bytes32& kek);

    // Appends a generation of `label`. Primary parent: fork_from (a branch)
    // or the current tip (none for a first write). Tags are copied from it. O(1).
    LineageNode record_version(const std::string& label, const std::optional<std::string>& manifest_filename,
                                uint64_t new_chunks, uint64_t total_chunks,
                                const std::vector<NodeUuid>& lateral_parent_uuids = {},
                                const LineageNode* fork_from = nullptr);

    // Open branch tips: nodes that aren't another node's primary parent.
    std::vector<LineageNode> get_heads(const std::string& label) const;
    std::vector<LineageNode> get_history(const std::string& label) const;  // generation 0 first
    std::optional<LineageNode> get_generation(const std::string& label, uint64_t generation_index) const;
    std::optional<LineageNode> get_tip(const std::string& label) const;
    std::optional<LineageNode> find_node_by_uuid(const NodeUuid& node_uuid) const;
    std::vector<std::string> all_labels() const;

    void delete_label(const std::string& label);  // all generations. O(N).
    std::optional<std::string> mark_pruned(const std::string& label, uint64_t generation_index);  // O(N)
    void rename_label(const std::string& old_label, const std::string& new_label);  // O(N)

    Tags get_tags(const std::string& label) const;
    void set_tag(const std::string& label, const std::string& key, const TagValue& value);  // O(N)
    bool remove_tag(const std::string& label, const std::string& key);  // O(N)

    // Collapses the append log into one snapshot. Manual maintenance.
    void compact();

private:
    std::string storage_root_;
    std::string path_;
    Bytes32 kek_;
    // deque: O(1) indexing, and push_back doesn't invalidate the pointers
    // by_uuid_ holds.
    std::map<std::string, std::deque<LineageNode>> history_;
    std::map<NodeUuid, LineageNode*> by_uuid_;

    void load();
    void save();  // full snapshot, O(N)
    void append_node(const LineageNode& node);  // O(1)
    void rebuild_by_uuid();
};

}  // namespace pfs_engine
