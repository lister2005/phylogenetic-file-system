#pragma once
// C++ port of lineage.py's LineageStore -- the per-label edit-history
// DAG (V1 -> V2 -> V3, branching via fork_from, cross-label provenance
// via lateral_parent_uuids, epigenetic tag inheritance).
//
// KEEPS Python's outer append-only framing architecture exactly (a
// magic header followed by a sequence of length-framed encrypted
// records, each either a full SNAPSHOT or one incremental NODE) --
// that architecture is what fixed a real O(N)-per-write bottleneck
// (measured: 3.7ms -> 42ms avg over 6000 nodes, a 7.8x slowdown,
// clearly growing with total vault history size, not per-write size),
// and is sound regardless of language. What's NOT kept is what's
// INSIDE each frame: Python pickles a dict; this uses a new portable
// binary node encoding (same reasoning as MANIFEST_FORMAT.md /
// KEYRING_FORMAT.md -- pickle is Python-specific, not worth
// replicating). See LINEAGE_FORMAT.md for the exact byte layout.
//
// record_version() is the hot path (called on every write) and MUST
// stay O(1) -- append one small framed record, never rewrite the whole
// file. Every other mutating method (delete_label, mark_pruned,
// rename_label, set_tag, remove_tag) is a rare, deliberate action and
// is allowed to be O(total history size), exactly matching Python's
// own stated design principle.
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

// A tag value is either a bool or a string -- the only two types
// pfs_cli.py's `tag` command ever actually produces (true/false/yes/
// no/1/0 parse to bool; everything else stays a string).
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
using Tags = std::map<std::string, TagValue>;  // sorted -- deterministic serialization

struct LineageNode {
    NodeUuid node_uuid{};
    bool has_parent = false;
    NodeUuid parent_uuid{};
    std::vector<NodeUuid> lateral_parent_uuids;
    std::string label;
    bool has_manifest = false;   // false once pruned (manifest_filename cleared, one-way)
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

    // Appends a new generation for `label`. Primary parent is
    // `fork_from` if given (creates a branch -- need not be label's
    // current tip), otherwise label's own current tip (nullopt = root
    // node, if this is the first write ever recorded for this label).
    // epigenetic_tags are copied from the parent automatically. O(1).
    LineageNode record_version(const std::string& label, const std::optional<std::string>& manifest_filename,
                                uint64_t new_chunks, uint64_t total_chunks,
                                const std::vector<NodeUuid>& lateral_parent_uuids = {},
                                const LineageNode* fork_from = nullptr);

    // Every currently-open branch tip: nodes not claimed as anyone's
    // PRIMARY parent yet. Normally exactly one; more once forked.
    std::vector<LineageNode> get_heads(const std::string& label) const;
    std::vector<LineageNode> get_history(const std::string& label) const;  // generation 0 first
    std::optional<LineageNode> get_generation(const std::string& label, uint64_t generation_index) const;
    std::optional<LineageNode> get_tip(const std::string& label) const;
    std::optional<LineageNode> find_node_by_uuid(const NodeUuid& node_uuid) const;
    std::vector<std::string> all_labels() const;

    void delete_label(const std::string& label);  // purges ALL generations. O(N).
    std::optional<std::string> mark_pruned(const std::string& label, uint64_t generation_index);  // O(N)
    void rename_label(const std::string& old_label, const std::string& new_label);  // O(N)

    Tags get_tags(const std::string& label) const;
    void set_tag(const std::string& label, const std::string& key, const TagValue& value);  // O(N)
    bool remove_tag(const std::string& label, const std::string& key);  // O(N)

    // Explicit maintenance: collapses the append log back into a
    // single fresh snapshot. Not run automatically on any hot path.
    void compact();

private:
    std::string storage_root_;
    std::string path_;
    Bytes32 kek_;
    // deque, not vector: get_generation() needs O(1) random access
    // (like vector), but by_uuid_ below holds POINTERS into these
    // elements that must survive record_version()'s push_back --
    // std::deque uniquely guarantees both (push_back never invalidates
    // references to existing elements, unlike vector's possible
    // reallocation).
    std::map<std::string, std::deque<LineageNode>> history_;
    std::map<NodeUuid, LineageNode*> by_uuid_;

    void load();
    void save();        // full snapshot -- O(N)
    void append_node(const LineageNode& node);  // O(1)
    void rebuild_by_uuid();
};

}  // namespace pfs_engine
