#include "lineage_store.hpp"

#include <algorithm>
#include <chrono>
#include <cstring>
#include <fstream>
#include <random>
#include <set>
#include <stdexcept>

#include <fcntl.h>
#include <unistd.h>

#include "binary_io.hpp"

namespace pfs_engine {

namespace {

constexpr char kMagic[8] = {'P', 'F', 'S', 'L', 'I', 'N', '0', '1'};
constexpr uint8_t kRecordSnapshot = 'S';
constexpr uint8_t kRecordNode = 'N';

bool file_exists(const std::string& path) {
    std::ifstream f(path);
    return f.good();
}

// -------- one node's plaintext encoding (encrypted inside each frame) --------

void write_node(BinaryWriter& w, const LineageNode& node) {
    w.fixed_bytes(node.node_uuid);
    w.u8(node.has_parent ? 1 : 0);
    if (node.has_parent) w.fixed_bytes(node.parent_uuid);
    w.u32(static_cast<uint32_t>(node.lateral_parent_uuids.size()));
    for (const auto& id : node.lateral_parent_uuids) w.fixed_bytes(id);
    w.string16(node.label);
    w.u8(node.has_manifest ? 1 : 0);
    if (node.has_manifest) w.string16(node.manifest_filename);
    w.u64(node.generation_index);
    w.f64(node.birth_timestamp);
    w.u64(node.new_chunks);
    w.u64(node.total_chunks);
    w.u8(node.pruned ? 1 : 0);
    w.u32(static_cast<uint32_t>(node.epigenetic_tags.size()));
    for (const auto& [key, value] : node.epigenetic_tags) {
        w.string16(key);
        w.u8(value.is_bool ? 0 : 1);
        if (value.is_bool) {
            w.u8(value.bool_value ? 1 : 0);
        } else {
            w.string16(value.string_value);
        }
    }
}

LineageNode read_node(BinaryReader& r) {
    LineageNode node;
    node.node_uuid = r.fixed_bytes<16>();
    node.has_parent = r.u8() != 0;
    if (node.has_parent) node.parent_uuid = r.fixed_bytes<16>();
    uint32_t lateral_count = r.u32();
    node.lateral_parent_uuids.reserve(lateral_count);
    for (uint32_t i = 0; i < lateral_count; i++) node.lateral_parent_uuids.push_back(r.fixed_bytes<16>());
    node.label = r.string16();
    node.has_manifest = r.u8() != 0;
    if (node.has_manifest) node.manifest_filename = r.string16();
    node.generation_index = r.u64();
    node.birth_timestamp = r.f64();
    node.new_chunks = r.u64();
    node.total_chunks = r.u64();
    node.pruned = r.u8() != 0;
    uint32_t tag_count = r.u32();
    for (uint32_t i = 0; i < tag_count; i++) {
        std::string key = r.string16();
        uint8_t type = r.u8();
        TagValue value;
        if (type == 0) {
            value = TagValue::from_bool(r.u8() != 0);
        } else {
            value = TagValue::from_string(r.string16());
        }
        node.epigenetic_tags[key] = value;
    }
    return node;
}

}  // namespace

NodeUuid generate_node_uuid() {
    static std::mt19937_64 rng(
        static_cast<uint64_t>(std::chrono::high_resolution_clock::now().time_since_epoch().count()));
    NodeUuid id{};
    for (int i = 0; i < 16; i++) id[i] = static_cast<uint8_t>(rng());
    return id;
}

std::string node_uuid_to_hex(const NodeUuid& id) {
    static const char* hex = "0123456789abcdef";
    std::string out;
    out.reserve(32);
    for (uint8_t b : id) {
        out.push_back(hex[b >> 4]);
        out.push_back(hex[b & 0xF]);
    }
    return out;
}

NodeUuid node_uuid_from_hex(const std::string& hex) {
    if (hex.size() != 32) throw std::runtime_error("node_uuid hex string must be exactly 32 chars");
    NodeUuid id{};
    for (int i = 0; i < 16; i++) {
        id[i] = static_cast<uint8_t>(std::stoi(hex.substr(i * 2, 2), nullptr, 16));
    }
    return id;
}

LineageStore::LineageStore(std::string storage_root, const Bytes32& kek)
    : storage_root_(std::move(storage_root)), kek_(kek) {
    path_ = storage_root_ + "/lineage.pfsl";
    load();
}

void LineageStore::load() {
    history_.clear();
    by_uuid_.clear();
    if (!file_exists(path_)) return;

    std::ifstream in(path_, std::ios::binary);
    std::vector<uint8_t> blob((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    if (blob.size() < 8 || memcmp(blob.data(), kMagic, 8) != 0) {
        throw std::runtime_error("bad lineage store magic/truncated file: " + path_);
    }

    size_t offset = 8;
    while (offset < blob.size()) {
        if (offset + 5 > blob.size()) throw std::runtime_error("lineage store truncated mid-record");
        uint8_t record_type = blob[offset];
        offset += 1;
        uint32_t length = (static_cast<uint32_t>(blob[offset]) << 24) | (static_cast<uint32_t>(blob[offset + 1]) << 16) |
                           (static_cast<uint32_t>(blob[offset + 2]) << 8) | static_cast<uint32_t>(blob[offset + 3]);
        offset += 4;
        if (offset + length > blob.size()) throw std::runtime_error("lineage store record length overruns file");

        std::string aad = (record_type == kRecordSnapshot) ? "lineage_snapshot" : "lineage_node";
        std::vector<uint8_t> raw = aead_decrypt(kek_, blob.data() + offset, length,
                                                 reinterpret_cast<const uint8_t*>(aad.data()), aad.size());
        offset += length;

        if (record_type == kRecordSnapshot) {
            BinaryReader r(raw.data(), raw.size());
            uint32_t node_count = r.u32();
            history_.clear();
            for (uint32_t i = 0; i < node_count; i++) {
                LineageNode node = read_node(r);
                history_[node.label].push_back(std::move(node));
            }
        } else if (record_type == kRecordNode) {
            BinaryReader r(raw.data(), raw.size());
            LineageNode node = read_node(r);
            history_[node.label].push_back(std::move(node));
        } else {
            throw std::runtime_error("unknown lineage record type in " + path_);
        }
    }
    rebuild_by_uuid();
}

void LineageStore::rebuild_by_uuid() {
    by_uuid_.clear();
    for (auto& [label, nodes] : history_) {
        for (auto& node : nodes) by_uuid_[node.node_uuid] = &node;
    }
}

void LineageStore::save() {
    // Full snapshot, O(N): only the rare mutating operations use this.
    BinaryWriter body;
    uint32_t total = 0;
    for (auto& [label, nodes] : history_) total += static_cast<uint32_t>(nodes.size());
    body.u32(total);
    for (auto& [label, nodes] : history_) {
        for (auto& node : nodes) write_node(body, node);
    }
    std::string aad = "lineage_snapshot";
    std::vector<uint8_t> encrypted = aead_encrypt(kek_, body.data().data(), body.data().size(),
                                                   reinterpret_cast<const uint8_t*>(aad.data()), aad.size());

    BinaryWriter framed;
    framed.raw_bytes(reinterpret_cast<const uint8_t*>(kMagic), 8);
    framed.u8(kRecordSnapshot);
    uint32_t len = static_cast<uint32_t>(encrypted.size());
    framed.u8(static_cast<uint8_t>((len >> 24) & 0xFF));
    framed.u8(static_cast<uint8_t>((len >> 16) & 0xFF));
    framed.u8(static_cast<uint8_t>((len >> 8) & 0xFF));
    framed.u8(static_cast<uint8_t>(len & 0xFF));
    framed.raw_bytes(encrypted.data(), encrypted.size());

    std::string tmp = path_ + ".tmp";
    {
        std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
        if (!out) throw std::runtime_error("failed to open lineage temp file: " + tmp);
        out.write(reinterpret_cast<const char*>(framed.data().data()),
                  static_cast<std::streamsize>(framed.data().size()));
    }
    int fd = open(tmp.c_str(), O_WRONLY);
    if (fd >= 0) { fsync(fd); close(fd); }
    if (rename(tmp.c_str(), path_.c_str()) != 0) {
        throw std::runtime_error("failed to rename lineage store into place: " + path_);
    }
}

void LineageStore::append_node(const LineageNode& node) {
    // Appends one framed record, O(1): the per-write path.
    BinaryWriter body;
    write_node(body, node);
    std::string aad = "lineage_node";
    std::vector<uint8_t> encrypted = aead_encrypt(kek_, body.data().data(), body.data().size(),
                                                   reinterpret_cast<const uint8_t*>(aad.data()), aad.size());

    BinaryWriter framed;
    framed.u8(kRecordNode);
    uint32_t len = static_cast<uint32_t>(encrypted.size());
    framed.u8(static_cast<uint8_t>((len >> 24) & 0xFF));
    framed.u8(static_cast<uint8_t>((len >> 16) & 0xFF));
    framed.u8(static_cast<uint8_t>((len >> 8) & 0xFF));
    framed.u8(static_cast<uint8_t>(len & 0xFF));
    framed.raw_bytes(encrypted.data(), encrypted.size());

    bool is_new_file = !file_exists(path_);
    std::ofstream out(path_, std::ios::binary | std::ios::app);
    if (!out) throw std::runtime_error("failed to open lineage store for append: " + path_);
    if (is_new_file) out.write(kMagic, 8);
    out.write(reinterpret_cast<const char*>(framed.data().data()),
              static_cast<std::streamsize>(framed.data().size()));
    out.flush();
    int fd = open(path_.c_str(), O_WRONLY);
    if (fd >= 0) { fsync(fd); close(fd); }
}

void LineageStore::compact() { save(); }

LineageNode LineageStore::record_version(const std::string& label, const std::optional<std::string>& manifest_filename,
                                          uint64_t new_chunks, uint64_t total_chunks,
                                          const std::vector<NodeUuid>& lateral_parent_uuids,
                                          const LineageNode* fork_from) {
    auto it = history_.find(label);
    const std::deque<LineageNode>* existing = (it != history_.end()) ? &it->second : nullptr;

    const LineageNode* parent = fork_from;
    if (parent == nullptr && existing != nullptr && !existing->empty()) parent = &existing->back();

    LineageNode node;
    node.node_uuid = generate_node_uuid();
    node.has_parent = (parent != nullptr);
    if (parent) node.parent_uuid = parent->node_uuid;
    node.lateral_parent_uuids = lateral_parent_uuids;
    node.label = label;
    node.has_manifest = manifest_filename.has_value();
    if (manifest_filename) node.manifest_filename = *manifest_filename;
    node.generation_index = existing ? existing->size() : 0;
    node.birth_timestamp = std::chrono::duration<double>(std::chrono::system_clock::now().time_since_epoch()).count();
    node.new_chunks = new_chunks;
    node.total_chunks = total_chunks;
    node.pruned = false;
    node.epigenetic_tags = parent ? parent->epigenetic_tags : Tags{};

    auto& deque_ref = history_[label];
    deque_ref.push_back(node);
    by_uuid_[node.node_uuid] = &deque_ref.back();
    append_node(node);
    return node;
}

std::vector<LineageNode> LineageStore::get_heads(const std::string& label) const {
    auto it = history_.find(label);
    if (it == history_.end()) return {};
    std::set<NodeUuid> claimed;  // nodes that are someone's primary parent
    for (const auto& n : it->second) {
        if (n.has_parent) claimed.insert(n.parent_uuid);
    }
    std::vector<LineageNode> heads;
    for (const auto& n : it->second) {
        if (claimed.find(n.node_uuid) == claimed.end()) heads.push_back(n);
    }
    return heads;
}

std::vector<LineageNode> LineageStore::get_history(const std::string& label) const {
    auto it = history_.find(label);
    if (it == history_.end()) return {};
    return std::vector<LineageNode>(it->second.begin(), it->second.end());
}

std::optional<LineageNode> LineageStore::get_generation(const std::string& label, uint64_t generation_index) const {
    auto it = history_.find(label);
    if (it == history_.end() || it->second.empty()) return std::nullopt;
    const auto& nodes = it->second;
    if (generation_index < nodes.size() && nodes[generation_index].generation_index == generation_index) {
        return nodes[generation_index];
    }
    for (const auto& n : nodes) {
        if (n.generation_index == generation_index) return n;
    }
    return std::nullopt;
}

std::optional<LineageNode> LineageStore::get_tip(const std::string& label) const {
    auto it = history_.find(label);
    if (it == history_.end() || it->second.empty()) return std::nullopt;
    return it->second.back();
}

std::optional<LineageNode> LineageStore::find_node_by_uuid(const NodeUuid& node_uuid) const {
    auto it = by_uuid_.find(node_uuid);
    if (it == by_uuid_.end()) return std::nullopt;
    return *it->second;
}

std::vector<std::string> LineageStore::all_labels() const {
    std::vector<std::string> labels;
    labels.reserve(history_.size());
    for (const auto& [label, _] : history_) labels.push_back(label);
    return labels;
}

void LineageStore::delete_label(const std::string& label) {
    auto it = history_.find(label);
    if (it == history_.end()) return;
    history_.erase(it);
    rebuild_by_uuid();
    save();
}

std::optional<std::string> LineageStore::mark_pruned(const std::string& label, uint64_t generation_index) {
    auto it = history_.find(label);
    if (it == history_.end()) return std::nullopt;
    for (auto& node : it->second) {
        if (node.generation_index == generation_index && !node.pruned) {
            std::string old_manifest = node.manifest_filename;
            node.pruned = true;
            node.has_manifest = false;
            node.manifest_filename.clear();
            save();
            return old_manifest;
        }
    }
    return std::nullopt;
}

void LineageStore::rename_label(const std::string& old_label, const std::string& new_label) {
    auto it = history_.find(old_label);
    if (it == history_.end()) return;
    std::deque<LineageNode> nodes = std::move(it->second);
    history_.erase(it);
    for (auto& node : nodes) node.label = new_label;
    auto& dest = history_[new_label];
    for (auto& node : nodes) dest.push_back(std::move(node));
    rebuild_by_uuid();
    save();
}

Tags LineageStore::get_tags(const std::string& label) const {
    auto tip = get_tip(label);
    return tip ? tip->epigenetic_tags : Tags{};
}

void LineageStore::set_tag(const std::string& label, const std::string& key, const TagValue& value) {
    auto it = history_.find(label);
    if (it == history_.end() || it->second.empty()) {
        throw std::runtime_error("'" + label + "' has no recorded lineage history to tag.");
    }
    it->second.back().epigenetic_tags[key] = value;
    save();
}

bool LineageStore::remove_tag(const std::string& label, const std::string& key) {
    auto it = history_.find(label);
    if (it == history_.end() || it->second.empty()) {
        throw std::runtime_error("'" + label + "' has no recorded lineage history to untag.");
    }
    auto& tags = it->second.back().epigenetic_tags;
    auto tag_it = tags.find(key);
    if (tag_it == tags.end()) return false;
    tags.erase(tag_it);
    save();
    return true;
}

}  // namespace pfs_engine
