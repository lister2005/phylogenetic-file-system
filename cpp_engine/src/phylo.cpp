#include "phylo.hpp"

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <functional>
#include <limits>
#include <random>
#include <stdexcept>

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include "chunker.h"
#include "gear_table.hpp"

namespace pfs_engine {

namespace {
constexpr double kInf = std::numeric_limits<double>::infinity();
}  // namespace

PhyloUuid generate_phylo_uuid() {
    static std::mt19937_64 rng(
        static_cast<uint64_t>(std::chrono::high_resolution_clock::now().time_since_epoch().count()));
    PhyloUuid id{};
    for (int i = 0; i < 16; i++) id[i] = static_cast<uint8_t>(rng());
    return id;
}

std::string phylo_uuid_to_hex(const PhyloUuid& id) {
    static const char* hex = "0123456789abcdef";
    std::string out;
    out.reserve(32);
    for (uint8_t b : id) {
        out.push_back(hex[b >> 4]);
        out.push_back(hex[b & 0xF]);
    }
    return out;
}

TraitSet extract_similarity_traits(const uint8_t* data, size_t size) {
    TraitSet traits;
    size_t cursor = 0;
    uint64_t rolling_hash = 0;
    while (cursor < size) {
        size_t chunk_len = scan_chunk_c(data, size, cursor, &rolling_hash, kSimilarityChunkMask,
                                         kSimilarityMinSize, kSimilarityMaxSize, kGearTable);
        if (chunk_len == 0) break;
        traits.insert(sha256(data + cursor, chunk_len));
        cursor += chunk_len;
    }
    return traits;
}

TraitSet extract_similarity_traits(const std::string& file_path) {
    int fd = open(file_path.c_str(), O_RDONLY);
    if (fd < 0) throw std::runtime_error("failed to open '" + file_path + "' for fingerprinting: " + strerror(errno));
    struct stat st{};
    fstat(fd, &st);
    size_t size = static_cast<size_t>(st.st_size);
    if (size == 0) {
        close(fd);
        return {};
    }
    void* mapped = mmap(nullptr, size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (mapped == MAP_FAILED) throw std::runtime_error("mmap failed while fingerprinting: " + file_path);
    TraitSet traits = extract_similarity_traits(static_cast<const uint8_t*>(mapped), size);
    munmap(mapped, size);
    return traits;
}

bool trait_set_is_reliable(const TraitSet& traits) {
    return traits.size() >= kMinReliableTraitCount;
}

double jaccard_distance(const TraitSet& a, const TraitSet& b) {
    if (a.empty() && b.empty()) return 1.0;
    size_t intersection = 0;
    // Linear merge-count over two sorted sets.
    auto ia = a.begin(), ib = b.begin();
    while (ia != a.end() && ib != b.end()) {
        if (*ia == *ib) { intersection++; ++ia; ++ib; }
        else if (*ia < *ib) { ++ia; }
        else { ++ib; }
    }
    size_t union_size = a.size() + b.size() - intersection;
    if (union_size == 0) return 1.0;
    return 1.0 - (static_cast<double>(intersection) / static_cast<double>(union_size));
}

namespace {

TraitSet trait_union(const TraitSet& a, const TraitSet& b) {
    TraitSet out = a;
    out.insert(b.begin(), b.end());
    return out;
}

uint64_t trait_symmetric_diff_count(const TraitSet& a, const TraitSet& b) {
    uint64_t count = 0;
    auto ia = a.begin(), ib = b.begin();
    while (ia != a.end() && ib != b.end()) {
        if (*ia == *ib) { ++ia; ++ib; }
        else if (*ia < *ib) { count++; ++ia; }
        else { count++; ++ib; }
    }
    count += static_cast<uint64_t>(std::distance(ia, a.end()));
    count += static_cast<uint64_t>(std::distance(ib, b.end()));
    return count;
}

std::vector<PhyloNode> make_leaves(const std::map<std::string, TraitSet>& named_traits) {
    std::vector<PhyloNode> leaves;
    leaves.reserve(named_traits.size());
    int i = 0;
    for (const auto& kv : named_traits) {
        PhyloNode node;
        node.node_uuid = generate_phylo_uuid();
        node.metadata_name = kv.first;
        node.trait_matrix = kv.second;
        node.branch_signature = (i < 32) ? (1u << i) : 0u;
        i++;
        leaves.push_back(std::move(node));
    }
    return leaves;
}

// Pairwise distances between leaves, by position.
std::vector<std::vector<double>> initial_distances(const std::vector<PhyloNode>& leaves) {
    size_t n = leaves.size();
    std::vector<std::vector<double>> d(n, std::vector<double>(n, 0.0));
    for (size_t i = 0; i < n; i++) {
        for (size_t j = i + 1; j < n; j++) {
            double dist = jaccard_distance(leaves[i].trait_matrix, leaves[j].trait_matrix);
            d[i][j] = d[j][i] = dist;
        }
    }
    return d;
}

}  // namespace

PhyloTree build_tree_upgma_from_traits(const std::map<std::string, TraitSet>& named_traits) {
    std::vector<PhyloNode> leaves = make_leaves(named_traits);
    if (leaves.size() <= 1) return leaves;

    PhyloTree all_nodes(leaves.begin(), leaves.end());  // index -> all_nodes[index], stable
    // active and distances use indices into all_nodes.
    std::vector<size_t> active;
    for (size_t i = 0; i < leaves.size(); i++) active.push_back(i);

    std::map<size_t, std::map<size_t, double>> distances;
    auto dense = initial_distances(leaves);
    for (size_t i = 0; i < leaves.size(); i++)
        for (size_t j = 0; j < leaves.size(); j++)
            if (i != j) distances[i][j] = dense[i][j];

    std::map<size_t, uint64_t> leaf_count_of;  // current leaf_count per active index
    for (size_t i = 0; i < leaves.size(); i++) leaf_count_of[i] = 1;

    while (active.size() > 1) {
        size_t best_i = 0, best_j = 0;
        double min_dist = kInf;
        for (size_t i = 0; i < active.size(); i++) {
            for (size_t j = i + 1; j < active.size(); j++) {
                size_t a = active[i], b = active[j];
                double dist = distances[a][b];
                if (dist < min_dist) { min_dist = dist; best_i = i; best_j = j; }
            }
        }
        size_t a = active[best_i], b = active[best_j];

        PhyloNode parent;
        parent.node_uuid = generate_phylo_uuid();
        parent.trait_matrix = trait_union(all_nodes[a].trait_matrix, all_nodes[b].trait_matrix);
        parent.generation_index = std::max(all_nodes[a].generation_index, all_nodes[b].generation_index) + 1;
        parent.leaf_count = leaf_count_of[a] + leaf_count_of[b];
        parent.branch_signature = all_nodes[a].branch_signature | all_nodes[b].branch_signature;
        parent.height = min_dist / 2.0;
        parent.trait_divergence_count = trait_symmetric_diff_count(all_nodes[a].trait_matrix, all_nodes[b].trait_matrix);

        all_nodes[a].has_parent = true;
        all_nodes[a].parent_uuid = parent.node_uuid;
        all_nodes[b].has_parent = true;
        all_nodes[b].parent_uuid = parent.node_uuid;
        all_nodes[a].branch_length = std::max(0.0, parent.height - all_nodes[a].height);
        all_nodes[b].branch_length = std::max(0.0, parent.height - all_nodes[b].height);

        all_nodes.push_back(parent);
        size_t p = all_nodes.size() - 1;
        leaf_count_of[p] = parent.leaf_count;

        std::map<size_t, double> new_row;
        for (size_t idx : active) {
            if (idx == a || idx == b) continue;
            double d_new = (static_cast<double>(leaf_count_of[a]) * distances[a][idx] +
                            static_cast<double>(leaf_count_of[b]) * distances[b][idx]) /
                           static_cast<double>(leaf_count_of[a] + leaf_count_of[b]);
            new_row[idx] = d_new;
            distances[idx][p] = d_new;
            distances[idx].erase(a);
            distances[idx].erase(b);
        }
        distances[p] = new_row;
        distances.erase(a);
        distances.erase(b);

        std::vector<size_t> next_active;
        for (size_t idx : active) if (idx != a && idx != b) next_active.push_back(idx);
        next_active.push_back(p);
        active = std::move(next_active);
    }

    return all_nodes;
}

PhyloTree build_tree_nj_from_traits(const std::map<std::string, TraitSet>& named_traits) {
    std::vector<PhyloNode> leaves = make_leaves(named_traits);
    if (leaves.size() <= 1) return leaves;

    PhyloTree all_nodes(leaves.begin(), leaves.end());
    std::vector<size_t> active;
    for (size_t i = 0; i < leaves.size(); i++) active.push_back(i);

    std::map<size_t, std::map<size_t, double>> distances;
    auto dense = initial_distances(leaves);
    for (size_t i = 0; i < leaves.size(); i++)
        for (size_t j = 0; j < leaves.size(); j++)
            if (i != j) distances[i][j] = dense[i][j];

    auto make_child = [&](size_t a, size_t b, double branch_a, double branch_b) -> size_t {
        PhyloNode parent;
        parent.node_uuid = generate_phylo_uuid();
        parent.trait_matrix = trait_union(all_nodes[a].trait_matrix, all_nodes[b].trait_matrix);
        parent.generation_index = std::max(all_nodes[a].generation_index, all_nodes[b].generation_index) + 1;
        parent.leaf_count = all_nodes[a].leaf_count + all_nodes[b].leaf_count;
        parent.branch_signature = all_nodes[a].branch_signature | all_nodes[b].branch_signature;
        parent.trait_divergence_count = trait_symmetric_diff_count(all_nodes[a].trait_matrix, all_nodes[b].trait_matrix);

        all_nodes[a].has_parent = true;
        all_nodes[a].parent_uuid = parent.node_uuid;
        all_nodes[b].has_parent = true;
        all_nodes[b].parent_uuid = parent.node_uuid;
        all_nodes[a].branch_length = branch_a;
        all_nodes[b].branch_length = branch_b;

        all_nodes.push_back(parent);
        return all_nodes.size() - 1;
    };

    while (active.size() > 2) {
        size_t n = active.size();
        std::map<size_t, double> total;
        for (size_t idx : active) {
            double sum = 0.0;
            for (size_t other : active) if (other != idx) sum += distances[idx][other];
            total[idx] = sum;
        }

        size_t best_i = 0, best_j = 0;
        double min_q = kInf;
        for (size_t i = 0; i < n; i++) {
            for (size_t j = i + 1; j < n; j++) {
                size_t a = active[i], b = active[j];
                double q = static_cast<double>(n - 2) * distances[a][b] - total[a] - total[b];
                if (q < min_q) { min_q = q; best_i = i; best_j = j; }
            }
        }
        size_t a = active[best_i], b = active[best_j];
        double d_ab = distances[a][b];
        double branch_a = 0.5 * d_ab + (total[a] - total[b]) / (2.0 * static_cast<double>(n - 2));
        double branch_b = d_ab - branch_a;
        branch_a = std::max(0.0, branch_a);
        branch_b = std::max(0.0, branch_b);

        size_t p = make_child(a, b, branch_a, branch_b);

        std::map<size_t, double> new_row;
        for (size_t idx : active) {
            if (idx == a || idx == b) continue;
            double d_new = std::max(0.0, 0.5 * (distances[a][idx] + distances[b][idx] - d_ab));
            new_row[idx] = d_new;
            distances[idx][p] = d_new;
            distances[idx].erase(a);
            distances[idx].erase(b);
        }
        distances[p] = new_row;
        distances.erase(a);
        distances.erase(b);

        std::vector<size_t> next_active;
        for (size_t idx : active) if (idx != a && idx != b) next_active.push_back(idx);
        next_active.push_back(p);
        active = std::move(next_active);
    }

    size_t a = active[0], b = active[1];
    double d_ab = distances[a][b];
    make_child(a, b, d_ab / 2.0, d_ab / 2.0);
    return all_nodes;
}

std::map<std::string, std::vector<std::string>> compute_clades(
    const std::map<std::string, TraitSet>& named_traits, double threshold) {
    std::vector<std::string> labels;
    for (const auto& kv : named_traits) labels.push_back(kv.first);

    std::map<std::string, std::string> parent;
    for (const auto& label : labels) parent[label] = label;

    std::function<std::string(const std::string&)> find = [&](const std::string& x) -> std::string {
        std::string root = x;
        while (parent[root] != root) root = parent[root];
        std::string cur = x;
        while (parent[cur] != root) {
            std::string next = parent[cur];
            parent[cur] = root;
            cur = next;
        }
        return root;
    };
    auto do_union = [&](const std::string& a, const std::string& b) {
        std::string ra = find(a), rb = find(b);
        if (ra != rb) parent[ra] = rb;
    };

    for (size_t i = 0; i < labels.size(); i++) {
        for (size_t j = i + 1; j < labels.size(); j++) {
            double d = jaccard_distance(named_traits.at(labels[i]), named_traits.at(labels[j]));
            if (d <= threshold) do_union(labels[i], labels[j]);
        }
    }

    std::map<std::string, std::vector<std::string>> groups;
    for (const auto& label : labels) groups[find(label)].push_back(label);

    std::map<std::string, std::vector<std::string>> result;
    for (auto& kv : groups) {
        std::sort(kv.second.begin(), kv.second.end());
        result[kv.second.front()] = kv.second;
    }
    return result;
}

std::string visualize_tree(const PhyloTree& nodes) {
    std::map<PhyloUuid, std::vector<size_t>> children;
    std::vector<size_t> roots;
    for (size_t i = 0; i < nodes.size(); i++) {
        if (nodes[i].has_parent) {
            children[nodes[i].parent_uuid].push_back(i);
        } else {
            roots.push_back(i);
        }
    }

    std::string out;
    std::function<void(size_t, const std::string&, bool)> print_node =
        [&](size_t idx, const std::string& prefix, bool is_last) {
            const PhyloNode& node = nodes[idx];
            std::string connector = is_last ? "\xe2\x94\x94\xe2\x94\x80\xe2\x94\x80 " : "\xe2\x94\x9c\xe2\x94\x80\xe2\x94\x80 ";
            std::string label = node.metadata_name.empty()
                ? "internal(" + phylo_uuid_to_hex(node.node_uuid).substr(0, 8) + ")"
                : node.metadata_name;
            char buf[128];
            snprintf(buf, sizeof(buf), "  [gen=%llu, branch_len=%.4f, leaves=%llu]\n",
                     (unsigned long long)node.generation_index, node.branch_length, (unsigned long long)node.leaf_count);
            out += prefix + connector + label + buf;
            auto it = children.find(node.node_uuid);
            if (it == children.end()) return;
            const auto& kids = it->second;
            std::string new_prefix = prefix + (is_last ? "    " : "\xe2\x94\x82   ");
            for (size_t k = 0; k < kids.size(); k++) print_node(kids[k], new_prefix, k == kids.size() - 1);
        };

    for (size_t r : roots) {
        const PhyloNode& root = nodes[r];
        std::string label = root.metadata_name.empty()
            ? "ROOT(" + phylo_uuid_to_hex(root.node_uuid).substr(0, 8) + ")"
            : root.metadata_name;
        char buf[64];
        snprintf(buf, sizeof(buf), "  [gen=%llu, leaves=%llu]\n",
                 (unsigned long long)root.generation_index, (unsigned long long)root.leaf_count);
        out += label + buf;
        auto it = children.find(root.node_uuid);
        if (it == children.end()) continue;
        const auto& kids = it->second;
        for (size_t k = 0; k < kids.size(); k++) print_node(kids[k], "", k == kids.size() - 1);
    }
    return out;
}

}  // namespace pfs_engine
