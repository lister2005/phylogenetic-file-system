#pragma once
// C++ port of PhylogeneticAnalyzer.py + TreeConstructor.py: clade
// clustering of different files by content similarity. Shares no types
// with lineage_store.hpp, which records a file's edit history.
#include <array>
#include <cstdint>
#include <map>
#include <set>
#include <string>
#include <vector>

#include "crypto_utils.hpp"

namespace pfs_engine {

using PhyloUuid = std::array<uint8_t, 16>;
PhyloUuid generate_phylo_uuid();
std::string phylo_uuid_to_hex(const PhyloUuid& id);

// SIMILARITY_PROFILE: a finer chunking used only for clade distances (same as Python).
constexpr uint64_t kSimilarityChunkMask = 0xFF;
constexpr size_t kSimilarityMinSize = 128;
constexpr size_t kSimilarityMaxSize = 512;

using TraitSet = std::set<Bytes32>;

// SHA-256 fingerprints of file_path's similarity chunks.
TraitSet extract_similarity_traits(const std::string& file_path);
// Same, from a buffer already in memory (no second read).
TraitSet extract_similarity_traits(const uint8_t* data, size_t size);

// Below this many chunks a Jaccard distance is noise. Equal to
// PhylogeneticAnalyzer.py's MIN_RELIABLE_TRAIT_COUNT, so both engines warn
// the same way.
constexpr size_t kMinReliableTraitCount = 8;

// True if `traits` has at least kMinReliableTraitCount chunks.
bool trait_set_is_reliable(const TraitSet& traits);

// 1 - |A ∩ B| / |A ∪ B|; 1.0 if both are empty.
double jaccard_distance(const TraitSet& a, const TraitSet& b);

struct PhyloNode {
    PhyloUuid node_uuid{};
    bool has_parent = false;
    PhyloUuid parent_uuid{};
    std::string metadata_name;  // leaves only
    uint64_t generation_index = 0;
    uint32_t branch_signature = 0;  // one bit per original leaf (32 max, as in Python)
    uint64_t leaf_count = 1;
    double height = 0.0;  // UPGMA only
    double branch_length = 0.0;  // edge length to the parent
    uint64_t trait_divergence_count = 0;  // clustering diagnostic, not a storage delta
    TraitSet trait_matrix;
};

// Leaves first, in the map's sorted order, then internal nodes in merge
// order. Only appended to, so indices stay valid.
using PhyloTree = std::vector<PhyloNode>;

// UPGMA: constant rate assumed (ultrametric tree).
PhyloTree build_tree_upgma_from_traits(const std::map<std::string, TraitSet>& named_traits);

// Neighbor-Joining: no constant rate; rooted at the final join.
PhyloTree build_tree_nj_from_traits(const std::map<std::string, TraitSet>& named_traits);

constexpr double kDefaultCladeThreshold = 0.80;  // D <= 0.80

// Clades: connected components of "Jaccard distance <= threshold", keyed
// by smallest member, singletons included.
std::map<std::string, std::vector<std::string>> compute_clades(
    const std::map<std::string, TraitSet>& named_traits, double threshold = kDefaultCladeThreshold);

// ASCII rendering, as TreeConstructor.py's visualize_tree.
std::string visualize_tree(const PhyloTree& nodes);

}  // namespace pfs_engine
