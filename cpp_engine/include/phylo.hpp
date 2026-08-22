#pragma once
// C++ port of PhylogeneticAnalyzer.py + TreeConstructor.py -- the CLADE
// CLUSTERING half of the system. Deliberately kept fully independent of
// lineage_store.hpp: this project's own design explicitly distinguishes
// the Lineage DAG (one file's real edit history, in lineage_store.hpp)
// from the Clade Clustering Tree (unrelated files grouped by content
// similarity, here) -- see TreeConstructor.py's own module docstring.
// Conflating the two was a real mistake caught earlier in this project;
// this header intentionally shares no types with lineage_store.hpp,
// including its own separate 16-byte node-uuid concept.
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

// SIMILARITY_PROFILE: a much finer chunking pass than STORAGE_PROFILE,
// used ONLY to build the Jaccard trait-set for clade clustering -- never
// stored/reconstructed from. Same mask/min/max as PhylogeneticAnalyzer.py.
constexpr uint64_t kSimilarityChunkMask = 0xFF;
constexpr size_t kSimilarityMinSize = 128;
constexpr size_t kSimilarityMaxSize = 512;

using TraitSet = std::set<Bytes32>;

// Chunks file_path with SIMILARITY_PROFILE and returns the set of
// SHA-256 fingerprints of its chunks (the "genetic material").
TraitSet extract_similarity_traits(const std::string& file_path);
// Same, over an already-in-memory buffer (e.g. a StoragePipeline write's
// own mmap'd source) -- avoids a second file read at write time.
TraitSet extract_similarity_traits(const uint8_t* data, size_t size);

// Below this many chunks, a Jaccard distance is noise, not signal: with
// kSimilarityMinSize/kSimilarityMaxSize's 128-512B chunks, a handful of
// chunks means the whole file is only a few hundred bytes to ~1-2KB, so
// ONE differing chunk can by itself swing the distance to a misleading
// 1.0 ("nothing shared") even between two otherwise near-identical
// files. Same value and rationale as PhylogeneticAnalyzer.py's
// MIN_RELIABLE_TRAIT_COUNT -- keep them equal so `--engine python` and
// `--engine cpp` warn identically.
constexpr size_t kMinReliableTraitCount = 8;

// True if `traits` has enough chunks for a Jaccard distance computed
// from it to be statistically meaningful -- see kMinReliableTraitCount.
bool trait_set_is_reliable(const TraitSet& traits);

// Jaccard Distance: 1 - (|A ∩ B| / |A ∪ B|). 0.0 = identical, 1.0 =
// nothing shared (or both empty).
double jaccard_distance(const TraitSet& a, const TraitSet& b);

struct PhyloNode {
    PhyloUuid node_uuid{};
    bool has_parent = false;
    PhyloUuid parent_uuid{};
    std::string metadata_name;  // set for leaves; empty for synthetic internal cluster nodes
    uint64_t generation_index = 0;
    uint32_t branch_signature = 0;  // one bit per ORIGINAL leaf (caps at 32 leaves, matching Python)
    uint64_t leaf_count = 1;
    double height = 0.0;          // UPGMA only (ultrametric); meaningless for NJ
    double branch_length = 0.0;   // universal: edge length up to this node's parent
    uint64_t trait_divergence_count = 0;  // clustering diagnostic, NOT a real storage delta
    TraitSet trait_matrix;
};

// Leaves at indices [0, named_traits.size()), insertion order == the
// map's own (sorted, since std::map) iteration order; internal nodes
// appended afterward in merge order. Index-stable throughout (only ever
// grown via push_back), so the tree can be safely indexed by uuid or
// position after construction.
using PhyloTree = std::vector<PhyloNode>;

// UPGMA: assumes a constant mutation rate (ultrametric tree -- every
// leaf the same total height from the root).
PhyloTree build_tree_upgma_from_traits(const std::map<std::string, TraitSet>& named_traits);

// Neighbor-Joining: does not assume a constant rate; asymmetric branch
// lengths. Rooted at the final join (a standard, simple choice).
PhyloTree build_tree_nj_from_traits(const std::map<std::string, TraitSet>& named_traits);

constexpr double kDefaultCladeThreshold = 0.80;  // design doc's own recommended value

// Partitions labels into clades: connected components of the graph
// where an edge connects any two labels with Jaccard distance <=
// threshold. Keyed by each clade's lexicographically-smallest member.
// Singleton clades (no neighbor within threshold) are included too.
std::map<std::string, std::vector<std::string>> compute_clades(
    const std::map<std::string, TraitSet>& named_traits, double threshold = kDefaultCladeThreshold);

// ASCII tree rendering, matching TreeConstructor.py's visualize_tree
// exactly (└──/├── box-drawing connectors).
std::string visualize_tree(const PhyloTree& nodes);

}  // namespace pfs_engine
