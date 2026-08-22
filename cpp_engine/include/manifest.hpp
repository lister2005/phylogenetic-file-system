#pragma once
// Per-file manifest -- the C++ engine's OWN format, not a port of
// gearhash/fks_index.py's pickled two-level perfect-hash (FKS)
// structure. That was a deliberate decision, not an oversight: pickle
// is a Python-specific serialization protocol not worth hand-
// replicating in C++, and FKS's whole point (guaranteed O(1)
// worst-case lookup via a randomized build-time construction) turned
// out to be solving a problem this data doesn't have -- checked against
// reconstruct.py directly: a manifest is ONLY ever looked up by
// block_index (0..total_blocks-1, dense and sequential, assigned in
// that exact order as a file is chunked), NEVER by content_hash. A
// perfect hash table is real machinery to guarantee O(1) lookup for an
// arbitrary key set; a plain array is ALREADY O(1) -- exact, not
// amortized -- when the key set is already a dense integer range. So
// this format is just: a small metadata header, then a flat array of
// 32-byte content hashes indexed directly by block_index.
//
// See cpp_port_plan.txt's "format compatibility findings" section for
// the full reasoning, and MANIFEST_FORMAT.md for the on-disk layout
// spec (byte-for-byte, for anyone -- including a portfolio reviewer --
// implementing a reader/writer independently).

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "crypto_utils.hpp"

namespace pfs_engine {

struct ManifestMetadata {
    std::string original_filename;
    Bytes32 content_sha256{};
    uint64_t total_blocks = 0;
    uint64_t original_size = 0;
    uint64_t new_chunks_written = 0;
    uint64_t duplicate_chunks_found = 0;
    uint32_t phenotype_mask = 0;
    std::string phenotype_name;
    // Precomputed SIMILARITY_PROFILE trait set (see
    // PhylogeneticAnalyzer.extract_traits) -- a set of 32-byte SHA-256
    // chunk fingerprints at a much finer granularity than storage
    // chunking, used only for clade-clustering distance, never for
    // reconstruction. Optional: absent until/unless the background
    // fingerprinting pass has run.
    std::optional<std::vector<Bytes32>> similarity_fingerprint;
};

class Manifest {
public:
    Manifest() = default;
    Manifest(ManifestMetadata metadata, std::vector<Bytes32> block_hashes);

    // Plaintext (unencrypted) serialization -- callers encrypt this
    // themselves, same division of responsibility as
    // FKSIndexBuilder.serialize() + StoragePipeline's own
    // crypto.encrypt_block call in the Python code.
    std::vector<uint8_t> serialize() const;
    static Manifest deserialize(const std::vector<uint8_t>& raw);

    const ManifestMetadata& metadata() const { return metadata_; }

    // O(1) exact (not amortized) -- direct array index. Returns
    // nullopt only if block_index is out of range (a manifest
    // corruption/mismatch signal to the caller, same as
    // FKSLookupEngine.lookup() returning None for a missing block).
    std::optional<Bytes32> lookup(uint64_t block_index) const;

private:
    ManifestMetadata metadata_;
    std::vector<Bytes32> block_hashes_;
};

// content_sha256 -> "<64 lowercase hex chars>.manifest.pfsm" -- same
// content-addressed-filename idea as Python's _manifest_filename
// (identity comes from the file's own bytes, not a name chosen by
// whoever's writing it), deliberately a DIFFERENT extension
// (.manifest.pfsm vs .manifest.fks) so the two formats can never be
// silently confused if a vault ever has both during a transition.
std::string manifest_filename_for(const Bytes32& content_sha256);

// Encrypts (AES-256-GCM under the KEK directly -- manifests are
// metadata, not bulk content, so they don't use a per-epoch DEK; see
// crypto.py's own docstring for why that's an intentional, not lazy,
// choice) and atomically writes a manifest to disk. AAD is bound to the
// manifest's own filename, matching secure_and_persist_file exactly.
void write_manifest_file(const std::string& path, const std::string& manifest_filename,
                          const Manifest& manifest, const Bytes32& kek);

Manifest read_manifest_file(const std::string& path, const std::string& manifest_filename,
                             const Bytes32& kek);

}  // namespace pfs_engine
