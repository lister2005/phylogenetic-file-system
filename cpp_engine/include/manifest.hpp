#pragma once
// The C++ engine's manifest: a metadata header and a flat array of 32-byte
// chunk hashes indexed by block_index. Not Python's pickled FKS table: a
// manifest is only ever read by dense block index, where a plain array is
// already O(1). Layout in MANIFEST_FORMAT.md.

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
    // Optional SIMILARITY_PROFILE fingerprint, used only for clade distances.
    std::optional<std::vector<Bytes32>> similarity_fingerprint;
};

class Manifest {
public:
    Manifest() = default;
    Manifest(ManifestMetadata metadata, std::vector<Bytes32> block_hashes);

    // Plaintext serialization; callers encrypt it.
    std::vector<uint8_t> serialize() const;
    static Manifest deserialize(const std::vector<uint8_t>& raw);

    const ManifestMetadata& metadata() const { return metadata_; }

    // Direct index; nullopt if block_index is out of range.
    std::optional<Bytes32> lookup(uint64_t block_index) const;

private:
    ManifestMetadata metadata_;
    std::vector<Bytes32> block_hashes_;
};

// content_sha256 -> "<64 hex>.manifest.pfsm": content-addressed, with an
// extension distinct from Python's .manifest.fks.
std::string manifest_filename_for(const Bytes32& content_sha256);

// Encrypts under the KEK (manifests are metadata) with the filename as
// AAD, and writes atomically.
void write_manifest_file(const std::string& path, const std::string& manifest_filename,
                          const Manifest& manifest, const Bytes32& kek);

Manifest read_manifest_file(const std::string& path, const std::string& manifest_filename,
                             const Bytes32& kek);

}  // namespace pfs_engine
