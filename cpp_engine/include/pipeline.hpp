#pragma once
// The C++ engine's write and read paths: ports of gearhash/pipeline.py's
// secure_and_persist_file() and reconstruct.py's reconstruct(), including
// Ancestral Hardening (widely shared chunks get a mirror copy; a read
// falls back to it, always with a warning).
#include <cstdint>
#include <deque>
#include <map>
#include <string>
#include <vector>

#include "crypto_utils.hpp"
#include "dedup_index.hpp"
#include "keyring.hpp"

namespace pfs_engine {

// AES-GCM bytes per chunk: 12-byte IV + 16-byte tag. A chunk's plaintext
// length is its stored length minus this (as reconstruct.py's AEAD_OVERHEAD).
constexpr uint64_t kAeadOverhead = 28;

struct WriteResult {
    std::string manifest_path;
    uint64_t total_blocks = 0;
    uint64_t new_chunks_written = 0;
    uint64_t duplicate_chunks_found = 0;
    bool was_duplicate_of_existing = false;  // true: the content was already stored; nothing new written
};

struct RefCountRepairReport {
    uint64_t chunks_checked = 0;
    uint64_t chunks_corrected = 0;
};

struct OrphanSweepReport {
    uint64_t removed = 0;
    uint64_t tmp_removed = 0;
};

struct VacuumReport {
    uint64_t old_size = 0;
    uint64_t new_size = 0;
    uint64_t bytes_reclaimed = 0;
    uint64_t live_chunks = 0;
    uint64_t chunks_corrected = 0;  // from the rebuild_ref_counts pass
    uint64_t orphaned_manifests_removed = 0;
    uint64_t orphaned_tmp_files_removed = 0;
    // Mirror container compaction; all 0 when nothing mirrored died.
    uint64_t mirror_old_size = 0;
    uint64_t mirror_new_size = 0;
    uint64_t mirror_bytes_reclaimed = 0;
    uint64_t live_mirrors = 0;
};

struct FsckReport {
    uint64_t scanned = 0;
    uint64_t healthy = 0;
    uint64_t healed = 0;
    std::vector<std::string> unrecoverable;  // hex content hashes
};

class StoragePipeline {
public:
    // A chunk referenced by this many manifests gets a mirror copy (pipeline.py's MIRROR_REF_THRESHOLD).
    static constexpr uint32_t kMirrorRefThreshold = 3;

    StoragePipeline(std::string storage_root, const Bytes32& kek);

    // Chunks, dedups, encrypts new chunks under the current DEK, mirrors any
    // chunk crossing kMirrorRefThreshold and writes the KEK-encrypted manifest.
    // Content identical to a stored manifest writes nothing (the index
    // transaction is rolled back).
    WriteResult secure_and_persist_file(const std::string& file_path,
                                         const std::string& original_filename);

    // Reconstructs a manifest to output_path, falling back to a chunk's
    // mirror (with a WARNING) when its primary copy fails. Throws if a chunk
    // has no working copy.
    void reconstruct(const std::string& manifest_path, const std::string& output_path);

    // One chunk's verified plaintext: primary copy, then mirror (with a
    // WARNING); throws if neither works. mirror_fd is opened lazily and left
    // for the caller to close. Shared by reconstruct() and ManifestReader.
    std::vector<uint8_t> fetch_verified_block(uint64_t idx, const Bytes32& content_hash,
                                              const BlockEntry& loc, int primary_fd, int& mirror_fd);

    // Decrements every chunk's ref count and removes the manifest; space is reclaimed by vacuum().
    void delete_file(const std::string& manifest_path);

    // Recomputes every chunk's ref_count from the manifests in
    // live_manifest_filenames (catalog and lineage). vacuum() runs it first.
    RefCountRepairReport rebuild_ref_counts(const std::vector<std::string>& live_manifest_filenames);

    // Removes unlisted .manifest.pfsm files and leftover .manifest.pfsm.tmp files.
    OrphanSweepReport sweep_orphaned_manifests(const std::vector<std::string>& live_manifest_filenames);

    // Repairs ref counts, sweeps orphaned manifests, then rewrites the
    // container with live chunks only (atomic replace), updates offsets and
    // compacts the index. The mirror container is compacted too, but only
    // when a mirrored chunk died.
    VacuumReport vacuum(const std::vector<std::string>& live_manifest_filenames);

    // Verifies every live chunk and repairs a bad primary from its mirror in
    // place (same length: AES-GCM overhead is fixed). Unrecoverable chunks are
    // reported.
    FsckReport verify_and_repair();

    // For operations that read stored chunks directly (merge_branches).
    DedupIndex& dedup_index() { return index_; }
    KeyRing& keyring() { return keyring_; }
    const std::string& container_path() const { return container_path_; }
    const std::string& mirror_container_path() const { return mirror_container_path_; }
    const std::string& storage_root() const { return storage_root_; }
    const Bytes32& kek() const { return kek_; }

private:
    std::string storage_root_;
    Bytes32 kek_;
    std::string container_path_;
    std::string mirror_container_path_;
    DedupIndex index_;
    KeyRing keyring_;
};

// Read-only, random-access view of one stored version: a read decrypts
// only the chunks it overlaps (the counterpart of reconstruct.py's
// ManifestReader). The chunk table is resolved once, so it keeps returning
// this version after later commits. Chunks are verified via
// fetch_verified_block(); the total size is checked up front, since a
// partial read can't check the whole-file hash. `pipeline` must outlive
// it; not thread-safe (pfs_fuse_cpp is single-threaded).
class ManifestReader {
public:
    static constexpr size_t kCacheChunks = 8;  // recent chunks, for small sequential reads

    ManifestReader(StoragePipeline& pipeline, const std::string& manifest_path);
    ~ManifestReader();
    ManifestReader(const ManifestReader&) = delete;
    ManifestReader& operator=(const ManifestReader&) = delete;

    uint64_t size() const { return size_; }
    // Copies up to `size` bytes from `offset`; returns the count (0 at the end). Throws on an unrecoverable chunk.
    size_t read(uint64_t offset, size_t size, uint8_t* out);

private:
    const std::vector<uint8_t>& chunk(uint64_t idx);

    StoragePipeline& pipeline_;
    std::vector<Bytes32> hashes_;
    std::vector<BlockEntry> locations_;
    std::vector<uint64_t> starts_;  // plaintext offset of each block
    uint64_t size_ = 0;
    int primary_fd_ = -1;
    int mirror_fd_ = -1;
    std::map<uint64_t, std::vector<uint8_t>> cache_;
    std::deque<uint64_t> cache_order_;  // oldest first
};

}  // namespace pfs_engine
