#pragma once
// The engine's actual entry points -- write a file, read a file back --
// consolidating what was, until now, duplicated across several bench
// files (chunk -> hash -> dedup -> encrypt -> container -> manifest,
// repeated in engine_write_bench_v2, engine_write_read_bench[_v2], and
// keyring_rotation_test). Ports gearhash/pipeline.py's
// secure_and_persist_file() and reconstruct.py's reconstruct(), INCLUDING
// Ancestral Hardening (StoragePipeline.MIRROR_REF_THRESHOLD): a chunk
// that becomes widely shared enough gets a redundant copy in a separate
// mirror container, and a read whose primary copy fails integrity
// verification falls back to the mirror instead of failing outright --
// always surfacing that the primary was bad, never silently papering
// over real corruption (matches reconstruct.py's WARNING print exactly).
//
// This is also, finally, the actual C ABI surface cpp_port_plan.txt
// described as the goal for Component 1 (pfs_engine_write /
// pfs_engine_read) -- a thin C wrapper around this class is what a
// ctypes binding from Python (CLI/GUI) would call.
#include <cstdint>
#include <deque>
#include <map>
#include <string>
#include <vector>

#include "crypto_utils.hpp"
#include "dedup_index.hpp"
#include "keyring.hpp"

namespace pfs_engine {

// Bytes aead_encrypt() adds to every chunk: a 12-byte IV prefix and a
// 16-byte GCM tag (crypto_utils.hpp). A chunk's plaintext length is its
// stored length minus this -- what lets ManifestReader map byte offsets
// to chunks without any per-chunk length in the manifest itself.
// Matches reconstruct.py's AEAD_OVERHEAD.
constexpr uint64_t kAeadOverhead = 28;

struct WriteResult {
    std::string manifest_path;
    uint64_t total_blocks = 0;
    uint64_t new_chunks_written = 0;
    uint64_t duplicate_chunks_found = 0;
    bool was_duplicate_of_existing = false;  // true = this exact content was already stored; nothing new written
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
    uint64_t chunks_corrected = 0;    // from the rebuild_ref_counts pass folded in, matching vault_session.py's vacuum()
    uint64_t orphaned_manifests_removed = 0;
    uint64_t orphaned_tmp_files_removed = 0;
    // Ancestral Hardening mirror container compaction, matching
    // gearhash/pipeline.py's vacuum(). Stay 0 (not just "unset") when
    // this call had no mirrored chunk to reclaim -- the mirror container
    // is left completely untouched in that case, not just "reported as
    // zero savings".
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
    // A chunk referenced by this many manifests (or more) gets a
    // redundant copy in the mirror container the moment it crosses the
    // threshold -- matches pipeline.py's MIRROR_REF_THRESHOLD exactly.
    static constexpr uint32_t kMirrorRefThreshold = 3;

    StoragePipeline(std::string storage_root, const Bytes32& kek);

    // Chunks, dedups, encrypts new chunks under the current epoch's
    // DEK, mirrors any chunk that crosses kMirrorRefThreshold, and
    // writes the manifest (encrypted under the KEK directly). If the
    // resulting content is byte-identical to an already-stored
    // manifest, nothing new is written -- the dedup-index transaction
    // is rolled back instead of committed (the fix from
    // gearhash/pipeline.py's redundant-pre-hash removal, done natively
    // here from the start rather than ported as an afterthought).
    WriteResult secure_and_persist_file(const std::string& file_path,
                                         const std::string& original_filename);

    // Reconstructs a manifest's content to output_path. Tries each
    // block's PRIMARY copy first (seek, decrypt, verify its hash);
    // on ANY failure (I/O error, decrypt/auth failure, or a hash
    // mismatch), falls back to that chunk's mirror copy if one exists,
    // printing a WARNING either way -- recovering silently would hide
    // real corruption from whoever's relying on this data. Throws if
    // a block has no working copy at all.
    void reconstruct(const std::string& manifest_path, const std::string& output_path);

    // One chunk's verified plaintext: primary copy (from primary_fd)
    // first, then its Ancestral Hardening mirror, with the same WARNING
    // on mirror recovery and the same throw on no working copy as
    // reconstruct(). mirror_fd is opened lazily (only on a primary
    // failure) and left open for the caller to close. The one
    // implementation behind both reconstruct() and ManifestReader, so
    // the two can't drift apart on integrity checks or self-healing.
    std::vector<uint8_t> fetch_verified_block(uint64_t idx, const Bytes32& content_hash,
                                              const BlockEntry& loc, int primary_fd, int& mirror_fd);

    // Decrements the ref count on every chunk manifest_path's file
    // referenced, then removes the manifest itself. Does NOT reclaim
    // container space immediately -- chunks that drop to ref_count=0
    // stay in the container until vacuum() runs (rewriting the
    // container isn't cheap and shouldn't be a side effect of every
    // delete). Matches pipeline.py's delete_file exactly.
    void delete_file(const std::string& manifest_path);

    // Recomputes every chunk's ref_count from scratch by reading the
    // block list of every manifest in live_manifest_filenames (the
    // caller's catalog + full lineage history across every label --
    // the authoritative live set, same source Python's VaultSession
    // uses), rather than trusting the incrementally-maintained
    // counter. Called by vacuum() before the dead-chunk sweep.
    RefCountRepairReport rebuild_ref_counts(const std::vector<std::string>& live_manifest_filenames);

    // Removes .manifest.pfsm files on disk that live_manifest_filenames
    // doesn't list, plus any leftover .manifest.pfsm.tmp (an
    // interrupted atomic write's write-half). Matches
    // pipeline.py's sweep_orphaned_manifests.
    OrphanSweepReport sweep_orphaned_manifests(const std::vector<std::string>& live_manifest_filenames);

    // Reclaims container space from chunks with ref_count == 0:
    // rewrites the container with only live chunks (atomic replace),
    // updates the index's offsets to match, then compacts the SQLite
    // index if anything was actually dropped. Runs rebuild_ref_counts
    // first (self-heals ref-count drift the same call that reclaims
    // space) then sweep_orphaned_manifests, matching
    // vault_session.py's vacuum() folding all three together.
    //
    // Also compacts the Ancestral Hardening mirror container the same
    // way, but only when this call actually killed a mirrored chunk
    // (index_.remove()'s bool return tracks that per dead hash) -- the
    // dead-chunk sweep above already drops the corresponding `mirrors`
    // DB row; this additionally rewrites data_container_mirror.bin
    // itself to drop the dead BYTES, and updates every remaining live
    // mirror's index entry to its new offset. Skipped entirely (mirror
    // container untouched) when nothing mirrored actually died this call
    // -- most calls, since most chunks are never mirrored at all.
    VacuumReport vacuum(const std::vector<std::string>& live_manifest_filenames);

    // Ancestral Hardening's proactive half: scans every LIVE chunk
    // (ref_count > 0), verifies it decrypts and hashes correctly, and
    // self-heals in place from its mirror if the primary is bad and a
    // working mirror exists (a same-length overwrite -- AES-GCM's
    // overhead is fixed for a given plaintext size). A chunk that fails
    // with no working mirror is reported, never silently dropped.
    FsckReport verify_and_repair();

    // Accessors for cross-cutting operations that need to read a
    // specific already-stored chunk directly (currently: merge_branches,
    // see merge.hpp) -- exposed narrowly, not because StoragePipeline's
    // internals are otherwise meant to be public.
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

// Random-access, read-only view of one stored file version: serves any
// byte range by decrypting only the chunks that range overlaps, instead
// of reconstructing the whole file first -- what lets pfs_fuse_cpp
// stream reads of large files with bounded memory. The C++ counterpart
// of reconstruct.py's ManifestReader.
//
// The constructor decrypts the manifest and resolves every chunk's
// container location in one batched index query; that chunk table is a
// snapshot of this version, so a later commit to the same label doesn't
// change what an already-open reader returns. Every chunk returned is
// individually authenticated (AES-GCM with its hash as AAD, then its
// SHA-256 against the authenticated manifest's hash for that position)
// via fetch_verified_block(), mirror self-healing included. A partial
// read can NOT check the whole-file content_sha256 (that needs every
// byte); the total size is checked against the manifest up front.
// Holds a reference to `pipeline`, which must outlive it. Not
// thread-safe on its own -- callers serialize access (pfs_fuse_cpp runs
// single-threaded).
class ManifestReader {
public:
    static constexpr size_t kCacheChunks = 8;  // recently-decrypted chunks kept, for small sequential reads

    ManifestReader(StoragePipeline& pipeline, const std::string& manifest_path);
    ~ManifestReader();
    ManifestReader(const ManifestReader&) = delete;
    ManifestReader& operator=(const ManifestReader&) = delete;

    uint64_t size() const { return size_; }
    // Copies up to `size` bytes starting at `offset` into `out`; returns
    // the number copied (0 at or past the end). Throws on a chunk with
    // no working copy.
    size_t read(uint64_t offset, size_t size, uint8_t* out);

private:
    const std::vector<uint8_t>& chunk(uint64_t idx);

    StoragePipeline& pipeline_;
    std::vector<Bytes32> hashes_;
    std::vector<BlockEntry> locations_;
    std::vector<uint64_t> starts_;  // plaintext byte offset where each block begins
    uint64_t size_ = 0;
    int primary_fd_ = -1;
    int mirror_fd_ = -1;
    std::map<uint64_t, std::vector<uint8_t>> cache_;
    std::deque<uint64_t> cache_order_;  // oldest first
};

}  // namespace pfs_engine
