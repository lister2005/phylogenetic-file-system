#include "pipeline.hpp"

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <stdexcept>

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include <openssl/evp.h>

#include <algorithm>
#include <filesystem>
#include <map>

#include "chunker.h"
#include "gear_table.hpp"
#include "immutability.hpp"
#include "manifest.hpp"
#include "phenotype.hpp"
#include "phylo.hpp"

namespace pfs_engine {

namespace {

constexpr uint64_t kChunkMask = 0x1FFF;  // pipeline.py's chunk_mask
constexpr size_t kMinSize = 4096;  // STORAGE_MIN_SIZE
constexpr size_t kMaxSize = 16384;  // STORAGE_MAX_SIZE

// Chunks per dedup-index batch: one lookup_many and one upsert_many per
// window instead of two round trips per chunk. Keeps bound parameters (up
// to 600) under SQLite's limit (999 before 3.32), as in pipeline.py.
constexpr size_t kDedupBatchSize = 300;

struct ChunkSpan {
    size_t offset;
    size_t length;
    Bytes32 digest;
};

struct MappedFile {
    int fd = -1;
    uint8_t* data = nullptr;
    size_t size = 0;
    explicit MappedFile(const std::string& path) {
        fd = open(path.c_str(), O_RDONLY);
        if (fd < 0) throw std::runtime_error("failed to open source file '" + path + "': " + strerror(errno));
        struct stat st{};
        fstat(fd, &st);
        size = static_cast<size_t>(st.st_size);
        if (size > 0) {
            void* m = mmap(nullptr, size, PROT_READ, MAP_PRIVATE, fd, 0);
            if (m == MAP_FAILED) { close(fd); throw std::runtime_error("mmap failed: " + path); }
            data = static_cast<uint8_t*>(m);
        }
    }
    ~MappedFile() { if (data) munmap(data, size); if (fd >= 0) close(fd); }
};

// True if a file exists.
bool file_exists(const std::string& path) {
    struct stat st{};
    return stat(path.c_str(), &st) == 0;
}

// Returns a file's size, or 0 if it can't be read.
uint64_t file_size(const std::string& path) {
    struct stat st{};
    if (stat(path.c_str(), &st) != 0) return 0;
    return static_cast<uint64_t>(st.st_size);
}

}  // namespace

// Opens a vault's storage: containers, keyring, index and settings.
StoragePipeline::StoragePipeline(std::string storage_root, const Bytes32& kek)
    : storage_root_(std::move(storage_root)),
      kek_(kek),
      container_path_(storage_root_ + "/data_container.bin"),
      mirror_container_path_(storage_root_ + "/data_container_mirror.bin"),
      index_(storage_root_ + "/global_index.db", kek),
      keyring_(storage_root_, kek) {}

// Chunks a file, stores only the chunks not already in the vault, writes spares and the recipe.
WriteResult StoragePipeline::secure_and_persist_file(const std::string& file_path,
                                                       const std::string& original_filename) {
    MappedFile src(file_path);
    auto [epoch_id, dek] = keyring_.get_current_dek();  // once per call

    uint64_t current_offset = file_size(container_path_);
    int out_fd = open(container_path_.c_str(), O_WRONLY | O_CREAT | O_APPEND, 0600);
    if (out_fd < 0) throw std::runtime_error("failed to open container '" + container_path_ + "' for append: " + strerror(errno));

    // Opened only if a chunk crosses the mirror threshold.
    int mirror_read_primary_fd = -1;  // reads a stored chunk back to copy it
    int mirror_write_fd = -1;
    uint64_t mirror_offset = file_exists(mirror_container_path_) ? file_size(mirror_container_path_) : 0;

    std::vector<Bytes32> block_hashes;
    size_t cursor = 0;
    uint64_t rolling_hash = 0;
    uint64_t new_chunks = 0, dup_chunks = 0;

    index_.begin();
    try {
        // Windowed batching: gather a window (offsets + digests), resolve it with
        // one lookup_many, apply ref counts and mirroring in chunk order against
        // local_state, then one upsert_many. A hash repeated within a window
        // collapses into one final row; the end state matches chunk-at-a-time.
        while (cursor < src.size) {
            std::vector<ChunkSpan> window;
            window.reserve(kDedupBatchSize);
            while (window.size() < kDedupBatchSize && cursor < src.size) {
                size_t chunk_len = scan_chunk_c(src.data, src.size, cursor, &rolling_hash,
                                                 kChunkMask, kMinSize, kMaxSize, kGearTable);
                if (chunk_len == 0) break;
                Bytes32 digest = sha256(src.data + cursor, chunk_len);
                block_hashes.push_back(digest);
                window.push_back(ChunkSpan{cursor, chunk_len, digest});
                cursor += chunk_len;
            }
            if (window.empty()) break;

            std::vector<Bytes32> window_hashes;
            window_hashes.reserve(window.size());
            for (const auto& span : window) window_hashes.push_back(span.digest);
            std::map<Bytes32, BlockEntry> db_state = index_.lookup_many(window_hashes);

            std::map<Bytes32, BlockEntry> local_state;
            for (const auto& span : window) {
                const uint8_t* chunk_ptr = src.data + span.offset;
                bool crossed = false;
                BlockEntry* entry_ptr = nullptr;

                auto it = local_state.find(span.digest);
                if (it != local_state.end()) {
                    it->second.ref_count += 1;
                    dup_chunks++;
                    crossed = (it->second.ref_count == StoragePipeline::kMirrorRefThreshold);
                    entry_ptr = &it->second;
                } else {
                    auto dbit = db_state.find(span.digest);
                    if (dbit != db_state.end()) {
                        BlockEntry e = dbit->second;
                        e.ref_count += 1;
                        auto inserted = local_state.emplace(span.digest, e);
                        dup_chunks++;
                        crossed = (e.ref_count == StoragePipeline::kMirrorRefThreshold);
                        entry_ptr = &inserted.first->second;
                    } else {
                        std::vector<uint8_t> encrypted =
                            aead_encrypt(dek, chunk_ptr, span.length, span.digest.data(), span.digest.size());
                        if (write(out_fd, encrypted.data(), encrypted.size()) != static_cast<ssize_t>(encrypted.size())) {
                            throw std::runtime_error("failed writing container");
                        }
                        BlockEntry e{current_offset, encrypted.size(), 1, epoch_id};
                        current_offset += encrypted.size();
                        new_chunks++;
                        auto inserted = local_state.emplace(span.digest, e);
                        entry_ptr = &inserted.first->second;
                        // a new chunk (ref_count 1) can't equal the threshold
                    }
                }

                // Crossing the threshold: copy the ciphertext as-is into the mirror
                // container (once, as pipeline.py does).
                if (crossed && !index_.get_mirror(span.digest)) {
                    if (mirror_read_primary_fd < 0) {
                        mirror_read_primary_fd = open(container_path_.c_str(), O_RDONLY);
                    }
                    if (mirror_write_fd < 0) {
                        mirror_write_fd = open(mirror_container_path_.c_str(),
                                                O_WRONLY | O_CREAT | O_APPEND, 0600);
                    }
                    std::vector<uint8_t> mirrored_bytes(entry_ptr->length);
                    if (pread(mirror_read_primary_fd, mirrored_bytes.data(), entry_ptr->length,
                              static_cast<off_t>(entry_ptr->offset)) != static_cast<ssize_t>(entry_ptr->length)) {
                        throw std::runtime_error("failed reading primary chunk to mirror it");
                    }
                    if (write(mirror_write_fd, mirrored_bytes.data(), mirrored_bytes.size()) !=
                        static_cast<ssize_t>(mirrored_bytes.size())) {
                        throw std::runtime_error("failed writing mirror container");
                    }
                    index_.set_mirror(span.digest, mirror_offset, mirrored_bytes.size());
                    mirror_offset += mirrored_bytes.size();
                }
            }

            std::vector<std::tuple<Bytes32, uint64_t, uint64_t, uint32_t, uint32_t>> to_upsert;
            to_upsert.reserve(local_state.size());
            for (const auto& [hash, e] : local_state) {
                to_upsert.emplace_back(hash, e.offset, e.length, e.ref_count, e.epoch_id);
            }
            index_.upsert_many(to_upsert);
        }
        fsync(out_fd);
        if (mirror_write_fd >= 0) fsync(mirror_write_fd);
    } catch (...) {
        index_.rollback();
        close(out_fd);
        if (mirror_read_primary_fd >= 0) close(mirror_read_primary_fd);
        if (mirror_write_fd >= 0) close(mirror_write_fd);
        throw;
    }
    close(out_fd);
    if (mirror_read_primary_fd >= 0) close(mirror_read_primary_fd);
    if (mirror_write_fd >= 0) close(mirror_write_fd);

    // Whole-file hash from the mmapped buffer: no second read.
    Bytes32 content_sha256 = sha256(src.data, src.size);
    std::string manifest_filename = manifest_filename_for(content_sha256);
    std::string manifest_path = storage_root_ + "/" + manifest_filename;

    WriteResult result;
    result.manifest_path = manifest_path;
    result.total_blocks = block_hashes.size();
    result.new_chunks_written = new_chunks;
    result.duplicate_chunks_found = dup_chunks;

    if (file_exists(manifest_path)) {
        // Already stored: nothing was appended, so roll back the ref-count changes.
        index_.rollback();
        result.was_duplicate_of_existing = true;
        return result;
    }
    index_.commit();

    ManifestMetadata meta;
    meta.original_filename = original_filename;
    meta.content_sha256 = content_sha256;
    meta.total_blocks = block_hashes.size();
    meta.original_size = src.size;
    meta.new_chunks_written = new_chunks;
    meta.duplicate_chunks_found = dup_chunks;
    Phenotype phenotype = detect_phenotype(src.data, std::min<size_t>(src.size, 64));
    meta.phenotype_mask = phenotype.mask;
    meta.phenotype_name = phenotype.name;

    // Similarity fingerprint, computed synchronously from the same mmapped buffer.
    TraitSet fingerprint = extract_similarity_traits(src.data, src.size);
    meta.similarity_fingerprint = std::vector<Bytes32>(fingerprint.begin(), fingerprint.end());

    Manifest manifest(meta, block_hashes);
    write_manifest_file(manifest_path, manifest_filename, manifest, kek_);
    return result;
}

// Reads, decrypts and checks one chunk; falls back to its spare copy if the main copy is damaged.
std::vector<uint8_t> StoragePipeline::fetch_verified_block(uint64_t idx, const Bytes32& content_hash,
                                                            const BlockEntry& loc, int primary_fd, int& mirror_fd) {
    Bytes32 dek = keyring_.get_dek(loc.epoch_id);

    std::vector<uint8_t> plaintext;
    bool ok = false;
    std::string primary_error;
    try {
        std::vector<uint8_t> payload(loc.length);
        if (pread(primary_fd, payload.data(), loc.length, static_cast<off_t>(loc.offset)) !=
            static_cast<ssize_t>(loc.length)) {
            throw std::runtime_error("short read");
        }
        plaintext = aead_decrypt(dek, payload.data(), payload.size(), content_hash.data(), content_hash.size());
        if (sha256(plaintext.data(), plaintext.size()) == content_hash) {
            ok = true;
        } else {
            primary_error = "decrypted content hash doesn't match the manifest's record";
        }
    } catch (const std::exception& e) {
        primary_error = e.what();
    }

    if (!ok) {
        // Mirror fallback, always reported.
        auto mirror_loc = index_.get_mirror(content_hash);
        if (mirror_loc && file_exists(mirror_container_path_)) {
            if (mirror_fd < 0) mirror_fd = open(mirror_container_path_.c_str(), O_RDONLY);
            try {
                std::vector<uint8_t> mirror_payload(mirror_loc->length);
                if (pread(mirror_fd, mirror_payload.data(), mirror_loc->length,
                          static_cast<off_t>(mirror_loc->offset)) == static_cast<ssize_t>(mirror_loc->length)) {
                    std::vector<uint8_t> candidate = aead_decrypt(
                        dek, mirror_payload.data(), mirror_payload.size(), content_hash.data(), content_hash.size());
                    if (sha256(candidate.data(), candidate.size()) == content_hash) {
                        plaintext = std::move(candidate);
                        ok = true;
                        fprintf(stderr,
                            "WARNING: block %llu failed on its primary copy (%s) -- recovered from its "
                            "Ancestral Hardening mirror instead. The primary copy is damaged.\n",
                            (unsigned long long)idx, primary_error.c_str());
                    }
                }
            } catch (const std::exception&) {
                // mirror failed too
            }
        }
    }

    if (!ok) {
        throw std::runtime_error(
            "block " + std::to_string(idx) + " failed integrity verification on its primary copy (" +
            primary_error + "), and either has no Ancestral Hardening mirror or the mirror also failed "
            "-- this data is genuinely unrecoverable.");
    }
    return plaintext;
}

// Rebuilds a whole file from its recipe and checks it against the original's hash.
void StoragePipeline::reconstruct(const std::string& manifest_path, const std::string& output_path) {
    std::string manifest_filename = manifest_path.substr(manifest_path.find_last_of('/') + 1);
    Manifest manifest = read_manifest_file(manifest_path, manifest_filename, kek_);

    int primary_fd = open(container_path_.c_str(), O_RDONLY);
    if (primary_fd < 0) throw std::runtime_error("failed to open container '" + container_path_ + "': " + strerror(errno));
    int mirror_fd = -1;  // opened only if a primary copy fails

    std::ofstream out(output_path, std::ios::binary | std::ios::trunc);
    if (!out) {
        close(primary_fd);
        throw std::runtime_error("failed to open output file '" + output_path + "': " + strerror(errno));
    }

    EVP_MD_CTX* hash_ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(hash_ctx, EVP_sha256(), nullptr);
    uint64_t bytes_written = 0;

    try {
        for (uint64_t idx = 0; idx < manifest.metadata().total_blocks; idx++) {
            auto hash_opt = manifest.lookup(idx);
            if (!hash_opt) {
                throw std::runtime_error("manifest declares block " + std::to_string(idx) + " but it's missing");
            }
            auto loc = index_.lookup(*hash_opt);
            if (!loc) {
                throw std::runtime_error("block " + std::to_string(idx) + " missing from the global block index");
            }
            std::vector<uint8_t> plaintext = fetch_verified_block(idx, *hash_opt, *loc, primary_fd, mirror_fd);
            out.write(reinterpret_cast<const char*>(plaintext.data()), static_cast<std::streamsize>(plaintext.size()));
            EVP_DigestUpdate(hash_ctx, plaintext.data(), plaintext.size());
            bytes_written += plaintext.size();
        }
    } catch (...) {
        close(primary_fd);
        if (mirror_fd >= 0) close(mirror_fd);
        EVP_MD_CTX_free(hash_ctx);
        throw;
    }
    close(primary_fd);
    if (mirror_fd >= 0) close(mirror_fd);
    out.close();

    Bytes32 final_hash{};
    unsigned int final_len = 0;
    EVP_DigestFinal_ex(hash_ctx, final_hash.data(), &final_len);
    EVP_MD_CTX_free(hash_ctx);

    if (bytes_written != manifest.metadata().original_size) {
        throw std::runtime_error("reconstructed " + std::to_string(bytes_written) + " bytes, expected " +
                                  std::to_string(manifest.metadata().original_size));
    }
    if (final_hash != manifest.metadata().content_sha256) {
        throw std::runtime_error("reconstructed content hash does not match the manifest's recorded hash");
    }
}

// Opens a recipe for random-access reads, as the mounted folder needs.
ManifestReader::ManifestReader(StoragePipeline& pipeline, const std::string& manifest_path)
    : pipeline_(pipeline) {
    std::string manifest_filename = manifest_path.substr(manifest_path.find_last_of('/') + 1);
    Manifest manifest = read_manifest_file(manifest_path, manifest_filename, pipeline_.kek());

    uint64_t total_blocks = manifest.metadata().total_blocks;
    hashes_.reserve(total_blocks);
    for (uint64_t idx = 0; idx < total_blocks; idx++) {
        auto hash_opt = manifest.lookup(idx);
        if (!hash_opt) {
            throw std::runtime_error("manifest declares block " + std::to_string(idx) + " but it's missing");
        }
        hashes_.push_back(*hash_opt);
    }

    std::map<Bytes32, BlockEntry> found = pipeline_.dedup_index().lookup_many(hashes_);
    locations_.reserve(total_blocks);
    starts_.reserve(total_blocks);
    uint64_t position = 0;
    for (uint64_t idx = 0; idx < total_blocks; idx++) {
        auto it = found.find(hashes_[idx]);
        if (it == found.end()) {
            throw std::runtime_error("block " + std::to_string(idx) + " missing from the global block index");
        }
        if (it->second.length < kAeadOverhead) {
            throw std::runtime_error("block " + std::to_string(idx) + " has an impossible stored length");
        }
        locations_.push_back(it->second);
        starts_.push_back(position);
        position += it->second.length - kAeadOverhead;
    }
    if (position != manifest.metadata().original_size) {
        throw std::runtime_error("chunk table adds up to " + std::to_string(position) + " bytes, manifest records " +
                                  std::to_string(manifest.metadata().original_size));
    }
    size_ = position;

    primary_fd_ = open(pipeline_.container_path().c_str(), O_RDONLY);
    if (primary_fd_ < 0) {
        throw std::runtime_error("failed to open container '" + pipeline_.container_path() + "': " + strerror(errno));
    }
}

ManifestReader::~ManifestReader() {
    if (primary_fd_ >= 0) close(primary_fd_);
    if (mirror_fd_ >= 0) close(mirror_fd_);
}

// Returns one decrypted chunk, from a small cache when possible.
const std::vector<uint8_t>& ManifestReader::chunk(uint64_t idx) {
    auto it = cache_.find(idx);
    if (it != cache_.end()) return it->second;
    std::vector<uint8_t> plaintext =
        pipeline_.fetch_verified_block(idx, hashes_[idx], locations_[idx], primary_fd_, mirror_fd_);
    if (plaintext.size() != locations_[idx].length - kAeadOverhead) {
        throw std::runtime_error("block " + std::to_string(idx) + " decrypted to an unexpected length");
    }
    if (cache_.size() >= kCacheChunks) {
        cache_.erase(cache_order_.front());
        cache_order_.pop_front();
    }
    cache_order_.push_back(idx);
    return cache_.emplace(idx, std::move(plaintext)).first->second;
}

// Copies size bytes from offset into out, decrypting only the chunks that range touches.
size_t ManifestReader::read(uint64_t offset, size_t size, uint8_t* out) {
    if (offset >= size_ || size == 0) return 0;
    uint64_t end = std::min<uint64_t>(offset + size, size_);
    // Last block starting at or before `offset`.
    uint64_t idx = static_cast<uint64_t>(std::upper_bound(starts_.begin(), starts_.end(), offset) - starts_.begin()) - 1;
    uint64_t position = offset;
    size_t copied = 0;
    while (position < end) {
        const std::vector<uint8_t>& data = chunk(idx);
        uint64_t start = starts_[idx];
        uint64_t take_from = position - start;
        uint64_t take_to = std::min<uint64_t>(data.size(), end - start);
        memcpy(out + copied, data.data() + take_from, take_to - take_from);
        copied += take_to - take_from;
        position = start + take_to;
        idx++;
    }
    return copied;
}

// Removes a recipe and lowers the reference counts of its chunks.
void StoragePipeline::delete_file(const std::string& manifest_path) {
    if (!file_exists(manifest_path)) {
        throw std::runtime_error("manifest not found: " + manifest_path);
    }
    std::string manifest_filename = manifest_path.substr(manifest_path.find_last_of('/') + 1);
    Manifest manifest = read_manifest_file(manifest_path, manifest_filename, kek_);

    index_.begin();
    try {
        for (uint64_t idx = 0; idx < manifest.metadata().total_blocks; idx++) {
            auto hash_opt = manifest.lookup(idx);
            if (hash_opt) index_.decrement_ref(*hash_opt);
        }
    } catch (...) {
        index_.rollback();
        throw;
    }
    index_.commit();

    set_immutable(manifest_path, false);
    if (remove(manifest_path.c_str()) != 0) {
        throw std::runtime_error("failed to remove manifest '" + manifest_path + "': " + strerror(errno));
    }
}

// Recounts every chunk's references from the recipes still in use, correcting wrong counts.
RefCountRepairReport StoragePipeline::rebuild_ref_counts(const std::vector<std::string>& live_manifest_filenames) {
    std::map<Bytes32, uint64_t> true_counts;
    for (const auto& manifest_filename : live_manifest_filenames) {
        std::string manifest_path = storage_root_ + "/" + manifest_filename;
        if (!file_exists(manifest_path)) continue;
        Manifest manifest = read_manifest_file(manifest_path, manifest_filename, kek_);
        for (uint64_t idx = 0; idx < manifest.metadata().total_blocks; idx++) {
            auto hash_opt = manifest.lookup(idx);
            if (hash_opt) true_counts[*hash_opt]++;
        }
    }

    RefCountRepairReport report;
    index_.begin();
    try {
        for (const auto& entry : index_.iter_all()) {
            report.chunks_checked++;
            auto it = true_counts.find(entry.content_hash);
            uint64_t true_count = (it != true_counts.end()) ? it->second : 0;
            if (true_count != entry.ref_count) {
                index_.set_ref_count(entry.content_hash, static_cast<uint32_t>(true_count));
                report.chunks_corrected++;
            }
        }
    } catch (...) {
        index_.rollback();
        throw;
    }
    index_.commit();
    return report;
}

// Deletes recipe files that nothing refers to any more.
OrphanSweepReport StoragePipeline::sweep_orphaned_manifests(const std::vector<std::string>& live_manifest_filenames) {
    OrphanSweepReport report;
    if (!file_exists(storage_root_)) return report;

    std::vector<std::string> live(live_manifest_filenames);
    std::sort(live.begin(), live.end());

    for (const auto& entry : std::filesystem::directory_iterator(storage_root_)) {
        std::string fname = entry.path().filename().string();
        if (fname.size() >= 18 && fname.compare(fname.size() - 18, 18, ".manifest.pfsm.tmp") == 0) {
            set_immutable(entry.path().string(), false);
            remove(entry.path().c_str());
            report.tmp_removed++;
        } else if (fname.size() >= 14 && fname.compare(fname.size() - 14, 14, ".manifest.pfsm") == 0 &&
                   !std::binary_search(live.begin(), live.end(), fname)) {
            set_immutable(entry.path().string(), false);
            remove(entry.path().c_str());
            report.removed++;
        }
    }
    return report;
}

// Rewrites the containers without unused chunks, after repairing counts and orphans.
VacuumReport StoragePipeline::vacuum(const std::vector<std::string>& live_manifest_filenames) {
    RefCountRepairReport repair = rebuild_ref_counts(live_manifest_filenames);
    OrphanSweepReport orphans = sweep_orphaned_manifests(live_manifest_filenames);

    uint64_t old_size = file_exists(container_path_) ? file_size(container_path_) : 0;
    std::string tmp_container_path = container_path_ + ".vacuum_tmp";

    std::vector<FullBlockEntry> live_entries;
    std::vector<Bytes32> dead_hashes;
    for (const auto& entry : index_.iter_all()) {
        if (entry.ref_count > 0) {
            live_entries.push_back(entry);
        } else {
            dead_hashes.push_back(entry.content_hash);
        }
    }

    uint64_t dead_mirrors = 0;
    {
        std::ifstream src(container_path_, std::ios::binary);
        std::ofstream dst(tmp_container_path, std::ios::binary | std::ios::trunc);
        if (!dst) throw std::runtime_error("failed to open vacuum temp container '" + tmp_container_path + "': " + strerror(errno));

        uint64_t new_offset = 0;
        index_.begin();
        try {
            for (const auto& entry : live_entries) {
                std::vector<char> buf(entry.length);
                src.seekg(static_cast<std::streamoff>(entry.offset));
                src.read(buf.data(), static_cast<std::streamsize>(entry.length));
                if (static_cast<uint64_t>(src.gcount()) != entry.length) {
                    throw std::runtime_error("short read while vacuuming a live chunk");
                }
                dst.write(buf.data(), static_cast<std::streamsize>(entry.length));
                if (new_offset != entry.offset) {
                    index_.update_offset(entry.content_hash, new_offset);
                }
                new_offset += entry.length;
            }
            // remove() reports whether the dead chunk had a mirror; dead_mirrors gates mirror compaction.
            for (const auto& content_hash : dead_hashes) {
                if (index_.remove(content_hash)) dead_mirrors++;
            }
        } catch (...) {
            index_.rollback();
            throw;
        }
        dst.flush();
        index_.commit();
    }

    set_immutable(container_path_, false);
    std::filesystem::rename(tmp_container_path, container_path_);
    set_immutable(container_path_, true);

    uint64_t new_size = file_exists(container_path_) ? file_size(container_path_) : 0;

    // Compact the mirror container too, only if a mirrored chunk died.
    uint64_t mirror_old_size = 0;
    uint64_t mirror_new_size = 0;
    uint64_t live_mirrors_count = 0;
    if (dead_mirrors > 0 && file_exists(mirror_container_path_)) {
        mirror_old_size = file_size(mirror_container_path_);
        std::string tmp_mirror_path = mirror_container_path_ + ".vacuum_tmp";

        std::vector<FullMirrorEntry> live_mirrors = index_.iter_all_mirrors();
        live_mirrors_count = live_mirrors.size();

        set_immutable(mirror_container_path_, false);
        {
            std::ifstream msrc(mirror_container_path_, std::ios::binary);
            std::ofstream mdst(tmp_mirror_path, std::ios::binary | std::ios::trunc);
            if (!mdst) {
                set_immutable(mirror_container_path_, true);
                throw std::runtime_error("failed to open vacuum temp mirror container '" + tmp_mirror_path + "': " + strerror(errno));
            }

            uint64_t new_mirror_offset = 0;
            index_.begin();
            try {
                for (const auto& entry : live_mirrors) {
                    std::vector<char> buf(entry.length);
                    msrc.seekg(static_cast<std::streamoff>(entry.offset));
                    msrc.read(buf.data(), static_cast<std::streamsize>(entry.length));
                    if (static_cast<uint64_t>(msrc.gcount()) != entry.length) {
                        throw std::runtime_error("short read while vacuuming a live mirror chunk");
                    }
                    mdst.write(buf.data(), static_cast<std::streamsize>(entry.length));
                    if (new_mirror_offset != entry.offset) {
                        index_.set_mirror(entry.content_hash, new_mirror_offset, entry.length);
                    }
                    new_mirror_offset += entry.length;
                }
            } catch (...) {
                index_.rollback();
                set_immutable(mirror_container_path_, true);
                throw;
            }
            mdst.flush();
            index_.commit();
        }
        std::filesystem::rename(tmp_mirror_path, mirror_container_path_);
        set_immutable(mirror_container_path_, true);

        mirror_new_size = file_exists(mirror_container_path_) ? file_size(mirror_container_path_) : 0;
    }
    uint64_t mirror_bytes_reclaimed = mirror_old_size - mirror_new_size;

    if (!dead_hashes.empty()) {
        // VACUUM on a separate connection: SQLite refuses it on a connection with
        // prepared statements, and index_ keeps some cached.
        DedupIndex compactor(storage_root_ + "/global_index.db", kek_);
        compactor.compact();
        // VACUUM invalidates index_'s cached statements: re-prepare them.
        index_.refresh_prepared_statements();
    }

    VacuumReport report;
    report.old_size = old_size;
    report.new_size = new_size;
    report.bytes_reclaimed = old_size - new_size;
    report.live_chunks = live_entries.size();
    report.chunks_corrected = repair.chunks_corrected;
    report.orphaned_manifests_removed = orphans.removed;
    report.orphaned_tmp_files_removed = orphans.tmp_removed;
    report.mirror_old_size = mirror_old_size;
    report.mirror_new_size = mirror_new_size;
    report.mirror_bytes_reclaimed = mirror_bytes_reclaimed;
    report.live_mirrors = live_mirrors_count;
    return report;
}

// Checks every stored chunk, repairs damaged ones from spares, and reports what can't be repaired.
FsckReport StoragePipeline::verify_and_repair() {
    FsckReport report;
    for (const auto& entry : index_.iter_all()) {
        if (entry.ref_count == 0) continue;
        report.scanned++;

        Bytes32 dek = keyring_.get_dek(entry.epoch_id);
        bool primary_ok = false;
        if (file_exists(container_path_)) {
            try {
                int fd = open(container_path_.c_str(), O_RDONLY);
                std::vector<uint8_t> payload(entry.length);
                bool read_ok = fd >= 0 && pread(fd, payload.data(), entry.length,
                                                 static_cast<off_t>(entry.offset)) == static_cast<ssize_t>(entry.length);
                if (fd >= 0) close(fd);
                if (read_ok) {
                    std::vector<uint8_t> plaintext = aead_decrypt(dek, payload.data(), payload.size(),
                                                                   entry.content_hash.data(), entry.content_hash.size());
                    primary_ok = sha256(plaintext.data(), plaintext.size()) == entry.content_hash;
                }
            } catch (const std::exception&) {
                primary_ok = false;
            }
        }

        if (primary_ok) {
            report.healthy++;
            continue;
        }

        auto mirror_loc = index_.get_mirror(entry.content_hash);
        bool mirror_ok = false;
        std::vector<uint8_t> mirror_payload;
        if (mirror_loc && file_exists(mirror_container_path_)) {
            try {
                int mfd = open(mirror_container_path_.c_str(), O_RDONLY);
                mirror_payload.resize(mirror_loc->length);
                bool read_ok = mfd >= 0 && pread(mfd, mirror_payload.data(), mirror_loc->length,
                                                  static_cast<off_t>(mirror_loc->offset)) ==
                                              static_cast<ssize_t>(mirror_loc->length);
                if (mfd >= 0) close(mfd);
                if (read_ok) {
                    std::vector<uint8_t> mirror_plain = aead_decrypt(dek, mirror_payload.data(), mirror_payload.size(),
                                                                      entry.content_hash.data(), entry.content_hash.size());
                    mirror_ok = sha256(mirror_plain.data(), mirror_plain.size()) == entry.content_hash;
                }
            } catch (const std::exception&) {
                mirror_ok = false;
            }
        }

        if (!mirror_ok || mirror_payload.size() != entry.length) {
            char hex[65];
            for (int i = 0; i < 32; i++) snprintf(hex + i * 2, 3, "%02x", entry.content_hash[i]);
            report.unrecoverable.emplace_back(hex, 64);
            continue;
        }

        set_immutable(container_path_, false);
        int fd = open(container_path_.c_str(), O_WRONLY);
        bool wrote_ok = false;
        if (fd >= 0) {
            wrote_ok = pwrite(fd, mirror_payload.data(), mirror_payload.size(),
                              static_cast<off_t>(entry.offset)) == static_cast<ssize_t>(mirror_payload.size());
            if (wrote_ok) fsync(fd);
            close(fd);
        }
        set_immutable(container_path_, true);
        if (!wrote_ok) {
            char hex[65];
            for (int i = 0; i < 32; i++) snprintf(hex + i * 2, 3, "%02x", entry.content_hash[i]);
            report.unrecoverable.emplace_back(hex, 64);
            continue;
        }
        report.healed++;
    }
    return report;
}

}  // namespace pfs_engine
