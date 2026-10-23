#pragma once
// C++ port of dedup_index.py's GlobalBlockIndex: the same global_index.db,
// with the same HKDF/HMAC/AES-256-GCM scheme (checked byte-for-byte by
// hkdf_check.cpp).

#include <array>
#include <cstdint>
#include <map>
#include <optional>
#include <stdexcept>
#include <string>
#include <tuple>
#include <vector>

#include <sqlite3.h>

#include "crypto_utils.hpp"

namespace pfs_engine {

struct BlockEntry {
    uint64_t offset;
    uint64_t length;
    uint32_t ref_count;
    uint32_t epoch_id;
};

struct MirrorEntry {
    uint64_t offset;
    uint64_t length;
};

// A row with its content hash, for full scans. The hash is inside the
// encrypted value (the lookup key is a one-way HMAC), so a scan decrypts
// every row.
struct FullBlockEntry {
    Bytes32 content_hash;
    uint64_t offset;
    uint64_t length;
    uint32_t ref_count;
    uint32_t epoch_id;
};

// A mirror row with its content hash, for full scans. Mirror payloads
// don't hold the hash; iter_all_mirrors() joins with `blocks` to get it.
struct FullMirrorEntry {
    Bytes32 content_hash;
    uint64_t offset;
    uint64_t length;
};

class DedupIndex {
public:
    // kek: the 32-byte KEK. Subkeys are derived once, as _derive_subkeys() does.
    DedupIndex(const std::string& db_path, const Bytes32& kek);
    ~DedupIndex();

    DedupIndex(const DedupIndex&) = delete;
    DedupIndex& operator=(const DedupIndex&) = delete;

    void begin();
    void commit();
    void rollback();

    std::optional<BlockEntry> lookup(const Bytes32& content_hash);

    // Batched lookup(): one IN (...) query. Duplicates are fine; missing
    // hashes are absent from the result.
    std::map<Bytes32, BlockEntry> lookup_many(const std::vector<Bytes32>& content_hashes);

    void register_new(const Bytes32& content_hash, uint64_t offset, uint64_t length, uint32_t epoch_id);
    void increment_ref(const Bytes32& content_hash);
    uint32_t decrement_ref(const Bytes32& content_hash);  // returns the new ref_count
    void set_ref_count(const Bytes32& content_hash, uint32_t ref_count);  // for rebuild_ref_counts
    void update_offset(const Bytes32& content_hash, uint64_t new_offset);  // for vacuum

    // Drops a chunk's row from blocks and mirrors. True if it had a mirror
    // row (vacuum uses this to decide on mirror compaction).
    bool remove(const Bytes32& content_hash);

    std::optional<MirrorEntry> get_mirror(const Bytes32& content_hash);
    void set_mirror(const Bytes32& content_hash, uint64_t offset, uint64_t length);

    // Batched upsert: one multi-row INSERT ... ON CONFLICT DO UPDATE for
    // (content_hash, offset, length, ref_count, epoch_id) rows, one per hash.
    void upsert_many(const std::vector<std::tuple<Bytes32, uint64_t, uint64_t, uint32_t, uint32_t>>& entries);

    // Every row, decrypted (for rebuild_ref_counts, vacuum, fsck).
    std::vector<FullBlockEntry> iter_all();

    // Every mirror row, with its content hash from a join on `blocks`.
    std::vector<FullMirrorEntry> iter_all_mirrors();

    // SQLite VACUUM. Rewrites the whole file; outside any transaction.
    void compact();

    // Re-prepares the cached statements. Needed after any VACUUM of the same
    // file, even from another connection, or the next use fails.
    void refresh_prepared_statements();

private:
    sqlite3* db_ = nullptr;
    bool in_transaction_ = false;
    Bytes32 hmac_key_{};
    Bytes32 value_key_{};

    // Prepared once and reused (reset + clear bindings), like Python's statement cache.
    sqlite3_stmt* stmt_lookup_block_ = nullptr;
    sqlite3_stmt* stmt_upsert_block_ = nullptr;
    sqlite3_stmt* stmt_lookup_mirror_ = nullptr;
    sqlite3_stmt* stmt_upsert_mirror_ = nullptr;

    Bytes32 lookup_key_for(const Bytes32& content_hash) const;
    BlockEntry require(const Bytes32& content_hash);
    void upsert(const Bytes32& content_hash, uint64_t offset, uint64_t length,
                uint32_t ref_count, uint32_t epoch_id);
};

}  // namespace pfs_engine
