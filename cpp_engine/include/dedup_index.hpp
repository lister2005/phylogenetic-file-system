#pragma once
// C++ port of gearhash/dedup_index.py's GlobalBlockIndex -- links
// libsqlite3 directly (the SAME global_index.db file Python already
// creates; SQLite's format is language-agnostic) and OpenSSL for the
// HKDF/HMAC/AES-256-GCM confidentiality scheme, replicated to match
// exactly (verified byte-for-byte against the Python reference via
// hkdf_check.cpp before this was written). Goal: remove the Python
// object-construction overhead profiling flagged (hmac.new() building a
// fresh object per lookup, sqlite3 Python-module call overhead) without
// changing anything about what's actually stored on disk.

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

// Like BlockEntry, but with the content hash included -- what a full
// table scan (iter_all) needs, since a plain BlockEntry alone gives you
// no way to know WHICH chunk you're looking at. content_hash is packed
// inside the encrypted value itself (see pack_value in dedup_index.cpp),
// not derivable from lookup_key (that's a one-way HMAC), so a scan has
// to decrypt every row anyway -- exactly what Python's iter_all() does.
struct FullBlockEntry {
    Bytes32 content_hash;
    uint64_t offset;
    uint64_t length;
    uint32_t ref_count;
    uint32_t epoch_id;
};

// What a full scan of the mirrors table needs. Unlike FullBlockEntry,
// content_hash isn't stored in the mirrors table's own encrypted payload
// (set_mirror only ever packs offset+length -- content_hash is used
// purely as part of the AAD, not as plaintext) -- iter_all_mirrors()
// recovers it by joining against the blocks table on the shared
// lookup_key instead. See dedup_index.cpp for the exact mechanism.
struct FullMirrorEntry {
    Bytes32 content_hash;
    uint64_t offset;
    uint64_t length;
};

class DedupIndex {
public:
    // kek: the 32-byte master Key-Encryption-Key (VaultSession's
    // crypto.key in the Python code). Subkeys are derived here, once,
    // matching _derive_subkeys() exactly.
    DedupIndex(const std::string& db_path, const Bytes32& kek);
    ~DedupIndex();

    DedupIndex(const DedupIndex&) = delete;
    DedupIndex& operator=(const DedupIndex&) = delete;

    void begin();
    void commit();
    void rollback();

    std::optional<BlockEntry> lookup(const Bytes32& content_hash);

    // Batched form of lookup() (PART 8 item #1 -- see cpp_port_plan.txt's
    // 1.5GB-benchmark profiling, ~19% of the core write loop was one
    // SELECT + one INSERT per chunk): ONE `WHERE lookup_key IN (...)`
    // query for N hashes at once instead of N individual point lookups.
    // content_hashes may contain duplicates (harmless -- SQLite doesn't
    // care about repeated IN-clause values, and the result map naturally
    // collapses them since they'd decrypt to the same row anyway). Only
    // hashes actually found in the table appear as keys in the result,
    // matching lookup()'s "None means not found" contract per-entry.
    std::map<Bytes32, BlockEntry> lookup_many(const std::vector<Bytes32>& content_hashes);

    void register_new(const Bytes32& content_hash, uint64_t offset, uint64_t length, uint32_t epoch_id);
    void increment_ref(const Bytes32& content_hash);
    uint32_t decrement_ref(const Bytes32& content_hash);  // returns new ref_count
    void set_ref_count(const Bytes32& content_hash, uint32_t ref_count);  // rebuild_ref_counts' repair path
    void update_offset(const Bytes32& content_hash, uint64_t new_offset);  // vacuum's compaction path

    // Drops the row from BOTH blocks and mirrors -- vacuum's dead-chunk
    // sweep. Returns true iff a mirrors row actually existed and was
    // dropped, so the caller (vacuum's mirror-container compaction pass)
    // can tell whether this dead chunk was ever mirrored at all, without
    // a second query.
    bool remove(const Bytes32& content_hash);

    std::optional<MirrorEntry> get_mirror(const Bytes32& content_hash);
    void set_mirror(const Bytes32& content_hash, uint64_t offset, uint64_t length);

    // Batched form of the private upsert() the single-chunk register_new/
    // increment_ref/etc. all funnel through: ONE multi-row
    // `INSERT ... VALUES (?,?),(?,?),... ON CONFLICT DO UPDATE` for all
    // given (content_hash, offset, length, ref_count, epoch_id) rows
    // instead of one upsert statement execution per row. Used by the
    // write-loop's per-window flush -- see pipeline.cpp's
    // secure_and_persist_file for how repeat occurrences of the same hash
    // within one window are folded into a single final-state row here,
    // rather than one row write per occurrence.
    void upsert_many(const std::vector<std::tuple<Bytes32, uint64_t, uint64_t, uint32_t, uint32_t>>& entries);

    // Full table scan, every row decrypted -- rebuild_ref_counts/vacuum/
    // fsck's shared authoritative source (matches Python's iter_all()).
    std::vector<FullBlockEntry> iter_all();

    // Full scan of the mirrors table, content_hash recovered via a join
    // against blocks (see FullMirrorEntry) -- vacuum()'s mirror-container
    // compaction pass, matching Python's iter_all_mirrors().
    std::vector<FullMirrorEntry> iter_all_mirrors();

    // SQLite's own VACUUM -- only worth calling after remove() actually
    // dropped rows (it rewrites the whole index file regardless of how
    // little there is to reclaim). Must run OUTSIDE any transaction.
    void compact();

    // Re-prepares the 4 cached statements against the database's
    // CURRENT structure. Must be called after ANY VACUUM on the same
    // underlying file, even one run through a completely separate
    // DedupIndex/connection (as StoragePipeline::vacuum() does, since
    // SQLite refuses to VACUUM a connection that has prepared
    // statements outstanding, and this object's are never finalized
    // during its lifetime otherwise) -- VACUUM rebuilds the whole file
    // in place, so any OTHER connection's statements, prepared against
    // the old structure, silently fail on their next use ("upsert
    // failed") if not refreshed. A real bug, caught by testing the
    // exact sequence a session actually goes through: write, delete,
    // vacuum, write again.
    void refresh_prepared_statements();

private:
    sqlite3* db_ = nullptr;
    bool in_transaction_ = false;
    Bytes32 hmac_key_{};
    Bytes32 value_key_{};

    // Prepared once, reused via sqlite3_reset()/sqlite3_clear_bindings()
    // on every call instead of re-parsing the SQL from scratch each
    // time -- matches what Python's sqlite3 module already does for you
    // automatically (its own internal statement cache). Without this,
    // an early version of this benchmark was, misleadingly, SLOWER than
    // Python -- not because C++ has no advantage here, but because it
    // was silently redoing work Python was already skipping.
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
