#include "dedup_index.hpp"

#include <cstring>

namespace pfs_engine {

namespace {

constexpr const char* kMirrorAadSuffix = "|mirror";  // matches _MIRROR_AAD_SUFFIX exactly

// Matches _VALUE_FORMAT = "32sQQII" (content_hash, offset, length,
// ref_count, epoch_id), little-endian, no padding -- verified via
// struct.calcsize()/struct.pack() against the Python reference.
constexpr size_t kValueSize = 32 + 8 + 8 + 4 + 4;

std::vector<uint8_t> pack_value(const Bytes32& content_hash, uint64_t offset, uint64_t length,
                                 uint32_t ref_count, uint32_t epoch_id) {
    std::vector<uint8_t> buf(kValueSize);
    memcpy(buf.data(), content_hash.data(), 32);
    memcpy(buf.data() + 32, &offset, 8);
    memcpy(buf.data() + 40, &length, 8);
    memcpy(buf.data() + 48, &ref_count, 4);
    memcpy(buf.data() + 52, &epoch_id, 4);
    return buf;
}

void unpack_value(const std::vector<uint8_t>& raw, BlockEntry& out) {
    if (raw.size() != kValueSize) throw std::runtime_error("bad block value size");
    memcpy(&out.offset, raw.data() + 32, 8);
    memcpy(&out.length, raw.data() + 40, 8);
    memcpy(&out.ref_count, raw.data() + 48, 4);
    memcpy(&out.epoch_id, raw.data() + 52, 4);
}

void unpack_full(const std::vector<uint8_t>& raw, FullBlockEntry& out) {
    if (raw.size() != kValueSize) throw std::runtime_error("bad block value size");
    memcpy(out.content_hash.data(), raw.data(), 32);
    memcpy(&out.offset, raw.data() + 32, 8);
    memcpy(&out.length, raw.data() + 40, 8);
    memcpy(&out.ref_count, raw.data() + 48, 4);
    memcpy(&out.epoch_id, raw.data() + 52, 4);
}

constexpr size_t kMirrorValueSize = 16;

std::vector<uint8_t> pack_mirror(uint64_t offset, uint64_t length) {
    std::vector<uint8_t> buf(kMirrorValueSize);
    memcpy(buf.data(), &offset, 8);
    memcpy(buf.data() + 8, &length, 8);
    return buf;
}

void unpack_mirror(const std::vector<uint8_t>& raw, MirrorEntry& out) {
    if (raw.size() != kMirrorValueSize) throw std::runtime_error("bad mirror value size");
    memcpy(&out.offset, raw.data(), 8);
    memcpy(&out.length, raw.data() + 8, 8);
}

void exec_or_throw(sqlite3* db, const char* sql) {
    char* errmsg = nullptr;
    if (sqlite3_exec(db, sql, nullptr, nullptr, &errmsg) != SQLITE_OK) {
        std::string msg = errmsg ? errmsg : "unknown sqlite error";
        sqlite3_free(errmsg);
        throw std::runtime_error("sqlite: " + msg + " (" + sql + ")");
    }
}

}  // namespace

DedupIndex::DedupIndex(const std::string& db_path, const Bytes32& kek) {
    if (sqlite3_open_v2(db_path.c_str(), &db_, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nullptr) != SQLITE_OK) {
        throw std::runtime_error("failed to open dedup index db: " + db_path);
    }
    exec_or_throw(db_, "PRAGMA journal_mode=WAL");
    exec_or_throw(db_, "PRAGMA synchronous=FULL");
    exec_or_throw(db_, "CREATE TABLE IF NOT EXISTS blocks (lookup_key BLOB PRIMARY KEY, encrypted_value BLOB NOT NULL)");
    exec_or_throw(db_, "CREATE TABLE IF NOT EXISTS mirrors (lookup_key BLOB PRIMARY KEY, encrypted_value BLOB NOT NULL)");

    hmac_key_ = hkdf_sha256(kek, "pfs-dedup-hmac-key");
    value_key_ = hkdf_sha256(kek, "pfs-dedup-value-key");

    sqlite3_prepare_v2(db_, "SELECT encrypted_value FROM blocks WHERE lookup_key = ?", -1, &stmt_lookup_block_, nullptr);
    sqlite3_prepare_v2(db_,
        "INSERT INTO blocks (lookup_key, encrypted_value) VALUES (?, ?) "
        "ON CONFLICT(lookup_key) DO UPDATE SET encrypted_value = excluded.encrypted_value",
        -1, &stmt_upsert_block_, nullptr);
    sqlite3_prepare_v2(db_, "SELECT encrypted_value FROM mirrors WHERE lookup_key = ?", -1, &stmt_lookup_mirror_, nullptr);
    sqlite3_prepare_v2(db_,
        "INSERT INTO mirrors (lookup_key, encrypted_value) VALUES (?, ?) "
        "ON CONFLICT(lookup_key) DO UPDATE SET encrypted_value = excluded.encrypted_value",
        -1, &stmt_upsert_mirror_, nullptr);
}

DedupIndex::~DedupIndex() {
    if (in_transaction_) {
        sqlite3_exec(db_, "ROLLBACK", nullptr, nullptr, nullptr);
    }
    sqlite3_finalize(stmt_lookup_block_);
    sqlite3_finalize(stmt_upsert_block_);
    sqlite3_finalize(stmt_lookup_mirror_);
    sqlite3_finalize(stmt_upsert_mirror_);
    if (db_) sqlite3_close(db_);
}

void DedupIndex::begin() {
    if (!in_transaction_) {
        exec_or_throw(db_, "BEGIN");
        in_transaction_ = true;
    }
}

void DedupIndex::commit() {
    if (in_transaction_) {
        exec_or_throw(db_, "COMMIT");
        in_transaction_ = false;
    }
}

void DedupIndex::rollback() {
    if (in_transaction_) {
        exec_or_throw(db_, "ROLLBACK");
        in_transaction_ = false;
    }
}

Bytes32 DedupIndex::lookup_key_for(const Bytes32& content_hash) const {
    return hmac_sha256(hmac_key_, content_hash.data(), content_hash.size());
}

std::optional<BlockEntry> DedupIndex::lookup(const Bytes32& content_hash) {
    Bytes32 key = lookup_key_for(content_hash);

    sqlite3_stmt* stmt = stmt_lookup_block_;
    sqlite3_reset(stmt);
    sqlite3_clear_bindings(stmt);
    sqlite3_bind_blob(stmt, 1, key.data(), static_cast<int>(key.size()), SQLITE_STATIC);

    std::optional<BlockEntry> result;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        const void* blob = sqlite3_column_blob(stmt, 0);
        int blob_len = sqlite3_column_bytes(stmt, 0);
        std::vector<uint8_t> encrypted(static_cast<const uint8_t*>(blob),
                                        static_cast<const uint8_t*>(blob) + blob_len);
        std::vector<uint8_t> raw = aead_decrypt(value_key_, encrypted.data(), encrypted.size(),
                                                 key.data(), key.size());
        BlockEntry entry{};
        unpack_value(raw, entry);
        result = entry;
    }
    return result;
}

std::map<Bytes32, BlockEntry> DedupIndex::lookup_many(const std::vector<Bytes32>& content_hashes) {
    std::map<Bytes32, BlockEntry> result;
    if (content_hashes.empty()) return result;

    // lookup_key -> content_hash, so a matched row can be reported back
    // under the caller's own hash (lookup_key is a one-way HMAC, not
    // reversible from the row itself).
    std::map<Bytes32, Bytes32> key_to_hash;
    std::vector<Bytes32> keys;
    keys.reserve(content_hashes.size());
    for (const auto& ch : content_hashes) {
        Bytes32 key = lookup_key_for(ch);
        keys.push_back(key);
        key_to_hash[key] = ch;
    }

    std::string sql = "SELECT lookup_key, encrypted_value FROM blocks WHERE lookup_key IN (";
    for (size_t i = 0; i < keys.size(); ++i) sql += (i == 0 ? "?" : ",?");
    sql += ")";

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
        throw std::runtime_error("failed to prepare batched lookup");
    }
    for (size_t i = 0; i < keys.size(); ++i) {
        sqlite3_bind_blob(stmt, static_cast<int>(i) + 1, keys[i].data(),
                           static_cast<int>(keys[i].size()), SQLITE_STATIC);
    }
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        const void* key_blob = sqlite3_column_blob(stmt, 0);
        int key_len = sqlite3_column_bytes(stmt, 0);
        const void* val_blob = sqlite3_column_blob(stmt, 1);
        int val_len = sqlite3_column_bytes(stmt, 1);

        Bytes32 key{};
        memcpy(key.data(), key_blob, key_len < 32 ? key_len : 32);
        auto it = key_to_hash.find(key);
        if (it == key_to_hash.end()) continue;  // shouldn't happen; defensive

        std::vector<uint8_t> raw = aead_decrypt(value_key_, static_cast<const uint8_t*>(val_blob), val_len,
                                                 static_cast<const uint8_t*>(key_blob), key_len);
        BlockEntry entry{};
        unpack_value(raw, entry);
        result[it->second] = entry;
    }
    sqlite3_finalize(stmt);
    return result;
}

void DedupIndex::upsert_many(const std::vector<std::tuple<Bytes32, uint64_t, uint64_t, uint32_t, uint32_t>>& entries) {
    if (entries.empty()) return;
    begin();

    std::string sql = "INSERT INTO blocks (lookup_key, encrypted_value) VALUES ";
    for (size_t i = 0; i < entries.size(); ++i) sql += (i == 0 ? "(?,?)" : ",(?,?)");
    sql += " ON CONFLICT(lookup_key) DO UPDATE SET encrypted_value = excluded.encrypted_value";

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
        throw std::runtime_error("failed to prepare batched upsert");
    }
    // SQLITE_STATIC bindings don't copy the bytes -- keep every row's
    // key/value buffers alive until sqlite3_step() actually runs below.
    std::vector<Bytes32> keys_buf;
    std::vector<std::vector<uint8_t>> vals_buf;
    keys_buf.reserve(entries.size());
    vals_buf.reserve(entries.size());
    for (const auto& [content_hash, offset, length, ref_count, epoch_id] : entries) {
        Bytes32 key = lookup_key_for(content_hash);
        std::vector<uint8_t> raw = pack_value(content_hash, offset, length, ref_count, epoch_id);
        std::vector<uint8_t> encrypted = aead_encrypt(value_key_, raw.data(), raw.size(), key.data(), key.size());
        keys_buf.push_back(key);
        vals_buf.push_back(std::move(encrypted));
    }
    int param = 1;
    for (size_t i = 0; i < entries.size(); ++i) {
        sqlite3_bind_blob(stmt, param++, keys_buf[i].data(), static_cast<int>(keys_buf[i].size()), SQLITE_STATIC);
        sqlite3_bind_blob(stmt, param++, vals_buf[i].data(), static_cast<int>(vals_buf[i].size()), SQLITE_STATIC);
    }
    if (sqlite3_step(stmt) != SQLITE_DONE) {
        sqlite3_finalize(stmt);
        throw std::runtime_error("batched upsert failed");
    }
    sqlite3_finalize(stmt);
}

BlockEntry DedupIndex::require(const Bytes32& content_hash) {
    auto existing = lookup(content_hash);
    if (!existing) throw std::runtime_error("no index entry for this content hash");
    return *existing;
}

void DedupIndex::upsert(const Bytes32& content_hash, uint64_t offset, uint64_t length,
                         uint32_t ref_count, uint32_t epoch_id) {
    Bytes32 key = lookup_key_for(content_hash);
    std::vector<uint8_t> raw = pack_value(content_hash, offset, length, ref_count, epoch_id);
    std::vector<uint8_t> encrypted = aead_encrypt(value_key_, raw.data(), raw.size(), key.data(), key.size());

    begin();
    sqlite3_stmt* stmt = stmt_upsert_block_;
    sqlite3_reset(stmt);
    sqlite3_clear_bindings(stmt);
    sqlite3_bind_blob(stmt, 1, key.data(), static_cast<int>(key.size()), SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 2, encrypted.data(), static_cast<int>(encrypted.size()), SQLITE_STATIC);
    if (sqlite3_step(stmt) != SQLITE_DONE) {
        throw std::runtime_error("upsert failed");
    }
}

void DedupIndex::register_new(const Bytes32& content_hash, uint64_t offset, uint64_t length, uint32_t epoch_id) {
    upsert(content_hash, offset, length, 1, epoch_id);
}

void DedupIndex::increment_ref(const Bytes32& content_hash) {
    BlockEntry e = require(content_hash);
    upsert(content_hash, e.offset, e.length, e.ref_count + 1, e.epoch_id);
}

uint32_t DedupIndex::decrement_ref(const Bytes32& content_hash) {
    BlockEntry e = require(content_hash);
    uint32_t new_ref = e.ref_count > 0 ? e.ref_count - 1 : 0;
    upsert(content_hash, e.offset, e.length, new_ref, e.epoch_id);
    return new_ref;
}

std::optional<MirrorEntry> DedupIndex::get_mirror(const Bytes32& content_hash) {
    Bytes32 key = lookup_key_for(content_hash);
    std::vector<uint8_t> aad(key.begin(), key.end());
    aad.insert(aad.end(), kMirrorAadSuffix, kMirrorAadSuffix + strlen(kMirrorAadSuffix));

    sqlite3_stmt* stmt = stmt_lookup_mirror_;
    sqlite3_reset(stmt);
    sqlite3_clear_bindings(stmt);
    sqlite3_bind_blob(stmt, 1, key.data(), static_cast<int>(key.size()), SQLITE_STATIC);

    std::optional<MirrorEntry> result;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        const void* blob = sqlite3_column_blob(stmt, 0);
        int blob_len = sqlite3_column_bytes(stmt, 0);
        std::vector<uint8_t> encrypted(static_cast<const uint8_t*>(blob),
                                        static_cast<const uint8_t*>(blob) + blob_len);
        std::vector<uint8_t> raw = aead_decrypt(value_key_, encrypted.data(), encrypted.size(),
                                                 aad.data(), aad.size());
        MirrorEntry entry{};
        unpack_mirror(raw, entry);
        result = entry;
    }
    return result;
}

void DedupIndex::set_ref_count(const Bytes32& content_hash, uint32_t ref_count) {
    BlockEntry e = require(content_hash);
    upsert(content_hash, e.offset, e.length, ref_count, e.epoch_id);
}

void DedupIndex::update_offset(const Bytes32& content_hash, uint64_t new_offset) {
    BlockEntry e = require(content_hash);
    upsert(content_hash, new_offset, e.length, e.ref_count, e.epoch_id);
}

bool DedupIndex::remove(const Bytes32& content_hash) {
    Bytes32 key = lookup_key_for(content_hash);
    begin();
    sqlite3_stmt* del_block = nullptr;
    sqlite3_prepare_v2(db_, "DELETE FROM blocks WHERE lookup_key = ?", -1, &del_block, nullptr);
    sqlite3_bind_blob(del_block, 1, key.data(), static_cast<int>(key.size()), SQLITE_STATIC);
    if (sqlite3_step(del_block) != SQLITE_DONE) {
        sqlite3_finalize(del_block);
        throw std::runtime_error("failed to delete block row");
    }
    sqlite3_finalize(del_block);

    sqlite3_stmt* del_mirror = nullptr;
    sqlite3_prepare_v2(db_, "DELETE FROM mirrors WHERE lookup_key = ?", -1, &del_mirror, nullptr);
    sqlite3_bind_blob(del_mirror, 1, key.data(), static_cast<int>(key.size()), SQLITE_STATIC);
    if (sqlite3_step(del_mirror) != SQLITE_DONE) {
        sqlite3_finalize(del_mirror);
        throw std::runtime_error("failed to delete mirror row");
    }
    sqlite3_finalize(del_mirror);
    // sqlite3_changes() reflects the row count of the last completed
    // INSERT/UPDATE/DELETE on this connection -- the mirror DELETE just
    // above, at this point -- so this tells the caller whether this
    // specific dead chunk was ever actually mirrored.
    return sqlite3_changes(db_) > 0;
}

std::vector<FullBlockEntry> DedupIndex::iter_all() {
    std::vector<FullBlockEntry> out;
    sqlite3_stmt* stmt = nullptr;
    sqlite3_prepare_v2(db_, "SELECT lookup_key, encrypted_value FROM blocks", -1, &stmt, nullptr);
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        const void* key_blob = sqlite3_column_blob(stmt, 0);
        int key_len = sqlite3_column_bytes(stmt, 0);
        const void* val_blob = sqlite3_column_blob(stmt, 1);
        int val_len = sqlite3_column_bytes(stmt, 1);

        std::vector<uint8_t> raw = aead_decrypt(value_key_, static_cast<const uint8_t*>(val_blob), val_len,
                                                 static_cast<const uint8_t*>(key_blob), key_len);
        FullBlockEntry entry{};
        unpack_full(raw, entry);
        out.push_back(entry);
    }
    sqlite3_finalize(stmt);
    return out;
}

std::vector<FullMirrorEntry> DedupIndex::iter_all_mirrors() {
    std::vector<FullMirrorEntry> out;
    sqlite3_stmt* stmt = nullptr;
    // Joined against blocks on the shared lookup_key -- both tables key
    // off HMAC(hmac_key, content_hash) for the SAME content_hash (see
    // set_mirror/upsert), and blocks' own payload carries content_hash in
    // plaintext (unpack_full), which the mirrors table's payload does
    // not. This recovers content_hash for every mirror row without any
    // on-disk format change to the mirrors table itself.
    sqlite3_prepare_v2(db_,
        "SELECT m.lookup_key, m.encrypted_value, b.encrypted_value "
        "FROM mirrors m JOIN blocks b ON m.lookup_key = b.lookup_key",
        -1, &stmt, nullptr);
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        const void* key_blob = sqlite3_column_blob(stmt, 0);
        int key_len = sqlite3_column_bytes(stmt, 0);
        const void* mirror_blob = sqlite3_column_blob(stmt, 1);
        int mirror_len = sqlite3_column_bytes(stmt, 1);
        const void* block_blob = sqlite3_column_blob(stmt, 2);
        int block_len = sqlite3_column_bytes(stmt, 2);

        std::vector<uint8_t> block_raw = aead_decrypt(value_key_, static_cast<const uint8_t*>(block_blob), block_len,
                                                        static_cast<const uint8_t*>(key_blob), key_len);
        FullBlockEntry block_entry{};
        unpack_full(block_raw, block_entry);

        std::vector<uint8_t> aad(static_cast<const uint8_t*>(key_blob),
                                  static_cast<const uint8_t*>(key_blob) + key_len);
        aad.insert(aad.end(), kMirrorAadSuffix, kMirrorAadSuffix + strlen(kMirrorAadSuffix));
        std::vector<uint8_t> mirror_raw = aead_decrypt(value_key_, static_cast<const uint8_t*>(mirror_blob), mirror_len,
                                                         aad.data(), aad.size());
        MirrorEntry mirror_entry{};
        unpack_mirror(mirror_raw, mirror_entry);

        FullMirrorEntry entry{};
        entry.content_hash = block_entry.content_hash;
        entry.offset = mirror_entry.offset;
        entry.length = mirror_entry.length;
        out.push_back(entry);
    }
    sqlite3_finalize(stmt);
    return out;
}

void DedupIndex::compact() {
    if (in_transaction_) throw std::runtime_error("cannot VACUUM the index from inside a transaction");
    exec_or_throw(db_, "VACUUM");
}

void DedupIndex::refresh_prepared_statements() {
    sqlite3_finalize(stmt_lookup_block_);
    sqlite3_finalize(stmt_upsert_block_);
    sqlite3_finalize(stmt_lookup_mirror_);
    sqlite3_finalize(stmt_upsert_mirror_);
    sqlite3_prepare_v2(db_, "SELECT encrypted_value FROM blocks WHERE lookup_key = ?", -1, &stmt_lookup_block_, nullptr);
    sqlite3_prepare_v2(db_,
        "INSERT INTO blocks (lookup_key, encrypted_value) VALUES (?, ?) "
        "ON CONFLICT(lookup_key) DO UPDATE SET encrypted_value = excluded.encrypted_value",
        -1, &stmt_upsert_block_, nullptr);
    sqlite3_prepare_v2(db_, "SELECT encrypted_value FROM mirrors WHERE lookup_key = ?", -1, &stmt_lookup_mirror_, nullptr);
    sqlite3_prepare_v2(db_,
        "INSERT INTO mirrors (lookup_key, encrypted_value) VALUES (?, ?) "
        "ON CONFLICT(lookup_key) DO UPDATE SET encrypted_value = excluded.encrypted_value",
        -1, &stmt_upsert_mirror_, nullptr);
}

void DedupIndex::set_mirror(const Bytes32& content_hash, uint64_t offset, uint64_t length) {
    Bytes32 key = lookup_key_for(content_hash);
    std::vector<uint8_t> aad(key.begin(), key.end());
    aad.insert(aad.end(), kMirrorAadSuffix, kMirrorAadSuffix + strlen(kMirrorAadSuffix));

    std::vector<uint8_t> raw = pack_mirror(offset, length);
    std::vector<uint8_t> encrypted = aead_encrypt(value_key_, raw.data(), raw.size(), aad.data(), aad.size());

    begin();
    sqlite3_stmt* stmt = stmt_upsert_mirror_;
    sqlite3_reset(stmt);
    sqlite3_clear_bindings(stmt);
    sqlite3_bind_blob(stmt, 1, key.data(), static_cast<int>(key.size()), SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 2, encrypted.data(), static_cast<int>(encrypted.size()), SQLITE_STATIC);
    if (sqlite3_step(stmt) != SQLITE_DONE) {
        throw std::runtime_error("mirror upsert failed");
    }
}

}  // namespace pfs_engine
