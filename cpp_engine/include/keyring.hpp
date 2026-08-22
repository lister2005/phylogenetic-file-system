#pragma once
// Envelope encryption with rotating Data Encryption Keys -- ports
// gearhash/keyring.py's SCHEME exactly (same wrap/unwrap math, same
// AAD binding, same rotation semantics), but not its on-disk FORMAT:
// keyring.py persists a pickled `Dict[int, bytes]`, and pickle is
// Python-specific for the same reason it wasn't worth replicating for
// the manifest (see MANIFEST_FORMAT.md) -- so this uses a new, small,
// portable binary format instead. See KEYRING_FORMAT.md for the layout.
//
// The master key (KEK, passed into the constructor) is NEVER used to
// encrypt file content directly -- only to wrap/unwrap per-epoch DEKs.
// Content is always encrypted under the CURRENT epoch's DEK. Rotating
// means generating one new 32-byte DEK and wrapping it -- it does NOT
// re-encrypt any existing data, so it's cheap regardless of vault size.
#include <cstdint>
#include <map>
#include <string>
#include <utility>

#include "crypto_utils.hpp"

namespace pfs_engine {

class KeyRing {
public:
    KeyRing(std::string storage_root, const Bytes32& kek);

    // (epoch_id, dek) for the currently active epoch. Creates epoch 0
    // automatically (and persists it) if this is a brand-new keyring.
    std::pair<uint32_t, Bytes32> get_current_dek();

    // The DEK for a specific (possibly older) epoch -- needed to
    // decrypt a chunk written before the most recent rotation. Throws
    // std::out_of_range if no such epoch was ever recorded.
    Bytes32 get_dek(uint32_t epoch_id) const;

    // Generates a fresh DEK for a new epoch, makes it current,
    // persists immediately. Returns the new epoch_id.
    uint32_t rotate();

    // KEK rotation: re-wraps every existing DEK under a new KEK and
    // persists. Still cheap -- only touches the small wrapped-DEK
    // entries, never any bulk content those DEKs protect. Caller must
    // start passing the new KEK to future KeyRing/CryptoEngine
    // instances themselves; this object keeps using it from here on.
    void rewrap_under_new_kek(const Bytes32& new_kek);

    int64_t current_epoch() const { return current_epoch_; }

private:
    std::string storage_root_;
    std::string path_;
    Bytes32 kek_;
    std::map<uint32_t, Bytes32> deks_;  // epoch_id -> raw DEK, in-memory only
    int64_t current_epoch_ = -1;        // -1 == no epoch recorded yet

    void load();
    void save();
};

}  // namespace pfs_engine
