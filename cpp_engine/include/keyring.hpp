#pragma once
// Envelope encryption with rotating DEKs: keyring.py's scheme exactly,
// in a portable binary file instead of pickle. The KEK
// only wraps DEKs; content uses the current epoch's DEK, and rotation
// re-encrypts nothing.
#include <cstdint>
#include <map>
#include <string>
#include <utility>

#include "crypto_utils.hpp"

namespace pfs_engine {

class KeyRing {
public:
    KeyRing(std::string storage_root, const Bytes32& kek);

    // (epoch_id, dek) for the current epoch; creates and persists epoch 0 if new.
    std::pair<uint32_t, Bytes32> get_current_dek();

    // The DEK of an older epoch. Throws std::out_of_range if unknown.
    Bytes32 get_dek(uint32_t epoch_id) const;

    // Makes a fresh DEK current and persists it. Returns the new epoch_id.
    uint32_t rotate();

    // Re-wraps every DEK under a new KEK, which this object then uses.
    void rewrap_under_new_kek(const Bytes32& new_kek);

    int64_t current_epoch() const { return current_epoch_; }

private:
    std::string storage_root_;
    std::string path_;
    Bytes32 kek_;
    std::map<uint32_t, Bytes32> deks_;  // epoch_id -> raw DEK, in memory only
    int64_t current_epoch_ = -1;  // -1: no epoch yet

    void load();
    void save();
};

}  // namespace pfs_engine
