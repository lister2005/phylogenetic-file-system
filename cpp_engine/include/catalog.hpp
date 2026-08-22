#pragma once
// C++ port of VaultSession's catalog (label -> current manifest_filename
// pointer). Same story as manifest/keyring/lineage: Python pickles a
// `Dict[str, str]` (catalog.enc); this is a new small portable format
// (catalog.pfsc) instead. Small enough that, like the keyring, there's
// nothing deeper to port than the container shape itself -- no
// algorithmic complexity here, just "don't use pickle."
//
// Why this can't just be derived from LineageStore alone: a label with
// multiple open branch heads (after a fork) has more than one valid
// "current" generation, and LineageStore has no notion of which one is
// THE one a plain, generation-unaware read/write should use -- that's
// exactly what the catalog records (vault_session.py: "the catalog
// pointer... always moves to whichever branch was written to most
// recently, fork or not"). It's genuinely separate state, not a cache.
#include <map>
#include <optional>
#include <string>
#include <vector>

#include "crypto_utils.hpp"

namespace pfs_engine {

class Catalog {
public:
    Catalog(std::string storage_root, const Bytes32& kek);

    bool contains(const std::string& label) const { return entries_.count(label) > 0; }
    std::optional<std::string> get(const std::string& label) const;
    void set(const std::string& label, const std::string& manifest_filename);  // persists immediately
    void remove(const std::string& label);                                     // persists immediately
    std::vector<std::string> labels() const;

private:
    std::string storage_root_;
    std::string path_;
    Bytes32 kek_;
    std::map<std::string, std::string> entries_;  // label -> manifest_filename

    void load();
    void save();
};

}  // namespace pfs_engine
