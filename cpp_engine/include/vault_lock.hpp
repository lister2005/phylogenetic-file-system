#pragma once
// Process-wide advisory lock on a vault: one process at a time (the C++
// counterpart of vault_lock.py).
//
// flock(LOCK_EX | LOCK_NB) on storage_root/.vault.lock; the OS releases it
// when the descriptor closes for any reason. Locks in the same process
// share one flock through a refcounted registry, so a second session in
// the same process (e.g. the 'attack' self-test's wrong-key session)
// still opens.
#include <string>

namespace pfs_engine {

class VaultLock {
public:
    // Throws std::runtime_error if another process holds the vault. Never blocks.
    explicit VaultLock(const std::string& storage_root);
    ~VaultLock();

    VaultLock(const VaultLock&) = delete;
    VaultLock& operator=(const VaultLock&) = delete;

private:
    std::string canonical_path_;
    bool active_ = false;
};

}  // namespace pfs_engine
