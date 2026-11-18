#pragma once
// Vault locking for the C++ engine, the counterpart of vault_lock.py:
// several processes may have a vault open; changes are serialized.
//
// - Open: flock(LOCK_SH) on storage_root/.vault.lock, held for the session's
//   lifetime. Any number of processes can hold it.
// - Each change: flock(LOCK_EX) on storage_root/.vault.write.lock, held only
//   while the change runs (WriteGuard). Re-entrant within a process.
// - Whole-vault rewrites (vacuum, fsck): ExclusiveGuard upgrades .vault.lock
//   to LOCK_EX, which only succeeds when no other process has the vault open.
//
// The OS releases flocks when the descriptor closes for any reason, so there
// is no stale lock to clean up. Sessions in one process share one descriptor
// per lock file through a refcounted registry.
#include <stdexcept>
#include <string>

namespace pfs_engine {

// The vault can't be opened, or locked for this operation, right now.
class VaultLockError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

// An operation needing the whole vault ran while other processes had it open.
class VaultBusyError : public VaultLockError {
public:
    using VaultLockError::VaultLockError;
};

class VaultLock {
public:
    // Takes the shared lock. Throws VaultLockError if the vault is held
    // exclusively (a vacuum or fsck is running elsewhere). Never blocks.
    explicit VaultLock(const std::string& storage_root);
    ~VaultLock();

    VaultLock(const VaultLock&) = delete;
    VaultLock& operator=(const VaultLock&) = delete;

    // One change, serialized against every other process and thread. Waits
    // up to kWriteLockTimeoutSeconds, then throws VaultLockError.
    class WriteGuard {
    public:
        explicit WriteGuard(VaultLock& lock);
        ~WriteGuard();
        WriteGuard(const WriteGuard&) = delete;
        WriteGuard& operator=(const WriteGuard&) = delete;

    private:
        VaultLock& lock_;
    };

    // Sole use of the vault, for whole-vault rewrites. Throws VaultBusyError
    // at once if another process has the vault open.
    class ExclusiveGuard {
    public:
        explicit ExclusiveGuard(VaultLock& lock);
        ~ExclusiveGuard();
        ExclusiveGuard(const ExclusiveGuard&) = delete;
        ExclusiveGuard& operator=(const ExclusiveGuard&) = delete;

    private:
        VaultLock& lock_;
    };

    static constexpr double kWriteLockTimeoutSeconds = 60.0;

private:
    std::string storage_root_;
    std::string key_;  // canonical path of the lock file: the registry key
    bool active_ = false;

    void acquire_write();
    void release_write();
};

}  // namespace pfs_engine
