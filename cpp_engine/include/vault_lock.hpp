#pragma once
// OS-level advisory lock enforcing this project's already-declared "one
// process at a time" invariant (manual.txt PART 6, "Real, not-yet-
// hardened risk surface") for a vault's storage_root. C++ counterpart
// to vault_lock.py -- same design, same reasoning; see that file's
// module docstring for the full story (the real lost-update bug this
// closes: two processes opening the SAME storage_root, both loading
// the catalog, both saving their own mutated copy, one silently
// overwriting the other's write with no error to either process).
//
// Uses flock(LOCK_EX | LOCK_NB) on storage_root/.vault.lock (created if
// missing). No PID-file/staleness handling on top of this -- that's
// flock's whole point: the OS releases the lock automatically the
// instant every file descriptor referencing it is closed, for ANY
// reason (clean exit, crash, kill -9).
//
// Deliberately PROCESS-scoped, not object-scoped: multiple VaultLock
// instances within the SAME process against the same storage_root
// (e.g. pfs_cli.py's C++-engine 'attack' self-test, which opens a
// second, deliberately-wrong-key CppVaultSession -- via pfs_open() ->
// this class's constructor -- against the same vault while the main
// session is still open, specifically to prove wrong keys are
// rejected) share one underlying flock via a refcounted, mutex-guarded
// registry keyed by the lock file's canonical path. The real OS-level
// flock is only ever taken once per process, matching the invariant as
// actually stated ("one PROCESS at a time", not "one session at a
// time") -- this is what keeps that self-test (and ordinary same-
// process sequential reopen, all over cpp_engine/bench/*_test.cpp)
// working exactly as before. A genuinely different OS process trying
// to open the same vault while any VaultLock for it is held anywhere
// in this process is refused immediately, no blocking or retry.
#include <string>

namespace pfs_engine {

class VaultLock {
public:
    // Throws std::runtime_error (with a clear, user-facing message)
    // if a DIFFERENT process already holds this vault's lock. Never
    // blocks.
    explicit VaultLock(const std::string& storage_root);
    ~VaultLock();

    VaultLock(const VaultLock&) = delete;
    VaultLock& operator=(const VaultLock&) = delete;

private:
    std::string canonical_path_;
    bool active_ = false;
};

}  // namespace pfs_engine
