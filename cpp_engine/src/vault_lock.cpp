#include "vault_lock.hpp"

#include <fcntl.h>
#include <sys/file.h>
#include <unistd.h>

#include <cerrno>
#include <chrono>
#include <cstring>
#include <filesystem>
#include <map>
#include <memory>
#include <mutex>
#include <thread>

namespace pfs_engine {

namespace {

constexpr const char* kLockFilename = ".vault.lock";
constexpr const char* kWriteLockFilename = ".vault.write.lock";

// One vault's lock state in this process, shared by its sessions.
struct LockEntry {
    int fd = -1;        // .vault.lock: LOCK_SH while open, LOCK_EX during ExclusiveGuard
    int write_fd = -1;  // .vault.write.lock: LOCK_EX during the outermost WriteGuard
    int refcount = 0;
    std::unique_ptr<std::recursive_mutex> write_mutex = std::make_unique<std::recursive_mutex>();
    int write_depth = 0;
    int exclusive_depth = 0;
};

std::mutex g_registry_mutex;
std::map<std::string, LockEntry> g_registry;

// The registry entry for key. Entries live until the last session closes.
LockEntry& entry_for(const std::string& key) {
    std::lock_guard<std::mutex> guard(g_registry_mutex);
    return g_registry.at(key);
}

// Tries to take a flock until timeout passes; returns whether it succeeded.
bool flock_with_timeout(int fd, int mode, double timeout_seconds) {
    auto deadline = std::chrono::steady_clock::now() + std::chrono::duration<double>(timeout_seconds);
    for (;;) {
        if (::flock(fd, mode | LOCK_NB) == 0) return true;
        if (std::chrono::steady_clock::now() >= deadline) return false;
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
}

}  // namespace

// Takes the shared lock for this session, reusing the process's descriptor if already open.
VaultLock::VaultLock(const std::string& storage_root) : storage_root_(storage_root) {
    std::filesystem::create_directories(storage_root);
    std::filesystem::path lock_path = std::filesystem::path(storage_root) / kLockFilename;
    std::filesystem::path write_path = std::filesystem::path(storage_root) / kWriteLockFilename;

    // Create it first: canonical() needs an existing path.
    int fd = ::open(lock_path.c_str(), O_CREAT | O_RDWR, 0600);
    if (fd < 0) {
        throw VaultLockError("Couldn't create lock file at '" + lock_path.string() + "': " + std::strerror(errno));
    }
    std::error_code ec;
    std::filesystem::path canonical = std::filesystem::canonical(lock_path, ec);
    key_ = ec ? lock_path.string() : canonical.string();

    std::lock_guard<std::mutex> guard(g_registry_mutex);
    auto it = g_registry.find(key_);
    if (it != g_registry.end()) {
        ::close(fd);
        it->second.refcount += 1;
        active_ = true;
        return;
    }
    if (::flock(fd, LOCK_SH | LOCK_NB) != 0) {
        ::close(fd);
        throw VaultLockError(
            "Vault '" + storage_root + "' is busy: another program is running an operation that needs the "
            "whole vault (vacuum or fsck). Try again shortly.");
    }
    int write_fd = ::open(write_path.c_str(), O_CREAT | O_RDWR, 0600);
    if (write_fd < 0) {
        ::flock(fd, LOCK_UN);
        ::close(fd);
        throw VaultLockError("Couldn't create lock file at '" + write_path.string() + "': " + std::strerror(errno));
    }
    LockEntry entry;
    entry.fd = fd;
    entry.write_fd = write_fd;
    entry.refcount = 1;
    g_registry.emplace(key_, std::move(entry));
    active_ = true;
}

// Releases the shared lock when the last session in this process closes.
VaultLock::~VaultLock() {
    if (!active_) return;
    std::lock_guard<std::mutex> guard(g_registry_mutex);
    auto it = g_registry.find(key_);
    if (it == g_registry.end()) return;
    it->second.refcount -= 1;
    if (it->second.refcount <= 0) {
        ::flock(it->second.fd, LOCK_UN);
        ::close(it->second.fd);
        ::close(it->second.write_fd);
        g_registry.erase(it);
    }
}

// Takes the change lock (re-entrant); the flock is taken by the outermost caller only.
void VaultLock::acquire_write() {
    LockEntry& entry = entry_for(key_);
    entry.write_mutex->lock();
    if (entry.write_depth == 0 && !flock_with_timeout(entry.write_fd, LOCK_EX, kWriteLockTimeoutSeconds)) {
        entry.write_mutex->unlock();
        throw VaultLockError("Timed out after 60s waiting for another program to finish changing vault '" +
                             storage_root_ + "'.");
    }
    entry.write_depth += 1;
}

// Releases one level of the change lock; the flock goes with the outermost.
void VaultLock::release_write() {
    LockEntry& entry = entry_for(key_);
    entry.write_depth -= 1;
    if (entry.write_depth == 0) ::flock(entry.write_fd, LOCK_UN);
    entry.write_mutex->unlock();
}

// Takes the change lock for the guard's lifetime.
VaultLock::WriteGuard::WriteGuard(VaultLock& lock) : lock_(lock) { lock_.acquire_write(); }

// Releases the change lock.
VaultLock::WriteGuard::~WriteGuard() { lock_.release_write(); }

// Takes the change lock, then upgrades the vault lock to exclusive; throws if others have it open.
VaultLock::ExclusiveGuard::ExclusiveGuard(VaultLock& lock) : lock_(lock) {
    lock_.acquire_write();
    LockEntry& entry = entry_for(lock_.key_);
    if (entry.exclusive_depth == 0 && ::flock(entry.fd, LOCK_EX | LOCK_NB) != 0) {
        // A failed conversion may have dropped the shared lock: take it back.
        ::flock(entry.fd, LOCK_SH);
        lock_.release_write();
        throw VaultBusyError("This needs vault '" + lock_.storage_root_ +
                             "' to itself, but another program has it open. Close the other PFS programs "
                             "using it and try again.");
    }
    entry.exclusive_depth += 1;
}

// Returns the vault lock to shared and releases the change lock.
VaultLock::ExclusiveGuard::~ExclusiveGuard() {
    LockEntry& entry = entry_for(lock_.key_);
    entry.exclusive_depth -= 1;
    if (entry.exclusive_depth == 0) ::flock(entry.fd, LOCK_SH);
    lock_.release_write();
}

}  // namespace pfs_engine
