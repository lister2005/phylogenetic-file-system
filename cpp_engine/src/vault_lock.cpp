#include "vault_lock.hpp"

#include <fcntl.h>
#include <sys/file.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <filesystem>
#include <map>
#include <mutex>
#include <stdexcept>

namespace pfs_engine {

namespace {

constexpr const char* kLockFilename = ".vault.lock";

struct LockEntry {
    int fd = -1;
    int refcount = 0;
};

std::mutex g_registry_mutex;
std::map<std::string, LockEntry> g_registry;

}  // namespace

VaultLock::VaultLock(const std::string& storage_root) {
    std::filesystem::create_directories(storage_root);
    std::filesystem::path lock_path = std::filesystem::path(storage_root) / kLockFilename;

    // Open (creating if needed) before canonicalizing -- canonical()
    // requires the path to already exist.
    int fd = ::open(lock_path.c_str(), O_CREAT | O_RDWR, 0600);
    if (fd < 0) {
        throw std::runtime_error("Couldn't create lock file at '" + lock_path.string() +
                                  "': " + std::strerror(errno));
    }

    std::error_code ec;
    std::filesystem::path canonical = std::filesystem::canonical(lock_path, ec);
    canonical_path_ = ec ? lock_path.string() : canonical.string();

    std::lock_guard<std::mutex> guard(g_registry_mutex);
    auto it = g_registry.find(canonical_path_);
    if (it != g_registry.end() && it->second.refcount > 0) {
        // Already held by THIS process (another VaultSession against
        // the same vault) -- join it, no new OS-level flock call
        // needed. Don't leak the fd we just opened; the registry's
        // original fd is what's actually holding the OS lock.
        ::close(fd);
        it->second.refcount += 1;
        active_ = true;
        return;
    }

    if (::flock(fd, LOCK_EX | LOCK_NB) != 0) {
        ::close(fd);
        throw std::runtime_error(
            "Vault '" + storage_root + "' is already open by another process. Only one process "
            "may use a PFS vault at a time -- this is a known, deliberate limitation (see "
            "manual.txt PART 6), not a bug.");
    }

    LockEntry entry;
    entry.fd = fd;
    entry.refcount = 1;
    g_registry[canonical_path_] = entry;
    active_ = true;
}

VaultLock::~VaultLock() {
    if (!active_) return;
    std::lock_guard<std::mutex> guard(g_registry_mutex);
    auto it = g_registry.find(canonical_path_);
    if (it == g_registry.end()) return;
    it->second.refcount -= 1;
    if (it->second.refcount <= 0) {
        ::flock(it->second.fd, LOCK_UN);
        ::close(it->second.fd);
        g_registry.erase(it);
    }
}

}  // namespace pfs_engine
