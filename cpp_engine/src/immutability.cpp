#include "immutability.hpp"

#include <cstdio>
#include <stdexcept>
#include <vector>

#include <fcntl.h>
#include <linux/fs.h>
#include <sys/ioctl.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <unistd.h>

namespace pfs_engine {

namespace {
bool g_warned = false;

// Prints, once per process, that deletion protection isn't available here.
void warn_once() {
    if (g_warned) return;
    fprintf(stderr,
        "\nNote: deletion protection (immutable attribute) is not active for this "
        "vault --\neither this filesystem doesn't support it, or this process lacks "
        "the CAP_LINUX_IMMUTABLE\ncapability (needs root or that specific "
        "capability). The vault still works normally\nwithout it; it just means "
        "someone with plain filesystem access could delete vault\nfiles even "
        "without the key. Run as root (or grant that capability) for this layer\n"
        "to take effect.\n\n");
    g_warned = true;
}
}  // namespace

// Sets or clears a file's immutable attribute; returns whether it worked.
bool set_immutable(const std::string& path, bool immutable) {
    int fd = open(path.c_str(), O_RDONLY);
    if (fd < 0) {
        warn_once();
        return false;
    }
    int flags = 0;
    if (ioctl(fd, FS_IOC_GETFLAGS, &flags) < 0) {
        close(fd);
        warn_once();
        return false;
    }
    if (immutable) {
        flags |= FS_IMMUTABLE_FL;
    } else {
        flags &= ~FS_IMMUTABLE_FL;
    }
    bool ok = ioctl(fd, FS_IOC_SETFLAGS, &flags) == 0;
    close(fd);
    if (!ok) warn_once();
    return ok;
}

// Overwrites a file's bytes with random data and syncs; the file stays. Throws on failure.
void scrub_file(const std::string& path) {
    int fd = open(path.c_str(), O_WRONLY);
    if (fd < 0) throw std::runtime_error("can't open '" + path + "' to overwrite it");
    struct stat st{};
    fstat(fd, &st);
    std::vector<unsigned char> block(1 << 20);
    off_t remaining = st.st_size, offset = 0;
    while (remaining > 0) {
        size_t n = static_cast<size_t>(std::min<off_t>(remaining, static_cast<off_t>(block.size())));
        if (getrandom(block.data(), n, 0) != static_cast<ssize_t>(n) ||
            pwrite(fd, block.data(), n, offset) != static_cast<ssize_t>(n)) {
            close(fd);
            throw std::runtime_error("failed to overwrite '" + path + "'");
        }
        offset += static_cast<off_t>(n);
        remaining -= static_cast<off_t>(n);
    }
    fsync(fd);
    close(fd);
}

// Overwrites a file with random data, then deletes it. No-op if it doesn't exist.
void scrub_and_remove(const std::string& path) {
    struct stat st{};
    if (stat(path.c_str(), &st) != 0) return;
    scrub_file(path);
    unlink(path.c_str());
}

// Overwrites the file at path (if any), then renames tmp_path over it.
void scrub_then_replace(const std::string& tmp_path, const std::string& path) {
    struct stat st{};
    if (stat(path.c_str(), &st) == 0) scrub_file(path);
    if (rename(tmp_path.c_str(), path.c_str()) != 0) {
        throw std::runtime_error("failed to move '" + tmp_path + "' into place");
    }
}

}  // namespace pfs_engine
