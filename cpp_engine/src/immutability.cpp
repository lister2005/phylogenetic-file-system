#include "immutability.hpp"

#include <cstdio>

#include <fcntl.h>
#include <linux/fs.h>
#include <sys/ioctl.h>
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

}  // namespace pfs_engine
