#pragma once
// Best-effort deletion resistance via the immutable (+i) attribute, like
// gearhash/immutability.py, but through the FS_IOC_SETFLAGS ioctl rather
// than running chattr.
#include <string>

namespace pfs_engine {

// Best-effort +i / -i. True if it took effect. Never throws.
bool set_immutable(const std::string& path, bool immutable);

}  // namespace pfs_engine
