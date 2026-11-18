#pragma once
// Best-effort deletion resistance via the immutable (+i) attribute, like
// gearhash/immutability.py, but through the FS_IOC_SETFLAGS ioctl rather
// than running chattr.
#include <string>

namespace pfs_engine {

// Best-effort +i / -i. True if it took effect. Never throws.
bool set_immutable(const std::string& path, bool immutable);

// For 'shred'. On SSDs and copy-on-write or journaling filesystems the old
// blocks may survive elsewhere on the device; these remove the data from the
// files PFS controls, which is as far as a program can reach.

// Overwrites a file's bytes with random data and syncs; the file stays. Throws on failure.
void scrub_file(const std::string& path);

// Overwrites a file with random data, then deletes it. No-op if it doesn't exist.
void scrub_and_remove(const std::string& path);

// Overwrites the file at path (if any), then renames tmp_path over it.
void scrub_then_replace(const std::string& tmp_path, const std::string& path);

}  // namespace pfs_engine
