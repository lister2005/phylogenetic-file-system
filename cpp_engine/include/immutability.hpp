#pragma once
// Best-effort deletion resistance via Linux's immutable (+i) file
// attribute -- ports gearhash/immutability.py's INTENT exactly (protects
// against "attacker can't decrypt but can still rm", fails safe, warns
// once rather than repeatedly), but not its IMPLEMENTATION mechanically:
// Python shells out to the `chattr` CLI via subprocess; this calls the
// same underlying FS_IOC_SETFLAGS ioctl directly. That's a deliberate
// upgrade made possible by the port, not a divergence worth avoiding --
// one fewer process spawn per call, same effect, same failure mode.
#include <string>

namespace pfs_engine {

// Best-effort +i / -i. Returns true if it actually took effect. Never
// throws -- a filesystem that doesn't support the attribute, or a
// process without CAP_LINUX_IMMUTABLE, is a normal, expected outcome
// (the vault still works without this layer), not an error condition.
bool set_immutable(const std::string& path, bool immutable);

}  // namespace pfs_engine
