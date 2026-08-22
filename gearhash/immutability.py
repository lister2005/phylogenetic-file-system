"""
Best-effort deletion resistance using Linux's chattr +i (immutable)
attribute. This protects a DIFFERENT property than encryption: an
attacker who can't decrypt your files can still just `rm` them,
destroying everything even without breaking in. Encryption alone never
stops that -- it only stops reading. +i does stop it, IF the caller has
the privilege to set/clear it (root, or CAP_LINUX_IMMUTABLE).

This is directly what your own design doc anticipated (the daemon
discussion: "requires a password/token/authentication check... executes
sudo chattr -i ... and then deletes the files"). It's also exactly the
kind of protection that becomes native and much stronger once this is a
real kernel module (Phase 3) instead of a userspace script -- right now
this is a userspace approximation using what Linux already exposes.

Fails safe: if chattr isn't available, this filesystem doesn't support
the attribute, or the caller lacks privilege, every function here just
returns False and prints ONE explanatory warning (not a repeated nag).
It NEVER blocks the actual vault operation -- protection is a bonus
layer, not a dependency.
"""

import subprocess
import shutil

_warned = False


def _warn_once():
    global _warned
    if _warned:
        return
    print("\nNote: deletion protection (chattr +i) is not active for this vault --")
    print("either 'chattr' isn't available, this filesystem doesn't support it, or this")
    print("process doesn't have permission (needs root or CAP_LINUX_IMMUTABLE). The")
    print("vault still works normally without it; it just means someone with plain")
    print("filesystem access could delete vault files even without your key. Run as")
    print("root (or grant that specific capability) for this layer to take effect.\n")
    _warned = True


def set_immutable(path: str, immutable: bool) -> bool:
    """Best-effort chattr +i / -i. Returns True if it actually took
    effect, False otherwise (and warns once, the first time it fails)."""
    if shutil.which("chattr") is None:
        _warn_once()
        return False
    flag = "+i" if immutable else "-i"
    try:
        result = subprocess.run(
            ["chattr", flag, path], capture_output=True, text=True, timeout=5
        )
        if result.returncode != 0:
            _warn_once()
            return False
        return True
    except Exception:
        _warn_once()
        return False


def with_mutable(path: str):
    """Context manager: temporarily clears +i (if it was set) so path
    can be written/deleted, then restores +i afterward. Safe to use on
    a path that was never protected -- both calls just no-op/warn-once
    without raising."""
    class _Ctx:
        def __enter__(self):
            set_immutable(path, False)
            return self

        def __exit__(self, exc_type, exc, tb):
            set_immutable(path, True)
            return False

    return _Ctx()
