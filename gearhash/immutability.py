"""
Best-effort deletion resistance via chattr +i, which stops `rm` where
encryption only stops reading. Needs root or CAP_LINUX_IMMUTABLE; without
it every call returns False after one warning and never blocks the vault
operation.
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
    """chattr +i / -i. True if it took effect; warns once on the first failure."""
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
    """Context manager: clears +i (if set) around a write or delete, then restores it."""
    class _Ctx:
        def __enter__(self):
            set_immutable(path, False)
            return self

        def __exit__(self, exc_type, exc, tb):
            set_immutable(path, True)
            return False

    return _Ctx()
