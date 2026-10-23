"""
Process-wide advisory lock on a vault: one process at a time.

flock(LOCK_EX | LOCK_NB) on storage_root/.vault.lock. The OS releases it
when the holder's descriptor closes for any reason, so there is no stale
lock to clean up. Locks in the same process share one flock through a
refcounted registry, so a second session in the same process (e.g. the
C++ 'attack' self-test's wrong-key session) still works.
"""

import fcntl
import os
import threading

LOCK_FILENAME = ".vault.lock"

# realpath of the lock file -> {"fd": int, "refcount": int}; guarded by _registry_lock.
_registry_lock = threading.Lock()
_registry = {}


class VaultLockError(Exception):
    """The vault is already locked by another process."""


class VaultLock:
    """Held for a vault session's lifetime; release() is idempotent.
    Raises VaultLockError at once if another process holds the vault.
    """

    def __init__(self, storage_root: str):
        os.makedirs(storage_root, exist_ok=True)
        lock_path = os.path.join(storage_root, LOCK_FILENAME)
        fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
        self._key = os.path.realpath(lock_path)
        self._active = False

        with _registry_lock:
            entry = _registry.get(self._key)
            if entry is not None:
                # Already held by this process: join it and close the extra fd.
                os.close(fd)
                entry["refcount"] += 1
                self._active = True
                return
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError:
                os.close(fd)
                raise VaultLockError(
                    f"Vault '{storage_root}' is already open by another process. Only one "
                    f"process may use a PFS vault at a time -- this is a known, deliberate "
                    f"limitation (see manual.txt PART 6), not a bug."
                )
            _registry[self._key] = {"fd": fd, "refcount": 1}
            self._active = True

    def release(self) -> None:
        """Idempotent."""
        if not self._active:
            return
        self._active = False
        with _registry_lock:
            entry = _registry.get(self._key)
            if entry is None:
                return
            entry["refcount"] -= 1
            if entry["refcount"] <= 0:
                try:
                    fcntl.flock(entry["fd"], fcntl.LOCK_UN)
                finally:
                    os.close(entry["fd"])
                del _registry[self._key]

    def __del__(self):
        try:
            self.release()
        except Exception:
            pass
