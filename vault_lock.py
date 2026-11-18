"""
Vault locking for the Python engine: several processes may have a vault
open; changes are serialized.

- Open: flock(LOCK_SH) on storage_root/.vault.lock, held for the session's
  lifetime. Any number of processes can hold it.
- Each change: flock(LOCK_EX) on storage_root/.vault.write.lock, held only
  while the change runs (write()). Re-entrant within a process.
- Whole-vault rewrites (vacuum, fsck repair, panic, reset): exclusive()
  upgrades .vault.lock to LOCK_EX, which only succeeds when no other
  process has the vault open.

The OS releases flocks when the descriptor closes for any reason, so there
is no stale lock to clean up. Sessions in one process share one descriptor
per lock file through a refcounted registry. The C++ engine uses the same
scheme (vault_lock.hpp); a vault still belongs to one engine.
"""

import fcntl
import os
import threading
import time
from contextlib import contextmanager

LOCK_FILENAME = ".vault.lock"
WRITE_LOCK_FILENAME = ".vault.write.lock"
WRITE_LOCK_TIMEOUT_SECONDS = 60.0

# realpath of the lock file -> {"fd": int, "refcount": int, ...}; guarded by _registry_lock.
_registry_lock = threading.Lock()
_registry = {}


class VaultLockError(Exception):
    """The vault can't be opened, or locked for this operation, right now."""


class VaultBusyError(VaultLockError):
    """An operation needing the whole vault ran while other processes had it open."""


def _flock_with_timeout(fd, mode, timeout):
    """Tries to take a flock until timeout seconds pass; returns whether it succeeded."""
    deadline = time.monotonic() + timeout
    while True:
        try:
            fcntl.flock(fd, mode | fcntl.LOCK_NB)
            return True
        except OSError:
            if time.monotonic() >= deadline:
                return False
            time.sleep(0.02)


class _WriteLock:
    """Per-process state for .vault.write.lock: one fd, a re-entrant thread
    lock and a depth count, so the flock is taken on the outermost write()."""

    def __init__(self, path):
        """Opens the write-lock file and sets up the in-process re-entrant lock."""
        self.fd = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
        self.thread_lock = threading.RLock()
        self.depth = 0


class VaultLock:
    """Held (shared) for a vault session's lifetime; release() is idempotent.
    Raises VaultLockError if the vault is held exclusively right now.
    """

    def __init__(self, storage_root: str):
        """Takes a shared lock on the vault for this session, reusing the process's descriptor if already open."""
        os.makedirs(storage_root, exist_ok=True)
        lock_path = os.path.join(storage_root, LOCK_FILENAME)
        write_path = os.path.join(storage_root, WRITE_LOCK_FILENAME)
        self._storage_root = storage_root
        self._key = os.path.realpath(lock_path)
        self._active = False

        with _registry_lock:
            entry = _registry.get(self._key)
            if entry is not None:
                entry["refcount"] += 1
                self._active = True
                return
            fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
            try:
                fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
            except OSError:
                os.close(fd)
                raise VaultLockError(
                    f"Vault '{storage_root}' is busy: another program is running an operation that "
                    f"needs the whole vault (vacuum, fsck repair or panic). Try again shortly.")
            _registry[self._key] = {"fd": fd, "refcount": 1, "write": _WriteLock(write_path),
                                    "exclusive_depth": 0}
            self._active = True

    def _entry(self):
        """Returns this vault's shared entry in the process-wide lock registry."""
        with _registry_lock:
            return _registry[self._key]

    @contextmanager
    def write(self):
        """Serializes one change against every other process (and thread)."""
        w = self._entry()["write"]
        with w.thread_lock:
            if w.depth == 0 and not _flock_with_timeout(w.fd, fcntl.LOCK_EX, WRITE_LOCK_TIMEOUT_SECONDS):
                raise VaultLockError(
                    f"Timed out after {WRITE_LOCK_TIMEOUT_SECONDS:.0f}s waiting for another program "
                    f"to finish changing vault '{self._storage_root}'.")
            w.depth += 1
            try:
                yield
            finally:
                w.depth -= 1
                if w.depth == 0:
                    fcntl.flock(w.fd, fcntl.LOCK_UN)

    @contextmanager
    def exclusive(self):
        """Sole use of the vault, for whole-vault rewrites. Raises
        VaultBusyError at once if another process has the vault open.
        """
        entry = self._entry()
        with self.write():
            if entry["exclusive_depth"] == 0:
                try:
                    fcntl.flock(entry["fd"], fcntl.LOCK_EX | fcntl.LOCK_NB)
                except OSError:
                    # A failed conversion may have dropped the shared lock: take it back.
                    fcntl.flock(entry["fd"], fcntl.LOCK_SH)
                    raise VaultBusyError(
                        f"This needs vault '{self._storage_root}' to itself, but another program "
                        f"has it open. Close the other PFS programs using it and try again.")
            entry["exclusive_depth"] += 1
            try:
                yield
            finally:
                entry["exclusive_depth"] -= 1
                if entry["exclusive_depth"] == 0:
                    fcntl.flock(entry["fd"], fcntl.LOCK_SH)

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
                    os.close(entry["write"].fd)
                del _registry[self._key]

    def __del__(self):
        """Releases the lock if the object is garbage-collected without release()."""
        try:
            self.release()
        except Exception:
            pass
