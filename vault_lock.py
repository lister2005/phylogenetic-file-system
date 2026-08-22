"""
OS-level advisory lock enforcing this project's already-declared "one
process at a time" invariant (manual.txt PART 6, "Real, not-yet-hardened
risk surface") for a vault's storage_root.

WHY THIS EXISTS: before this, nothing stopped two processes opening the
SAME storage_root at once. Both would load the encrypted catalog into
memory, both would mutate their own in-memory copy, both would call
save_catalog() -- and whichever one wrote last silently won, discarding
the other's write with NO error to either process (reproduced live in
NEW_USER_ACCEPTANCE_REPORT.md SS3.6/SS6 bug #1: two CLI processes each
wrote a different label to the same vault, both printed "Stored as
'X'", and one label vanished from the catalog with the encrypted chunk
data for it still on disk but unreachable). The invariant ("single-
process-at-a-time") was already the documented, deliberate design --
this module is what actually enforces it, turning a silent lost update
into an immediate, clear refusal.

Uses flock(LOCK_EX | LOCK_NB) on a dedicated storage_root/.vault.lock
file (created if missing). Deliberately NOT combined with any PID-file
staleness check -- that's flock's whole point: the OS releases the lock
automatically the instant the holding process's last file descriptor
onto it closes, for ANY reason (clean exit, crash, kill -9), so there's
no stale-lock state to ever detect or clean up.

Deliberately PROCESS-scoped, not object-scoped: multiple VaultLock
instances within the SAME process against the same storage_root (e.g.
pfs_cli.py's C++-engine 'attack' self-test, which opens a second,
deliberately-wrong-key CppVaultSession against the same vault while the
main session is still open, to prove wrong keys are rejected) share one
underlying flock via a refcounted registry keyed by the lock file's
canonical path -- the real OS-level flock is only ever taken once per
process. That matches the invariant as actually stated ("one PROCESS at
a time", not "one session object at a time") and is what keeps ordinary
same-process sequential reopen (open a vault, do work, close it, reopen
it later -- all over this project's own test suite) and legitimate
same-process concurrent secondary sessions working exactly as before.
A second, genuinely different OS PROCESS trying to open the same vault
while any VaultLock for it is still held anywhere in this process gets
refused immediately by the OS-level flock, no polling or retry needed.
"""

import fcntl
import os
import threading

LOCK_FILENAME = ".vault.lock"

# path (realpath of the lock file) -> {"fd": int, "refcount": int}.
# Guarded by _registry_lock. Process-wide, not per-VaultSession-class,
# so it also covers the rare case of a Python-engine VaultSession and a
# C++-engine CppVaultSession both somehow pointed at the same
# storage_root within one process (cross-engine access to the same
# vault is separately refused by the existing wrong-engine-marker-file
# check in both _existing_vault_engine() implementations; this registry
# would just make it redundantly safe, not the primary defense there).
_registry_lock = threading.Lock()
_registry = {}


class VaultLockError(Exception):
    """Raised when a vault's storage_root is already locked by another
    process. Callers should surface this exactly like any other
    unlock failure (sys.exit for a CLI, a failed mount for FUSE, a
    dialog for the GUI) -- see vault_session.py's unlock_or_create,
    which raises this same condition wrapped as VaultUnlockError so
    every existing caller's `except VaultUnlockError` already handles
    it with no changes needed."""


class VaultLock:
    """Acquired for the full lifetime of a vault session: construct it
    when the session opens, call release() (idempotent) when it closes.
    Raises VaultLockError immediately if a DIFFERENT process already
    holds it -- never blocks."""

    def __init__(self, storage_root: str):
        os.makedirs(storage_root, exist_ok=True)
        lock_path = os.path.join(storage_root, LOCK_FILENAME)
        # Open (creating if needed) before canonicalizing so realpath
        # has something to resolve against.
        fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
        self._key = os.path.realpath(lock_path)
        self._active = False

        with _registry_lock:
            entry = _registry.get(self._key)
            if entry is not None:
                # Already held by THIS process (another VaultLock/
                # VaultSession against the same vault) -- join it, no
                # new OS-level flock call needed. Don't leak the fd we
                # just opened; the registry's original fd is what's
                # actually holding the OS lock.
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
        """Idempotent -- safe to call more than once (close()/__del__
        both call it)."""
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
