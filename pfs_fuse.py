#!/usr/bin/env python3
"""
FUSE mount for the Phylogenetic File System vault -- Phase 2 of the
design doc's roadmap, built in Python rather than C++ (see the project's
Phase 2 decision: gearhash/ is already built, tested, and correct, so
this maps POSIX filesystem calls onto it directly instead of duplicating
that logic in a new language and toolchain from scratch).

PRESENTATION MODEL: two levels, computed from the same clade
partitioning TreeConstructor.compute_clades() does for the CLI's 'tree'
command. Files with no near neighbor (Jaccard distance > threshold, or
no fingerprint yet) sit directly at the mount root. Files that DO share
enough content with at least one other file are grouped into a
subdirectory named after their clade's alphabetically-first member --
e.g. a photo edited three times and saved under three labels shows up
as a 'photo_v1/' directory containing all three, automatically, with no
folder ever explicitly created. This answers the design doc's own
question ("will you build a translation layer that presents the
lineages looking like a traditional folder structure?") with its
simplest useful form. Clade membership is COMPUTED, not stored or
manually assignable -- new files can ONLY be created at the root
(clade directories are read-only containers you browse, not a place to
drop new files into); a file may appear at the root today and inside a
clade directory tomorrow once something similar enough to it gets
written, or vice versa if its clade-mates are deleted. That's
intentional -- it mirrors the design doc's own "automatic evolutionary
self-organization" -- not a bug, but worth knowing about if a path that
worked a moment ago suddenly doesn't.

The partition is maintained by a background worker (clade_worker.py),
incrementally, never on the path of a filesystem call: lookups use its
latest partition, filtered against the live catalog, so a deleted or
renamed file never lingers in a clade directory, and a just-written file
shows at the root until the worker has clustered it.

Two concrete, OBSERVED consequences of that dynamism, confirmed against
a real mount (2026-07-23), not just theorized:
1. Editing a file that currently lives inside a clade directory clears
   its old fingerprint immediately (the edit changed its content, so
   the old one is simply wrong now) and the new one attaches on its own
   background thread, same as every other write. For that ~1-2 second
   gap, the file has NO fingerprint at all, so it's excluded from
   clustering entirely and briefly appears back at the ROOT instead of
   inside the clade directory you just wrote through -- then reappears
   inside it once refingerprinting lands. A process with the file still
   open by its file handle is unaffected either way; only a fresh path
   lookup during that window sees it move.
2. The kernel's own dentry cache can briefly surface EIO (not ENOENT)
   for a path that transitions from file to directory (or back) between
   its own cached lookup and a following stat -- this is standard FUSE
   behavior when a name's type changes underneath an already-cached
   entry, not a bug in this code (nothing here raises or catches
   anything in that window). Both of these settle on their own within
   about a second; neither has been observed to leave anything
   inconsistent once it settles.

READ/WRITE MODEL: streaming, with memory bounded regardless of file
size. open() does NOT reconstruct the file: it opens a
reconstruct.ManifestReader, which resolves the version's chunk table
once and then serves each read() by decrypting only the chunks that
byte range overlaps (same per-chunk integrity checks and mirror
self-healing as reconstruct()). The first write() or truncate() on a
handle copies that version into a scratch file on DISK (never RAM) and
from then on reads and writes go to that file; open(O_TRUNC)/create()
start with an empty scratch file. release() (the file actually being
closed) is the real commit point -- this IS the design doc's
"Speciation on Write": nothing lands in the vault until the file handle
closes, and the scratch file is handed to VaultSession.commit_write(),
the same tested path the CLI's 'write' uses. A commit re-chunks the
whole file (unchanged chunks still dedup, so storage only grows by what
actually changed); a write needs temporary disk space equal to the
file's size.

CONCURRENCY: mounted with nothreads=True on purpose. The storage engine
underneath (SQLite connections, the crypto engine, the catalog dict)
was built and tested for one call at a time, not concurrent FUSE
callback threads -- serializing filesystem calls is the safe choice for
a first working version. This is a real scalability limit (one
operation at a time) worth knowing about, not a hidden one.

LOCKING/AUTH: unlike the CLI, this does NOT reauth per operation --
there's no prompt mechanism inside a read()/write() syscall. The
passphrase is asked once at mount time; from then until unmount, this
behaves like any other mounted encrypted volume (LUKS, VeraCrypt, ...)
-- anyone with OS-level access to the mountpoint can read/write through
it. That's not a new weakness this introduces, just worth being
explicit about: unmount is what re-locks it, not idle time.

DAEMON MODEL: 'mount' unlocks the vault interactively (passphrase
prompt needs a real TTY) and THEN detaches -- a single explicit
os.fork()+setsid(), done ourselves rather than delegated to libfuse's
own internal daemonize, specifically so the parent knows the real
child PID and can record it. The parent writes that PID (plus the
mountpoint) to a small file inside storage_root and exits; the child
closes stdin/stdout/stderr, redirects them to a log file under
storage_root, and runs the FUSE event loop from there. No threads
exist yet at fork time (background fingerprint threads only start
later, from inside FUSE callbacks), so there's nothing fork-across-
thread-unsafe about this. 'status'/'stop' read that PID file; neither
needs the vault passphrase since they only touch the PID file and the
OS mount table, not vault content.

Run with:
  python3 pfs_fuse.py mount <storage_root> <mountpoint> [--foreground]
  python3 pfs_fuse.py status <storage_root>
  python3 pfs_fuse.py stop <storage_root>
Unmount directly (also works, 'stop' is just this + PID cleanup):
  fusermount3 -u <mountpoint>
"""

import os
import sys
import stat
import time
import errno
import getpass
import threading
import tempfile
import argparse
import subprocess

from fuse import FUSE, FuseOSError, Operations

from vault_session import VaultSession, VaultUnlockError
from reconstruct import ManifestReader
from PhylogeneticAnalyzer import PhylogeneticAnalyzer, SIMILARITY_PROFILE
from clade_worker import CladeWorker, filtered_view, python_session_loader

SCRATCH_DIRNAME = ".fuse_scratch"
# How much of a file version one read() pulls through ManifestReader at a
# time when copying it into a scratch file (copy-on-first-write).
SPILL_COPY_BYTES = 1 << 20
PID_FILENAME = ".fuse_daemon.pid"
LOG_FILENAME = ".fuse_daemon.log"


class PFSFuse(Operations):
    def __init__(self, storage_root: str):
        self.session = VaultSession(storage_root)
        self._unlock()

        self.scratch_dir = os.path.join(storage_root, SCRATCH_DIRNAME)
        os.makedirs(self.scratch_dir, exist_ok=True)

        self._next_fh = 1
        # fh -> {"label": str, "reader": ManifestReader or None,
        #        "spill_fd": int or None, "spill_path": str or None, "dirty": bool}
        # Exactly one of reader/spill_fd is set: reader until the first
        # write/truncate, scratch file after (see READ/WRITE MODEL).
        self._handles = {}
        # Guards catalog mutation and the handle/job tables. FUSE itself
        # is mounted single-threaded (nothreads=True) so callbacks never
        # overlap each other, but background fingerprint threads (see
        # _start_background_fingerprint) run concurrently with whatever
        # FUSE call happens next, so shared state they touch still needs
        # this.
        self._lock = threading.RLock()
        self._fingerprint_jobs = []  # (label, Thread) currently running
        # Background clade clustering (clade_worker.py). Started in
        # init(), not here: in daemon mode do_mount() forks AFTER this
        # constructor, and a thread doesn't survive fork().
        self._clades = None
        # Filtered view of the worker's latest snapshot, cached until the
        # snapshot or the catalog changes -- see _get_clades().
        self._catalog_epoch = 0
        self._clade_view = None
        self._clade_view_key = None

    # ---------- setup ----------

    def _unlock(self):
        def get_new_passphrase():
            return getpass.getpass("Set a new vault passphrase: "), getpass.getpass("Confirm passphrase: ")

        def get_existing_passphrase():
            return getpass.getpass("Enter vault passphrase: ")

        def confirm_reset():
            answer = input(
                "Vault's other files don't decrypt under this key. Type 'reset' to "
                "discard them and start fresh, or anything else to abort: "
            )
            return answer.strip().lower() == "reset"

        try:
            self.session.unlock_or_create(get_new_passphrase, get_existing_passphrase, confirm_reset)
        except VaultUnlockError as e:
            print(str(e))
            sys.exit(1)
        print(f"Vault unlocked ({len(self.session.catalog)} file(s) currently stored). Mounting...")

    # ---------- clade computation (cached) ----------

    def init(self, path):
        """Called by FUSE once mounted, in the process that serves the
        mount (after any daemon fork)."""
        with self._lock:
            labels = list(self.session.catalog.keys())
        self._clades = CladeWorker(python_session_loader(self.session), name="fuse-clade-worker").start(labels)

    def _catalog_changed(self) -> None:
        with self._lock:
            self._catalog_epoch += 1

    def _get_clades(self):
        """Returns (clade_to_labels, label_to_clade) from the clade
        worker's latest snapshot, never waiting for a recompute in
        progress. Only clades with 2+ current members are directories --
        a "clade" of one is just a file at the root, not a directory
        (avoids a mount where every single file is its own one-entry
        folder, which would be technically accurate to the design doc
        but genuinely annoying to browse). Filtered against the live
        catalog, so a label deleted or renamed since the snapshot was
        computed never appears; a new label sits at the root until the
        worker has clustered it."""
        if self._clades is None:
            return {}, {}
        snapshot = self._clades.snapshot()
        with self._lock:
            key = (snapshot.version, self._catalog_epoch)
            if self._clade_view_key != key:
                self._clade_view = filtered_view(snapshot, self.session.catalog, min_members=2)
                self._clade_view_key = key
            return self._clade_view

    # ---------- path resolution ----------

    def _resolve(self, path):
        """Resolves a FUSE path against the current (cached) clade
        partition. Returns one of:
            ("root",)                   -- path == "/"
            ("clade_dir", clade_name)   -- a clade subdirectory
            ("file", label)             -- an actual file, wherever it
                                            currently sits
        or None if the path doesn't resolve to anything that exists
        right now."""
        parts = [p for p in path.split("/") if p]
        clade_to_labels, label_to_clade = self._get_clades()

        if not parts:
            return ("root",)

        if len(parts) == 1:
            name = parts[0]
            if name in clade_to_labels:
                return ("clade_dir", name)
            with self._lock:
                in_catalog = name in self.session.catalog
                has_open_handle = any(h["label"] == name for h in self._handles.values())
            if name not in label_to_clade and (in_catalog or has_open_handle):
                return ("file", name)
            return None

        if len(parts) == 2:
            clade_name, label = parts
            if clade_name in clade_to_labels and label in clade_to_labels[clade_name]:
                return ("file", label)
            return None

        return None

    # ---------- directory / metadata ----------

    def getattr(self, path, fh=None):
        now = time.time()
        resolved = self._resolve(path)
        if resolved is None:
            raise FuseOSError(errno.ENOENT)

        if resolved[0] in ("root", "clade_dir"):
            return dict(st_mode=(stat.S_IFDIR | 0o755), st_nlink=2,
                        st_uid=os.getuid(), st_gid=os.getgid(),
                        st_ctime=now, st_mtime=now, st_atime=now)

        label = resolved[1]
        with self._lock:
            # An open-but-not-yet-committed handle for this label should
            # report ITS size -- otherwise 'ls -l' mid-edit looks wrong
            # (still showing the last-committed size).
            for handle in self._handles.values():
                if handle["label"] == label:
                    return dict(st_mode=(stat.S_IFREG | 0o644), st_nlink=1,
                                st_size=self._handle_size(handle),
                                st_uid=os.getuid(), st_gid=os.getgid(),
                                st_ctime=now, st_mtime=now, st_atime=now)
            if label not in self.session.catalog:
                raise FuseOSError(errno.ENOENT)
            manifest_path = self.session.manifest_path_for(label)
            meta = self.session.read_manifest_metadata(manifest_path)

        mtime = os.path.getmtime(manifest_path)
        return dict(st_mode=(stat.S_IFREG | 0o644), st_nlink=1, st_size=meta["original_size"],
                    st_uid=os.getuid(), st_gid=os.getgid(),
                    st_ctime=mtime, st_mtime=mtime, st_atime=mtime)

    def readdir(self, path, fh):
        resolved = self._resolve(path)
        if resolved is None:
            raise FuseOSError(errno.ENOENT)
        kind = resolved[0]
        clade_to_labels, label_to_clade = self._get_clades()

        if kind == "clade_dir":
            return [".", ".."] + sorted(clade_to_labels.get(resolved[1], []))

        if kind != "root":
            raise FuseOSError(errno.ENOTDIR)

        with self._lock:
            all_labels = set(self.session.catalog.keys())
            open_labels = {h["label"] for h in self._handles.values()}
        root_files = {l for l in (all_labels | open_labels) if l not in label_to_clade}
        return [".", ".."] + sorted(clade_to_labels.keys()) + sorted(root_files)

    # ---------- read path ----------

    def _open_reader(self, manifest_path: str) -> ManifestReader:
        try:
            return ManifestReader(manifest_path, self.session.pipeline.container_path,
                                  self.session.crypto.key)
        except Exception:
            raise FuseOSError(errno.EIO)

    def _new_spill(self):
        return tempfile.mkstemp(dir=self.scratch_dir, prefix="write_")

    def _copy_into(self, reader: ManifestReader, fd: int) -> None:
        position = 0
        while position < reader.size:
            piece = reader.read(position, SPILL_COPY_BYTES)
            os.pwrite(fd, piece, position)
            position += len(piece)

    def _materialize(self, handle: dict) -> None:
        """Copy-on-first-write: moves a handle from streaming reads to its
        own scratch file, copying the version it opened chunk by chunk
        (never the whole file in memory). A no-op once it's been done."""
        if handle["spill_fd"] is not None:
            return
        fd, path = self._new_spill()
        try:
            self._copy_into(handle["reader"], fd)
        except Exception:
            os.close(fd)
            os.remove(path)
            raise FuseOSError(errno.EIO)
        handle["reader"].close()
        handle["reader"] = None
        handle["spill_fd"], handle["spill_path"] = fd, path

    def _handle_size(self, handle: dict) -> int:
        if handle["spill_fd"] is not None:
            return os.fstat(handle["spill_fd"]).st_size
        return handle["reader"].size

    def open(self, path, flags):
        resolved = self._resolve(path)
        if resolved is None or resolved[0] != "file":
            raise FuseOSError(errno.ENOENT)
        label = resolved[1]
        with self._lock:
            manifest_path = self.session.manifest_path_for(label)

        if flags & os.O_TRUNC:
            return self._new_handle(label, spill=self._new_spill(), dirty=True)
        return self._new_handle(label, reader=self._open_reader(manifest_path))

    def create(self, path, mode, fi=None):
        # Clade directories are computed, not a place to manually drop
        # new files into -- new files can only be created at the root;
        # they'll be filed into a clade automatically once their
        # fingerprint is ready and it turns out something matches.
        parts = [p for p in path.split("/") if p]
        if len(parts) != 1:
            raise FuseOSError(errno.EACCES)
        return self._new_handle(parts[0], spill=self._new_spill(), dirty=True)

    def _new_handle(self, label: str, reader: ManifestReader = None, spill=None, dirty: bool = False) -> int:
        spill_fd, spill_path = spill if spill is not None else (None, None)
        with self._lock:
            fh = self._next_fh
            self._next_fh += 1
            self._handles[fh] = {"label": label, "reader": reader, "spill_fd": spill_fd,
                                 "spill_path": spill_path, "dirty": dirty}
        return fh

    def read(self, path, size, offset, fh):
        with self._lock:
            handle = self._handles.get(fh)
        if handle is None:
            raise FuseOSError(errno.EBADF)
        if handle["spill_fd"] is not None:
            return os.pread(handle["spill_fd"], size, offset)
        try:
            return handle["reader"].read(offset, size)
        except Exception:
            raise FuseOSError(errno.EIO)

    # ---------- write path ----------

    def write(self, path, data, offset, fh):
        with self._lock:
            handle = self._handles.get(fh)
            if handle is None:
                raise FuseOSError(errno.EBADF)
            self._materialize(handle)
            # Writing past the end leaves a hole the OS reads back as
            # zeros -- the same zero-filled sparse-write gap as before.
            os.pwrite(handle["spill_fd"], data, offset)
            handle["dirty"] = True
        return len(data)

    def _truncate_handle(self, handle: dict, length: int) -> None:
        self._materialize(handle)
        os.ftruncate(handle["spill_fd"], length)
        handle["dirty"] = True

    def truncate(self, path, length, fh=None):
        with self._lock:
            if fh is not None and fh in self._handles:
                self._truncate_handle(self._handles[fh], length)
                return

        resolved = self._resolve(path)
        if resolved is None or resolved[0] != "file":
            if length == 0:
                return  # truncating a not-yet-existent file to 0 is a no-op
            raise FuseOSError(errno.ENOENT)
        label = resolved[1]

        # A path truncate while the file is open applies to every open
        # handle on it; each commits the truncated content on release().
        # This is also how fusepy (libfuse2) delivers open(O_TRUNC): a
        # plain open() and then truncate(path, 0) with no fh. Committing
        # a separate truncated version here instead would be silently
        # overwritten by those handles' pre-truncate copies on release.
        with self._lock:
            open_handles = [h for h in self._handles.values() if h["label"] == label]
            for handle in open_handles:
                self._truncate_handle(handle, length)
        if open_handles:
            return

        # No open handle covers this path (truncate called standalone,
        # e.g. the `truncate` command) -- there's no release() to defer
        # to, so copy into a scratch file, resize it, and commit now.
        manifest_path = self.session.manifest_path_for(label)
        reader = self._open_reader(manifest_path)
        fd, tmp_path = self._new_spill()
        try:
            self._copy_into(reader, fd)
            os.ftruncate(fd, length)
        except Exception:
            os.remove(tmp_path)
            raise FuseOSError(errno.EIO)
        finally:
            reader.close()
            os.close(fd)
        self._commit(label, tmp_path)

    def release(self, path, fh):
        with self._lock:
            handle = self._handles.pop(fh, None)
        if handle is None:
            return 0
        if handle["reader"] is not None:
            handle["reader"].close()
        if handle["spill_fd"] is not None:
            os.close(handle["spill_fd"])
            if handle["dirty"]:
                self._commit(handle["label"], handle["spill_path"])
            else:
                os.remove(handle["spill_path"])
        return 0

    def _commit(self, label: str, tmp_path: str) -> None:
        """The actual Speciation-on-Write event: hands a complete scratch
        file to VaultSession.commit_write() -- the exact same path
        pfs_cli.py's 'write' command uses, so this gets the same
        lineage-generation tracking and catalog handling for free, with
        no separate, unreviewed ingestion path for FUSE writes. Takes
        ownership of tmp_path: the background fingerprint job deletes it
        once it's done reading it (or this does, on failure)."""
        try:
            with self._lock:
                manifest_path = self.session.commit_write(label, tmp_path)
        except Exception:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
            raise FuseOSError(errno.EIO)

        # The new content's fingerprint isn't attached yet (background
        # job below), so this drops the label from clustering until it is.
        self._catalog_changed()
        self._clades.changed(label)
        self._start_background_fingerprint(label, tmp_path, manifest_path)

    def _start_background_fingerprint(self, label: str, tmp_path: str, manifest_path: str) -> None:
        """Same decoupling as pfs_cli.py's write path: the SIMILARITY_
        PROFILE fingerprint (used only by the clade tree, not by data
        integrity) runs on a background thread so closing a file in your
        editor doesn't hang waiting for it. Unlike the CLI, tmp_path here
        is OUR OWN scratch file, not the user's -- so this thread, not
        the caller, is responsible for deleting it once it's done reading
        from it."""
        def _job():
            try:
                fingerprint = PhylogeneticAnalyzer(SIMILARITY_PROFILE).extract_traits(tmp_path)
                self.session.pipeline.attach_similarity_fingerprint(manifest_path, fingerprint)
            except Exception as e:
                sys.stderr.write(f"[pfs_fuse background] fingerprinting '{label}' failed: "
                                  f"{type(e).__name__}: {e}\n")
            finally:
                if os.path.exists(tmp_path):
                    os.remove(tmp_path)
                self._clades.changed(label)  # fingerprint attached -- cluster it
                with self._lock:
                    self._fingerprint_jobs = [
                        (l, t) for l, t in self._fingerprint_jobs if t is not threading.current_thread()
                    ]

        thread = threading.Thread(target=_job, name=f"fuse-fingerprint-{label}")
        with self._lock:
            self._fingerprint_jobs.append((label, thread))
        thread.start()

    # ---------- delete / rename ----------

    def unlink(self, path):
        resolved = self._resolve(path)
        if resolved is None or resolved[0] != "file":
            raise FuseOSError(errno.ENOENT)
        label = resolved[1]
        with self._lock:
            # delete_label(), not a raw pipeline.delete_file() call: a
            # manifest can be shared by more than one label (byte-
            # identical content dedups to the same manifest file) or by
            # this label's own older generations -- only actually free
            # it once nothing else still needs it. See VaultSession.
            # delete_label's docstring for the bug this fixes.
            self.session.delete_label(label)
        self._catalog_changed()
        self._clades.removed(label)

    def rename(self, old, new):
        # A clade-dir prefix on the destination, if any, is ignored --
        # membership is computed, not chosen by which path you typed;
        # only the destination's basename (the new label) is meaningful.
        old_resolved = self._resolve(old)
        if old_resolved is None or old_resolved[0] != "file":
            raise FuseOSError(errno.ENOENT)
        old_label = old_resolved[1]
        new_parts = [p for p in new.split("/") if p]
        if not new_parts:
            raise FuseOSError(errno.EINVAL)
        new_label = new_parts[-1]

        with self._lock:
            if new_label in self.session.catalog and new_label != old_label:
                # POSIX rename silently replaces an existing destination
                # -- go through delete_label so a manifest shared with
                # something else doesn't get destroyed out from under it.
                self.session.delete_label(new_label)
            self.session.catalog[new_label] = self.session.catalog.pop(old_label)
            self.session.lineage.rename_label(old_label, new_label)
            self.session.save_catalog()
        self._catalog_changed()
        self._clades.renamed(old_label, new_label)

    # ---------- clean shutdown ----------

    def destroy(self, path):
        """Called on unmount. Waits for any in-flight background
        fingerprint jobs so unmounting doesn't silently drop one."""
        with self._lock:
            pending = list(self._fingerprint_jobs)
        for _label, thread in pending:
            thread.join()
        if self._clades is not None:
            self._clades.stop(timeout=10)
        try:
            os.rmdir(self.scratch_dir)
        except OSError:
            pass  # non-empty (a job raced us) or already gone -- harmless either way
        # Belt-and-suspenders: if this was a daemonized mount, the PID
        # file should already be gone by the time do_mount's finally
        # block runs, but a manual `fusermount3 -u` (bypassing 'stop')
        # still ends up here via the same destroy() callback, so this
        # is the one place guaranteed to run on every clean unmount.
        pid_file = os.path.join(self.session.storage_root, PID_FILENAME)
        if os.path.exists(pid_file):
            try:
                os.remove(pid_file)
            except OSError:
                pass
        # Release the vault lock (vault_lock.py) explicitly on this
        # normal-unmount path rather than relying on process exit --
        # this process may not exit immediately after destroy() returns
        # in every FUSE binding/version, so don't assume it does.
        self.session.close()


def _pid_file_path(storage_root: str) -> str:
    return os.path.join(storage_root, PID_FILENAME)


def _read_pid_file(storage_root: str):
    """Returns (pid, mountpoint) or None if no daemon is recorded."""
    pid_file = _pid_file_path(storage_root)
    if not os.path.exists(pid_file):
        return None
    with open(pid_file) as f:
        lines = f.read().splitlines()
    if not lines:
        return None
    pid = int(lines[0])
    mountpoint = lines[1] if len(lines) > 1 else None
    return pid, mountpoint


def _pid_is_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)  # signal 0: existence/permission check only, doesn't actually signal
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True  # exists, just owned by someone else


def do_mount(storage_root: str, mountpoint: str, foreground: bool) -> None:
    existing = _read_pid_file(storage_root)
    if existing is not None and _pid_is_alive(existing[0]):
        print(f"Already running: pid {existing[0]}, mounted at {existing[1]}. "
              f"Stop it first with: python3 pfs_fuse.py stop {storage_root}")
        sys.exit(1)

    # Passphrase prompt needs a real TTY -- must happen here, in the
    # original foreground process, before any detaching below.
    fs = PFSFuse(storage_root)
    # print() doesn't flush when stdout isn't a TTY. Without this, output
    # already written by PFSFuse.__init__ (e.g. "Vault unlocked...") sits
    # in an unflushed buffer, gets duplicated into the child by fork(),
    # and only actually reaches a file once the CHILD's stdio eventually
    # flushes -- by which point dup2() below has repointed fd 1 at the
    # log file, so it silently ends up there instead of the terminal.
    sys.stdout.flush()
    sys.stderr.flush()

    if foreground:
        print(f"Mounted at {mountpoint} (foreground). Unmount with: fusermount3 -u {mountpoint}")
        FUSE(fs, mountpoint, foreground=True, nothreads=True)
        return

    pid_file = _pid_file_path(storage_root)
    log_path = os.path.join(storage_root, LOG_FILENAME)

    child_pid = os.fork()
    if child_pid > 0:
        # Parent: record the child's PID + mountpoint, confirm, and get
        # out of the way -- the child carries on in the background.
        with open(pid_file, "w") as f:
            f.write(f"{child_pid}\n{mountpoint}\n")
        print(f"Mounted at {mountpoint} as a background daemon (pid {child_pid}).")
        print(f"Log:    {log_path}")
        print(f"Status: python3 pfs_fuse.py status {storage_root}")
        print(f"Stop:   python3 pfs_fuse.py stop {storage_root}")
        # os._exit (not sys.exit) on purpose -- skips atexit/interpreter
        # teardown so the parent doesn't touch anything the child also
        # holds a copy of (SQLite connections, open fds) post-fork. That
        # means it ALSO skips stdio flushing, so do it explicitly first
        # or these prints never reach the terminal at all.
        sys.stdout.flush()
        sys.stderr.flush()
        os._exit(0)

    # Child: detach for real (new session, no controlling terminal), then
    # redirect stdio to a log file since nothing will ever read a
    # terminal here again. foreground=True in the FUSE() call below is
    # deliberate -- we've already done our own daemonization; letting
    # libfuse ALSO fork here would spawn a second, untracked process and
    # the PID recorded above would stop meaning anything.
    os.setsid()
    log_fd = os.open(log_path, os.O_CREAT | os.O_WRONLY | os.O_APPEND, 0o600)
    devnull_fd = os.open(os.devnull, os.O_RDONLY)
    os.dup2(devnull_fd, 0)
    os.dup2(log_fd, 1)
    os.dup2(log_fd, 2)
    os.close(devnull_fd)
    os.close(log_fd)
    try:
        FUSE(fs, mountpoint, foreground=True, nothreads=True)
    finally:
        if os.path.exists(pid_file):
            try:
                os.remove(pid_file)
            except OSError:
                pass


def do_status(storage_root: str) -> None:
    existing = _read_pid_file(storage_root)
    if existing is None:
        print("Not running (no PID file).")
        return
    pid, mountpoint = existing
    if _pid_is_alive(pid):
        print(f"Running: pid {pid}, mounted at {mountpoint or '(unknown)'}")
    else:
        print(f"STALE PID file (process {pid} is not running -- the mount likely crashed or was "
              f"killed without cleanup). Removing stale PID file.")
        os.remove(_pid_file_path(storage_root))


def do_stop(storage_root: str) -> None:
    existing = _read_pid_file(storage_root)
    if existing is None:
        print("Not running (no PID file).")
        return
    pid, mountpoint = existing
    if not mountpoint:
        print("PID file doesn't record a mountpoint -- can't unmount automatically. "
              f"If you know it, run: fusermount3 -u <mountpoint>")
        return
    if not _pid_is_alive(pid):
        print(f"STALE PID file (process {pid} is not running). Removing it.")
        os.remove(_pid_file_path(storage_root))
        return
    print(f"Unmounting {mountpoint}...")
    result = subprocess.run(["fusermount3", "-u", mountpoint], capture_output=True, text=True)
    if result.returncode == 0:
        print("Unmounted cleanly -- the daemon process will exit on its own now.")
    else:
        print(f"fusermount3 failed: {result.stderr.strip()}")
        print("The mountpoint may be busy (something still has a file open there) or already unmounted.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="FUSE mount for a Phylogenetic File System vault.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    mount_parser = subparsers.add_parser("mount", help="Mount the vault (runs as a background daemon by default)")
    mount_parser.add_argument("storage_root")
    mount_parser.add_argument("mountpoint")
    mount_parser.add_argument("--foreground", action="store_true",
                               help="Stay attached to this terminal instead of daemonizing (for debugging)")

    status_parser = subparsers.add_parser("status", help="Check whether a mount daemon is running")
    status_parser.add_argument("storage_root")

    stop_parser = subparsers.add_parser("stop", help="Unmount and stop the background daemon")
    stop_parser.add_argument("storage_root")

    args = parser.parse_args()
    if args.command == "mount":
        do_mount(args.storage_root, args.mountpoint, args.foreground)
    elif args.command == "status":
        do_status(args.storage_root)
    elif args.command == "stop":
        do_stop(args.storage_root)
