#!/usr/bin/env python3
"""
FUSE mount of a Python-engine vault.

Layout: files with no close relative sit at the root; files in a clade
(Jaccard distance <= threshold to another file) appear together in a
directory named after the clade's smallest member. Membership is computed
by a background worker (clade_worker.py), so it changes as files change;
new files can only be created at the root. Lookups use the worker's
latest partition filtered against the catalog, so a file deleted or
renamed never lingers, and a new or just-edited file sits at the root
until it's fingerprinted and clustered. The kernel can briefly report
EIO for a path whose type just changed between file and directory.

I/O streams: reads decrypt only the chunks a range touches
(reconstruct.ManifestReader). The first write or truncate copies the file
to a scratch file on disk; release() commits it through
VaultSession.commit_write() (re-chunking the whole file; unchanged chunks
dedup). A write needs temporary disk space equal to the file's size.

Single-threaded (nothreads=True): the engine isn't built for concurrent
callbacks. The passphrase is asked once at mount time; anyone with access
to the mountpoint can use it until unmount.

'mount' unlocks interactively, then forks and setsid()s itself (so the
real PID can be recorded in storage_root) and logs to a file there.

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
from gearhash.pipeline import release_free_memory

SCRATCH_DIRNAME = ".fuse_scratch"
# Bytes per ManifestReader read when copying a version into a scratch file.
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
        # fh -> {"label", "reader": ManifestReader or None, "spill_fd", "spill_path", "dirty"}.
        # reader until the first write or truncate, the scratch file after.
        self._handles = {}
        # Guards the catalog and the handle/job tables against the background
        # fingerprint threads (FUSE callbacks themselves never overlap).
        self._lock = threading.RLock()
        self._fingerprint_jobs = []  # (label, Thread) currently running
        # Clade worker, started in init(): daemon mode forks after this constructor, and threads don't survive fork().
        self._clades = None
        # Filtered view of the worker's snapshot, cached until it or the catalog changes.
        self._catalog_epoch = 0
        self._clade_view = None
        self._clade_view_key = None
        # Other processes may change the vault: check at most this often.
        self._last_refresh = 0.0
        self.session.add_change_listener(self._on_external_change)

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

    # ---------- clade presentation ----------

    def init(self, path):
        """Called once mounted, in the serving process (after any fork)."""
        with self._lock:
            labels = list(self.session.catalog.keys())
        self._clades = CladeWorker(python_session_loader(self.session), name="fuse-clade-worker").start(labels)

    def _catalog_changed(self) -> None:
        with self._lock:
            self._catalog_epoch += 1

    REFRESH_INTERVAL_SECONDS = 0.5

    def _refresh(self) -> None:
        """Picks up changes other processes made to the vault (throttled)."""
        now = time.monotonic()
        if now - self._last_refresh < self.REFRESH_INTERVAL_SECONDS:
            return
        self._last_refresh = now
        with self._lock:  # same lock order as every write: self._lock, then the vault's
            if self.session.refresh():
                self._catalog_epoch += 1

    def _on_external_change(self, changed, removed) -> None:
        # Runs under the vault's write lock: only queue events, take no other lock.
        if self._clades is None:
            return
        for label in removed:
            self._clades.removed(label)
        for label in changed:
            self._clades.changed(label)

    def _get_clades(self):
        """(clade_to_labels, label_to_clade) from the worker's latest snapshot,
        never waiting. Only clades with 2+ live members are directories.
        """
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
        """Resolves a path against the current clade partition: ("root",),
        ("clade_dir", clade_name), ("file", label), or None.
        """
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
        self._refresh()
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
            # An open handle reports its own (possibly uncommitted) size.
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
        self._refresh()
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
        """Moves a handle from streaming reads to its own scratch file (once), copying chunk by chunk."""
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
        self._refresh()
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
        # New files only at the root; they're clustered once fingerprinted.
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
            # Writing past the end leaves a zero-filled hole.
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
                return
            raise FuseOSError(errno.ENOENT)
        label = resolved[1]

        # A path truncate applies to every open handle of the file, which commit
        # on release -- fusepy delivers open(O_TRUNC) this way too. Committing a
        # separate version here would be overwritten by their stale copies.
        with self._lock:
            open_handles = [h for h in self._handles.values() if h["label"] == label]
            for handle in open_handles:
                self._truncate_handle(handle, length)
        if open_handles:
            return

        # No open handle: copy, resize and commit now.
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
        """Commits a complete scratch file through VaultSession.commit_write().
        Takes ownership of tmp_path: the fingerprint job (or this, on failure)
        deletes it.
        """
        try:
            with self._lock:
                manifest_path = self.session.commit_write(label, tmp_path)
        except Exception:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
            raise FuseOSError(errno.EIO)

        # No fingerprint yet: this drops the label from clustering until one is attached.
        self._catalog_changed()
        self._clades.changed(label)
        self._start_background_fingerprint(label, tmp_path, manifest_path)

    def _start_background_fingerprint(self, label: str, tmp_path: str, manifest_path: str) -> None:
        """Fingerprints the committed scratch file on a background thread, then
        deletes it.
        """
        def _job():
            try:
                fingerprint = PhylogeneticAnalyzer(SIMILARITY_PROFILE).extract_traits(tmp_path)
                self.session.pipeline.attach_similarity_fingerprint(manifest_path, fingerprint)
                del fingerprint
                release_free_memory()
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
            # delete_label frees a manifest only once nothing else references it.
            self.session.delete_label(label)
        self._catalog_changed()
        self._clades.removed(label)

    def rename(self, old, new):
        # Only the destination's basename (the new label) matters.
        old_resolved = self._resolve(old)
        if old_resolved is None or old_resolved[0] != "file":
            raise FuseOSError(errno.ENOENT)
        old_label = old_resolved[1]
        new_parts = [p for p in new.split("/") if p]
        if not new_parts:
            raise FuseOSError(errno.EINVAL)
        new_label = new_parts[-1]

        if new_label == old_label:
            return
        with self._lock, self.session.write_lock():  # replace + rename as one change
            if new_label in self.session.catalog and new_label != old_label:
                # Replacing an existing destination goes through delete_label too.
                self.session.delete_label(new_label)
            try:
                self.session.rename_label(old_label, new_label)
            except KeyError:  # another program removed it meanwhile
                raise FuseOSError(errno.ENOENT)
        self._catalog_changed()
        self._clades.renamed(old_label, new_label)

    # ---------- clean shutdown ----------

    def destroy(self, path):
        """On unmount: waits for running fingerprint jobs."""
        with self._lock:
            pending = list(self._fingerprint_jobs)
        for _label, thread in pending:
            thread.join()
        if self._clades is not None:
            self._clades.stop(timeout=10)
        try:
            os.rmdir(self.scratch_dir)
        except OSError:
            pass  # non-empty or already gone
        # Remove the PID file here too: a manual fusermount3 -u skips 'stop'.
        pid_file = os.path.join(self.session.storage_root, PID_FILENAME)
        if os.path.exists(pid_file):
            try:
                os.remove(pid_file)
            except OSError:
                pass
        # Release the vault lock now; the process may not exit right away.
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
        os.kill(pid, 0)  # signal 0: existence check only
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True  # exists, owned by someone else


def do_mount(storage_root: str, mountpoint: str, foreground: bool) -> None:
    existing = _read_pid_file(storage_root)
    if existing is not None and _pid_is_alive(existing[0]):
        print(f"Already running: pid {existing[0]}, mounted at {existing[1]}. "
              f"Stop it first with: python3 pfs_fuse.py stop {storage_root}")
        sys.exit(1)

    # The passphrase prompt needs the original foreground TTY.
    fs = PFSFuse(storage_root)
    # Flush before fork(), or buffered output is duplicated into the child and lands in its log.
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
        # Parent: record the child's PID and mountpoint, then exit.
        with open(pid_file, "w") as f:
            f.write(f"{child_pid}\n{mountpoint}\n")
        print(f"Mounted at {mountpoint} as a background daemon (pid {child_pid}).")
        print(f"Log:    {log_path}")
        print(f"Status: python3 pfs_fuse.py status {storage_root}")
        print(f"Stop:   python3 pfs_fuse.py stop {storage_root}")
        # os._exit skips teardown of state the child shares, and skips flushing -- so flush first.
        sys.stdout.flush()
        sys.stderr.flush()
        os._exit(0)

    # Child: new session, stdio to the log file. foreground=True below
    # because this process already daemonized itself.
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
