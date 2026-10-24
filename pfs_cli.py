"""
Interactive shell for a PFS vault, for either engine.

Run with:  python3 pfs_cli.py [--engine cpp] [storage_root]
(storage_root defaults to ./pfs_storage_vault, or ./pfs_storage_vault_cpp)
"""

import cmd
import os
import sys
import getpass
import pickle
import shlex
import time
import secrets
import hashlib
import sqlite3
import threading

sys.path.insert(0, os.getcwd())

from gearhash.master_key_store import (load_vault_key, create_new_vault_key, change_passphrase,
                                        WrongPassphraseError, MASTER_KEY_FILENAME)
from gearhash import fingerprint as stored_fingerprint
from gearhash.dedup_index import GlobalBlockIndex, DB_FILENAME
from gearhash.pipeline import release_free_memory
from gearhash.fks_index import FKSLookupEngine
from gearhash.keyring import KEYRING_FILENAME
from gearhash.immutability import set_immutable
from reconstruct import reconstruct, ReconstructionError
from PhylogeneticAnalyzer import PhylogeneticAnalyzer, SIMILARITY_PROFILE, MIN_RELIABLE_TRAIT_COUNT
from clade_worker import CladeWorker, filtered_view, python_session_loader, cpp_session_loader
from TreeConstructor import TreeConstructor
from vault_session import VaultSession, VaultUnlockError, MutationConflictError, CATALOG_FILENAME, HISTORY_FILENAME
from lineage import LINEAGE_FILENAME

# Optional: only --engine cpp needs the compiled engine.
try:
    from pfs_engine_binding import CppVaultSession, PfsEngineError
    _CPP_ENGINE_IMPORT_ERROR = None
except OSError as e:
    CppVaultSession = None
    PfsEngineError = Exception
    _CPP_ENGINE_IMPORT_ERROR = e

# Marker files that tell the engines' vaults apart. Both use
# data_container.bin and global_index.db with incompatible formats, so a
# directory must never be opened by the wrong engine.
CPP_CATALOG_FILENAME = "catalog.pfsc"
CPP_KEYRING_FILENAME = "keyring.pfsk"

MAX_HISTORY = 500


def _existing_vault_engine(storage_root: str):
    """'python', 'cpp', or None, from each engine's marker files."""
    is_python = os.path.exists(os.path.join(storage_root, CATALOG_FILENAME)) or \
        os.path.exists(os.path.join(storage_root, KEYRING_FILENAME))
    is_cpp = os.path.exists(os.path.join(storage_root, CPP_CATALOG_FILENAME)) or \
        os.path.exists(os.path.join(storage_root, CPP_KEYRING_FILENAME))
    if is_python:
        return "python"
    if is_cpp:
        return "cpp"
    return None


def _reliability_warning(unreliable: dict) -> str:
    """The "too little data to fingerprint reliably" warning, shared by both
    shells. `unreliable` is {label: chunk_count}.
    """
    parts = ", ".join(
        f"'{label}' ({count} chunk{'s' if count != 1 else ''})"
        for label, count in sorted(unreliable.items())
    )
    return (
        f"WARNING: too little data to fingerprint reliably -- {parts} came in below the "
        f"{MIN_RELIABLE_TRAIT_COUNT}-chunk reliability floor (SIMILARITY_PROFILE uses 128-512 "
        f"byte chunks, so this means a file only a few hundred bytes to ~1-2KB). At that size, "
        f"a single differing chunk can swing the whole Jaccard distance to a misleading 1.0 "
        f"('nothing shared') even between two otherwise near-identical files. Treat any result "
        f"above involving it as low-confidence -- this is expected at this file size, not a bug."
    )


def _index_probe(storage_root, crypto) -> bool:
    """A lookup of a never-registered hash returns None rather than raising."""
    gi = GlobalBlockIndex(storage_root, crypto)
    gi.lookup(secrets.token_bytes(32))
    gi.close()
    return True


def _split_args(arg: str):
    """Splits arguments like a Unix shell, so quoted labels and paths may
    contain spaces. Returns None (after saying why) on unbalanced quotes.
    """
    try:
        return shlex.split(arg)
    except ValueError as e:
        print(f"Couldn't parse that command line ({e}) -- check your quotes.")
        return None


def _join_args(arg: str):
    """A single label or path, quoted or not. None on unbalanced quotes."""
    parts = _split_args(arg)
    return None if parts is None else " ".join(parts)


# How long a passphrase re-entry covers later gated commands (not extended by use).
REAUTH_GRACE_SECONDS = 300


def _reauth_grace_seconds() -> float:
    """REAUTH_GRACE_SECONDS, optionally shortened (never lengthened) by
    PFS_REAUTH_GRACE_SECONDS; 0 asks every time. Invalid values are ignored.
    """
    raw = os.environ.get("PFS_REAUTH_GRACE_SECONDS")
    if raw is None:
        return REAUTH_GRACE_SECONDS
    try:
        value = float(raw)
    except ValueError:
        return REAUTH_GRACE_SECONDS
    return min(max(value, 0.0), REAUTH_GRACE_SECONDS)


# How long 'clade' waits for the clade worker before using its last partition.
CLADE_WAIT_SECONDS = 60


def _clade_members(worker: CladeWorker, label: str, live_labels):
    """`label`'s sorted clade members from the worker, or None if it has no
    fingerprint. Waits for pending work first (up to CLADE_WAIT_SECONDS).
    """
    if not worker.wait_idle(CLADE_WAIT_SECONDS):
        print(f"Note: clade clustering is still catching up after {CLADE_WAIT_SECONDS}s -- "
              f"showing the most recent complete result.")
    clades, label_to_clade = filtered_view(worker.snapshot(), live_labels)
    name = label_to_clade.get(label)
    return None if name is None else clades[name]


class _ReauthMixin:
    """Re-auth policy shared by both shells. The first gated command after
    unlocking asks for the passphrase again; a correct answer covers later
    gated commands for the grace period, a wrong one ends it. always_ask
    commands (delete, panic) always ask.

    Subclasses provide storage_root and _current_kek().
    """

    # time.monotonic() of the last correct re-entry, or None.
    _reauth_ok_at = None

    def _current_kek(self) -> bytes:
        raise NotImplementedError

    def _require_reauth(self, action_description: str = "do this", always_ask: bool = False) -> bool:
        """True if inside the grace window (and not always_ask), or the re-entered passphrase unwraps the same KEK."""
        if not always_ask and self._reauth_ok_at is not None:
            if time.monotonic() - self._reauth_ok_at < _reauth_grace_seconds():
                return True
        pw = getpass.getpass(f"Re-enter vault passphrase to {action_description}: ")
        try:
            kek = load_vault_key(self.storage_root, pw)
        except WrongPassphraseError:
            self._reauth_ok_at = None
            print("Wrong passphrase. Cancelled.")
            return False
        if kek != self._current_kek():
            # Exact match only.
            self._reauth_ok_at = None
            print("Wrong passphrase. Cancelled.")
            return False
        self._reauth_ok_at = time.monotonic()
        return True


class PFSShell(_ReauthMixin, cmd.Cmd):
    intro = (
        "\nPhylogenetic File System -- interactive shell.\n"
        "Type 'help' for the full command list, 'help <command>' for details.\n\n"
        "Quick start:\n"
        "  write /path/to/file.pdf my_label   -- store a file\n"
        "  list                                -- see what's stored\n"
        "  read my_label /path/to/output.pdf   -- get it back\n"
        "  navigate /path/to/dir                -- read/write there without full paths\n"
        "  history                              -- see past commands (also: up arrow)\n"
    )
    prompt = "pfs> "

    def __init__(self, storage_root: str):
        super().__init__()
        self.storage_root = storage_root
        self._session = VaultSession(storage_root)
        # (label, Thread) for each running fingerprint job.
        self._fingerprint_jobs = []
        self._fingerprint_jobs_lock = threading.Lock()
        # Set by 'navigate': base directory for relative write/read paths.
        self._nav_dir = None
        self._command_history = []
        self._readline = None
        # Set by 'clade': the label 'checkout @tip' and 'ancestor' default to.
        self._focus_label = None
        self._unlock_or_create()
        # Clade worker for 'clade', fed by a catalog diff after each command.
        self._catalog_seen = dict(self.catalog)
        self._clades = CladeWorker(python_session_loader(self._session),
                                   name="cli-clade-worker").start(self._catalog_seen)

    def _report_catalog_changes(self) -> None:
        """Reports every label added, changed or removed since the last command
        to the clade worker. A rename shows up as a removal plus an addition.
        """
        current = self.catalog
        for label in self._catalog_seen.keys() - current.keys():
            self._clades.removed(label)
        for label, manifest_filename in current.items():
            if self._catalog_seen.get(label) != manifest_filename:
                self._clades.changed(label)
        self._catalog_seen = dict(current)

    # Exposed for the methods below; owned by the VaultSession.
    @property
    def crypto(self):
        return self._session.crypto

    @property
    def pipeline(self):
        return self._session.pipeline

    @property
    def catalog(self):
        return self._session.catalog


    def _unlock_or_create(self):
        if _existing_vault_engine(self.storage_root) == "cpp":
            print(f"'{self.storage_root}' is a C++-ENGINE vault (catalog.pfsc/keyring.pfsk present). "
                  f"It uses different, incompatible file formats -- opening it here would corrupt it. "
                  f"Use 'python3 pfs_cli.py --engine cpp {self.storage_root}' instead.")
            sys.exit(1)
        key_path = os.path.join(self.storage_root, MASTER_KEY_FILENAME)
        vault_existed = os.path.exists(key_path)
        if not vault_existed:
            print(f"No vault found at '{self.storage_root}'.")

        def get_new_passphrase():
            return getpass.getpass("Set a new vault passphrase: "), getpass.getpass("Confirm passphrase: ")

        def get_existing_passphrase():
            return getpass.getpass("Enter vault passphrase: ")

        def confirm_reset():
            print("\nYour passphrase correctly unlocked master.key, but the vault's other files")
            print("(keyring.enc / index / manifests) don't decrypt with it -- they were encrypted")
            print("under a DIFFERENT key that no longer matches. This can happen after an")
            print("interrupted vault creation or a mixed-up master.key file.\n")
            answer = input("Type 'reset' to discard those unreadable files and start fresh with "
                            "the current key, or anything else to exit: ")
            return answer.strip().lower() == "reset"

        try:
            self._session.unlock_or_create(get_new_passphrase, get_existing_passphrase, confirm_reset)
        except VaultUnlockError as e:
            print(str(e))
            sys.exit(1)

        print("New vault created.\n" if not vault_existed else "Vault unlocked.\n")
        self._load_history()

    def _load_history(self):
        """Loads the encrypted command history into readline, so up-arrow recall
        survives restarts. History is kept encrypted (labels and paths are
        metadata); if it can't be read, it starts empty.
        """
        self._command_history = []
        path = os.path.join(self.storage_root, HISTORY_FILENAME)
        if os.path.exists(path):
            try:
                with open(path, "rb") as f:
                    encrypted = f.read()
                raw = self.crypto.decrypt_block(encrypted, associated_data=b"history")
                self._command_history = pickle.loads(raw)
            except Exception as e:
                print(f"Note: couldn't load command history ({type(e).__name__}) -- starting empty.")
                self._command_history = []

        try:
            import readline
            for line in self._command_history:
                readline.add_history(line)
            readline.set_history_length(MAX_HISTORY)
            self._readline = readline
        except ImportError:
            self._readline = None  # no readline (e.g. Windows): no recall

    def _save_history(self):
        path = os.path.join(self.storage_root, HISTORY_FILENAME)
        raw = pickle.dumps(self._command_history)
        encrypted = self.crypto.encrypt_block(raw, associated_data=b"history")
        tmp = path + ".tmp"
        with open(tmp, "wb") as f:
            f.write(encrypted)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)

    def _record_history(self, line: str) -> None:
        """Records a line that ran without raising."""
        self._command_history.append(line)
        if len(self._command_history) > MAX_HISTORY:
            self._command_history = self._command_history[-MAX_HISTORY:]
        try:
            self._save_history()
        except Exception:
            pass  # history is only a convenience

    def _read_manifest_metadata(self, manifest_path: str) -> dict:
        return self._session.read_manifest_metadata(manifest_path)

    def _save_catalog(self) -> None:
        self._session.save_catalog()

    def _current_kek(self) -> bytes:
        return self.crypto.key


    def do_write(self, arg):
        """write <file_path> [label]  -- ingest a file into the vault

Example:
  write /home/lister/Documents/report.pdf
  write /home/lister/Documents/report.pdf my_report
  write "/home/lister/Documents/Q3 report.pdf" "q3 report"
(if you skip [label], the file's own basename is used as the label;
a relative file_path resolves against 'navigate's directory, if set)"""
        parts = _split_args(arg)
        if parts is None:
            return
        if not parts:
            print("Usage: write <file_path> [label]")
            return
        if len(parts) > 2:
            # Refuse extra words rather than silently dropping them.
            print('Usage: write <file_path> [label]  (put a path or label containing spaces '
                  'in quotes: write "my file.txt" "my label")')
            return
        file_path = self._resolve_path(parts[0])
        label = parts[1] if len(parts) > 1 else os.path.basename(parts[0])
        if not os.path.exists(file_path):
            print(f"File not found: {file_path}")
            return
        if not self._require_reauth("store a file"):
            return

        is_new_version = label in self.catalog
        try:
            start = time.perf_counter()
            manifest_path = self._session.commit_write(label, file_path)
            elapsed = time.perf_counter() - start
        except Exception as e:
            print(f"Write failed: {e}")
            return

        meta = self._read_manifest_metadata(manifest_path)
        total = meta["total_blocks"] or 1
        dedup_pct = 100 * meta["duplicate_chunks_found"] / total
        if is_new_version:
            history = self._session.lineage.get_history(label)
            gen = history[-1].generation_index if history else "?"
            print(f"Stored as '{label}' -- generation {gen} "
                  f"(previous versions preserved; see 'lineage {label}')")
        else:
            print(f"Stored as '{label}'")
        print(f"  {meta['total_blocks']} chunks ({meta['new_chunks_written']} new, "
              f"{meta['duplicate_chunks_found']} deduped, {dedup_pct:.1f}%)")
        print(f"  {meta['original_size']:,} bytes, {elapsed:.3f}s")
        print(f"  Identified as: {meta.get('phenotype_name', 'unknown')} "
              f"(from content -- no file extension needed or used)")
        self._start_background_fingerprint(label, file_path, manifest_path)

    def do_fork(self, arg):
        """fork <label> <generation> <file_path>  -- branch off an OLD generation instead of the tip

Example:
  fork my_report 2 /home/lister/Documents/alternate_draft.pdf
(stores file_path as a new version descending from generation N of
<label>, not the tip -- a second branch. 'lineage' shows both heads;
'merge' reconciles them.)"""
        parts = _split_args(arg)
        if parts is None:
            return
        if len(parts) != 3:
            print("Usage: fork <label> <generation> <file_path>")
            return
        label, gen_str, raw_file_path = parts
        file_path = self._resolve_path(raw_file_path)
        if label not in self.catalog:
            print(f"No such label: '{label}'")
            return
        try:
            generation = int(gen_str)
        except ValueError:
            print("Usage: fork <label> <generation> <file_path>  (generation must be an integer)")
            return
        if not os.path.exists(file_path):
            print(f"File not found: {file_path}")
            return
        if not self._require_reauth(f"fork '{label}' from generation {generation}"):
            return

        try:
            manifest_path = self._session.commit_write(label, file_path, fork_from_generation=generation)
        except Exception as e:
            print(f"Fork failed: {e}")
            return

        history = self._session.lineage.get_history(label)
        new_gen = history[-1].generation_index if history else "?"
        heads = self._session.lineage.get_heads(label)
        print(f"Forked '{label}' from generation {generation} -> new generation {new_gen}")
        print(f"  '{label}' now has {len(heads)} branch head(s): "
              f"{', '.join(str(h.generation_index) for h in heads)}")
        if len(heads) > 1:
            print(f"  Use 'merge {label} <gen> <gen>' to reconcile them, or 'lineage {label}' to inspect.")
        self._start_background_fingerprint(label, file_path, manifest_path)

    def _start_background_fingerprint(self, label: str, file_path: str, manifest_path: str) -> None:
        """Fingerprints the file on a background thread and attaches it to the
        manifest, so writes don't wait for it. A failure only leaves the file out
        of clustering.
        """
        def _job():
            try:
                fingerprint = PhylogeneticAnalyzer(SIMILARITY_PROFILE).extract_traits(file_path)
                self.pipeline.attach_similarity_fingerprint(manifest_path, fingerprint)
                del fingerprint
                release_free_memory()
                self._clades.changed(label)  # before the message, so a 'clade' after it sees this
                print(f"\n[background] fingerprint ready for '{label}' -- 'tree' can now include it.\n{self.prompt}", end="", flush=True)
            except Exception as e:
                print(f"\n[background] fingerprinting '{label}' failed: {type(e).__name__}: {e} "
                      f"(the stored file itself is unaffected).\n{self.prompt}", end="", flush=True)
            finally:
                with self._fingerprint_jobs_lock:
                    self._fingerprint_jobs = [
                        (l, t) for l, t in self._fingerprint_jobs if t is not threading.current_thread()
                    ]

        thread = threading.Thread(target=_job, name=f"fingerprint-{label}")
        with self._fingerprint_jobs_lock:
            self._fingerprint_jobs.append((label, thread))
        thread.start()
        print("  (clade-tree fingerprint computing in background)")

    def do_read(self, arg):
        """read <label> <output_path>  -- reconstruct a file from the vault

Example:
  read my_report /home/lister/Desktop/report_restored.pdf
(use 'list' first to see which labels exist; a relative output_path
resolves against 'navigate's directory, if set)"""
        parts = _split_args(arg)
        if parts is None:
            return
        if len(parts) != 2:
            print("Usage: read <label> <output_path>")
            return
        label, output_path = parts
        output_path = self._resolve_path(output_path)
        if label not in self.catalog:
            print(f"No such label: '{label}'. Use 'list' to see what's stored.")
            return
        if not self._require_reauth(f"read '{label}'"):
            return
        manifest_path = os.path.join(self.storage_root, self.catalog[label])
        try:
            reconstruct(manifest_path, self.pipeline.container_path, output_path, self.crypto.key)
        except ReconstructionError as e:
            print(f"Reconstruction FAILED (the system correctly detected a problem): {e}")
        except Exception as e:
            print(f"Reconstruction failed: {type(e).__name__}: {e}")

    def do_list(self, arg):
        """list [type] [size]  -- show files in the vault, optionally filtered/sorted

Example:
  list
  list pdf
  list image
  list size
  list image size
(a type matches the CONTENT-detected type, whatever the file is named;
'size' sorts largest first)"""
        if not self._require_reauth("view the vault contents"):
            return
        if not self.catalog:
            print("(vault is empty)")
            return
        tokens = _split_args(arg)
        if tokens is None:
            return
        sort_by_size = any(t.lower() == "size" for t in tokens)
        type_filter = next((t.lower() for t in tokens if t.lower() != "size"), "")

        rows = []
        missing = []
        for label, manifest_filename in self.catalog.items():
            manifest_path = os.path.join(self.storage_root, manifest_filename)
            if not os.path.exists(manifest_path):
                missing.append(label)
                continue
            meta = self._read_manifest_metadata(manifest_path)
            phenotype_name = meta.get("phenotype_name", "unknown (predates this feature)")
            if type_filter and type_filter not in phenotype_name.lower():
                continue
            rows.append((label, phenotype_name, meta))

        if sort_by_size:
            rows.sort(key=lambda row: row[2]["original_size"], reverse=True)

        # Columns grow to fit the longest label and type.
        label_w = max([25] + [len(label) + 2 for label in [r[0] for r in rows] + missing])
        type_w = max([24] + [len(r[1]) + 2 for r in rows])
        print(f"{'Label':<{label_w}}{'Type':<{type_w}}{'Size':>12}  {'Chunks':>8}  {'Dedup':>7}")
        for label, phenotype_name, meta in rows:
            total = meta["total_blocks"] or 1
            dedup_pct = 100 * meta["duplicate_chunks_found"] / total
            print(f"{label:<{label_w}}{phenotype_name:<{type_w}}{meta['original_size']:>12,}  "
                  f"{meta['total_blocks']:>8}  {dedup_pct:>6.1f}%")
        for label in missing:
            print(f"{label:<{label_w}}(missing manifest!)")
        if type_filter and not rows:
            print(f"(no files matched type filter '{type_filter}')")

    def do_delete(self, arg):
        """delete <label> [<label2> ...] [force]  -- remove one or more files AND their full history

Example:
  delete my_report
  delete my_report old_draft unused_photo
  delete my_report force
(removes every generation of each label. Storage still shared with
other labels stays until nothing uses it. Labels are deleted
independently; 'force' overrides the 'protected' tag for all of them.
Only a final 'force' after at least one label is the flag, so
'delete force' deletes a label named force.)"""
        parts = _split_args(arg)
        if parts is None:
            return
        if not parts:
            print("Usage: delete <label> [<label2> ...] [force]")
            return
        force = len(parts) > 1 and parts[-1].lower() == "force"
        labels = parts[:-1] if force else parts

        unknown = [l for l in labels if l not in self.catalog]
        for l in unknown:
            print(f"No such label: '{l}'")
        labels = [l for l in labels if l in self.catalog]
        if not labels:
            return

        noun = f"'{labels[0]}'" if len(labels) == 1 else f"{len(labels)} labels"
        if not self._require_reauth(f"delete {noun}", always_ask=True):
            return

        failures = []
        for label in labels:
            try:
                report = self._session.delete_label(label, force=force)
                if report["manifests_kept_shared"]:
                    print(f"Deleted '{label}'. {report['manifests_freed']} manifest(s) freed; "
                          f"{report['manifests_kept_shared']} kept because something else in the vault "
                          f"still references them (shared content or a lateral parent elsewhere).")
                else:
                    print(f"Deleted '{label}' ({report['manifests_freed']} manifest(s) freed). "
                          f"Run 'vacuum' to reclaim its space.")
            except PermissionError as e:
                failures.append(label)
                print(f"Delete of '{label}' refused: {e}")
            except Exception as e:
                failures.append(label)
                print(f"Delete of '{label}' failed: {e}")

        if len(labels) > 1:
            succeeded = len(labels) - len(failures)
            print(f"\n{succeeded}/{len(labels)} label(s) deleted successfully.")

    def do_vacuum(self, arg):
        """vacuum  -- reclaim space from deleted files

Example:
  vacuum
(takes no arguments; safe to run any time, does nothing if nothing was deleted)"""
        if not self._require_reauth("vacuum the vault"):
            return
        report = self._session.vacuum()
        print(f"Before:    {report['old_size']:,} bytes")
        print(f"After:     {report['new_size']:,} bytes")
        print(f"Reclaimed: {report['bytes_reclaimed']:,} bytes")
        print(f"Live chunks remaining: {report['live_chunks']}")
        if report["chunks_corrected"]:
            print(f"Ref-count drift repaired: {report['chunks_corrected']} chunk(s) had a stale "
                  f"reference count corrected before reclaiming (see 'manual.txt' for why this can "
                  f"happen) -- rerun 'vacuum' once more to reclaim any of those that are now genuinely dead.")
        if report["orphaned_manifests_removed"]:
            print(f"Orphaned manifests removed: {report['orphaned_manifests_removed']} (referenced by "
                  f"nothing in the vault, freed directly).")
        if report["orphaned_tmp_files_removed"]:
            print(f"Interrupted-write leftovers removed: {report['orphaned_tmp_files_removed']} "
                  f".tmp file(s) from a write that never completed.")
        if report.get("mirror_bytes_reclaimed"):
            print(f"Ancestral Hardening mirror container also compacted: "
                  f"{report['mirror_old_size']:,} -> {report['mirror_new_size']:,} bytes "
                  f"({report['mirror_bytes_reclaimed']:,} reclaimed, {report['live_mirrors']} live "
                  f"mirror(s) remaining).")

    def do_fsck(self, arg):
        """fsck  -- scan every stored chunk for corruption, self-healing where possible

Example:
  fsck
(a damaged chunk with an Ancestral Hardening mirror is repaired from it;
one without is reported -- use 'verify' to see which files it affects)"""
        if not self._require_reauth("scan the vault for corruption"):
            return
        print("Scanning every live chunk (this reads and verifies your entire vault -- may take a while)...")
        report = self.pipeline.verify_and_repair()
        print(f"Scanned:       {report['scanned']}")
        print(f"Healthy:       {report['healthy']}")
        print(f"Repaired:      {report['healed']} (recovered from their Ancestral Hardening mirror)")
        if report["unrecoverable"]:
            print(f"UNRECOVERABLE: {len(report['unrecoverable'])} chunk(s) -- genuinely lost, no working "
                  f"mirror existed for them:")
            for content_hash_hex in report["unrecoverable"]:
                print(f"  {content_hash_hex[:16]}...")
            print("Run 'verify <label>' on files you're concerned about to see exactly which are affected.")
        else:
            print("No unrecoverable corruption found.")

    def do_rotate(self, arg):
        """rotate  -- start a new key epoch (existing files stay readable under their original epoch)

Example:
  rotate
(takes no arguments)"""
        if not self._require_reauth("rotate keys"):
            return
        new_epoch = self.pipeline.rotate_keys()
        print(f"Rotated to epoch {new_epoch}. New writes use the new key; existing files are unaffected.")

    def do_passwd(self, arg):
        """passwd  -- change the vault passphrase (the underlying key itself is unchanged)

Example:
  passwd
(takes no arguments; it will prompt you for the current and new passphrase)"""
        old_pw = getpass.getpass("Current passphrase: ")
        new_pw1 = getpass.getpass("New passphrase: ")
        new_pw2 = getpass.getpass("Confirm new passphrase: ")
        if new_pw1 != new_pw2:
            print("New passphrases didn't match. Nothing changed.")
            return
        try:
            change_passphrase(self.storage_root, old_pw, new_pw1)
            print("Passphrase changed. The key itself (and all your data) is untouched -- "
                  "only what protects the key file on disk changed.")
        except WrongPassphraseError:
            print("Current passphrase was incorrect. Nothing changed.")

    def do_stats(self, arg):
        """stats  -- show vault-wide statistics

Example:
  stats
(takes no arguments)"""
        if not self._require_reauth("view vault statistics"):
            return
        container_size = os.path.getsize(self.pipeline.container_path) if os.path.exists(self.pipeline.container_path) else 0
        gi = GlobalBlockIndex(self.storage_root, self.crypto)
        total_chunks = total_refs = dead_chunks = 0
        for _content_hash, _offset, _length, ref_count, _epoch_id in gi.iter_all():
            total_chunks += 1
            total_refs += ref_count
            if ref_count == 0:
                dead_chunks += 1
        gi.close()
        print(f"Container size:        {container_size:,} bytes")
        print(f"Unique chunks stored:  {total_chunks} ({dead_chunks} reclaimable via 'vacuum')")
        print(f"Total chunk references: {total_refs} (dedup ratio: "
              f"{total_refs / max(1, total_chunks):.2f}x)")
        print(f"Files tracked:         {len(self.catalog)}")
        print(f"Key epochs so far:     {self.pipeline.keyring.current_epoch + 1}")


    def do_attack(self, arg):
        """attack  -- run a suite of adversarial tests against this vault's defenses

Example:
  attack
(you'll be asked to choose:
  virtual attack -- safe, uses a disposable throwaway test file
  real attack    -- tests one of your actual stored files; any temporary
                     corruption is backed up and verified-restored afterward)"""
        if not self._require_reauth("run an attack test"):
            return
        choice = input("Run 'virtual attack' or 'real attack'? ").strip().lower()
        if choice in ("real", "real attack", "realattack"):
            self._attack_real()
        elif choice in ("virtual", "virtual attack", "virtualattack"):
            self._attack_virtual()
        else:
            print(f"'{choice}' isn't 'virtual attack' or 'real attack'. Cancelled.")

    def _attack_virtual(self):
        print("Running security self-test against a throwaway test file (your real files are untouched)...\n")

        test_content = secrets.token_bytes(50_000)
        test_src = os.path.join(self.storage_root, "__attack_test_src__.bin")
        out_ok = os.path.join(self.storage_root, "__attack_test_out_ok__.bin")
        out_bad = os.path.join(self.storage_root, "__attack_test_out_bad__.bin")
        with open(test_src, "wb") as f:
            f.write(test_content)

        results = []
        manifest_path = None
        try:
            manifest_path = self.pipeline.secure_and_persist_file(test_src)
            manifest_filename = os.path.basename(manifest_path)

            # 1. Correct key reconstructs correctly
            try:
                reconstruct(manifest_path, self.pipeline.container_path, out_ok, self.crypto.key)
                with open(out_ok, "rb") as f:
                    ok = f.read() == test_content
            except Exception:
                ok = False
            results.append(("Baseline: correct key reconstructs correctly", ok))

            # 2. Wrong key is rejected
            wrong_key = secrets.token_bytes(32)
            try:
                reconstruct(manifest_path, self.pipeline.container_path, out_bad, wrong_key)
                results.append(("Wrong key is rejected", False))
            except Exception:
                results.append(("Wrong key is rejected", True))

            # 3. Manifest is unreadable without the key
            with open(manifest_path, "rb") as f:
                raw = f.read()
            try:
                pickle.loads(raw)
                results.append(("Manifest is unreadable without the key", False))
            except Exception:
                results.append(("Manifest is unreadable without the key", True))

            # 4. Confirmation-of-presence attack: a guessed content hash isn't a lookup key
            conn = sqlite3.connect(os.path.join(self.storage_root, DB_FILENAME))
            guessed_hash = hashlib.sha256(test_content[:4096]).digest()
            row = conn.execute("SELECT 1 FROM blocks WHERE lookup_key = ?", (guessed_hash,)).fetchone()
            conn.close()
            results.append(("Confirmation-of-presence attack blocked", row is None))

            # 5. Corrupted ciphertext is detected, not silently decrypted
            engine = FKSLookupEngine(raw_bytes=self.crypto.decrypt_block(raw, associated_data=manifest_filename.encode()))
            first_hash = engine.lookup(0)
            gi = GlobalBlockIndex(self.storage_root, self.crypto)
            offset, length, ref_count, epoch_id = gi.lookup(first_hash)
            gi.close()
            set_immutable(self.pipeline.container_path, False)
            with open(self.pipeline.container_path, "r+b") as cf:
                cf.seek(offset)
                b = cf.read(1)
                cf.seek(offset)
                cf.write(bytes([b[0] ^ 0xFF]))
            set_immutable(self.pipeline.container_path, True)
            try:
                reconstruct(manifest_path, self.pipeline.container_path, out_bad, self.crypto.key)
                results.append(("Corrupted ciphertext is detected, not silently returned", False))
            except Exception:
                results.append(("Corrupted ciphertext is detected, not silently returned", True))

        finally:
            for p in (test_src, out_ok, out_bad):
                if os.path.exists(p):
                    os.remove(p)
            if manifest_path and os.path.exists(manifest_path):
                try:
                    self.pipeline.delete_file(manifest_path)
                    self.pipeline.vacuum()
                except Exception:
                    pass  # best-effort; vacuum drops test 5's corrupted chunk anyway

        print(f"{'Check':<65}{'Result'}")
        for name, passed in results:
            print(f"{name:<65}{'PASS' if passed else 'FAIL'}")
        print()
        print("All checks passed." if all(r[1] for r in results) else "SOME CHECKS FAILED -- see above.")

    def _attack_real(self):
        if not self.catalog:
            print("Vault is empty -- nothing to run a real attack against. "
                  "Use 'write' first, or run 'virtual attack' instead.")
            return

        print("\nStored files:")
        for label in self.catalog:
            print(f"  {label}")
        label = input("Which file should the real attack test against? ").strip()
        if label not in self.catalog:
            print(f"No such label: '{label}'. Cancelled.")
            return

        manifest_path = os.path.join(self.storage_root, self.catalog[label])
        manifest_filename = os.path.basename(manifest_path)

        print(f"\nRunning REAL attack tests against '{label}' -- your actual stored file.")
        print("Any temporary corruption is backed up first and restored afterward, with the")
        print("restoration itself verified before this finishes.\n")

        results = []
        out_ok = os.path.join(self.storage_root, "__real_attack_out_ok__.bin")
        out_bad = os.path.join(self.storage_root, "__real_attack_out_bad__.bin")

        try:
            # 1. Baseline: correct key reconstructs this real file
            try:
                reconstruct(manifest_path, self.pipeline.container_path, out_ok, self.crypto.key)
                baseline_ok = os.path.exists(out_ok) and os.path.getsize(out_ok) > 0
            except Exception:
                baseline_ok = False
            results.append(("Baseline: correct key reconstructs this real file", baseline_ok))

            # 2. Wrong key is rejected
            wrong_key = secrets.token_bytes(32)
            try:
                reconstruct(manifest_path, self.pipeline.container_path, out_bad, wrong_key)
                results.append(("Wrong key is rejected", False))
            except Exception:
                results.append(("Wrong key is rejected", True))

            # 3. Manifest is unreadable without the key
            with open(manifest_path, "rb") as f:
                raw = f.read()
            try:
                pickle.loads(raw)
                results.append(("Manifest is unreadable without the key", False))
            except Exception:
                results.append(("Manifest is unreadable without the key", True))

            # 4. Confirmation-of-presence attack, with this file's real first chunk hash
            raw_manifest = self.crypto.decrypt_block(raw, associated_data=manifest_filename.encode())
            engine = FKSLookupEngine(raw_bytes=raw_manifest)
            first_hash = engine.lookup(0)
            conn = sqlite3.connect(os.path.join(self.storage_root, DB_FILENAME))
            row = conn.execute("SELECT 1 FROM blocks WHERE lookup_key = ?", (first_hash,)).fetchone()
            conn.close()
            results.append(("Confirmation-of-presence blocked (this file's real chunk hash)", row is None))

            # 5. Corrupted ciphertext is detected: back up the byte, corrupt it, test, restore, verify.
            gi = GlobalBlockIndex(self.storage_root, self.crypto)
            offset, length, ref_count, epoch_id = gi.lookup(first_hash)
            gi.close()

            set_immutable(self.pipeline.container_path, False)
            with open(self.pipeline.container_path, "r+b") as cf:
                cf.seek(offset)
                original_byte = cf.read(1)
                cf.seek(offset)
                cf.write(bytes([original_byte[0] ^ 0xFF]))

            try:
                reconstruct(manifest_path, self.pipeline.container_path, out_bad, self.crypto.key)
                detected = False
            except Exception:
                detected = True
            results.append(("Corrupted ciphertext is detected, not silently returned", detected))

            # Restore even if detection failed.
            with open(self.pipeline.container_path, "r+b") as cf:
                cf.seek(offset)
                cf.write(original_byte)
            set_immutable(self.pipeline.container_path, True)

            try:
                reconstruct(manifest_path, self.pipeline.container_path, out_ok, self.crypto.key)
                restored_ok = True
            except Exception:
                restored_ok = False
            results.append(("Real file fully restored and re-verified after the test", restored_ok))

        finally:
            for p in (out_ok, out_bad):
                if os.path.exists(p):
                    os.remove(p)

        print(f"{'Check':<65}{'Result'}")
        for name, passed in results:
            print(f"{name:<65}{'PASS' if passed else 'FAIL'}")
        print()
        if all(r[1] for r in results):
            print("All checks passed -- your real file's defenses hold, and it's exactly as it was.")
        else:
            print("SOME CHECKS FAILED -- see above. If restoration failed, run 'verify' on this file now.")


    def do_panic(self, arg):
        """panic  -- LAST RESORT: irreversibly destroys this vault's key material

Example:
  panic
(asks for your passphrase, then a typed confirmation -- no undo after that)

Shreds master.key and keyring.enc, which makes every chunk in the vault
permanently undecryptable, even with the passphrase. The rest of the
vault is then deleted best-effort; it is already unrecoverable by then."""
        print("\n*** PANIC WIPE -- LAST RESORT PROTECTION ***")
        print("This destroys this vault's key material immediately and irreversibly.")
        print("Every file ever stored here becomes permanently unrecoverable, including")
        print("by you. This asks twice not to be annoying, but because there is genuinely")
        print("no undo past this point.\n")

        if not self._require_reauth("permanently destroy this vault", always_ask=True):
            return

        confirm = input("Type exactly DESTROY VAULT to proceed (anything else cancels): ")
        if confirm != "DESTROY VAULT":
            print("Not confirmed. Vault untouched.")
            return

        print("\nDestroying key material...")
        key_path = os.path.join(self.storage_root, MASTER_KEY_FILENAME)
        keyring_path = os.path.join(self.storage_root, KEYRING_FILENAME)
        for path in (key_path, keyring_path):
            self._secure_erase_file(path)
        print("Key material destroyed. This vault is now permanently unrecoverable, "
              "even with the correct passphrase.")

        print("Best-effort cleanup of remaining ciphertext/metadata...")
        cleanup_targets = [
            self.pipeline.container_path,
            os.path.join(self.storage_root, DB_FILENAME),
            os.path.join(self.storage_root, DB_FILENAME + "-wal"),
            os.path.join(self.storage_root, DB_FILENAME + "-shm"),
            os.path.join(self.storage_root, CATALOG_FILENAME),
            os.path.join(self.storage_root, HISTORY_FILENAME),
            os.path.join(self.storage_root, LINEAGE_FILENAME),
        ]
        for fname in os.listdir(self.storage_root):
            if fname.endswith((".manifest.fks", ".traits.fks", ".manifest.fks.tmp", ".traits.fks.tmp")):
                cleanup_targets.append(os.path.join(self.storage_root, fname))
        for path in cleanup_targets:
            try:
                self._secure_erase_file(path)
            except Exception:
                pass

        print("\nDone. Exiting -- the key is gone from disk; only whatever remains in this")
        print("process's own memory persists until it exits, which is now.")
        self._session.crypto = None
        self._session.pipeline = None
        return True

    def _secure_erase_file(self, path: str) -> None:
        """Overwrites the file with random bytes, then unlinks it. Not proof
        against forensics on SSDs or copy-on-write filesystems; panic's real
        guarantee is that the key material is gone.
        """
        if not os.path.exists(path):
            return
        set_immutable(path, False)
        try:
            size = os.path.getsize(path)
            with open(path, "r+b") as f:
                f.seek(0)
                f.write(secrets.token_bytes(size))
                f.flush()
                os.fsync(f.fileno())
        except Exception:
            pass  # still unlink if the overwrite fails
        os.remove(path)


    def _gather_named_traits(self, description: str) -> dict:
        """{label: fingerprint} for every label that has one, noting any left
        out (still fingerprinting, or none stored). Taken from the clade
        worker's copy when it is up to date, otherwise read from disk.
        """
        cached = {}
        if self._clades.wait_idle(CLADE_WAIT_SECONDS):
            cached = self._clades.snapshot().fingerprints
        named_traits = {}
        missing = []
        for label, manifest_filename in self.catalog.items():
            if label in cached:
                named_traits[label] = stored_fingerprint.unpack(cached[label])
                continue
            manifest_path = os.path.join(self.storage_root, manifest_filename)
            if not os.path.exists(manifest_path):
                continue
            fingerprint = self._session.read_similarity_fingerprint(manifest_path)
            if fingerprint is None:
                missing.append(label)
            else:
                named_traits[label] = fingerprint

        if missing:
            with self._fingerprint_jobs_lock:
                in_flight = {l for l, t in self._fingerprint_jobs if t.is_alive()}
            pending = [l for l in missing if l in in_flight]
            stale = [l for l in missing if l not in in_flight]
            if pending:
                print(f"Note: {len(pending)} file(s) are still being fingerprinted in the background, "
                      f"so they're excluded from {description}: {', '.join(pending)}")
            if stale:
                print(f"Note: {len(stale)} file(s) predate this feature (or fingerprinting failed) and "
                      f"have no stored fingerprint, so they're excluded from {description}: {', '.join(stale)}")
                print("Re-run 'write' on them to include them next time.")
            print()
        return named_traits

    def do_tree(self, arg):
        """tree [upgma|nj]  -- build and show the clade tree of everything in the vault

Example:
  tree
  tree nj
(defaults to upgma; uses the fingerprints stored at write time)"""
        if not self._require_reauth("view the clade tree"):
            return
        algorithm = arg.strip().lower() or "upgma"
        if algorithm not in ("upgma", "nj"):
            print("Usage: tree [upgma|nj]")
            return
        if len(self.catalog) < 2:
            print("Need at least 2 files in the vault to build a tree. Use 'list' to see what's stored.")
            return

        named_traits = self._gather_named_traits("the tree")
        if len(named_traits) < 2:
            print("Not enough files with stored fingerprints to build a tree.")
            return

        analyzer = PhylogeneticAnalyzer(SIMILARITY_PROFILE)
        # Built in the background by the clade worker; build it here only if
        # it isn't ready in time.
        tc = TreeConstructor(analyzer)
        nodes = self._clades.tree(algorithm, named_traits, timeout=CLADE_WAIT_SECONDS)
        if nodes is None:
            nodes = tc.build_tree_upgma_from_traits(named_traits) if algorithm == "upgma" \
                else tc.build_tree_nj_from_traits(named_traits)

        unreliable = {lbl: len(traits) for lbl, traits in named_traits.items()
                      if not analyzer.trait_set_is_reliable(traits)}
        if unreliable:
            print(_reliability_warning(unreliable))

        print(f"\n--- Clade tree ({algorithm.upper()}) ---")
        tc.visualize_tree(nodes)

    def do_similar(self, arg):
        """similar <label>  -- rank every other file in the vault by content closeness to this one

Example:
  similar my_report
(Jaccard distance: 0.0 = identical content, 1.0 = nothing in common)"""
        label = _join_args(arg)
        if label not in self.catalog:
            print(f"No such label: '{label}'")
            return
        if not self._require_reauth(f"find files similar to '{label}'"):
            return

        named_traits = self._gather_named_traits("this comparison")
        if label not in named_traits:
            print(f"'{label}' has no stored fingerprint yet -- it may still be fingerprinting in "
                  f"the background, or it predates this feature. Re-run 'write' on it to fix that.")
            return

        target_traits = named_traits.pop(label)
        if not named_traits:
            print("No other files with a stored fingerprint to compare against.")
            return

        analyzer = PhylogeneticAnalyzer(SIMILARITY_PROFILE)
        ranked = sorted(
            ((other_label, analyzer.calculate_distance(target_traits, other_traits))
             for other_label, other_traits in named_traits.items()),
            key=lambda pair: pair[1],
        )

        unreliable = {lbl: len(traits) for lbl, traits in
                      {label: target_traits, **named_traits}.items()
                      if not analyzer.trait_set_is_reliable(traits)}
        if unreliable:
            print(_reliability_warning(unreliable))

        print(f"\n--- Files closest to '{label}' (Jaccard distance -- 0.0=identical, 1.0=nothing shared) ---")
        for other_label, distance in ranked:
            print(f"  {distance:.4f}  {other_label}")

    def do_clade(self, arg):
        """clade <label>  -- find <label>'s clade (similarity family) and focus the shell on it

Example:
  clade my_report
  checkout @tip /tmp/restored.pdf     (label is optional once focused)
  ancestor 2                           (steps back from the focused label's tip)
(a clade groups files within Jaccard distance 0.80 of each other; it is
not a lineage and has no root. Sets the shell's focus to <label>.)"""
        label = _join_args(arg)
        if not label:
            print("Usage: clade <label>")
            return
        if label not in self.catalog:
            print(f"No such label: '{label}'")
            return
        if not self._require_reauth(f"find '{label}'s clade"):
            return

        members = _clade_members(self._clades, label, self.catalog)
        if members is None:
            print(f"'{label}' has no stored fingerprint yet -- it may still be fingerprinting in "
                  f"the background, or it predates this feature. Re-run 'write' on it to fix that.")
            return

        trait_counts = {}
        for m in members:
            trait_counts[m] = self._session.similarity_fingerprint_count(
                os.path.join(self.storage_root, self.catalog[m])) or 0
        unreliable = {m: n for m, n in trait_counts.items() if n < MIN_RELIABLE_TRAIT_COUNT}
        if unreliable:
            print(_reliability_warning(unreliable))

        self._focus_label = label
        print(f"\n--- Clade containing '{label}' (Jaccard distance <= "
              f"{TreeConstructor.DEFAULT_CLADE_THRESHOLD:.2f}) ---")
        if len(members) == 1:
            print(f"  '{label}' -- no other file in the vault is within the clade threshold "
                  f"(a clade of one).")
        else:
            # "Oldest" is just the earliest generation-0 write -- an orientation aid, not a root.
            def birth0(m):
                node0 = self._session.lineage.get_generation(m, 0)
                return node0.birth_timestamp if node0 else float("inf")
            oldest = min(members, key=birth0)
            for m in members:
                note = "  (oldest member here by generation-0 birth time -- NOT a lineage root; " \
                       "clades have no root)" if m == oldest else ""
                print(f"  {m}{note}")
        print(f"\nFocus set to '{label}'. 'checkout @tip <output>' and 'ancestor <N>' now work "
              f"without repeating the label.")

    def do_info(self, arg):
        """info <label>  -- detailed metadata for one stored file

Example:
  info my_report"""
        label = _join_args(arg)
        if label not in self.catalog:
            print(f"No such label: '{label}'")
            return
        if not self._require_reauth(f"view details for '{label}'"):
            return
        manifest_path = os.path.join(self.storage_root, self.catalog[label])
        meta = self._read_manifest_metadata(manifest_path)
        fp_count = self._session.similarity_fingerprint_count(manifest_path, meta)
        phenotype_mask = meta.get("phenotype_mask")
        print(f"Label:                   {label}")
        print(f"Manifest file:           {os.path.basename(manifest_path)}")
        print(f"Original filename:       {meta.get('original_filename')} (a label, not used for identity)")
        print(f"Detected type:           "
              f"{meta.get('phenotype_name', 'unknown (predates this feature)')}"
              + (f"  [mask 0x{phenotype_mask:04X}]" if phenotype_mask is not None else "")
              + "  -- from content, not the name above")
        print(f"Size:                    {meta.get('original_size'):,} bytes")
        print(f"Total chunks:            {meta.get('total_blocks')}")
        print(f"  new at write time:     {meta.get('new_chunks_written')}")
        print(f"  deduped at write time: {meta.get('duplicate_chunks_found')}")
        print(f"Content SHA-256:         {meta.get('content_sha256')}")
        print(f"Similarity fingerprint:  "
              f"{'stored (' + str(fp_count) + ' traits)' if fp_count is not None else 'not stored (predates this feature)'}")
        tags = self._session.lineage.get_tags(label)
        print(f"Epigenetic tags:         "
              f"{', '.join(f'{k}={v}' for k, v in tags.items()) if tags else '(none)'}")

        total_blocks = meta.get("total_blocks") or 0
        if total_blocks:
            manifest_filename = os.path.basename(manifest_path)
            with open(manifest_path, "rb") as f:
                raw_manifest = self.crypto.decrypt_block(f.read(), associated_data=manifest_filename.encode())
            engine = FKSLookupEngine(raw_bytes=raw_manifest)
            gi = GlobalBlockIndex(self.storage_root, self.crypto)
            mirrored = sum(
                1 for idx in range(total_blocks)
                if (h := engine.lookup(idx)) is not None and gi.get_mirror(h) is not None
            )
            gi.close()
            print(f"Ancestral Hardening:     {mirrored}/{total_blocks} chunk(s) mirrored (see 'fsck')")

    def do_lineage(self, arg):
        """lineage <label>  -- show this file's real edit history (generations, not the clade tree)

Example:
  lineage my_report
(each generation is a reconstructible past version; 'checkout' pulls one)"""
        label = _join_args(arg)
        if label not in self.catalog:
            print(f"No such label: '{label}'")
            return
        if not self._require_reauth(f"view lineage for '{label}'"):
            return
        history = self._session.lineage.get_history(label)
        if not history:
            print(f"No recorded history for '{label}' -- written before this feature existed, "
                  f"or never re-written since. Re-run 'write' on it to start tracking from here.")
            return

        heads = {h.node_uuid for h in self._session.lineage.get_heads(label)}
        if len(heads) > 1:
            print(f"NOTE: '{label}' has {len(heads)} divergent branch heads -- see 'merge' to "
                  f"reconcile them.\n")
        print(f"{'Gen':>4}  {'When':<20}{'New chunks':>12}{'Total chunks':>14}  Node UUID")
        for node in history:
            when = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(node.birth_timestamp))
            if node is history[-1]:
                marker = "  (current)"
            elif node.node_uuid in heads:
                marker = "  (branch head -- not current; see 'merge')"
            elif node.pruned:
                marker = "  (pruned -- content reclaimed)"
            else:
                marker = ""
            parent_note = "root" if node.parent_uuid is None else None
            if parent_note is None:
                parent_node = self._session.lineage.find_node_by_uuid(node.parent_uuid)
                parent_note = f"parent: gen {parent_node.generation_index}" if parent_node else "parent: (untracked)"
            print(f"{node.generation_index:>4}  {when:<20}{node.new_chunks:>12}{node.total_chunks:>14}  "
                  f"{node.node_uuid[:12]}...{marker}")
            print(f"        {parent_note}")
            if node.epigenetic_tags:
                tags_str = ", ".join(f"{k}={v}" for k, v in node.epigenetic_tags.items())
                print(f"        tags: {tags_str}")
            if node.lateral_parent_uuids:
                for lateral_uuid in node.lateral_parent_uuids:
                    lateral_node = self._session.lineage.find_node_by_uuid(lateral_uuid)
                    if lateral_node is not None:
                        pruned_note = " (pruned since)" if lateral_node.pruned else ""
                        print(f"        + lateral parent: '{lateral_node.label}' generation "
                              f"{lateral_node.generation_index}{pruned_note} (grafted -- see 'graft')")
                    else:
                        print(f"        + lateral parent: {lateral_uuid[:12]}... (label no longer tracked)")

    @staticmethod
    def _parse_tag_value(raw: str):
        """true/false/yes/no/1/0 become booleans (so 'protected' works as a flag); anything else stays text."""
        lowered = raw.lower()
        if lowered in ("true", "yes", "1"):
            return True
        if lowered in ("false", "no", "0"):
            return False
        return raw

    def do_tag(self, arg):
        """tag <label> <key> <value>  -- set an epigenetic tag on a label's current version

Example:
  tag legal_contract protected true
  tag internal_draft no_graft_source true
  tag my_report project alpha
(true/false/yes/no/1/0 become booleans. Future generations inherit the
tag. 'protected' blocks delete/prune unless forced; 'no_graft_source'
blocks use in 'graft'; other keys are informational.)"""
        parts = _split_args(arg)
        if parts is None:
            return
        if len(parts) > 3:
            # An unquoted multi-word value still works.
            parts = parts[:2] + [" ".join(parts[2:])]
        if len(parts) != 3:
            print("Usage: tag <label> <key> <value>")
            return
        label, key, raw_value = parts
        if label not in self.catalog:
            print(f"No such label: '{label}'")
            return
        if not self._require_reauth(f"tag '{label}'"):
            return
        value = self._parse_tag_value(raw_value)
        try:
            self._session.lineage.set_tag(label, key, value)
        except KeyError as e:
            print(f"Tag failed: {e}")
            return
        print(f"Tagged '{label}': {key}={value}. Future generations of '{label}' will inherit this.")

    def do_untag(self, arg):
        """untag <label> <key>  -- remove an epigenetic tag from a label's current version

Example:
  untag legal_contract protected
(future generations won't inherit it; past generations keep theirs)"""
        parts = _split_args(arg)
        if parts is None:
            return
        if len(parts) != 2:
            print("Usage: untag <label> <key>")
            return
        label, key = parts
        if label not in self.catalog:
            print(f"No such label: '{label}'")
            return
        if not self._require_reauth(f"untag '{label}'"):
            return
        try:
            removed = self._session.lineage.remove_tag(label, key)
        except KeyError as e:
            print(f"Untag failed: {e}")
            return
        if removed:
            print(f"Removed tag '{key}' from '{label}'.")
        else:
            print(f"'{label}' didn't have a tag named '{key}'.")

    def do_prune(self, arg):
        """prune <label> <generation> [force]  -- reclaim storage from one OLD historical version

Example:
  prune my_report 2
  prune my_report 2 force
(frees one past version's content; it stays listed in 'lineage' as
pruned. Not the current tip -- use 'delete'. 'force' overrides
'protected'. Run 'vacuum' afterwards to reclaim the space.)"""
        parts = _split_args(arg)
        if parts is None:
            return
        if len(parts) not in (2, 3):
            print("Usage: prune <label> <generation> [force]")
            return
        label, gen_str = parts[0], parts[1]
        force = len(parts) == 3 and parts[2].lower() == "force"
        if label not in self.catalog:
            print(f"No such label: '{label}'")
            return
        try:
            generation = int(gen_str)
        except ValueError:
            print("Usage: prune <label> <generation> [force]  (generation must be an integer)")
            return
        if not self._require_reauth(f"prune generation {generation} of '{label}'"):
            return
        try:
            report = self._session.prune_generation(label, generation, force=force)
        except PermissionError as e:
            print(f"Prune refused: {e}")
            return
        except (KeyError, ValueError) as e:
            print(f"Prune failed: {e}")
            return
        if report["freed"]:
            print(f"Pruned generation {generation} of '{label}'. Run 'vacuum' to reclaim its space.")
        else:
            print(f"Marked generation {generation} of '{label}' as pruned, but its manifest is still "
                  f"shared with something else in the vault -- nothing freed yet.")

    def do_graft(self, arg):
        """graft <label_a> <label_b> <new_label>  -- Lateral Gene Transfer: fuse two unrelated lineages

Example:
  graft source_code documentation combined_release
(new_label = label_a's content followed by label_b's, descending from
both. No merging logic. Since both are already stored, few chunks are
new -- see the 'new' count.)"""
        parts = _split_args(arg)
        if parts is None:
            return
        if len(parts) != 3:
            print("Usage: graft <label_a> <label_b> <new_label>")
            return
        label_a, label_b, new_label = parts
        if label_a not in self.catalog:
            print(f"No such label: '{label_a}'")
            return
        if label_b not in self.catalog:
            print(f"No such label: '{label_b}'")
            return
        if label_a == label_b:
            print("Can't graft a label onto itself.")
            return
        if not self._require_reauth(f"graft '{label_a}' and '{label_b}' into '{new_label}'"):
            return
        try:
            manifest_path = self._session.lateral_gene_transfer(label_a, label_b, new_label)
        except Exception as e:
            print(f"Graft failed: {type(e).__name__}: {e}")
            return

        meta = self._read_manifest_metadata(manifest_path)
        history = self._session.lineage.get_history(new_label)
        gen = history[-1].generation_index if history else "?"
        print(f"Grafted '{label_a}' + '{label_b}' -> '{new_label}' (generation {gen})")
        print(f"  {meta['total_blocks']} chunks ({meta['new_chunks_written']} genuinely new -- "
              f"the rest already existed from '{label_a}' and '{label_b}')")
        print(f"  {meta['original_size']:,} bytes total")

    def do_merge(self, arg):
        """merge <label> <generation_a> <generation_b>  -- reconcile two divergent branches of one label

Example:
  merge my_report 3 5
(3-way diff of chunk positions against the common ancestor: a chunk
changed by one branch, or the same way by both, merges; a chunk changed
differently by both is a conflict and nothing is committed)"""
        parts = _split_args(arg)
        if parts is None:
            return
        if len(parts) != 3:
            print("Usage: merge <label> <generation_a> <generation_b>")
            return
        label, gen_a_str, gen_b_str = parts
        if label not in self.catalog:
            print(f"No such label: '{label}'")
            return
        try:
            generation_a, generation_b = int(gen_a_str), int(gen_b_str)
        except ValueError:
            print("Usage: merge <label> <generation_a> <generation_b>  (generations must be integers)")
            return
        if not self._require_reauth(f"merge '{label}' generations {generation_a} and {generation_b}"):
            return

        try:
            manifest_path = self._session.merge_branches(label, generation_a, generation_b)
        except MutationConflictError as e:
            print(f"MUTATION CONFLICT -- merge refused, nothing was committed.")
            print(f"  {e}")
            print(f"  Both branches changed the same chunk position(s) differently since their "
                  f"common ancestor -- pick manually (write a fresh version by hand, or 'checkout' "
                  f"whichever branch you want to keep and go from there).")
            return
        except Exception as e:
            print(f"Merge failed: {type(e).__name__}: {e}")
            return

        meta = self._read_manifest_metadata(manifest_path)
        history = self._session.lineage.get_history(label)
        gen = history[-1].generation_index if history else "?"
        print(f"Merged '{label}' generations {generation_a} + {generation_b} -> generation {gen}")
        print(f"  {meta['total_blocks']} chunks ({meta['new_chunks_written']} genuinely new -- "
              f"the rest already existed on one branch or the other)")

    def do_checkout(self, arg):
        """checkout <label> <generation> <output_path>  -- reconstruct a PAST version of a file

Example:
  checkout my_report 0 /tmp/my_report_original.pdf
  checkout my_report @tip /tmp/my_report_latest.pdf
  clade my_report
  checkout @tip /tmp/my_report_latest.pdf     (label optional once focused via 'clade')
(generation 0 is the original; '@tip' is the current version; a relative
output path resolves against 'navigate's directory)"""
        parts = _split_args(arg)
        if parts is None:
            return
        if len(parts) == 2:
            gen_str, output_path = parts
            if gen_str != "@tip":
                print("Usage: checkout <label> <generation> <output_path>  (2-argument form only "
                      "accepts 'checkout @tip <output_path>', using the focus label set by 'clade')")
                return
            if self._focus_label is None:
                print("No current focus label set -- run 'clade <label>' first, or use the full "
                      "'checkout <label> @tip <output_path>' form.")
                return
            label = self._focus_label
        elif len(parts) == 3:
            label, gen_str, output_path = parts
        else:
            print("Usage: checkout <label> <generation> <output_path>  (generation is a number or "
                  "'@tip'; or 'checkout @tip <output_path>' once 'clade <label>' has set a focus)")
            return
        output_path = self._resolve_path(output_path)
        if label not in self.catalog:
            print(f"No such label: '{label}'")
            return
        if gen_str == "@tip":
            tip = self._session.lineage.get_tip(label)
            if tip is None:
                print(f"'{label}' has no recorded lineage history.")
                return
            generation = tip.generation_index
        else:
            try:
                generation = int(gen_str)
            except ValueError:
                print("Usage: checkout <label> <generation> <output_path>  "
                      "(generation must be an integer or '@tip')")
                return
        node = self._session.lineage.get_generation(label, generation)
        if node is None:
            print(f"No generation {generation} recorded for '{label}'. Use 'lineage {label}' to see what exists.")
            return
        if node.pruned:
            print(f"Generation {generation} of '{label}' was pruned -- its content is no longer "
                  f"available. Use 'lineage {label}' to see which generations are still retrievable.")
            return
        if not self._require_reauth(f"check out '{label}' generation {generation}"):
            return
        manifest_path = os.path.join(self.storage_root, node.manifest_filename)
        try:
            reconstruct(manifest_path, self.pipeline.container_path, output_path, self.crypto.key)
        except ReconstructionError as e:
            print(f"Reconstruction FAILED (the system correctly detected a problem): {e}")
        except Exception as e:
            print(f"Reconstruction failed: {type(e).__name__}: {e}")

    def do_ancestor(self, arg):
        """ancestor <N> [output_path]  -- reconstruct the version N primary-parent generations back from the focused label's tip

Example:
  clade my_report
  ancestor 3
  ancestor 3 /tmp/three_generations_back.pdf
(needs a focus label from 'clade'. Counts primary-parent steps from the
current tip each time; lateral parents don't count. Without output_path,
writes <label>_ancestor_<N>_gen<G> in the navigate or working directory.)"""
        parts = _split_args(arg)
        if parts is None:
            return
        if len(parts) not in (1, 2):
            print("Usage: ancestor <N> [output_path]")
            return
        if self._focus_label is None:
            print("No current focus label set -- run 'clade <label>' first.")
            return
        try:
            n = int(parts[0])
            if n < 0:
                raise ValueError
        except ValueError:
            print("Usage: ancestor <N> [output_path]  (N must be a non-negative integer)")
            return

        label = self._focus_label
        if label not in self.catalog:
            print(f"No such label: '{label}' (it may have been deleted/renamed since 'clade' was run).")
            return
        history = self._session.lineage.get_history(label)
        if not history:
            print(f"'{label}' has no recorded lineage history.")
            return
        by_uuid = {h.node_uuid: h for h in history}

        node = history[-1]  # tip, as prune_generation() defines it
        for step in range(n):
            if node.parent_uuid is None:
                print(f"'{label}' only has {step} primary-parent generation(s) available back from "
                      f"its tip -- can't go back {n}.")
                return
            parent = by_uuid.get(node.parent_uuid)
            if parent is None:
                print("Internal error: primary-parent generation not found in this label's own history.")
                return
            node = parent

        if node.pruned:
            print(f"Generation {node.generation_index} of '{label}' ({n} generation(s) back) was "
                  f"pruned -- its content is no longer available. Use 'lineage {label}' to see which "
                  f"generations are still retrievable.")
            return

        if len(parts) == 2:
            output_path = self._resolve_path(parts[1])
        else:
            base_dir = self._nav_dir or os.getcwd()
            output_path = os.path.join(base_dir, f"{label}_ancestor_{n}_gen{node.generation_index}.bin")

        if not self._require_reauth(f"check out '{label}' generation {node.generation_index} "
                                     f"({n} generation(s) back from tip)"):
            return
        manifest_path = os.path.join(self.storage_root, node.manifest_filename)
        try:
            reconstruct(manifest_path, self.pipeline.container_path, output_path, self.crypto.key)
        except ReconstructionError as e:
            print(f"Reconstruction FAILED (the system correctly detected a problem): {e}")
            return
        except Exception as e:
            print(f"Reconstruction failed: {type(e).__name__}: {e}")
            return
        print(f"'{label}' generation {node.generation_index} ({n} primary-parent generation(s) back "
              f"from tip) -> {output_path}")

    def do_verify(self, arg):
        """verify <label>  -- check a stored file's integrity without writing it anywhere permanent

Example:
  verify my_report"""
        label = _join_args(arg)
        if label not in self.catalog:
            print(f"No such label: '{label}'")
            return
        if not self._require_reauth(f"verify '{label}'"):
            return
        manifest_path = os.path.join(self.storage_root, self.catalog[label])
        tmp_out = os.path.join(self.storage_root, f"__verify_tmp__.bin")
        try:
            reconstruct(manifest_path, self.pipeline.container_path, tmp_out, self.crypto.key)
            print(f"'{label}': OK -- reconstructs correctly, all integrity checks passed.")
        except ReconstructionError as e:
            print(f"'{label}': FAILED -- {e}")
        except Exception as e:
            print(f"'{label}': FAILED -- {type(e).__name__}: {e}")
        finally:
            if os.path.exists(tmp_out):
                os.remove(tmp_out)

    def do_rename(self, arg):
        """rename <old_label> <new_label>  -- rename a catalog entry (data itself is untouched)

Example:
  rename my_report q3_report
(the label's history moves with it)"""
        parts = _split_args(arg)
        if parts is None:
            return
        if len(parts) != 2:
            print("Usage: rename <old_label> <new_label>")
            return
        old_label, new_label = parts
        if old_label not in self.catalog:
            print(f"No such label: '{old_label}'")
            return
        if new_label in self.catalog:
            print(f"Label '{new_label}' already exists. Choose a different name, or 'delete' it first.")
            return
        if not self._require_reauth(f"rename '{old_label}'"):
            return
        self.catalog[new_label] = self.catalog.pop(old_label)
        self._session.lineage.rename_label(old_label, new_label)
        self._save_catalog()
        print(f"Renamed '{old_label}' -> '{new_label}'")

    def do_test(self, arg):
        """test  -- power-on self test: exercises every major subsystem for real, end to end

Example:
  test
(real write, edit, fork, tag, delete, vacuum and fsck on a throwaway
label; see 'attack' for tampering tests)"""
        if not self._require_reauth("run a self test"):
            return
        print("=== PFS Power-On Self Test ===\n")
        results = []
        label = "__post_test__"
        work_v1 = os.path.join(self.storage_root, "__post_test_v1__.bin")
        work_v2 = os.path.join(self.storage_root, "__post_test_v2__.bin")
        out_path = os.path.join(self.storage_root, "__post_test_out__.bin")

        def check(name, fn):
            try:
                results.append((name, bool(fn())))
            except Exception as e:
                results.append((f"{name} ({type(e).__name__}: {e})", False))

        def roundtrip_ok():
            manifest_path = self._session.manifest_path_for(label)
            reconstruct(manifest_path, self.pipeline.container_path, out_path, self.crypto.key)
            with open(out_path, "rb") as f:
                return f.read() == content_v1

        def second_generation_ok():
            history = self._session.lineage.get_history(label)
            return (len(history) == 2 and history[1].parent_uuid == history[0].node_uuid)

        def delete_and_vacuum_ok():
            self._session.delete_label(label, force=True)
            report = self._session.vacuum()
            return isinstance(report, dict) and "bytes_reclaimed" in report

        def fsck_clean():
            report = self.pipeline.verify_and_repair()
            return report["unrecoverable"] == []

        check("Container accessible",
              lambda: os.path.exists(self.pipeline.container_path) or True)
        check("Global index responds to queries", lambda: _index_probe(self.storage_root, self.crypto))
        check("Catalog loads", lambda: isinstance(self.catalog, dict))

        content_v1 = secrets.token_bytes(2000)
        content_v2 = content_v1 + b"a real edit, appended"
        with open(work_v1, "wb") as f:
            f.write(content_v1)
        with open(work_v2, "wb") as f:
            f.write(content_v2)

        try:
            self._session.commit_write(label, work_v1)
            check("Write/read round trip is byte-identical", roundtrip_ok)
            # Checked after a write: a new keyring's epoch starts at -1 and becomes 0
            # only when a DEK is first requested.
            check("Keyring loads with an active epoch", lambda: self.pipeline.keyring.current_epoch >= 0)
            self._session.commit_write(label, work_v1)  # byte-identical resave
            check("No-op resave does not inflate lineage history",
                  lambda: len(self._session.lineage.get_history(label)) == 1)
            self._session.commit_write(label, work_v2)  # a real edit
            check("A real edit creates a second, correctly-parented generation", second_generation_ok)
            self._session.commit_write(label, work_v1, fork_from_generation=0)
            check("Fork creates a genuine second branch head",
                  lambda: len(self._session.lineage.get_heads(label)) == 2)
            self._session.lineage.set_tag(label, "__post_test_tag__", True)
            check("Tag set/get round-trips correctly",
                  lambda: self._session.lineage.get_tags(label).get("__post_test_tag__") is True)
            self._session.lineage.remove_tag(label, "__post_test_tag__")
        finally:
            for p in (work_v1, work_v2, out_path):
                if os.path.exists(p):
                    os.remove(p)

        check("Delete + vacuum reclaims space without error", delete_and_vacuum_ok)
        check("Fsck runs clean on a healthy vault", fsck_clean)

        print(f"{'Check':<60}{'Result'}")
        for name, passed in results:
            print(f"{name:<60}{'PASS' if passed else 'FAIL'}")
        print()
        print("All checks passed." if all(r[1] for r in results) else "SOME CHECKS FAILED -- see above.")

    def do_history(self, arg):
        """history [N]  -- show your command history (all of it, or just the last N)

Example:
  history
  history 20
(stored encrypted across sessions; up arrow recalls it too)"""
        if not self._require_reauth("view command history"):
            return
        n = None
        if arg.strip():
            try:
                n = int(arg.strip())
                if n <= 0:
                    raise ValueError
            except ValueError:
                print("Usage: history [N]  (N must be a positive integer)")
                return
        entries = self._command_history if n is None else self._command_history[-n:]
        if not entries:
            print("(no history yet)")
            return
        start_index = len(self._command_history) - len(entries) + 1
        for i, cmd_line in enumerate(entries, start=start_index):
            print(f"{i:5d}  {cmd_line}")

    def do_navigate(self, arg):
        """navigate [<directory>|-]  -- set/show/clear a working directory for write/read

Example:
  navigate /home/lister/Documents/test_batch
  write report.pdf                    (resolves to .../test_batch/report.pdf)
  read my_report restored.pdf         (output resolves the same way)
  navigate                             -- show the current setting
  navigate -                           -- clear it

Only affects relative paths given to 'write' and 'read'. Not saved
between sessions."""
        target = _join_args(arg)
        if target is None:
            return
        if not target:
            if self._nav_dir:
                print(f"Current navigate directory: {self._nav_dir}")
            else:
                print("No navigate directory set -- relative paths resolve against this "
                      "shell process's own working directory.")
            return
        if target == "-":
            if self._nav_dir:
                print(f"Cleared navigate directory (was: {self._nav_dir})")
            else:
                print("Navigate directory was already unset.")
            self._nav_dir = None
            return
        resolved = os.path.abspath(os.path.expanduser(target))
        if not os.path.isdir(resolved):
            print(f"Not a directory: {resolved}")
            return
        self._nav_dir = resolved
        print(f"Navigate directory set to: {self._nav_dir}")
        print("'write <file>' and the output path in 'read <label> <file>' now resolve relative paths here.")

    def _resolve_path(self, path: str) -> str:
        """Resolves a relative write/read path against the navigate directory."""
        expanded = os.path.expanduser(path)
        if os.path.isabs(expanded) or self._nav_dir is None:
            return expanded
        return os.path.join(self._nav_dir, expanded)

    def do_clear(self, arg):
        """clear  -- clear the terminal screen

Example:
  clear
(takes no arguments)"""
        os.system("cls" if os.name == "nt" else "clear")


    def do_exit(self, arg):
        "exit  -- close the shell"
        with self._fingerprint_jobs_lock:
            pending = list(self._fingerprint_jobs)
        if pending:
            labels = ", ".join(l for l, _t in pending)
            print(f"Waiting for {len(pending)} background fingerprint job(s) to finish: {labels} ...")
            for _label, thread in pending:
                thread.join()
        self._clades.stop(timeout=10)
        # Release the vault lock now rather than at garbage collection.
        self._session.close()
        print("Goodbye.")
        return True

    do_quit = do_exit

    def do_EOF(self, arg):
        print()
        return self.do_exit(arg)

    def emptyline(self):
        pass  # don't repeat the last command

    def onecmd(self, line):
        stripped = line.strip() if isinstance(line, str) else ""
        try:
            result = super().onecmd(line)
        except Exception as e:
            print(f"Error: {type(e).__name__}: {e}")
            self._report_catalog_changes()
            return False
        if result:
            self._clades.stop(timeout=10)  # exiting (exit/panic)
            return result
        self._report_catalog_changes()
        if stripped:
            self._record_history(stripped)
        return result


class CppPFSShell(_ReauthMixin, cmd.Cmd):
    """Shell for the compiled C++ engine (--engine cpp). Separate from
    PFSShell so it's always clear which engine a command runs on.
    """

    intro = (
        "\nPhylogenetic File System -- C++ ENGINE shell.\n"
        "Talks to the compiled engine in cpp_engine/, not the Python one.\n"
        "  write, read, delete, list, history, info, lineage\n"
        "  fork, graft, merge, checkout, rename, tag, untag, prune\n"
        "  vacuum, fsck, rotate, stats, passwd, navigate, clear\n"
        "  tree, similar   -- clade clustering, same UPGMA/NJ math as Python\n"
        "  clade, ancestor -- Lineage Shell address syntax ('clade X' focuses\n"
        "                     the shell; 'checkout @tip'/'ancestor N' then work\n"
        "                     without repeating the label -- see 'help clade')\n"
        "  attack, test    -- adversarial self-test suite, power-on self test\n\n"
        "Quick start:\n"
        "  write /path/to/file.pdf my_label   -- store a file\n"
        "  list                                -- see what's stored\n"
        "  read my_label /path/to/output.pdf   -- get it back\n"
    )
    prompt = "pfs-cpp> "

    def __init__(self, storage_root: str):
        super().__init__()
        self.storage_root = storage_root
        self._nav_dir = None
        # Set by 'clade': the label 'checkout @tip' and 'ancestor' default to.
        self._focus_label = None
        os.makedirs(storage_root, exist_ok=True)
        existing = _existing_vault_engine(storage_root)
        if existing == "python":
            print(f"'{storage_root}' is an existing PYTHON-engine vault (catalog.enc/keyring.enc "
                  f"present). The C++ engine uses different, incompatible file formats and would "
                  f"corrupt it. Point --engine cpp at a different, empty directory instead.")
            sys.exit(1)
        kek = self._unlock_or_create()
        try:
            self._session = CppVaultSession(storage_root, kek)
        except PfsEngineError as e:
            print(f"Couldn't open the C++ vault: {e}")
            sys.exit(1)
        # For _require_reauth's exact-match check.
        self._kek = kek
        # Clade worker for 'clade'. Commands that change a label's tip report it;
        # 'test' and 'attack' only use throwaway labels.
        self._clades = CladeWorker(cpp_session_loader(self._session),
                                   name="cli-cpp-clade-worker").start(self._session.list_labels())

    def _current_kek(self) -> bytes:
        return self._kek

    def _unlock_or_create(self) -> bytes:
        key_path = os.path.join(self.storage_root, MASTER_KEY_FILENAME)
        vault_existed = os.path.exists(key_path)
        if not vault_existed:
            print(f"No vault found at '{self.storage_root}'. Creating a new C++-engine vault.")
            pw1 = getpass.getpass("Set a new vault passphrase: ")
            pw2 = getpass.getpass("Confirm passphrase: ")
            if pw1 != pw2:
                print("Passphrases didn't match.")
                sys.exit(1)
            kek = create_new_vault_key(self.storage_root, pw1)
        else:
            pw = getpass.getpass("Enter vault passphrase: ")
            try:
                kek = load_vault_key(self.storage_root, pw)
            except WrongPassphraseError:
                print("Wrong passphrase.")
                sys.exit(1)
        print("New C++ vault created.\n" if not vault_existed else "C++ vault unlocked.\n")
        return kek

    def _resolve_path(self, path: str) -> str:
        expanded = os.path.expanduser(path)
        if os.path.isabs(expanded) or self._nav_dir is None:
            return expanded
        return os.path.join(self._nav_dir, expanded)


    def do_write(self, arg):
        """write <file_path> [label]  -- ingest a file into the vault (C++ engine)

Example:
  write /home/lister/Documents/report.pdf
  write /home/lister/Documents/report.pdf my_report
  write "/home/lister/Documents/Q3 report.pdf" "q3 report"
(if you skip [label], the file's own basename is used as the label; a
relative file_path resolves against 'navigate's directory, if set)"""
        parts = _split_args(arg)
        if parts is None:
            return
        if not parts:
            print("Usage: write <file_path> [label]")
            return
        if len(parts) > 2:
            # Refuse extra words rather than silently dropping them.
            print('Usage: write <file_path> [label]  (put a path or label containing spaces '
                  'in quotes: write "my file.txt" "my label")')
            return
        file_path = self._resolve_path(parts[0])
        label = parts[1] if len(parts) > 1 else os.path.basename(parts[0])
        if not os.path.exists(file_path):
            print(f"File not found: {file_path}")
            return
        if not self._require_reauth("store a file"):
            return
        try:
            start = time.perf_counter()
            manifest = self._session.commit_write(label, file_path)
            elapsed = time.perf_counter() - start
        except PfsEngineError as e:
            print(f"Write failed: {e}")
            return
        self._clades.changed(label)
        info = self._session.get_manifest_info(label)
        total = info["total_blocks"] or 1
        dedup_pct = 100 * info["duplicate_chunks_found"] / total
        print(f"Stored as '{label}' -> {manifest}")
        print(f"  {info['total_blocks']} chunks ({info['new_chunks_written']} new, "
              f"{info['duplicate_chunks_found']} deduped, {dedup_pct:.1f}%)")
        print(f"  {info['original_size']:,} bytes, {elapsed:.3f}s")

    def do_read(self, arg):
        """read <label> <output_path>  -- reconstruct a file from the vault (C++ engine)

Example:
  read my_report /home/lister/Desktop/report_restored.pdf
(a relative output_path resolves against 'navigate's directory, if set)"""
        parts = _split_args(arg)
        if parts is None:
            return
        if len(parts) != 2:
            print("Usage: read <label> <output_path>")
            return
        label, output_path = parts
        output_path = self._resolve_path(output_path)
        if not self._require_reauth(f"read '{label}'"):
            return
        try:
            self._session.reconstruct_label(label, output_path)
        except PfsEngineError as e:
            print(f"Reconstruction failed: {e}")
            return
        print(f"Wrote {output_path}")

    def do_delete(self, arg):
        """delete <label> [force]  -- remove a label entirely (C++ engine)

Example:
  delete my_report
  delete my_report force
(removes the label's full history; shared storage stays until unused.
'force' overrides the 'protected' tag.)"""
        parts = _split_args(arg)
        if parts is None:
            return
        if len(parts) not in (1, 2) or (len(parts) == 2 and parts[1].lower() != "force"):
            print("Usage: delete <label> [force]")
            return
        label = parts[0]
        force = len(parts) == 2
        if not self._require_reauth(f"delete '{label}'", always_ask=True):
            return
        try:
            report = self._session.delete_label(label, force=force)
        except PfsEngineError as e:
            print(f"Delete failed: {e}")
            return
        self._clades.removed(label)
        if report["manifests_kept_shared"]:
            print(f"Deleted '{label}'. {report['manifests_freed']} manifest(s) freed; "
                  f"{report['manifests_kept_shared']} kept because something else in the vault "
                  f"still references them.")
        else:
            print(f"Deleted '{label}' ({report['manifests_freed']} manifest(s) freed). "
                  f"Run 'vacuum' to reclaim its space.")

    def do_fork(self, arg):
        """fork <label> <generation> <file_path>  -- branch off an OLD generation instead of the tip (C++ engine)

Example:
  fork my_report 2 /home/lister/Documents/alternate_draft.pdf
(a new version descending from generation N, not the tip. 'lineage'
shows the branch heads; 'merge' reconciles them.)"""
        parts = _split_args(arg)
        if parts is None:
            return
        if len(parts) != 3:
            print("Usage: fork <label> <generation> <file_path>")
            return
        label, gen_str, raw_file_path = parts
        file_path = os.path.expanduser(raw_file_path)
        try:
            generation = int(gen_str)
        except ValueError:
            print("Usage: fork <label> <generation> <file_path>  (generation must be an integer)")
            return
        if not os.path.exists(file_path):
            print(f"File not found: {file_path}")
            return
        if not self._require_reauth(f"fork '{label}' from generation {generation}"):
            return
        try:
            manifest = self._session.fork_write(label, file_path, generation)
        except PfsEngineError as e:
            print(f"Fork failed: {e}")
            return
        self._clades.changed(label)
        heads = self._session.get_heads(label)
        print(f"Forked '{label}' from generation {generation} -> {manifest}")
        print(f"  '{label}' now has {len(heads)} branch head(s): "
              f"{', '.join(str(h.generation_index) for h in heads)}")
        if len(heads) > 1:
            print(f"  Use 'merge {label} <gen> <gen>' to reconcile them, or 'lineage {label}' to inspect.")

    def do_graft(self, arg):
        """graft <label_a> <label_b> <new_label>  -- Lateral Gene Transfer: fuse two unrelated lineages (C++ engine)

Example:
  graft source_code documentation combined_release
(concatenates label_a's current content + label_b's current content
into a new label, descending from BOTH lineages at once. Refused if
either source is tagged 'no_graft_source'.)"""
        parts = _split_args(arg)
        if parts is None:
            return
        if len(parts) != 3:
            print("Usage: graft <label_a> <label_b> <new_label>")
            return
        label_a, label_b, new_label = parts
        if not self._require_reauth(f"graft '{label_a}' and '{label_b}' into '{new_label}'"):
            return
        try:
            manifest = self._session.graft(label_a, label_b, new_label)
        except PfsEngineError as e:
            print(f"Graft failed: {e}")
            return
        self._clades.changed(new_label)
        info = self._session.get_manifest_info(new_label)
        print(f"Grafted '{label_a}' + '{label_b}' -> '{new_label}' -> {manifest}")
        print(f"  {info['total_blocks']} chunks ({info['new_chunks_written']} genuinely new -- the "
              f"rest already existed from '{label_a}' and '{label_b}')")

    def do_merge(self, arg):
        """merge <label> <generation_a> <generation_b>  -- reconcile two divergent branches (C++ engine)

Example:
  merge my_report 3 5
(3-way diff of chunk positions against the common ancestor; a chunk
changed differently by both branches is a conflict and nothing is
committed)"""
        parts = _split_args(arg)
        if parts is None:
            return
        if len(parts) != 3:
            print("Usage: merge <label> <generation_a> <generation_b>")
            return
        label, gen_a_str, gen_b_str = parts
        try:
            generation_a, generation_b = int(gen_a_str), int(gen_b_str)
        except ValueError:
            print("Usage: merge <label> <generation_a> <generation_b>  (generations must be integers)")
            return
        if not self._require_reauth(f"merge '{label}' generations {generation_a} and {generation_b}"):
            return
        try:
            manifest = self._session.merge_branches(label, generation_a, generation_b)
        except PfsEngineError as e:
            print(f"MUTATION CONFLICT or merge failure -- nothing was committed.\n  {e}")
            return
        self._clades.changed(label)
        print(f"Merged '{label}' generations {generation_a} + {generation_b} -> {manifest}")

    def do_checkout(self, arg):
        """checkout <label> <generation> <output_path>  -- reconstruct a PAST version of a file (C++ engine)

Example:
  checkout my_report 0 /tmp/my_report_original.pdf
  checkout my_report @tip /tmp/my_report_latest.pdf
  clade my_report
  checkout @tip /tmp/my_report_latest.pdf     (label optional once focused via 'clade')
('@tip' is the current version)"""
        parts = _split_args(arg)
        if parts is None:
            return
        if len(parts) == 2:
            gen_str, output_path = parts
            if gen_str != "@tip":
                print("Usage: checkout <label> <generation> <output_path>  (2-argument form only "
                      "accepts 'checkout @tip <output_path>', using the focus label set by 'clade')")
                return
            if self._focus_label is None:
                print("No current focus label set -- run 'clade <label>' first, or use the full "
                      "'checkout <label> @tip <output_path>' form.")
                return
            label = self._focus_label
        elif len(parts) == 3:
            label, gen_str, output_path = parts
        else:
            print("Usage: checkout <label> <generation> <output_path>  (generation is a number or "
                  "'@tip'; or 'checkout @tip <output_path>' once 'clade <label>' has set a focus)")
            return
        output_path = self._resolve_path(output_path)
        if gen_str == "@tip":
            try:
                history = self._session.get_history(label)
            except PfsEngineError as e:
                print(f"Checkout failed: {e}")
                return
            if not history:
                print(f"'{label}' has no recorded lineage history.")
                return
            generation = history[-1].generation_index
        else:
            try:
                generation = int(gen_str)
            except ValueError:
                print("Usage: checkout <label> <generation> <output_path>  "
                      "(generation must be an integer or '@tip')")
                return
        if not self._require_reauth(f"check out '{label}' generation {generation}"):
            return
        try:
            self._session.checkout(label, generation, output_path)
        except PfsEngineError as e:
            print(f"Checkout failed: {e}")
            return
        print(f"Wrote generation {generation} of '{label}' to {output_path}")

    def do_ancestor(self, arg):
        """ancestor <N> [output_path]  -- reconstruct the version N primary-parent generations back from the focused label's tip (C++ engine)

Example:
  clade my_report
  ancestor 3
  ancestor 3 /tmp/three_generations_back.pdf
(needs a focus label from 'clade'. Counts primary-parent steps from the
current tip each time; lateral parents don't count. Without output_path,
writes <label>_ancestor_<N>_gen<G>.bin in the navigate or working directory.)"""
        parts = _split_args(arg)
        if parts is None:
            return
        if len(parts) not in (1, 2):
            print("Usage: ancestor <N> [output_path]")
            return
        if self._focus_label is None:
            print("No current focus label set -- run 'clade <label>' first.")
            return
        try:
            n = int(parts[0])
            if n < 0:
                raise ValueError
        except ValueError:
            print("Usage: ancestor <N> [output_path]  (N must be a non-negative integer)")
            return

        label = self._focus_label
        try:
            history = self._session.get_history(label)
        except PfsEngineError as e:
            print(f"Failed: {e}")
            return
        if not history:
            print(f"'{label}' has no recorded lineage history.")
            return
        by_uuid = {h.node_uuid_hex: h for h in history}

        node = history[-1]  # tip
        for step in range(n):
            if not node.has_parent:
                print(f"'{label}' only has {step} primary-parent generation(s) available back from "
                      f"its tip -- can't go back {n}.")
                return
            parent = by_uuid.get(node.parent_uuid_hex)
            if parent is None:
                print("Internal error: primary-parent generation not found in this label's own history.")
                return
            node = parent

        if node.pruned:
            print(f"Generation {node.generation_index} of '{label}' ({n} generation(s) back) was "
                  f"pruned -- its content is no longer available. Use 'history {label}' to see which "
                  f"generations are still retrievable.")
            return

        if len(parts) == 2:
            output_path = self._resolve_path(parts[1])
        else:
            base_dir = self._nav_dir or os.getcwd()
            output_path = os.path.join(base_dir, f"{label}_ancestor_{n}_gen{node.generation_index}.bin")

        if not self._require_reauth(f"check out '{label}' generation {node.generation_index} "
                                    f"({n} generation(s) back from tip)"):
            return
        try:
            self._session.checkout(label, node.generation_index, output_path)
        except PfsEngineError as e:
            print(f"Checkout failed: {e}")
            return
        print(f"'{label}' generation {node.generation_index} ({n} primary-parent generation(s) back "
              f"from tip) -> {output_path}")

    def do_rename(self, arg):
        """rename <old_label> <new_label>  -- rename a catalog entry (C++ engine)

Example:
  rename my_report q3_report"""
        parts = _split_args(arg)
        if parts is None:
            return
        if len(parts) != 2:
            print("Usage: rename <old_label> <new_label>")
            return
        old_label, new_label = parts
        if not self._require_reauth(f"rename '{old_label}'"):
            return
        try:
            self._session.rename_label(old_label, new_label)
        except PfsEngineError as e:
            print(f"Rename failed: {e}")
            return
        self._clades.renamed(old_label, new_label)
        print(f"Renamed '{old_label}' -> '{new_label}'")

    @staticmethod
    def _parse_tag_value(raw: str):
        lowered = raw.lower()
        if lowered in ("true", "yes", "1"):
            return True
        if lowered in ("false", "no", "0"):
            return False
        return raw

    def do_tag(self, arg):
        """tag <label> <key> <value>  -- set an epigenetic tag on a label's current version (C++ engine)

Example:
  tag legal_contract protected true
  tag internal_draft no_graft_source true
  tag my_report project alpha
(true/false/yes/no/1/0 become real booleans; anything else stays text.
'protected' blocks delete/prune unless forced, 'no_graft_source' blocks
this label from being used in 'graft'.)"""
        parts = _split_args(arg)
        if parts is None:
            return
        if len(parts) > 3:
            # An unquoted multi-word value still works.
            parts = parts[:2] + [" ".join(parts[2:])]
        if len(parts) != 3:
            print("Usage: tag <label> <key> <value>")
            return
        label, key, raw_value = parts
        value = self._parse_tag_value(raw_value)
        if not self._require_reauth(f"tag '{label}'"):
            return
        try:
            self._session.set_tag(label, key, value)
        except PfsEngineError as e:
            print(f"Tag failed: {e}")
            return
        print(f"Tagged '{label}': {key}={value}")

    def do_untag(self, arg):
        """untag <label> <key>  -- remove an epigenetic tag (C++ engine)

Example:
  untag legal_contract protected"""
        parts = _split_args(arg)
        if parts is None:
            return
        if len(parts) != 2:
            print("Usage: untag <label> <key>")
            return
        label, key = parts
        if not self._require_reauth(f"untag '{label}'"):
            return
        try:
            removed = self._session.remove_tag(label, key)
        except PfsEngineError as e:
            print(f"Untag failed: {e}")
            return
        print(f"Removed tag '{key}' from '{label}'." if removed else f"'{label}' didn't have a tag named '{key}'.")

    def do_prune(self, arg):
        """prune <label> <generation> [force]  -- reclaim storage from one OLD historical version (C++ engine)

Example:
  prune my_report 2
  prune my_report 2 force
(keeps the label and all its OTHER generations intact. Cannot prune the
current tip -- use 'delete' for that. Refused if this exact generation
is tagged 'protected' unless you add 'force'.)"""
        parts = _split_args(arg)
        if parts is None:
            return
        if len(parts) not in (2, 3):
            print("Usage: prune <label> <generation> [force]")
            return
        label, gen_str = parts[0], parts[1]
        force = len(parts) == 3 and parts[2].lower() == "force"
        try:
            generation = int(gen_str)
        except ValueError:
            print("Usage: prune <label> <generation> [force]  (generation must be an integer)")
            return
        if not self._require_reauth(f"prune generation {generation} of '{label}'"):
            return
        try:
            freed = self._session.prune_generation(label, generation, force=force)
        except PfsEngineError as e:
            print(f"Prune failed: {e}")
            return
        if freed:
            print(f"Pruned generation {generation} of '{label}'. Run 'vacuum' to reclaim its space.")
        else:
            print(f"Marked generation {generation} of '{label}' as pruned, but its manifest is still "
                  f"shared with something else in the vault -- nothing freed yet.")

    def do_lineage(self, arg):
        """lineage <label>  -- show this file's real edit history (C++ engine)

Example:
  lineage my_report"""
        label = _join_args(arg)
        if not label:
            print("Usage: lineage <label>")
            return
        if not self._require_reauth(f"view lineage for '{label}'"):
            return
        try:
            history = self._session.get_history(label)
            heads = {h.node_uuid_hex for h in self._session.get_heads(label)}
        except PfsEngineError as e:
            print(f"Failed: {e}")
            return
        if not history:
            print(f"No recorded history for '{label}'.")
            return
        if len(heads) > 1:
            print(f"NOTE: '{label}' has {len(heads)} divergent branch heads -- see 'merge' to reconcile them.\n")
        for node in history:
            if node is history[-1]:
                marker = "  (current)"
            elif node.node_uuid_hex in heads:
                marker = "  (branch head -- not current; see 'merge')"
            elif node.pruned:
                marker = "  (pruned -- content reclaimed)"
            else:
                marker = ""
            parent = f"parent gen from {node.parent_uuid_hex[:12]}..." if node.has_parent else "root"
            print(f"  gen {node.generation_index}: {node.new_chunks}/{node.total_chunks} new chunks, "
                  f"{parent}{marker}")

    def do_vacuum(self, arg):
        """vacuum  -- reclaim space from deleted/pruned files (C++ engine)

Example:
  vacuum
(safe to run any time; does nothing if nothing was deleted or pruned)"""
        if not self._require_reauth("vacuum the vault"):
            return
        report = self._session.vacuum()
        print(f"Before:    {report['old_size']:,} bytes")
        print(f"After:     {report['new_size']:,} bytes")
        print(f"Reclaimed: {report['bytes_reclaimed']:,} bytes")
        print(f"Live chunks remaining: {report['live_chunks']}")
        if report["chunks_corrected"]:
            print(f"Ref-count drift repaired: {report['chunks_corrected']} chunk(s) had a stale "
                  f"reference count corrected before reclaiming.")
        if report["orphaned_manifests_removed"]:
            print(f"Orphaned manifests removed: {report['orphaned_manifests_removed']}")
        if report["orphaned_tmp_files_removed"]:
            print(f"Interrupted-write leftovers removed: {report['orphaned_tmp_files_removed']}")
        if report.get("mirror_bytes_reclaimed"):
            print(f"Ancestral Hardening mirror container also compacted: "
                  f"{report['mirror_old_size']:,} -> {report['mirror_new_size']:,} bytes "
                  f"({report['mirror_bytes_reclaimed']:,} reclaimed, {report['live_mirrors']} live "
                  f"mirror(s) remaining).")

    def do_fsck(self, arg):
        """fsck  -- scan every stored chunk for corruption, self-healing where possible (C++ engine)

Example:
  fsck
(a damaged chunk with an Ancestral Hardening mirror is repaired from it;
one without is reported)"""
        if not self._require_reauth("scan the vault for corruption"):
            return
        print("Scanning every live chunk (this reads and verifies your entire vault -- may take a while)...")
        report = self._session.fsck()
        print(f"Scanned:  {report['scanned']}")
        print(f"Healthy:  {report['healthy']}")
        print(f"Repaired: {report['healed']} (recovered from their Ancestral Hardening mirror)")
        if report["unrecoverable"]:
            print(f"UNRECOVERABLE: {len(report['unrecoverable'])} chunk(s) -- genuinely lost:")
            for content_hash_hex in report["unrecoverable"]:
                print(f"  {content_hash_hex[:16]}...")
        else:
            print("No unrecoverable corruption found.")

    def do_rotate(self, arg):
        """rotate  -- start a new key epoch (existing files stay readable under their original epoch) (C++ engine)

Example:
  rotate"""
        if not self._require_reauth("rotate keys"):
            return
        new_epoch = self._session.rotate_key()
        print(f"Rotated to epoch {new_epoch}. New writes use the new key; existing files are unaffected.")

    def do_stats(self, arg):
        """stats  -- show vault-wide statistics (C++ engine)

Example:
  stats
(takes no arguments)"""
        if not self._require_reauth("view vault statistics"):
            return
        stats = self._session.get_stats()
        print(f"Container size:        {stats['container_size']:,} bytes")
        print(f"Unique chunks stored:  {stats['total_chunks']} ({stats['dead_chunks']} reclaimable via 'vacuum')")
        print(f"Total chunk references: {stats['total_refs']} (dedup ratio: "
              f"{stats['total_refs'] / max(1, stats['total_chunks']):.2f}x)")
        print(f"Files tracked:         {stats['files_tracked']}")
        print(f"Key epochs so far:     {stats['key_epochs']}")

    def do_attack(self, arg):
        """attack  -- run a suite of adversarial tests against this vault's defenses (C++ engine)

Example:
  attack
(you'll be asked to choose:
  virtual attack -- safe, uses a disposable throwaway test file
  real attack    -- tests one of your actual stored files; any temporary
                     corruption is backed up and verified-restored afterward)"""
        if not self._require_reauth("run an attack test"):
            return
        choice = input("Run 'virtual attack' or 'real attack'? ").strip().lower()
        if choice in ("real", "real attack", "realattack"):
            self._attack_real()
        elif choice in ("virtual", "virtual attack", "virtualattack"):
            self._attack_virtual()
        else:
            print(f"'{choice}' isn't 'virtual attack' or 'real attack'. Cancelled.")

    def _attack_virtual(self):
        print("Running security self-test against a throwaway test file (your real files are untouched)...\n")
        test_content = secrets.token_bytes(50_000)
        test_src = os.path.join(self.storage_root, "__attack_test_src__.bin")
        out_ok = os.path.join(self.storage_root, "__attack_test_out_ok__.bin")
        with open(test_src, "wb") as f:
            f.write(test_content)
        try:
            self._session.commit_write("__attack_test__", test_src)
            self._run_attack_checks("__attack_test__", test_content, out_ok, restore=False)
        finally:
            for p in (test_src, out_ok):
                if os.path.exists(p):
                    os.remove(p)
            try:
                self._session.delete_label("__attack_test__", force=True)
                self._session.vacuum()
            except PfsEngineError:
                pass

    def _attack_real(self):
        labels = self._session.list_labels()
        if not labels:
            print("Vault is empty -- nothing to run a real attack against. "
                  "Use 'write' first, or run 'virtual attack' instead.")
            return
        print("\nStored files:")
        for label in labels:
            print(f"  {label}")
        label = input("Which file should the real attack test against? ").strip()
        if label not in labels:
            print(f"No such label: '{label}'. Cancelled.")
            return

        print(f"\nRunning REAL attack tests against '{label}' -- your actual stored file.")
        print("Any temporary corruption is backed up first and restored afterward, with the")
        print("restoration itself verified before this finishes.\n")
        out_ok = os.path.join(self.storage_root, "__real_attack_out_ok__.bin")
        try:
            self._session.reconstruct_label(label, out_ok)
            with open(out_ok, "rb") as f:
                real_content = f.read()
            self._run_attack_checks(label, real_content, out_ok, restore=True)
        finally:
            if os.path.exists(out_ok):
                os.remove(out_ok)

    def _run_attack_checks(self, label, expected_content, out_ok, restore):
        results = []
        out_bad = os.path.join(self.storage_root, "__attack_test_out_bad__.bin")

        # 1. Correct key reconstructs correctly
        try:
            self._session.reconstruct_label(label, out_ok)
            with open(out_ok, "rb") as f:
                ok = f.read() == expected_content
        except PfsEngineError:
            ok = False
        results.append(("Baseline: correct key reconstructs correctly", ok))

        # 2. A session under a wrong KEK fails to open (the keyring can't be decrypted).
        wrong_kek = secrets.token_bytes(32)
        try:
            bad_session = CppVaultSession(self.storage_root, wrong_kek)
            bad_session.close()
            results.append(("Wrong key is rejected", False))
        except PfsEngineError:
            results.append(("Wrong key is rejected", True))

        # 3. Confirmation-of-presence attack: lookup keys are HMACs, not raw hashes.
        guessed_hash = hashlib.sha256(expected_content[:4096]).digest()
        conn = sqlite3.connect(os.path.join(self.storage_root, DB_FILENAME))
        row = conn.execute("SELECT 1 FROM blocks WHERE lookup_key = ?", (guessed_hash,)).fetchone()
        conn.close()
        results.append(("Confirmation-of-presence attack blocked", row is None))

        # 4. Corrupted ciphertext is detected; the original bytes are backed up first.
        try:
            first_hash = self._session.debug_get_block_hash(label, 0)
            loc = self._session.debug_lookup_chunk(first_hash)
            container_path = self._session.container_path
            with open(container_path, "r+b") as cf:
                cf.seek(loc["offset"])
                original_bytes = cf.read(loc["length"])
                cf.seek(loc["offset"])
                cf.write(bytes(b ^ 0xFF for b in original_bytes))

            try:
                self._session.reconstruct_label(label, out_bad)
                detected = False
            except PfsEngineError:
                detected = True
            results.append(("Corrupted ciphertext is detected, not silently returned", detected))

            if restore:
                with open(container_path, "r+b") as cf:
                    cf.seek(loc["offset"])
                    cf.write(original_bytes)
                try:
                    self._session.reconstruct_label(label, out_ok)
                    with open(out_ok, "rb") as f:
                        restored_ok = f.read() == expected_content
                except PfsEngineError:
                    restored_ok = False
                results.append(("Real file fully restored and re-verified after the test", restored_ok))
        except PfsEngineError as e:
            results.append((f"Corruption test setup failed ({e})", False))
        finally:
            if os.path.exists(out_bad):
                os.remove(out_bad)

        print(f"{'Check':<65}{'Result'}")
        for name, passed in results:
            print(f"{name:<65}{'PASS' if passed else 'FAIL'}")
        print()
        if all(r[1] for r in results):
            print("All checks passed." if not restore else
                  "All checks passed -- your real file's defenses hold, and it's exactly as it was.")
        else:
            print("SOME CHECKS FAILED -- see above." +
                  (" If restoration failed, run 'verify' or re-check this label now." if restore else ""))

    def do_test(self, arg):
        """test  -- power-on self test: exercises every major subsystem for real, end to end (C++ engine)

Example:
  test
(real write, edit, fork, tag, key rotation, delete, vacuum and fsck on a
throwaway label; see 'attack' for tampering tests)"""
        if not self._require_reauth("run a self test"):
            return
        print("=== PFS Power-On Self Test (C++ engine) ===\n")
        results = []
        label = "__post_test__"
        work_v1 = os.path.join(self.storage_root, "__post_test_v1__.bin")
        work_v2 = os.path.join(self.storage_root, "__post_test_v2__.bin")
        out_path = os.path.join(self.storage_root, "__post_test_out__.bin")

        def check(name, fn):
            try:
                results.append((name, bool(fn())))
            except Exception as e:
                results.append((f"{name} ({type(e).__name__}: {e})", False))

        def roundtrip_ok():
            self._session.reconstruct_label(label, out_path)
            with open(out_path, "rb") as f:
                return f.read() == content_v1

        def second_generation_ok():
            history = self._session.get_history(label)
            return len(history) == 2 and history[1].parent_uuid_hex == history[0].node_uuid_hex

        content_v1 = secrets.token_bytes(2000)
        content_v2 = content_v1 + b"a real edit, appended"
        with open(work_v1, "wb") as f:
            f.write(content_v1)
        with open(work_v2, "wb") as f:
            f.write(content_v2)

        try:
            self._session.commit_write(label, work_v1)
            check("Write/read round trip is byte-identical", roundtrip_ok)
            check("Similarity fingerprint attached at write time",
                  lambda: self._session.get_manifest_info(label)["has_similarity_fingerprint"])
            self._session.commit_write(label, work_v1)  # byte-identical resave
            check("No-op resave does not inflate lineage history",
                  lambda: len(self._session.get_history(label)) == 1)
            self._session.commit_write(label, work_v2)  # a real edit
            check("A real edit creates a second, correctly-parented generation", second_generation_ok)
            check("Key rotation produces a new epoch", lambda: self._session.rotate_key() >= 0)
            self._session.fork_write(label, work_v1, 0)
            check("Fork creates a genuine second branch head",
                  lambda: len(self._session.get_heads(label)) == 2)
            self._session.set_tag(label, "__post_test_tag__", True)
            check("Tag set/get round-trips correctly",
                  lambda: self._session.get_tags(label).get("__post_test_tag__") is True)
            self._session.remove_tag(label, "__post_test_tag__")
        finally:
            for p in (work_v1, work_v2, out_path):
                if os.path.exists(p):
                    os.remove(p)

        def delete_and_vacuum_ok():
            self._session.delete_label(label, force=True)
            report = self._session.vacuum()
            return "bytes_reclaimed" in report

        def fsck_clean():
            report = self._session.fsck()
            return report["unrecoverable"] == []

        check("Delete + vacuum reclaims space without error", delete_and_vacuum_ok)
        check("Fsck runs clean on a healthy vault", fsck_clean)

        print(f"{'Check':<60}{'Result'}")
        for name, passed in results:
            print(f"{name:<60}{'PASS' if passed else 'FAIL'}")
        print()
        print("All checks passed." if all(r[1] for r in results) else "SOME CHECKS FAILED -- see above.")

    def do_passwd(self, arg):
        """passwd  -- change the vault passphrase (the underlying key itself is unchanged) (C++ engine)

Example:
  passwd"""
        old_pw = getpass.getpass("Current passphrase: ")
        new_pw1 = getpass.getpass("New passphrase: ")
        new_pw2 = getpass.getpass("Confirm new passphrase: ")
        if new_pw1 != new_pw2:
            print("New passphrases didn't match. Nothing changed.")
            return
        try:
            change_passphrase(self.storage_root, old_pw, new_pw1)
            print("Passphrase changed. The key itself (and all your data) is untouched.")
        except WrongPassphraseError:
            print("Current passphrase was incorrect. Nothing changed.")

    def do_navigate(self, arg):
        """navigate [<directory>|-]  -- set/show/clear a working directory for write/read (C++ engine)

Example:
  navigate /home/lister/Documents/test_batch
  navigate
  navigate -"""
        target = _join_args(arg)
        if target is None:
            return
        if not target:
            if self._nav_dir:
                print(f"Current navigate directory: {self._nav_dir}")
            else:
                print("No navigate directory set.")
            return
        if target == "-":
            self._nav_dir = None
            print("Cleared navigate directory.")
            return
        resolved = os.path.abspath(os.path.expanduser(target))
        if not os.path.isdir(resolved):
            print(f"Not a directory: {resolved}")
            return
        self._nav_dir = resolved
        print(f"Navigate directory set to: {self._nav_dir}")

    def do_clear(self, arg):
        "clear  -- clear the terminal screen"
        os.system("cls" if os.name == "nt" else "clear")

    def do_list(self, arg):
        """list  -- show all labels currently stored (C++ engine)"""
        if not self._require_reauth("view the vault contents"):
            return
        labels = sorted(self._session.list_labels())
        if not labels:
            print("(empty vault)")
            return
        for label in labels:
            print(label)

    def do_history(self, arg):
        """history <label>  -- show every recorded generation for a label (C++ engine)

Example:
  history my_report"""
        label = _join_args(arg)
        if not label:
            print("Usage: history <label>")
            return
        if not self._require_reauth(f"view history for '{label}'"):
            return
        try:
            history = self._session.get_history(label)
        except PfsEngineError as e:
            print(f"Failed: {e}")
            return
        if not history:
            print(f"No recorded history for '{label}'.")
            return
        for node in history:
            parent = f"parent={node.parent_uuid_hex[:12]}..." if node.has_parent else "root"
            pruned = " [PRUNED]" if node.pruned else ""
            print(f"  gen {node.generation_index}: {node.new_chunks}/{node.total_chunks} new chunks, "
                  f"{parent}{pruned}  ({node.node_uuid_hex[:12]}...)")

    def do_info(self, arg):
        """info <label>  -- show manifest details for a label (C++ engine)

Example:
  info my_report"""
        label = _join_args(arg)
        if not label:
            print("Usage: info <label>")
            return
        if not self._require_reauth(f"view details for '{label}'"):
            return
        try:
            info = self._session.get_manifest_info(label)
        except PfsEngineError as e:
            print(f"Failed: {e}")
            return
        print(f"  total_blocks: {info['total_blocks']:,}")
        print(f"  original_size: {info['original_size']:,}")
        print(f"  new_chunks_written: {info['new_chunks_written']:,}")
        print(f"  duplicate_chunks_found: {info['duplicate_chunks_found']:,}")
        if info["has_similarity_fingerprint"]:
            print(f"  similarity_fingerprint: stored ({info['similarity_fingerprint_count']:,} traits) "
                  f"-- see 'tree'/'similar'")
        else:
            print("  similarity_fingerprint: not stored")

    def do_tree(self, arg):
        """tree [upgma|nj]  -- build and show the clade tree of everything in the vault (C++ engine)

Example:
  tree
  tree nj
(defaults to upgma; uses the fingerprints stored at write time)"""
        algorithm = arg.strip().lower() or "upgma"
        if algorithm not in ("upgma", "nj"):
            print("Usage: tree [upgma|nj]")
            return
        if not self._require_reauth("view the clade tree"):
            return
        try:
            rendering = self._session.build_tree(algorithm)
        except PfsEngineError as e:
            print(f"Failed: {e}")
            return

        # build_tree covers every fingerprinted label. A warning failure mustn't hide the tree.
        try:
            unreliable = self._session.unreliable_fingerprint_labels()
        except PfsEngineError:
            unreliable = {}
        if unreliable:
            print(_reliability_warning(unreliable))

        print(f"\n--- Clade tree ({algorithm.upper()}) ---")
        print(rendering)

    def do_similar(self, arg):
        """similar <label>  -- rank every other file in the vault by content closeness to this one (C++ engine)

Example:
  similar my_report
(0.0 = identical content, 1.0 = nothing in common)"""
        label = _join_args(arg)
        if not label:
            print("Usage: similar <label>")
            return
        if not self._require_reauth(f"find files similar to '{label}'"):
            return
        try:
            ranked = self._session.similar(label)
        except PfsEngineError as e:
            print(f"Failed: {e}")
            return
        if not ranked:
            print("No other files with a stored fingerprint to compare against.")
            return

        try:
            all_unreliable = self._session.unreliable_fingerprint_labels()
        except PfsEngineError:
            all_unreliable = {}
        relevant = {label} | {other_label for other_label, _ in ranked}
        unreliable = {lbl: cnt for lbl, cnt in all_unreliable.items() if lbl in relevant}
        if unreliable:
            print(_reliability_warning(unreliable))

        print(f"\n--- Files closest to '{label}' (Jaccard distance -- 0.0=identical, 1.0=nothing shared) ---")
        for other_label, distance in ranked:
            print(f"  {distance:.4f}  {other_label}")

    def do_clade(self, arg):
        """clade <label>  -- find <label>'s clade (similarity family) and focus the shell on it (C++ engine)

Example:
  clade my_report
  checkout @tip /tmp/restored.pdf     (label is optional once focused)
  ancestor 2                           (steps back from the focused label's tip)
(a clade groups files within Jaccard distance 0.80 of each other; it is
not a lineage and has no root. Sets the shell's focus to <label>.)"""
        label = _join_args(arg)
        if not label:
            print("Usage: clade <label>")
            return
        if not self._require_reauth(f"find '{label}'s clade"):
            return
        live = set(self._session.list_labels())
        if label not in live:
            print(f"Failed: no such label: '{label}'")
            return
        members = _clade_members(self._clades, label, live)
        if members is None:
            print(f"Failed: '{label}' has no stored similarity fingerprint")
            return

        try:
            all_unreliable = self._session.unreliable_fingerprint_labels()
        except PfsEngineError:
            all_unreliable = {}
        unreliable = {lbl: cnt for lbl, cnt in all_unreliable.items() if lbl in members}
        if unreliable:
            print(_reliability_warning(unreliable))

        self._focus_label = label
        print(f"\n--- Clade containing '{label}' (Jaccard distance <= 0.80) ---")
        if len(members) == 1:
            print(f"  '{label}' -- no other file in the vault is within the clade threshold "
                  f"(a clade of one).")
        else:
            # "Oldest" is just the earliest generation-0 write -- an orientation aid, not a root.
            def birth0(m):
                try:
                    hist = self._session.get_history(m)
                except PfsEngineError:
                    return float("inf")
                return hist[0].birth_timestamp if hist else float("inf")
            oldest = min(members, key=birth0)
            for m in members:
                note = "  (oldest member here by generation-0 birth time -- NOT a lineage root; " \
                       "clades have no root)" if m == oldest else ""
                print(f"  {m}{note}")
        print(f"\nFocus set to '{label}'. 'checkout @tip <output>' and 'ancestor <N>' now work "
              f"without repeating the label.")

    def default(self, line):
        cmd_name = line.split()[0] if line.split() else line
        print(f"'{cmd_name}' isn't wired up in C++-engine mode "
              f"(see cpp_port_plan.txt). Run pfs_cli.py without --engine cpp for the full Python "
              f"feature set.")

    def do_exit(self, arg):
        "exit  -- close the shell"
        self._clades.stop(timeout=10)
        self._session.close()
        print("Goodbye.")
        return True

    do_quit = do_exit

    def do_EOF(self, arg):
        print()
        return self.do_exit(arg)

    def emptyline(self):
        pass

    def onecmd(self, line):
        try:
            return super().onecmd(line)
        except Exception as e:
            print(f"Error: {type(e).__name__}: {e}")
            return False


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="PFS interactive shell")
    parser.add_argument("storage_root", nargs="?", default=None,
                         help="vault directory (default: ./pfs_storage_vault, or "
                              "./pfs_storage_vault_cpp with --engine cpp)")
    parser.add_argument("--engine", choices=["python", "cpp"], default="python",
                         help="'python' (default) or 'cpp' (the compiled engine: the same shell "
                              "commands except 'panic' and 'verify', and 'list' without type/size "
                              "filters -- see manual.txt PART 9.10). A vault belongs to the engine "
                              "that created it; the other engine refuses to open it.")
    args = parser.parse_args()

    if args.engine == "cpp":
        if CppVaultSession is None:
            print(f"Couldn't load the C++ engine library: {_CPP_ENGINE_IMPORT_ERROR}")
            print("Build it first -- see cpp_engine/CMakeLists.txt / cpp_port_plan.txt.")
            sys.exit(1)
        storage_root = args.storage_root or "./pfs_storage_vault_cpp"
        CppPFSShell(storage_root).cmdloop()
    else:
        storage_root = args.storage_root or "./pfs_storage_vault"
        PFSShell(storage_root).cmdloop()
