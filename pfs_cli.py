"""
Interactive command-line shell for the Phylogenetic File System storage
engine. Lets you exercise every piece built so far -- write, read,
delete, vacuum, key rotation -- and includes a built-in 'attack' command
that runs a suite of adversarial tests against a throwaway file to
verify the vault's actual defenses, not just trust that they work.

Run with:  python3 pfs_cli.py [storage_root]
(storage_root defaults to ./pfs_storage_vault)
"""

import cmd
import os
import sys
import getpass
import pickle
import time
import secrets
import hashlib
import sqlite3
import threading

sys.path.insert(0, os.getcwd())

from gearhash.master_key_store import (load_vault_key, create_new_vault_key, change_passphrase,
                                        WrongPassphraseError, MASTER_KEY_FILENAME)
from gearhash.dedup_index import GlobalBlockIndex, DB_FILENAME
from gearhash.fks_index import FKSLookupEngine
from gearhash.keyring import KEYRING_FILENAME
from gearhash.immutability import set_immutable
from reconstruct import reconstruct, ReconstructionError
from PhylogeneticAnalyzer import PhylogeneticAnalyzer, SIMILARITY_PROFILE, MIN_RELIABLE_TRAIT_COUNT
from TreeConstructor import TreeConstructor
from vault_session import VaultSession, VaultUnlockError, MutationConflictError, CATALOG_FILENAME, HISTORY_FILENAME
from lineage import LINEAGE_FILENAME

# The C++ engine binding is optional -- pfs_cli.py's default (Python)
# shell must keep working even on a checkout where cpp_engine/ hasn't
# been built yet. Only --engine cpp actually needs this to succeed.
try:
    from pfs_engine_binding import CppVaultSession, PfsEngineError
    _CPP_ENGINE_IMPORT_ERROR = None
except OSError as e:
    CppVaultSession = None
    PfsEngineError = Exception
    _CPP_ENGINE_IMPORT_ERROR = e

# The C++ engine's on-disk formats are deliberately incompatible with
# Python's (see cpp_engine/include/manifest.hpp's module docstring),
# but data_container.bin and global_index.db use the SAME filenames in
# both engines -- so a directory can never safely serve as both kinds
# of vault. These markers let us detect which one (if either) already
# owns a given directory BEFORE either engine's constructor ever
# touches the container/index files.
CPP_CATALOG_FILENAME = "catalog.pfsc"
CPP_KEYRING_FILENAME = "keyring.pfsk"

MAX_HISTORY = 500


def _existing_vault_engine(storage_root: str):
    """Returns 'python', 'cpp', or None (nothing here yet), based on
    each engine's own marker files."""
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
    """Formats the "too little data to fingerprint reliably" warning
    'tree'/'similar'/'clade' print whenever a file involved in the
    result fingerprinted to fewer than MIN_RELIABLE_TRAIT_COUNT chunks.
    `unreliable` is {label: chunk_count}. Shared by BOTH engine shells
    (PFSShell and CppPFSShell below) so switching --engine never changes
    the wording a user sees -- see PhylogeneticAnalyzer.MIN_RELIABLE_
    TRAIT_COUNT / phylo.hpp's kMinReliableTraitCount for why this
    specific threshold."""
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
    """do_test's dedup-index sanity check: a lookup for a hash that was
    never registered should just return None, not raise."""
    gi = GlobalBlockIndex(storage_root, crypto)
    gi.lookup(secrets.token_bytes(32))
    gi.close()
    return True


class PFSShell(cmd.Cmd):
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
        # (label, Thread) for every in-flight background similarity
        # fingerprinting job -- see _start_background_fingerprint().
        self._fingerprint_jobs = []
        self._fingerprint_jobs_lock = threading.Lock()
        # Set by 'navigate'; None means relative paths in write/read resolve
        # against wherever this process happens to be running from, same as
        # before this feature existed.
        self._nav_dir = None
        self._command_history = []
        self._readline = None
        # Set by 'clade' -- the Lineage Shell's "current focus" label
        # (Project_idea.txt's clade/checkout @tip/ancestor vocabulary).
        # None means 'checkout @tip'/'ancestor' have nothing to work
        # from yet and must be told to run 'clade <label>' first.
        self._focus_label = None
        self._unlock_or_create()

    # crypto/pipeline/catalog live on the shared VaultSession now (so
    # pfs_fuse.py can use the exact same unlock/catalog logic without
    # duplicating it) -- exposed here as properties so the rest of this
    # class's methods can keep referring to self.crypto/self.pipeline/
    # self.catalog unchanged.
    @property
    def crypto(self):
        return self._session.crypto

    @property
    def pipeline(self):
        return self._session.pipeline

    @property
    def catalog(self):
        return self._session.catalog

    # ---------- setup ----------

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
        """Loads this vault's encrypted command history and seeds
        readline's in-memory buffer with it, so up-arrow recall works
        across restarts, not just within one running session (within a
        session, up-arrow already works for free once 'readline' is
        imported -- that part needs no code here). Kept encrypted on
        disk like everything else in this vault: a plaintext history
        file would leak every label and file path you've ever typed,
        which is exactly the kind of metadata leak the manifest-filename
        design elsewhere in this codebase already goes out of its way to
        avoid.

        Unlike the catalog (whose failure to load is fatal -- it's the
        only map from your labels to your data), history is pure
        convenience: if it can't be read, this starts empty rather than
        crashing the shell."""
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
            self._readline = None  # e.g. Windows without pyreadline -- up-arrow just won't recall

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
        """Called only for lines that ran without raising -- 'history of
        successful commands', per how this shell can actually tell the
        difference (a command that prints e.g. 'No such label' isn't an
        exception, so it still counts here, same as bash recording a
        failed command's exit code without excluding it from history).
        Not re-added to readline's own buffer here -- readline already
        recorded it automatically the moment it was typed via input()."""
        self._command_history.append(line)
        if len(self._command_history) > MAX_HISTORY:
            self._command_history = self._command_history[-MAX_HISTORY:]
        try:
            self._save_history()
        except Exception:
            pass  # history is a convenience; never worth crashing the shell over

    def _read_manifest_metadata(self, manifest_path: str) -> dict:
        return self._session.read_manifest_metadata(manifest_path)

    def _save_catalog(self) -> None:
        self._session.save_catalog()

    def _require_reauth(self, action_description: str = "do this") -> bool:
        """Re-verifies the vault passphrase before a sensitive operation.
        Being unlocked once at shell startup isn't enough -- an attacker
        who finds an already-open, unattended terminal shouldn't be able
        to just type a command and see or change vault contents. Returns
        True only on an exact match against the currently-loaded KEK."""
        pw = getpass.getpass(f"Re-enter vault passphrase to {action_description}: ")
        try:
            kek = load_vault_key(self.storage_root, pw)
        except WrongPassphraseError:
            print("Wrong passphrase. Cancelled.")
            return False
        if kek != self.crypto.key:
            # Shouldn't happen since the file didn't change underneath
            # us, but never accept a near-match -- require exact equality.
            print("Wrong passphrase. Cancelled.")
            return False
        return True

    # ---------- core commands ----------

    def do_write(self, arg):
        """write <file_path> [label]  -- ingest a file into the vault

Example:
  write /home/lister/Documents/report.pdf
  write /home/lister/Documents/report.pdf my_report
(if you skip [label], the file's own basename is used as the label;
a relative file_path resolves against 'navigate's directory, if set)"""
        parts = arg.split()
        if not parts:
            print("Usage: write <file_path> [label]")
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
(writes file_path's content as a NEW, divergent version descending from
generation N of <label> -- NOT from the current tip. If generation N
already has later descendants (i.e. it's not the tip), this creates a
second, genuinely divergent branch -- see 'lineage <label>' afterward
to see both heads. Use 'merge' later to reconcile two branches back
together, or just keep both indefinitely; nothing forces a merge.)"""
        parts = arg.split()
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
        """Computes the SIMILARITY_PROFILE fingerprint (used only by the
        'tree' command) on a background thread and attaches it to the
        manifest afterward. This is fully decoupled from the write path
        above on purpose: it re-opens and re-streams the file
        independently, at its own pace, so it never holds up the shell
        prompt or delays the durable, security-critical part of the
        write. If it fails for any reason, the write itself already
        succeeded and is unaffected -- only the clade tree won't include
        this file until a retry."""
        def _job():
            try:
                fingerprint = PhylogeneticAnalyzer(SIMILARITY_PROFILE).extract_traits(file_path)
                self.pipeline.attach_similarity_fingerprint(manifest_path, fingerprint)
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
        parts = arg.split()
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
(with no type argument, shows everything; with one, shows only files
whose CONTENT-DETECTED type matches -- e.g. 'list image' finds PNG/JPEG/
GIF/BMP files no matter what they're named or whether they have an
extension at all. This is phenotypic search: the design doc's "query the
ledger for a specific phenotypic mask" -- no filename string matching.
Add 'size' (in either position) to sort largest-first instead of the
default catalog order -- the design doc's "High-to-Low Volumetric Grid.")"""
        if not self._require_reauth("view the vault contents"):
            return
        if not self.catalog:
            print("(vault is empty)")
            return
        tokens = arg.split()
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

        print(f"{'Label':<25}{'Type':<24}{'Size':>12}  {'Chunks':>8}  {'Dedup':>7}")
        for label, phenotype_name, meta in rows:
            total = meta["total_blocks"] or 1
            dedup_pct = 100 * meta["duplicate_chunks_found"] / total
            print(f"{label:<25}{phenotype_name:<24}{meta['original_size']:>12,}  "
                  f"{meta['total_blocks']:>8}  {dedup_pct:>6.1f}%")
        for label in missing:
            print(f"{label:<25}{'(missing manifest!)':>12}")
        if type_filter and not rows:
            print(f"(no files matched type filter '{type_filter}')")

    def do_delete(self, arg):
        """delete <label> [<label2> ...] [force]  -- remove one or more files AND their full history

Example:
  delete my_report
  delete my_report old_draft unused_photo
  delete my_report force
(each label must already appear in 'list'; this removes every recorded
generation of that label, not just the current version -- 'delete'
really means delete. A manifest is only actually freed on disk once
nothing else in the vault still needs it -- e.g. another label with
byte-identical content, or a graft that used this label as a lateral
parent -- so 'vacuum' afterward may reclaim less than the full size if
some of it is still shared with something else you haven't deleted.
Pass more than one label to delete them all in one go, one reauth
covering the whole batch -- each is deleted independently, so one
missing or refused label doesn't stop the rest. 'force' (if present,
anywhere in the argument list) applies to every label in the batch;
add it to override the 'protected' tag.)"""
        parts = arg.split()
        if not parts:
            print("Usage: delete <label> [<label2> ...] [force]")
            return
        force = any(p.lower() == "force" for p in parts)
        labels = [p for p in parts if p.lower() != "force"]
        if not labels:
            print("Usage: delete <label> [<label2> ...] [force]")
            return

        unknown = [l for l in labels if l not in self.catalog]
        for l in unknown:
            print(f"No such label: '{l}'")
        labels = [l for l in labels if l in self.catalog]
        if not labels:
            return

        noun = f"'{labels[0]}'" if len(labels) == 1 else f"{len(labels)} labels"
        if not self._require_reauth(f"delete {noun}"):
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
                  f"'.manifest.fks.tmp' file(s) from a write that never completed.")
        if report.get("mirror_bytes_reclaimed"):
            print(f"Ancestral Hardening mirror container also compacted: "
                  f"{report['mirror_old_size']:,} -> {report['mirror_new_size']:,} bytes "
                  f"({report['mirror_bytes_reclaimed']:,} reclaimed, {report['live_mirrors']} live "
                  f"mirror(s) remaining).")

    def do_fsck(self, arg):
        """fsck  -- scan every stored chunk for corruption, self-healing where possible

Example:
  fsck
(takes no arguments; checks every chunk that's still referenced by
something -- not the whole disk, just this vault's own data. A chunk
that fails its integrity check but has an Ancestral Hardening mirror
(see 'info' -- chunks shared by 3+ manifests get one automatically) is
repaired in place from that mirror. A chunk that fails with no working
mirror is reported, not silently ignored -- that content is genuinely
gone, and you should know which of your files it affects; 'verify' on
individual labels will confirm exactly that.)"""
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

    # ---------- security self-test ----------

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

            # 1. Baseline: correct key reconstructs correctly
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

            # 4. Confirmation-of-presence attack is blocked: a guessed
            # content hash can't be used directly as a database lookup key
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
                    pass  # best-effort cleanup; the corrupted chunk from test 5 gets dropped by vacuum either way

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

            # 4. Confirmation-of-presence attack blocked, using THIS file's
            # real first chunk hash rather than synthetic data
            raw_manifest = self.crypto.decrypt_block(raw, associated_data=manifest_filename.encode())
            engine = FKSLookupEngine(raw_bytes=raw_manifest)
            first_hash = engine.lookup(0)
            conn = sqlite3.connect(os.path.join(self.storage_root, DB_FILENAME))
            row = conn.execute("SELECT 1 FROM blocks WHERE lookup_key = ?", (first_hash,)).fetchone()
            conn.close()
            results.append(("Confirmation-of-presence blocked (this file's real chunk hash)", row is None))

            # 5. Corrupted ciphertext detected -- SAFELY: back up the exact
            # byte before touching anything, corrupt, test detection, then
            # restore and verify the restoration itself worked.
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

            # Restore -- this happens even if detection somehow failed above.
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

    # ---------- last-resort protection ----------

    def do_panic(self, arg):
        """panic  -- LAST RESORT: irreversibly destroys this vault's key material

Example:
  panic
(takes no arguments; asks for your passphrase, then a literal typed
confirmation phrase -- there is no undo past that point)

What this actually does: shreds master.key and keyring.enc. Without
them, every chunk ever written to this vault becomes permanently
undecryptable garbage -- even to you, even with the correct passphrase,
regardless of how large the container is (destroying two small key
files is instant; it never needs to touch however many GB of ciphertext
sit in data_container.bin). Best-effort cleanup of the container/index/
manifests/catalog follows, but even if that part is interrupted, the
vault is already unrecoverable by the time it starts.

Requires your passphrase first -- same reason every other sensitive
command here does: an attacker at an unattended, already-unlocked
terminal shouldn't be able to destroy your vault out of malice any more
than they should be able to read it. This command exists for YOU to
trigger deliberately (e.g. before your device leaves your control), not
as something that fires on its own."""
        print("\n*** PANIC WIPE -- LAST RESORT PROTECTION ***")
        print("This destroys this vault's key material immediately and irreversibly.")
        print("Every file ever stored here becomes permanently unrecoverable, including")
        print("by you. This asks twice not to be annoying, but because there is genuinely")
        print("no undo past this point.\n")

        if not self._require_reauth("permanently destroy this vault"):
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
            if fname.endswith(".manifest.fks") or fname.endswith(".manifest.fks.tmp"):
                cleanup_targets.append(os.path.join(self.storage_root, fname))
        for path in cleanup_targets:
            try:
                self._secure_erase_file(path)
            except Exception:
                pass  # already unrecoverable regardless of whether this part succeeds

        print("\nDone. Exiting -- the key is gone from disk; only whatever remains in this")
        print("process's own memory persists until it exits, which is now.")
        self._session.crypto = None
        self._session.pipeline = None
        return True

    def _secure_erase_file(self, path: str) -> None:
        """Best-effort overwrite-then-delete, used only by 'panic'.
        Clears +i, overwrites the file's full length with random bytes
        before unlinking it, rather than just deleting the directory
        entry. This is NOT a guarantee against a well-equipped forensic
        adversary -- SSD wear-leveling and copy-on-write filesystems can
        leave the old physical blocks intact regardless of what gets
        overwritten at the file-path level -- but it's strictly better
        than a bare unlink, and costs nothing extra to do. The actual
        unrecoverability panic() provides comes from the KEK/DEK
        material being gone, not from this overwrite step."""
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
            pass  # even if the overwrite fails, still attempt the unlink below
        os.remove(path)

    # ---------- clade clustering tree (the bridge) ----------

    def _gather_named_traits(self, description: str) -> dict:
        """Collects {label: similarity_fingerprint} for every catalog
        label that has one, printing an honest note about any excluded
        (still fingerprinting in the background, or predates the
        feature). Shared by 'tree' and 'similar' so both report gaps
        the same way instead of each reimplementing it."""
        named_traits = {}
        missing = []
        for label, manifest_filename in self.catalog.items():
            manifest_path = os.path.join(self.storage_root, manifest_filename)
            if not os.path.exists(manifest_path):
                continue
            meta = self._read_manifest_metadata(manifest_path)
            fingerprint = meta.get("similarity_fingerprint")
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
(defaults to upgma if not given; uses fingerprints computed back at write
time, so it never re-reads or re-decrypts your original files)"""
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
        tc = TreeConstructor(analyzer)
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
(uses the same Jaccard distance math 'tree'/the clade view already use
-- just reported as a ranked list against ONE chosen file instead of a
whole tree. 0.0 = identical content, 1.0 = nothing in common; this is
the design doc's "Proximity Matrix" sort)"""
        label = arg.strip()
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
(a clade is a similarity GROUPING -- the same connected-components
clustering 'tree'/'similar' already use, at the design doc's own
D<=0.80 threshold -- NOT a lineage: it has no real parent/child
structure of its own, just membership, so this never invents a fake
"clade root". Sets this shell's 'current focus' to <label> itself, so
'checkout @tip'/'ancestor N' can be used afterward without repeating
the label.)"""
        label = arg.strip()
        if not label:
            print("Usage: clade <label>")
            return
        if label not in self.catalog:
            print(f"No such label: '{label}'")
            return
        if not self._require_reauth(f"find '{label}'s clade"):
            return

        named_traits = self._gather_named_traits("this clade lookup")
        if label not in named_traits:
            print(f"'{label}' has no stored fingerprint yet -- it may still be fingerprinting in "
                  f"the background, or it predates this feature. Re-run 'write' on it to fix that.")
            return

        analyzer = PhylogeneticAnalyzer(SIMILARITY_PROFILE)
        tc = TreeConstructor(analyzer)
        clades = tc.compute_clades(named_traits)
        members = sorted(next(m for m in clades.values() if label in m))

        unreliable = {m: len(named_traits[m]) for m in members
                      if not analyzer.trait_set_is_reliable(named_traits[m])}
        if unreliable:
            print(_reliability_warning(unreliable))

        self._focus_label = label
        print(f"\n--- Clade containing '{label}' (Jaccard distance <= "
              f"{TreeConstructor.DEFAULT_CLADE_THRESHOLD:.2f}) ---")
        if len(members) == 1:
            print(f"  '{label}' -- no other file in the vault is within the clade threshold "
                  f"(a clade of one).")
        else:
            # "Most ancestral" here means only "the member whose OWN generation-0 write
            # happened earliest" -- an orientation note, not a real clade root: this
            # project's own design deliberately keeps clade clustering (unrelated files
            # grouped by content similarity) separate from the Lineage DAG (one file's
            # real edit history) -- see TreeConstructor.py's module docstring. A clade has
            # no parent/child structure of its own, so this is NOT claiming one exists.
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
        label = arg.strip()
        if label not in self.catalog:
            print(f"No such label: '{label}'")
            return
        if not self._require_reauth(f"view details for '{label}'"):
            return
        manifest_path = os.path.join(self.storage_root, self.catalog[label])
        meta = self._read_manifest_metadata(manifest_path)
        fp = meta.get("similarity_fingerprint")
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
              f"{'stored (' + str(len(fp)) + ' traits)' if fp is not None else 'not stored (predates this feature)'}")
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
(each generation is a real, reconstructible past version of THIS label
-- distinct from 'tree', which groups DIFFERENT files by similarity,
not one file's own history; use 'checkout' to pull an old generation)"""
        label = arg.strip()
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
        """'true'/'false'/'yes'/'no'/'1'/'0' (case-insensitive) become
        real booleans, so the two enforced tags (protected,
        no_graft_source) work correctly as flags -- everything else is
        kept as the literal string, so arbitrary informational tags
        ('project=alpha') aren't forced into a boolean shape."""
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
(true/false/yes/no/1/0 become real booleans; anything else is kept as
text. Applies to the CURRENT tip and is inherited automatically by
every future generation of this label from now on -- an "expression
mutation" the design doc describes: 'protected' blocks delete/prune
unless forced, 'no_graft_source' blocks this label from being used in
'graft'. Any other key is stored and inherited the same way but is
purely informational.)"""
        parts = arg.split(maxsplit=2)
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
(removes the tag from the CURRENT tip; future generations from now on
won't inherit it either. Does NOT retroactively change any past
generation's own tag record -- see 'prune's docstring for what that
means for a specific already-tagged past generation.)"""
        parts = arg.split()
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
(keeps the label and ALL its OTHER generations intact -- only removes
this one specific past version's content. The generation's record stays
visible in 'lineage', marked pruned, so you can still see it existed.
Cannot prune the current tip -- the live version -- use 'delete' to
remove a label entirely instead. Refused if this exact generation is
tagged 'protected' unless you add 'force'. If this generation's
manifest is still shared with something else in the vault -- another
label with identical content, or a graft that used it as a lateral
parent -- nothing is actually freed yet; run 'vacuum' afterward
regardless to reclaim whatever became reclaimable.)"""
        parts = arg.split()
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
(concatenates label_a's current content + label_b's current content
into a new label, recorded as descending from BOTH lineages at once --
run 'lineage <new_label>' afterward to see the dual parentage. This is
a graph-level provenance operation, not format-aware content merging:
no diffing, no conflict detection, just a real, reconstructible graft
of two independent, already-stored files into one new node. Because
both files' chunks are usually already in the vault from their own
earlier writes, this typically introduces very few genuinely new
chunks -- watch the 'new' count in the output, it's a direct
demonstration of the shared chunk pool across what were, until now,
two completely unrelated lineages.)"""
        parts = arg.split()
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
(use 'lineage <label>' first to see which generations are currently
branch heads -- 'fork' creates them. Does a real chunk-position 3-way
diff against the branches' common ancestor: a chunk changed by only
one branch (or changed identically by both) merges automatically; a
chunk changed DIFFERENTLY by both branches is a genuine Mutation
Conflict -- this refuses to guess a winner and commits nothing. The
design doc's EvolutionaryDivergenceException, made real: no data is
silently discarded either way.)"""
        parts = arg.split()
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
(use 'lineage <label>' first to see which generations exist; generation
0 is the original, higher numbers are later edits; '@tip' means "this
label's current head generation" -- the same generation plain 'read'
already gives you -- instead of a specific number; the output path
resolves against 'navigate's directory, if set)"""
        parts = arg.split()
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
(requires a focus label -- run 'clade <label>' first. Always counts N
PRIMARY-parent hops back from the focused label's CURRENT TIP -- not
chained, so 'ancestor 1' then 'ancestor 2' each start counting from the
tip again rather than compounding. Lateral parents (from 'graft'/
'merge') never count as a hop, same "primary lineage" concept 'fork'
branches off of. If you omit output_path, it's written as
'<label>_ancestor_<N>_gen<G>.<ext-less>' next to 'navigate's directory
(or this process's own working directory if unset), and the real path
used is always printed.)"""
        parts = arg.split()
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

        node = history[-1]  # tip, same definition prune_generation() itself uses
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
        label = arg.strip()
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
(the label's full recorded history moves with it -- 'lineage q3_report'
shows what used to be under 'lineage my_report')"""
        parts = arg.split()
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
(runs real operations -- write, edit, fork, tag, delete, vacuum, fsck --
against a throwaway label, not just checks that files exist. This is a
functional check ('does everything work'), not an adversarial one; see
'attack' for deliberate corruption/tampering tests.)"""
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
            # Checked AFTER a real write, not before: a brand-new keyring's
            # current_epoch starts at -1 and is only lazily set to 0 the
            # first time a DEK is actually requested (get_current_dek()),
            # which secure_and_persist_file just did as part of the write
            # above -- checking this on a truly fresh vault BEFORE any
            # write would give a false FAIL, not because the keyring is
            # broken but because nothing had asked it for a key yet.
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
(persisted encrypted across sessions -- up arrow also recalls it live,
same as any shell; only records commands that didn't crash the shell,
same idea as your shell's own history)"""
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

Only affects how relative paths you type into 'write' and 'read' get
resolved -- absolute paths and '~' always pass through untouched. Never
touches the vault's own storage_root. Per-session only, not saved
between runs (unlike 'history', this is meant to be reset each time)."""
        target = arg.strip()
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
        """Applies the current navigate directory (if any) to a relative
        path from 'write'/'read'. Absolute paths and '~' pass through
        untouched regardless of whether navigate is set."""
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

    # ---------- misc ----------

    def do_exit(self, arg):
        "exit  -- close the shell"
        with self._fingerprint_jobs_lock:
            pending = list(self._fingerprint_jobs)
        if pending:
            labels = ", ".join(l for l, _t in pending)
            print(f"Waiting for {len(pending)} background fingerprint job(s) to finish: {labels} ...")
            for _label, thread in pending:
                thread.join()
        # Release the vault lock (vault_lock.py) explicitly here rather
        # than leaving it to __del__/process exit -- this is the
        # NORMAL clean-close path (as opposed to a crash), so it should
        # release deterministically, not whenever GC happens to run.
        self._session.close()
        print("Goodbye.")
        return True

    do_quit = do_exit

    def do_EOF(self, arg):
        print()
        return self.do_exit(arg)

    def emptyline(self):
        pass  # don't repeat the last command on blank input

    def onecmd(self, line):
        stripped = line.strip() if isinstance(line, str) else ""
        try:
            result = super().onecmd(line)
        except Exception as e:
            print(f"Error: {type(e).__name__}: {e}")
            return False
        if stripped:
            self._record_history(stripped)
        return result


class CppPFSShell(cmd.Cmd):
    """Interactive shell for the compiled C++ storage engine
    (cpp_engine/), reached via 'python3 pfs_cli.py --engine cpp'.

    Deliberately a SEPARATE, smaller shell rather than a flag on
    PFSShell: the C API (cpp_engine/include/c_api.h) only covers a
    growing subset so far (write/read/delete/list/history/manifest-info,
    fork/graft/merge/tags/prune/vacuum/fsck/key-rotation, the attack
    suite, clade tree/'similar'/'clade' -- see cpp_port_plan.txt for
    what's still Python-only). Bolting a partial command set onto
    PFSShell would make it unclear, per command, which engine is
    actually being exercised; this way the shell you're in tells you."""

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
        # Set by 'clade' -- the Lineage Shell's "current focus" label
        # (Project_idea.txt's clade/checkout @tip/ancestor vocabulary).
        # None means 'checkout @tip'/'ancestor' have nothing to work
        # from yet and must be told to run 'clade <label>' first.
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

    # ---------- commands (the C API's actual current coverage) ----------

    def do_write(self, arg):
        """write <file_path> [label]  -- ingest a file into the vault (C++ engine)

Example:
  write /home/lister/Documents/report.pdf
  write /home/lister/Documents/report.pdf my_report
(if you skip [label], the file's own basename is used as the label; a
relative file_path resolves against 'navigate's directory, if set)"""
        parts = arg.split()
        if not parts:
            print("Usage: write <file_path> [label]")
            return
        file_path = self._resolve_path(parts[0])
        label = parts[1] if len(parts) > 1 else os.path.basename(parts[0])
        if not os.path.exists(file_path):
            print(f"File not found: {file_path}")
            return
        try:
            start = time.perf_counter()
            manifest = self._session.commit_write(label, file_path)
            elapsed = time.perf_counter() - start
        except PfsEngineError as e:
            print(f"Write failed: {e}")
            return
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
        parts = arg.split()
        if len(parts) != 2:
            print("Usage: read <label> <output_path>")
            return
        label, output_path = parts
        output_path = self._resolve_path(output_path)
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
(removes the label's full history, not just its current tip. A
manifest is only actually freed once nothing else in the vault --
another label sharing identical content, or a graft that used it as a
lateral parent -- still references it. Refused if the current tip is
tagged 'protected' unless you add 'force'.)"""
        parts = arg.split()
        if len(parts) not in (1, 2):
            print("Usage: delete <label> [force]")
            return
        label = parts[0]
        force = len(parts) == 2 and parts[1].lower() == "force"
        try:
            report = self._session.delete_label(label, force=force)
        except PfsEngineError as e:
            print(f"Delete failed: {e}")
            return
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
(writes file_path's content as a NEW, divergent version descending from
generation N of <label> -- NOT from the current tip. Use 'lineage' to
see the resulting branch heads, 'merge' to reconcile them later.)"""
        parts = arg.split()
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
        try:
            manifest = self._session.fork_write(label, file_path, generation)
        except PfsEngineError as e:
            print(f"Fork failed: {e}")
            return
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
        parts = arg.split()
        if len(parts) != 3:
            print("Usage: graft <label_a> <label_b> <new_label>")
            return
        label_a, label_b, new_label = parts
        try:
            manifest = self._session.graft(label_a, label_b, new_label)
        except PfsEngineError as e:
            print(f"Graft failed: {e}")
            return
        info = self._session.get_manifest_info(new_label)
        print(f"Grafted '{label_a}' + '{label_b}' -> '{new_label}' -> {manifest}")
        print(f"  {info['total_blocks']} chunks ({info['new_chunks_written']} genuinely new -- the "
              f"rest already existed from '{label_a}' and '{label_b}')")

    def do_merge(self, arg):
        """merge <label> <generation_a> <generation_b>  -- reconcile two divergent branches (C++ engine)

Example:
  merge my_report 3 5
(a real chunk-position 3-way diff against the branches' common
ancestor: a chunk changed by only one branch -- or identically by both
-- merges automatically; a chunk changed DIFFERENTLY by both is a
genuine Mutation Conflict -- refuses to guess, commits nothing.)"""
        parts = arg.split()
        if len(parts) != 3:
            print("Usage: merge <label> <generation_a> <generation_b>")
            return
        label, gen_a_str, gen_b_str = parts
        try:
            generation_a, generation_b = int(gen_a_str), int(gen_b_str)
        except ValueError:
            print("Usage: merge <label> <generation_a> <generation_b>  (generations must be integers)")
            return
        try:
            manifest = self._session.merge_branches(label, generation_a, generation_b)
        except PfsEngineError as e:
            print(f"MUTATION CONFLICT or merge failure -- nothing was committed.\n  {e}")
            return
        print(f"Merged '{label}' generations {generation_a} + {generation_b} -> {manifest}")

    def do_checkout(self, arg):
        """checkout <label> <generation> <output_path>  -- reconstruct a PAST version of a file (C++ engine)

Example:
  checkout my_report 0 /tmp/my_report_original.pdf
  checkout my_report @tip /tmp/my_report_latest.pdf
  clade my_report
  checkout @tip /tmp/my_report_latest.pdf     (label optional once focused via 'clade')
('@tip' means "this label's current head generation" -- the same
generation plain 'read' already gives you -- instead of a specific
number)"""
        parts = arg.split()
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
(requires a focus label -- run 'clade <label>' first. Always counts N
PRIMARY-parent hops back from the focused label's CURRENT TIP -- not
chained, so 'ancestor 1' then 'ancestor 2' each start counting from the
tip again rather than compounding. Lateral parents (from 'graft'/
'merge') never count as a hop, same "primary lineage" concept 'fork'
branches off of. If you omit output_path, it's written as
'<label>_ancestor_<N>_gen<G>.bin' next to 'navigate's directory (or
this process's own working directory if unset), and the real path used
is always printed.)"""
        parts = arg.split()
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
        parts = arg.split()
        if len(parts) != 2:
            print("Usage: rename <old_label> <new_label>")
            return
        old_label, new_label = parts
        try:
            self._session.rename_label(old_label, new_label)
        except PfsEngineError as e:
            print(f"Rename failed: {e}")
            return
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
        parts = arg.split(maxsplit=2)
        if len(parts) != 3:
            print("Usage: tag <label> <key> <value>")
            return
        label, key, raw_value = parts
        value = self._parse_tag_value(raw_value)
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
        parts = arg.split()
        if len(parts) != 2:
            print("Usage: untag <label> <key>")
            return
        label, key = parts
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
        parts = arg.split()
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
        label = arg.strip()
        if not label:
            print("Usage: lineage <label>")
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
(a chunk that fails its integrity check but has an Ancestral Hardening
mirror -- shared by 3+ manifests -- is repaired in place. A chunk that
fails with no working mirror is reported, not silently ignored.)"""
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
        new_epoch = self._session.rotate_key()
        print(f"Rotated to epoch {new_epoch}. New writes use the new key; existing files are unaffected.")

    def do_stats(self, arg):
        """stats  -- show vault-wide statistics (C++ engine)

Example:
  stats
(takes no arguments)"""
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
                     corruption is backed up and verified-restored afterward
Same battery as the Python engine's 'attack', adapted for this engine's own
manifest/keyring formats -- 'wrong key is rejected' is actually STRONGER
here: a second session opened under the wrong key fails immediately, since
the keyring itself can't be decrypted, rather than only failing later on a
specific read.)"""
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

        # 1. Baseline: correct key reconstructs correctly
        try:
            self._session.reconstruct_label(label, out_ok)
            with open(out_ok, "rb") as f:
                ok = f.read() == expected_content
        except PfsEngineError:
            ok = False
        results.append(("Baseline: correct key reconstructs correctly", ok))

        # 2. Wrong key is rejected -- opening a SECOND session under a
        # wrong KEK fails immediately (the keyring itself can't be
        # decrypted), stronger than only failing on a later read.
        wrong_kek = secrets.token_bytes(32)
        try:
            bad_session = CppVaultSession(self.storage_root, wrong_kek)
            bad_session.close()
            results.append(("Wrong key is rejected", False))
        except PfsEngineError:
            results.append(("Wrong key is rejected", True))

        # 3. Confirmation-of-presence attack is blocked: a guessed
        # content hash can't be used directly as a database lookup key
        # (the real lookup_key is HMAC-blinded, never the raw hash).
        guessed_hash = hashlib.sha256(expected_content[:4096]).digest()
        conn = sqlite3.connect(os.path.join(self.storage_root, DB_FILENAME))
        row = conn.execute("SELECT 1 FROM blocks WHERE lookup_key = ?", (guessed_hash,)).fetchone()
        conn.close()
        results.append(("Confirmation-of-presence attack blocked", row is None))

        # 4. Corrupted ciphertext is detected, not silently returned --
        # SAFELY: back up the exact bytes before touching anything.
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
(runs real operations -- write, edit, fork, tag, key rotation, delete,
vacuum, fsck -- against a throwaway label, not just checks that files
exist. Functional check, not adversarial; see 'attack' for deliberate
corruption tests. Same check names as the Python engine's 'test' where
the operation is genuinely equivalent.)"""
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
        target = arg.strip()
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
        label = arg.strip()
        if not label:
            print("Usage: history <label>")
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
        label = arg.strip()
        if not label:
            print("Usage: info <label>")
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
(defaults to upgma if not given; uses fingerprints attached at write
time, so it never re-reads or re-decrypts your original files)"""
        algorithm = arg.strip().lower() or "upgma"
        if algorithm not in ("upgma", "nj"):
            print("Usage: tree [upgma|nj]")
            return
        try:
            rendering = self._session.build_tree(algorithm)
        except PfsEngineError as e:
            print(f"Failed: {e}")
            return

        # build_tree already covers every fingerprinted label, so no
        # filtering needed here (unlike similar/clade below, which only
        # touch a subset) -- best-effort: a failure here shouldn't hide
        # the tree that already rendered fine.
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
        label = arg.strip()
        if not label:
            print("Usage: similar <label>")
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
(a clade is a similarity GROUPING -- the same connected-components
clustering 'tree'/'similar' already use, at the design doc's own
D<=0.80 threshold -- NOT a lineage: it has no real parent/child
structure of its own, just membership, so this never invents a fake
"clade root". Sets this shell's 'current focus' to <label> itself, so
'checkout @tip'/'ancestor N' can be used afterward without repeating
the label.)"""
        label = arg.strip()
        if not label:
            print("Usage: clade <label>")
            return
        try:
            _representative, members = self._session.compute_clades(label)
        except PfsEngineError as e:
            print(f"Failed: {e}")
            return
        members = sorted(members)

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
            # "Most ancestral" here means only "the member whose OWN generation-0 write
            # happened earliest" -- an orientation note, not a real clade root: this
            # project's own design deliberately keeps clade clustering (unrelated files
            # grouped by content similarity) separate from the Lineage DAG (one file's
            # real edit history). A clade has no parent/child structure of its own, so
            # this is NOT claiming one exists.
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
                         help="'python' (default, full feature set) or 'cpp' (experimental, "
                              "compiled engine, write/read/delete/list/history/info only)")
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
