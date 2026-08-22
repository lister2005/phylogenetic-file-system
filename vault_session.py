"""
Shared vault lifecycle: unlock-or-create, catalog load/save, manifest
metadata reads. This is security-critical logic (key unwrapping, catalog
encryption, stale-key-file handling) that both pfs_cli.py (the shell) and
pfs_fuse.py (the FUSE mount) need identically -- it lives here exactly
once so the two front ends can't drift out of sync with each other.

Interactive bits (prompting for a passphrase, asking to confirm a reset)
are passed in as callbacks rather than hardcoded to getpass/input, so a
FUSE mount script (which may want to prompt once at mount time, before
any filesystem callback ever fires) and the CLI shell (which prompts
per-command via getpass) can each supply their own without this class
caring which.
"""

import os
import pickle
import hashlib
from cryptography.exceptions import InvalidTag
from gearhash.master_key_store import create_new_vault_key, load_vault_key, WrongPassphraseError, MASTER_KEY_FILENAME
from gearhash.pipeline import StoragePipeline
from gearhash.crypto import CryptoEngine
from gearhash.dedup_index import DB_FILENAME, GlobalBlockIndex
from gearhash.keyring import KEYRING_FILENAME
from gearhash.fks_index import FKSLookupEngine
from lineage import LineageStore, LINEAGE_FILENAME
from reconstruct import reconstruct
from PhylogeneticAnalyzer import PhylogeneticAnalyzer, SIMILARITY_PROFILE
from vault_lock import VaultLock, VaultLockError

CATALOG_FILENAME = "catalog.enc"
HISTORY_FILENAME = "history.enc"


class VaultUnlockError(Exception):
    """Raised when the vault couldn't be unlocked or created -- wrong
    passphrase, mismatched passphrases on creation, or a keyring
    mismatch that the caller declined to reset. Callers decide how to
    surface this (sys.exit for a CLI, a failed mount for FUSE)."""


class MutationConflictError(Exception):
    """The design doc's EvolutionaryDivergenceException: raised when two
    divergent branches of the same label changed the SAME chunk
    position DIFFERENTLY since their common ancestor. merge_branches()
    refuses to guess a winner -- lists the conflicting chunk positions
    (0-indexed, matching each generation's own manifest block order)
    so the caller can resolve manually (write a fresh version by hand,
    or explicitly discard one branch)."""

    def __init__(self, conflicting_positions):
        self.conflicting_positions = list(conflicting_positions)
        preview = self.conflicting_positions[:10]
        more = "..." if len(self.conflicting_positions) > 10 else ""
        super().__init__(
            f"{len(self.conflicting_positions)} chunk position(s) were changed differently on "
            f"both branches since their common ancestor: {preview}{more}"
        )


class VaultSession:
    def __init__(self, storage_root: str):
        self.storage_root = storage_root
        os.makedirs(storage_root, exist_ok=True)
        self.crypto = None
        self.pipeline = None
        self.catalog = {}
        self.lineage = None
        # Acquired in unlock_or_create (see vault_lock.py) -- that's
        # where this session actually OPENS the vault (this constructor
        # only creates the directory and zeroes out fields). Released
        # in close()/__del__ so ordinary sequential reopen (open a
        # vault, do work, close it, reopen it later -- all over this
        # project's own test suite) keeps working exactly as before;
        # only a genuinely concurrent SECOND PROCESS gets refused.
        self._lock = None

    def unlock_or_create(self, get_new_passphrase, get_existing_passphrase, confirm_reset) -> None:
        """get_new_passphrase() -> (pw1, pw2), asked only when no vault
        exists yet at storage_root.
        get_existing_passphrase() -> pw, asked when a vault already exists.
        confirm_reset() -> bool, asked only if master.key unlocks but the
        rest of the vault was encrypted under a different, now-lost key
        (see _handle_keyring_mismatch's original docstring in pfs_cli.py
        for why that state is possible and why reset is the only way out).
        Raises VaultUnlockError on any failure -- never leaves self.crypto/
        self.pipeline partially set.

        The very first thing this does is take an OS-level advisory
        lock (flock, non-blocking) on storage_root/.vault.lock -- before
        even prompting for a passphrase, so a second process opening an
        already-open vault gets an immediate, clear refusal instead of
        being prompted first and only THEN told no. This is what
        actually enforces the "single-process-at-a-time" invariant
        manual.txt PART 6 already documented as assumed-but-unenforced
        (see vault_lock.py's module docstring for the full story,
        including the real lost-update bug this closes)."""
        try:
            self._lock = VaultLock(self.storage_root)
        except VaultLockError as e:
            raise VaultUnlockError(str(e))
        try:
            self._unlock_or_create_locked(get_new_passphrase, get_existing_passphrase, confirm_reset)
        except Exception:
            # Unlock failed for some other reason (wrong passphrase,
            # mismatched passphrases, declined reset) -- this session
            # never actually opened, so don't hold the lock hostage:
            # release it so the same process can retry (or a caller
            # can construct a fresh VaultSession) without being
            # refused by its own leftover lock.
            self._lock.release()
            self._lock = None
            raise

    def _unlock_or_create_locked(self, get_new_passphrase, get_existing_passphrase, confirm_reset) -> None:
        key_path = os.path.join(self.storage_root, MASTER_KEY_FILENAME)
        if not os.path.exists(key_path):
            pw1, pw2 = get_new_passphrase()
            if pw1 != pw2:
                raise VaultUnlockError("Passphrases didn't match.")
            kek = create_new_vault_key(self.storage_root, pw1)
            self._wipe_stale_vault_files()
        else:
            pw = get_existing_passphrase()
            try:
                kek = load_vault_key(self.storage_root, pw)
            except WrongPassphraseError:
                raise VaultUnlockError("Wrong passphrase.")

        self.crypto = CryptoEngine(kek)
        try:
            self.pipeline = StoragePipeline(self.storage_root, crypto_engine=self.crypto)
        except InvalidTag:
            if not confirm_reset():
                self.crypto = None
                raise VaultUnlockError(
                    "The vault's other files don't decrypt under this key, and reset wasn't confirmed."
                )
            self._wipe_stale_vault_files()
            self.pipeline = StoragePipeline(self.storage_root, crypto_engine=self.crypto)

        self._load_catalog()
        self.lineage = LineageStore(self.storage_root, self.crypto)

    def close(self) -> None:
        """Releases the vault lock taken in unlock_or_create (see
        vault_lock.py), if any. Idempotent -- safe to call more than
        once, and safe to call on a session that never successfully
        unlocked. Not previously needed (this project's existing
        pattern was to just let a VaultSession get garbage collected --
        see tests/test_lineage_diff.py's own comment on this), but the
        lock has to be released deterministically now, not whenever GC
        happens to run, so this exists and __del__ calls it as a
        backstop for callers that don't call it explicitly."""
        if self._lock is not None:
            self._lock.release()
            self._lock = None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass

    def _wipe_stale_vault_files(self) -> list:
        """Called right after creating a brand new vault key, or after an
        explicitly confirmed keyring-mismatch reset. Files from a
        previous vault key that no longer exists can never be decrypted
        again regardless of what happens next, so rather than crash on
        the mismatch the moment KeyRing tries to load them, clear them
        out now. Returns the list of filenames actually removed, so a
        caller can report what happened."""
        stale_names = [
            "data_container.bin",
            DB_FILENAME, DB_FILENAME + "-wal", DB_FILENAME + "-shm",
            KEYRING_FILENAME,
            CATALOG_FILENAME,
            HISTORY_FILENAME,
            LINEAGE_FILENAME,
        ]
        removed = []
        for fname in stale_names:
            path = os.path.join(self.storage_root, fname)
            if os.path.exists(path):
                os.remove(path)
                removed.append(fname)
        for fname in os.listdir(self.storage_root):
            if fname.endswith(".manifest.fks") or fname.endswith(".manifest.fks.tmp"):
                os.remove(os.path.join(self.storage_root, fname))
                removed.append(fname)
        return removed

    def _load_catalog(self) -> None:
        path = os.path.join(self.storage_root, CATALOG_FILENAME)
        if os.path.exists(path):
            with open(path, "rb") as f:
                encrypted = f.read()
            raw = self.crypto.decrypt_block(encrypted, associated_data=b"catalog")
            self.catalog = pickle.loads(raw)
        else:
            self.catalog = {}

    def save_catalog(self) -> None:
        path = os.path.join(self.storage_root, CATALOG_FILENAME)
        raw = pickle.dumps(self.catalog)
        encrypted = self.crypto.encrypt_block(raw, associated_data=b"catalog")
        tmp = path + ".tmp"
        with open(tmp, "wb") as f:
            f.write(encrypted)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)

    def read_manifest_metadata(self, manifest_path: str) -> dict:
        manifest_filename = os.path.basename(manifest_path)
        with open(manifest_path, "rb") as f:
            encrypted = f.read()
        raw = self.crypto.decrypt_block(encrypted, associated_data=manifest_filename.encode())
        engine = FKSLookupEngine(raw_bytes=raw)
        return engine.metadata

    def manifest_path_for(self, label: str) -> str:
        return os.path.join(self.storage_root, self.catalog[label])

    def commit_write(self, label: str, source_path: str, similarity_fingerprint=None,
                      lateral_parent_labels=None, fork_from_generation=None) -> str:
        """The one place both front ends (pfs_cli.py, pfs_fuse.py) should
        call to persist a (label, file content) write. Wraps
        secure_and_persist_file, records the REAL per-edit lineage
        generation (see lineage.py -- new_chunks is the actual count of
        genuinely new content-defined chunks this write introduced, not
        a synthetic statistic), and updates+saves the catalog -- so
        neither front end can forget any of the three, and neither can
        drift out of sync with the other.

        If this write reproduces byte-identical content to the label's
        current tip (same resulting manifest) AND isn't a fork, no new
        generation is recorded -- that's not a real mutation, just a
        no-op re-save. A fork always records a new generation even if
        its content happens to match something else exactly -- the
        FORK ITSELF (a new branch point) is the meaningful event.

        lateral_parent_labels: optional list of OTHER labels whose
        CURRENT tips should be recorded as additional (non-primary)
        parents of this generation -- Lateral Gene Transfer. Their tips
        are resolved at call time, before the write, so a graft always
        records exactly the ancestry that was actually merged in.

        fork_from_generation: optional. If given, the new generation's
        PRIMARY parent is THAT SPECIFIC past generation of `label`
        instead of its current tip -- this is what actually creates a
        branch (see lineage.py's get_heads()). The catalog pointer
        (what plain read/write default to) always moves to whichever
        branch was written to most recently, fork or not."""
        lateral_parent_uuids = None
        if lateral_parent_labels:
            lateral_parent_uuids = []
            for other_label in lateral_parent_labels:
                tip = self.lineage.get_tip(other_label)
                if tip is None:
                    raise ValueError(f"'{other_label}' has no recorded lineage tip to graft from.")
                lateral_parent_uuids.append(tip.node_uuid)

        fork_from_node = None
        if fork_from_generation is not None:
            fork_from_node = self.lineage.get_generation(label, fork_from_generation)
            if fork_from_node is None:
                raise ValueError(f"No generation {fork_from_generation} recorded for '{label}' to fork from.")
            if fork_from_node.pruned:
                raise ValueError(
                    f"Generation {fork_from_generation} of '{label}' was pruned -- its content is "
                    f"gone, so there's nothing to fork from."
                )

        manifest_path = self.pipeline.secure_and_persist_file(source_path, similarity_fingerprint=similarity_fingerprint)
        manifest_filename = os.path.basename(manifest_path)

        existing_history = self.lineage.get_history(label)
        if fork_from_node is not None or not existing_history or existing_history[-1].manifest_filename != manifest_filename:
            meta = self.read_manifest_metadata(manifest_path)
            self.lineage.record_version(
                label, manifest_filename,
                new_chunks=meta["new_chunks_written"], total_chunks=meta["total_blocks"],
                lateral_parent_uuids=lateral_parent_uuids,
                fork_from=fork_from_node,
            )

        self.catalog[label] = manifest_filename
        self.save_catalog()
        return manifest_path

    def lateral_gene_transfer(self, label_a: str, label_b: str, new_label: str) -> str:
        """The actual Lateral Gene Transfer operation: grafts two
        independent, already-published lineages into one new node that
        descends from both. Concatenates label_a's current content +
        label_b's current content into a real, byte-correct, reconstructible
        file (label_a's bytes first, then label_b's), then commits it
        under new_label with both labels' current tips recorded as
        parents.

        Deliberately content-agnostic (no format-aware splicing) --
        see lineage.py's module docstring for why this doesn't attempt
        the design doc's speculative format-aware merge/conflict model.
        Because both label_a's and label_b's chunks are already in the
        global dedup index from when they were first written, this
        graft will typically introduce very few genuinely NEW chunks --
        usually just one, at the seam where A's tail and B's head don't
        happen to land on an existing content-defined chunk boundary --
        a concrete demonstration of the shared Flyweight gene pool the
        design doc describes, not just an assertion of it."""
        if label_a == label_b:
            raise ValueError("Can't graft a label onto itself.")
        if label_a not in self.catalog:
            raise KeyError(f"No such label: '{label_a}'")
        if label_b not in self.catalog:
            raise KeyError(f"No such label: '{label_b}'")
        for source_label in (label_a, label_b):
            if self.lineage.get_tags(source_label).get("no_graft_source"):
                raise ValueError(
                    f"'{source_label}' is tagged 'no_graft_source' -- won't use it as a graft "
                    f"source. Remove the tag first with 'untag {source_label} no_graft_source' "
                    f"if this graft is really intended."
                )

        tmp_a = os.path.join(self.storage_root, "__graft_a__.tmp")
        tmp_b = os.path.join(self.storage_root, "__graft_b__.tmp")
        tmp_combined = os.path.join(self.storage_root, "__graft_combined__.tmp")
        try:
            reconstruct(self.manifest_path_for(label_a), self.pipeline.container_path, tmp_a, self.crypto.key)
            reconstruct(self.manifest_path_for(label_b), self.pipeline.container_path, tmp_b, self.crypto.key)
            with open(tmp_combined, "wb") as out, open(tmp_a, "rb") as fa, open(tmp_b, "rb") as fb:
                out.write(fa.read())
                out.write(fb.read())

            # Computed synchronously, not backgrounded like a normal write's
            # fingerprint -- grafts combine two files already in the vault,
            # so their combined size is inherently bounded by two prior
            # writes, not an arbitrary new upload. No large-file case to
            # protect a shell prompt from here.
            fingerprint = PhylogeneticAnalyzer(SIMILARITY_PROFILE).extract_traits(tmp_combined)

            return self.commit_write(new_label, tmp_combined, similarity_fingerprint=fingerprint,
                                      lateral_parent_labels=[label_a, label_b])
        finally:
            for tmp in (tmp_a, tmp_b, tmp_combined):
                if os.path.exists(tmp):
                    os.remove(tmp)

    def _manifest_reference_count(self, manifest_filename: str) -> int:
        """How many live references -- catalog entries (current tips)
        PLUS lineage nodes (every past generation, across every label,
        including labels whose tip has since moved on) -- currently
        point at this manifest filename. This is the piece that was
        missing before: GlobalBlockIndex already ref-counts individual
        CHUNKS correctly, but nothing counted references to a MANIFEST
        FILE itself. Two labels (or two generations, including via
        lateral gene transfer) can perfectly legitimately share one
        manifest file when they happen to have byte-identical content
        -- secure_and_persist_file's own whole-file dedup shortcut is
        what makes that happen. Deleting one of them must never delete
        a manifest the other one still depends on."""
        count = sum(1 for filename in self.catalog.values() if filename == manifest_filename)
        for label in self.lineage.all_labels():
            count += sum(1 for node in self.lineage.get_history(label) if node.manifest_filename == manifest_filename)
        return count

    def delete_label(self, label: str, force: bool = False) -> dict:
        """The one safe way to fully remove a label: drops the catalog
        entry AND this label's entire recorded lineage history (every
        generation -- "delete" means delete, not "hide the tip and
        silently keep paying for its full history forever"; trimming
        JUST some old generations while keeping the label alive is
        prune_generation() instead). A manifest is only actually
        removed from disk (and its chunks' ref-counts decremented, via
        StoragePipeline.delete_file) once NOTHING else in the vault --
        no other label's tip, no other label's or this label's own
        other generations -- still references it. This is the fix for
        a real bug found on 2026-07-23: two labels with byte-identical
        content share one manifest file by design (whole-file dedup),
        and blindly deleting either one's manifest used to silently
        destroy the other.

        Refuses (unless force=True) if the current tip is tagged
        "protected" -- the epigenetic tag's real enforcement; see
        lineage.py's module docstring.

        Returns {"manifests_freed": int, "manifests_kept_shared": int}
        so a caller can report honestly when "delete" didn't free
        everything because something else still needs it."""
        if label not in self.catalog:
            raise KeyError(f"No such label: '{label}'")
        if not force and self.lineage.get_tags(label).get("protected"):
            raise PermissionError(
                f"'{label}' is tagged 'protected' -- won't delete without an explicit override. "
                f"Use 'untag {label} protected' first, or pass force."
            )

        manifest_filenames = {self.catalog[label]}
        manifest_filenames.update(
            node.manifest_filename for node in self.lineage.get_history(label)
            if node.manifest_filename is not None  # already-pruned generations have nothing to free
        )

        del self.catalog[label]
        self.lineage.delete_label(label)
        self.save_catalog()

        freed = 0
        kept = 0
        for manifest_filename in manifest_filenames:
            if self._manifest_reference_count(manifest_filename) > 0:
                kept += 1
                continue
            manifest_path = os.path.join(self.storage_root, manifest_filename)
            if os.path.exists(manifest_path):
                self.pipeline.delete_file(manifest_path)
                freed += 1

        return {"manifests_freed": freed, "manifests_kept_shared": kept}

    def _live_manifest_filenames(self) -> set:
        """Every manifest filename currently referenced anywhere in the
        vault -- catalog tips plus every recorded generation (including
        non-tip ones still in a label's history) across every label.
        Already-pruned generations have manifest_filename=None and are
        naturally excluded. Same authoritative source
        _manifest_reference_count checks per-manifest, gathered here as
        a full set for StoragePipeline.rebuild_ref_counts."""
        names = set(self.catalog.values())
        for label in self.lineage.all_labels():
            names.update(
                node.manifest_filename for node in self.lineage.get_history(label)
                if node.manifest_filename is not None
            )
        return names

    def vacuum(self) -> dict:
        """The one place both front ends should call to vacuum: repairs
        any chunk ref-count drift first (rebuild_ref_counts, using this
        session's own catalog+lineage as the authoritative live set --
        StoragePipeline can't see those on its own), THEN reclaims space
        from chunks that are genuinely unreferenced. Folding the repair
        into 'vacuum' itself means a vault affected by the ref-count
        inflation bug self-heals the moment its owner runs the vacuum
        they'd already run anyway, with no separate step to remember."""
        live = self._live_manifest_filenames()
        repair_report = self.pipeline.rebuild_ref_counts(live)
        orphan_report = self.pipeline.sweep_orphaned_manifests(live)
        vacuum_report = self.pipeline.vacuum()
        vacuum_report["chunks_corrected"] = repair_report["chunks_corrected"]
        vacuum_report["orphaned_manifests_removed"] = orphan_report["removed"]
        vacuum_report["orphaned_tmp_files_removed"] = orphan_report["tmp_removed"]
        return vacuum_report

    def prune_generation(self, label: str, generation_index: int, force: bool = False) -> dict:
        """Reclaims ONE specific historical generation's storage while
        keeping the label and every OTHER generation intact -- unlike
        delete_label, which removes a label entirely. Refuses to prune
        the current tip (the live version); use delete_label for that.

        See lineage.py's module docstring for why pruning a MIDDLE
        generation is safe here (no "Graph Re-Grafting" needed) in a
        way it wouldn't be in a real byte-delta-chain design.

        Refuses (unless force=True) if THIS SPECIFIC generation is
        tagged "protected" -- note this checks the generation being
        pruned, not the current tip (unlike delete_label, which only
        has one tip to check). A generation tagged protected AFTER
        this one, further down the lineage, does not retroactively
        protect this one -- inheritance only flows forward.

        Returns {"freed": bool} -- False if the manifest was kept
        because something else in the vault still references it (same
        manifest-reference-counting as delete_label)."""
        if label not in self.catalog:
            raise KeyError(f"No such label: '{label}'")

        history = self.lineage.get_history(label)
        if not history:
            raise ValueError(f"'{label}' has no recorded lineage history to prune.")

        tip = history[-1]
        if tip.generation_index == generation_index:
            raise ValueError(
                f"Generation {generation_index} is '{label}'s current tip -- can't prune the live "
                f"version. Use 'delete' to remove '{label}' entirely instead."
            )

        node = self.lineage.get_generation(label, generation_index)
        if node is None:
            raise ValueError(f"No generation {generation_index} recorded for '{label}'.")
        if node.pruned:
            raise ValueError(f"Generation {generation_index} of '{label}' was already pruned.")
        if not force and node.epigenetic_tags.get("protected"):
            raise PermissionError(
                f"Generation {generation_index} of '{label}' is tagged 'protected' -- won't prune "
                f"without an explicit override. That tag is fixed in this specific generation's own "
                f"history record (untagging the current tip only affects future generations, not this "
                f"past one), so pass force if you're sure you want to prune it anyway."
            )

        manifest_filename = self.lineage.mark_pruned(label, generation_index)

        freed = False
        if manifest_filename and self._manifest_reference_count(manifest_filename) == 0:
            manifest_path = os.path.join(self.storage_root, manifest_filename)
            if os.path.exists(manifest_path):
                self.pipeline.delete_file(manifest_path)
                freed = True

        return {"freed": freed}

    def _find_common_ancestor(self, node_a, node_b):
        """Walks PRIMARY parent pointers back from both nodes to find
        their lowest common ancestor. A simple linear walk -- fine at
        this project's scale (one label's own history), not the kind
        of graph size that needs a real LCA algorithm."""
        ancestors_a = set()
        node = node_a
        while node is not None:
            ancestors_a.add(node.node_uuid)
            node = self.lineage.find_node_by_uuid(node.parent_uuid) if node.parent_uuid else None
        node = node_b
        while node is not None:
            if node.node_uuid in ancestors_a:
                return node
            node = self.lineage.find_node_by_uuid(node.parent_uuid) if node.parent_uuid else None
        return None

    def _manifest_chunk_list(self, manifest_filename: str):
        """This generation's ordered (block_index -> content_hash) list
        -- the real, already-stored data merge_branches diffs against,
        no separate delta storage needed."""
        manifest_path = os.path.join(self.storage_root, manifest_filename)
        with open(manifest_path, "rb") as f:
            raw = self.crypto.decrypt_block(f.read(), associated_data=os.path.basename(manifest_path).encode())
        engine = FKSLookupEngine(raw_bytes=raw)
        total = engine.metadata.get("total_blocks", 0)
        return [engine.lookup(i) for i in range(total)]

    def get_generation_chunk_hashes(self, label: str, generation_index: int) -> list:
        """This generation's ordered (block_index -> content_hash) list
        -- the public counterpart to _manifest_chunk_list, resolved from
        a generation_index rather than an already-known manifest
        filename. Unlike merge_branches's internal use of
        _manifest_chunk_list (always against generations the caller
        already looked up), this is the entry point a caller like the
        GUI's lineage diff uses: given just a label and a generation
        index, get that generation's real chunk-hash list. Raises
        ValueError if the generation doesn't exist or is pruned (its
        content is no longer available)."""
        node = self.lineage.get_generation(label, generation_index)
        if node is None:
            raise ValueError(f"No generation {generation_index} recorded for '{label}'.")
        if node.manifest_filename is None:
            raise ValueError(
                f"Generation {generation_index} of '{label}' is pruned -- its content is no longer available."
            )
        return self._manifest_chunk_list(node.manifest_filename)

    def merge_branches(self, label: str, generation_a: int, generation_b: int) -> str:
        """Resolves the design doc's Mutation Conflict scenario for
        real: finds the lowest common ancestor of two divergent
        branches of `label`, then does a chunk-POSITION 3-way diff
        (using each generation's own ordered chunk-hash list, already
        stored in every manifest -- no separate delta storage needed)
        against it:
          - a position unchanged by both, or changed IDENTICALLY by
            both -> keep it
          - a position changed by exactly one branch -> take that
            branch's version
          - a position changed DIFFERENTLY by both branches -> raises
            MutationConflictError and commits NOTHING -- no automated
            guess is attempted, matching the design doc's own choice
            to make a human pick.

        On success, every chunk in the merged result is already in the
        global dedup store (it came from the ancestor's, A's, or B's
        own already-committed manifest) -- this reconstructs the real
        merged bytes and commits them through the ordinary write path,
        so the result is a fully independent, ordinarily-reconstructable
        manifest like everything else here, not a special delta-only
        record. The merge result's primary parent is generation_a, with
        generation_b recorded as a lateral parent -- the exact same
        mechanism 'graft' uses, just within one label instead of two.

        Returns the new manifest path."""
        if label not in self.catalog:
            raise KeyError(f"No such label: '{label}'")

        node_a = self.lineage.get_generation(label, generation_a)
        node_b = self.lineage.get_generation(label, generation_b)
        if node_a is None:
            raise ValueError(f"No generation {generation_a} recorded for '{label}'.")
        if node_b is None:
            raise ValueError(f"No generation {generation_b} recorded for '{label}'.")
        if node_a.pruned or node_b.pruned:
            raise ValueError("Can't merge a pruned generation -- its content is no longer available.")
        if node_a.node_uuid == node_b.node_uuid:
            raise ValueError("Can't merge a generation with itself.")

        ancestor = self._find_common_ancestor(node_a, node_b)
        if ancestor is None:
            raise ValueError(
                f"Generations {generation_a} and {generation_b} of '{label}' share no common "
                f"ancestor -- can't 3-way merge them."
            )
        if ancestor.node_uuid in (node_a.node_uuid, node_b.node_uuid):
            raise ValueError(
                "One of these generations is a direct ancestor of the other -- that's just "
                "linear history, not a divergent branch. Nothing to merge."
            )

        chunks_ancestor = self._manifest_chunk_list(ancestor.manifest_filename)
        chunks_a = self._manifest_chunk_list(node_a.manifest_filename)
        chunks_b = self._manifest_chunk_list(node_b.manifest_filename)

        # A dedicated sentinel, not None -- "this branch's chunk list
        # doesn't reach this position" needs to compare unequal to any
        # real content hash AND be distinguishable from "the winning
        # choice at this position IS absence" (i.e. one or both branches
        # truncated here), which the position-diff below has to treat
        # as "stop appending" rather than "append a fake chunk".
        _ABSENT = object()

        max_len = max(len(chunks_ancestor), len(chunks_a), len(chunks_b))
        merged = []
        conflicts = []
        for i in range(max_len):
            base = chunks_ancestor[i] if i < len(chunks_ancestor) else _ABSENT
            a = chunks_a[i] if i < len(chunks_a) else _ABSENT
            b = chunks_b[i] if i < len(chunks_b) else _ABSENT
            a_changed = a != base
            b_changed = b != base

            if not a_changed and not b_changed:
                winner = base
            elif a_changed and not b_changed:
                winner = a
            elif b_changed and not a_changed:
                winner = b
            elif a == b:
                winner = a  # both changed, but agree (including both truncating here) -- no real conflict
            else:
                # Both changed, DIFFERENTLY -- including "one branch
                # truncated here while the other made an unrelated real
                # edit at this same position", a genuine delete-vs-edit
                # divergence, not something to silently pick a winner for.
                conflicts.append(i)
                continue

            if winner is _ABSENT:
                # The winning choice at this position is "doesn't exist"
                # -- one or both branches truncated the file here. Stop
                # the merged sequence at this point rather than emitting
                # a placeholder for a position nothing actually has.
                break
            merged.append(winner)

        if conflicts:
            raise MutationConflictError(conflicts)

        global_index = GlobalBlockIndex(self.storage_root, self.crypto)
        tmp_merged = os.path.join(self.storage_root, "__merge_result__.tmp")
        try:
            with open(tmp_merged, "wb") as out:
                for content_hash in merged:
                    location = global_index.lookup(content_hash)
                    if location is None:
                        raise RuntimeError(
                            f"Merge chunk {content_hash.hex()[:16]}... missing from the global "
                            f"index -- this should be impossible given it came from an "
                            f"already-committed manifest."
                        )
                    offset, length, _ref_count, epoch_id = location
                    dek = self.pipeline.keyring.get_dek(epoch_id)
                    with open(self.pipeline.container_path, "rb") as container:
                        container.seek(offset)
                        payload = container.read(length)
                    plaintext = self.crypto.decrypt_block(payload, key=dek, associated_data=content_hash)
                    if hashlib.sha256(plaintext).digest() != content_hash:
                        raise RuntimeError(
                            f"Merge chunk {content_hash.hex()[:16]}... failed integrity "
                            f"verification -- run 'fsck' to check for corruption, then try the "
                            f"merge again."
                        )
                    out.write(plaintext)
        finally:
            global_index.close()

        try:
            fingerprint = PhylogeneticAnalyzer(SIMILARITY_PROFILE).extract_traits(tmp_merged)
            manifest_path = self.pipeline.secure_and_persist_file(tmp_merged, similarity_fingerprint=fingerprint)
            manifest_filename = os.path.basename(manifest_path)

            meta = self.read_manifest_metadata(manifest_path)
            self.lineage.record_version(
                label, manifest_filename,
                new_chunks=meta["new_chunks_written"], total_chunks=meta["total_blocks"],
                lateral_parent_uuids=[node_b.node_uuid],
                fork_from=node_a,
            )
            self.catalog[label] = manifest_filename
            self.save_catalog()
            return manifest_path
        finally:
            if os.path.exists(tmp_merged):
                os.remove(tmp_merged)
