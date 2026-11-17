"""
Vault lifecycle shared by the CLI and FUSE front ends: unlock or create,
catalog load/save, manifest metadata, and every operation that changes
the catalog and lineage together. Prompts are passed in as callbacks.
"""

import os
import pickle
import functools
import hashlib
from contextlib import contextmanager
from typing import Callable, Dict, List, Optional
from cryptography.exceptions import InvalidTag
from gearhash.master_key_store import (create_new_vault_key, load_vault_key, change_passphrase,
                                       WrongPassphraseError, MASTER_KEY_FILENAME)
from gearhash.pipeline import (StoragePipeline, MANIFEST_SUFFIX, TRAITS_SUFFIX, SETTINGS_FILENAME,
                               read_similarity_fingerprint, similarity_fingerprint_count)
from gearhash.crypto import CryptoEngine
from gearhash.dedup_index import DB_FILENAME, GlobalBlockIndex
from gearhash.keyring import KeyRing, KEYRING_FILENAME
from gearhash.fks_index import FKSLookupEngine
from lineage import LineageStore, LINEAGE_FILENAME
from reconstruct import reconstruct
from PhylogeneticAnalyzer import PhylogeneticAnalyzer, SIMILARITY_PROFILE
from vault_lock import VaultBusyError, VaultLock, VaultLockError

CATALOG_FILENAME = "catalog.enc"
HISTORY_FILENAME = "history.enc"


class VaultUnlockError(Exception):
    """The vault couldn't be unlocked or created."""


class MutationConflictError(Exception):
    """Two branches changed the same chunk position differently since their
    common ancestor. `conflicting_positions` lists them (0-indexed manifest block order);
    nothing was committed.
    """

    def __init__(self, conflicting_positions):
        """Records which chunk positions clash, with a readable message listing the first few."""
        self.conflicting_positions = list(conflicting_positions)
        preview = self.conflicting_positions[:10]
        more = "..." if len(self.conflicting_positions) > 10 else ""
        super().__init__(
            f"{len(self.conflicting_positions)} chunk position(s) were changed differently on "
            f"both branches since their common ancestor: {preview}{more}"
        )


def _changes_vault(method):
    """Runs a VaultSession method under the vault's write lock, after
    reloading whatever other processes changed (vault_lock.py)."""
    @functools.wraps(method)
    def wrapper(self, *args, **kwargs):
        """Runs the wrapped method inside _changing(), under the vault's write lock."""
        with self._changing():
            return method(self, *args, **kwargs)
    return wrapper


# Files whose change on disk means another process changed the vault.
_SHARED_STATE_FILES = (CATALOG_FILENAME, LINEAGE_FILENAME, KEYRING_FILENAME, SETTINGS_FILENAME)


class VaultSession:
    """One process's view of a vault. Several processes may have a vault open:
    every change runs under the write lock and first reloads what others
    changed; refresh() picks up others' changes between operations.
    """

    def __init__(self, storage_root: str):
        """Prepares a session for a vault folder; nothing is unlocked until unlock_or_create()."""
        self.storage_root = storage_root
        os.makedirs(storage_root, exist_ok=True)
        self.crypto = None
        self.pipeline = None
        self.catalog = {}
        self.lineage = None
        # Taken in unlock_or_create, released in close().
        self._lock = None
        self._seen_state = None
        self._change_listeners: List[Callable[[set, set], None]] = []

    def unlock_or_create(self, get_new_passphrase, get_existing_passphrase, confirm_reset) -> None:
        """Takes the vault lock first (vault_lock.py), then unlocks or creates.

        get_new_passphrase() -> (pw1, pw2): no vault exists yet.
        get_existing_passphrase() -> pw: a vault exists.
        confirm_reset() -> bool: master.key unlocks but the other files were
        encrypted under a different key, which only a reset can recover from.
        Raises VaultUnlockError, leaving nothing half-initialized.
        """
        try:
            self._lock = VaultLock(self.storage_root)
        except VaultLockError as e:
            raise VaultUnlockError(str(e))
        try:
            with self._lock.write():
                self._unlock_or_create_locked(get_new_passphrase, get_existing_passphrase, confirm_reset)
                self._seen_state = self._state_signature()
        except Exception:
            # Never opened: release the lock so this process can retry.
            self._lock.release()
            self._lock = None
            raise

    def _unlock_or_create_locked(self, get_new_passphrase, get_existing_passphrase, confirm_reset) -> None:
        """Creates a new vault (asking for a passphrase twice) or unlocks an existing one, then loads its state."""
        key_path = os.path.join(self.storage_root, MASTER_KEY_FILENAME)
        if not os.path.exists(key_path):
            pw1, pw2 = get_new_passphrase()
            if pw1 != pw2:
                raise VaultUnlockError("Passphrases didn't match.")
            kek = create_new_vault_key(self.storage_root, pw1)
            self._wipe_stale_vault_files_exclusively()
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
            self._wipe_stale_vault_files_exclusively()
            self.pipeline = StoragePipeline(self.storage_root, crypto_engine=self.crypto)

        self._load_catalog()
        self.lineage = LineageStore(self.storage_root, self.crypto)

    def close(self) -> None:
        """Releases the vault lock. Idempotent; __del__ calls it as a backstop."""
        if self._lock is not None:
            self._lock.release()
            self._lock = None

    def __enter__(self):
        """Lets the session be used in a with-block."""
        return self

    def __exit__(self, *exc):
        """Closes the session at the end of a with-block."""
        self.close()

    def __del__(self):
        """Closes the session if it is garbage-collected while still open."""
        try:
            self.close()
        except Exception:
            pass

    def _wipe_stale_vault_files_exclusively(self) -> list:
        """Removes leftover files from an earlier vault, but only if no other program has the folder open."""
        try:
            with self._lock.exclusive():
                return self._wipe_stale_vault_files()
        except VaultBusyError as e:
            raise VaultUnlockError(str(e))

    # ---------- sharing a vault between processes ----------

    def _state_signature(self):
        """Returns size/time/inode of the shared state files, used to notice changes made by other programs."""
        sig = []
        for name in _SHARED_STATE_FILES:
            try:
                st = os.stat(os.path.join(self.storage_root, name))
                sig.append((st.st_mtime_ns, st.st_size, st.st_ino))
            except FileNotFoundError:
                sig.append(None)
        return tuple(sig)

    def add_change_listener(self, listener: Callable[[set, set], None]) -> None:
        """listener(changed_labels, removed_labels) runs after a reload that
        picked up another process's changes."""
        self._change_listeners.append(listener)

    def refresh(self) -> bool:
        """Reloads catalog, history and keys if another process changed them.
        True if anything was reloaded. Cheap when nothing changed (three stats).
        """
        if self._lock is None or self._state_signature() == self._seen_state:
            return False
        with self._lock.write():
            return self._reload_if_changed()

    def _reload_if_changed(self) -> bool:
        """Under the write lock, so no file is read half-written."""
        state = self._state_signature()
        if state == self._seen_state:
            return False
        before = dict(self.catalog)
        self._load_catalog()
        self.lineage._load()
        self.pipeline.keyring = KeyRing(self.storage_root, self.crypto.key)
        self.pipeline.settings = self.pipeline.load_settings()
        self._seen_state = state
        removed = set(before) - set(self.catalog)
        changed = {label for label, m in self.catalog.items() if before.get(label) != m}
        if changed or removed:
            for listener in list(self._change_listeners):
                listener(changed, removed)
        return True

    @contextmanager
    def _changing(self):
        """Context manager for one change: takes the write lock, reloads others' changes first, then records the new state."""
        with self._lock.write():
            self._reload_if_changed()
            try:
                yield
            finally:
                self._seen_state = self._state_signature()

    def write_lock(self):
        """The vault's write lock, for a change made outside these methods."""
        return self._lock.write()

    @contextmanager
    def sole_use(self):
        """For whole-vault rewrites: raises VaultBusyError if another process
        has the vault open."""
        with self._lock.exclusive():
            self._reload_if_changed()
            try:
                yield
            finally:
                self._seen_state = self._state_signature()

    def _wipe_stale_vault_files(self) -> list:
        """Removes files a lost previous key encrypted (after creating a new key
        or a confirmed reset). Returns the filenames removed.
        """
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
            if fname.endswith((MANIFEST_SUFFIX, TRAITS_SUFFIX, MANIFEST_SUFFIX + ".tmp", TRAITS_SUFFIX + ".tmp")):
                os.remove(os.path.join(self.storage_root, fname))
                removed.append(fname)
        return removed

    def _load_catalog(self) -> None:
        """Decrypts and loads the catalog (file name -> recipe), updating the existing dictionary in place."""
        path = os.path.join(self.storage_root, CATALOG_FILENAME)
        if os.path.exists(path):
            with open(path, "rb") as f:
                encrypted = f.read()
            raw = self.crypto.decrypt_block(encrypted, associated_data=b"catalog")
            loaded = pickle.loads(raw)
        else:
            loaded = {}
        # In place: front ends hold a reference to this dict.
        self.catalog.clear()
        self.catalog.update(loaded)

    def save_catalog(self) -> None:
        """Encrypts the catalog and replaces the file atomically."""
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
        """Decrypts a recipe file and returns its metadata."""
        manifest_filename = os.path.basename(manifest_path)
        with open(manifest_path, "rb") as f:
            encrypted = f.read()
        raw = self.crypto.decrypt_block(encrypted, associated_data=manifest_filename.encode())
        engine = FKSLookupEngine(raw_bytes=raw)
        return engine.metadata

    def read_similarity_fingerprint(self, manifest_path: str, metadata: dict = None):
        """Returns the similarity fingerprints stored for a recipe, or None."""
        return read_similarity_fingerprint(manifest_path, self.crypto, metadata)

    def similarity_fingerprint_count(self, manifest_path: str, metadata: dict = None):
        """Returns how many similarity fingerprints a recipe has, without loading them all if possible."""
        return similarity_fingerprint_count(manifest_path, self.crypto, metadata)

    def manifest_path_for(self, label: str) -> str:
        """Returns the full path of the recipe for a file name."""
        return os.path.join(self.storage_root, self.catalog[label])

    @_changes_vault
    def commit_write(self, label: str, source_path: str, similarity_fingerprint=None,
                      lateral_parent_labels=None, fork_from_generation=None) -> str:
        """Stores a file as `label`: writes it, records a lineage generation and
        saves the catalog -- the one write path for every front end.

        A byte-identical resave (same manifest, not a fork) records no generation.
        lateral_parent_labels: other labels whose current tips become extra
        parents (graft). fork_from_generation: make that past generation the
        primary parent instead of the tip, creating a branch. The catalog always
        points at the most recent write.
        """
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

    @_changes_vault
    def lateral_gene_transfer(self, label_a: str, label_b: str, new_label: str) -> str:
        """Grafts two labels into new_label: label_a's content followed by
        label_b's, with both current tips recorded as parents. Content-agnostic;
        since both inputs' chunks are already stored, usually only the seam
        chunk is new.
        """
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

            # Fingerprinted synchronously: both inputs are already bounded, stored files.
            fingerprint = PhylogeneticAnalyzer(SIMILARITY_PROFILE).extract_traits(tmp_combined)

            return self.commit_write(new_label, tmp_combined, similarity_fingerprint=fingerprint,
                                      lateral_parent_labels=[label_a, label_b])
        finally:
            for tmp in (tmp_a, tmp_b, tmp_combined):
                if os.path.exists(tmp):
                    os.remove(tmp)

    def _manifest_reference_count(self, manifest_filename: str) -> int:
        """References to a manifest file from catalog tips plus every lineage
        generation. Labels or generations with identical content share one
        manifest, so it may only be deleted at zero.
        """
        count = sum(1 for filename in self.catalog.values() if filename == manifest_filename)
        for label in self.lineage.all_labels():
            count += sum(1 for node in self.lineage.get_history(label) if node.manifest_filename == manifest_filename)
        return count

    @_changes_vault
    def delete_label(self, label: str, force: bool = False) -> dict:
        """Removes a label: its catalog entry and its whole history. A manifest
        is deleted only once nothing else references it.

        Refuses a "protected" tip unless force=True. Returns
        {"manifests_freed": int, "manifests_kept_shared": int}.
        """
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
            if node.manifest_filename is not None
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
        """Every manifest filename referenced by a catalog tip or a live generation."""
        names = set(self.catalog.values())
        for label in self.lineage.all_labels():
            names.update(
                node.manifest_filename for node in self.lineage.get_history(label)
                if node.manifest_filename is not None
            )
        return names

    def rename_label(self, old_label: str, new_label: str) -> None:
        """Renames a file; its content and history are unchanged."""
        with self._changing():
            if old_label not in self.catalog:
                raise KeyError(f"No such label: '{old_label}'")
            if new_label in self.catalog:
                raise ValueError(f"'{new_label}' already exists")
            self.catalog[new_label] = self.catalog.pop(old_label)
            self.lineage.rename_label(old_label, new_label)
            self.save_catalog()

    def set_tag(self, label: str, key: str, value) -> None:
        """Sets a tag on a file's history."""
        with self._changing():
            self.lineage.set_tag(label, key, value)

    def remove_tag(self, label: str, key: str) -> bool:
        """Removes a tag from a file; returns whether it was there."""
        with self._changing():
            return self.lineage.remove_tag(label, key)

    def rotate_keys(self) -> int:
        """Starts a new key epoch: new chunks are encrypted with a fresh data key; returns its number."""
        with self._changing():
            return self.pipeline.rotate_keys()

    def change_passphrase(self, old_passphrase: str, new_passphrase: str) -> None:
        """Re-wraps the same key; other processes' sessions are unaffected."""
        with self._changing():
            change_passphrase(self.storage_root, old_passphrase, new_passphrase)

    @property
    def mirror_all(self) -> bool:
        """True if spare copies are kept for every chunk (the 'spares all' setting)."""
        return bool(self.pipeline.settings.get("mirror_all"))

    def set_mirror_all(self, enabled: bool) -> int:
        """Spare copies for every chunk (True) or only chunks shared by 3+
        manifests (False, the default). Turning it on mirrors existing chunks
        now; returns how many. Turning it off keeps the spares already made.
        """
        with self._changing():
            self.pipeline.settings["mirror_all"] = bool(enabled)
            self.pipeline.save_settings()
            return self.pipeline.mirror_existing_chunks() if enabled else 0

    def fsck(self) -> dict:
        """Verifies every chunk and repairs from mirrors; needs the vault to itself."""
        with self.sole_use():
            return self.pipeline.verify_and_repair()

    def vacuum(self) -> dict:
        """Repairs chunk ref counts from the catalog and lineage, then reclaims
        unreferenced space. Needs the vault to itself (VaultBusyError if
        another process has it open): it rewrites the container.
        """
        with self.sole_use():
            live = self._live_manifest_filenames()
            repair_report = self.pipeline.rebuild_ref_counts(live)
            orphan_report = self.pipeline.sweep_orphaned_manifests(live)
            vacuum_report = self.pipeline.vacuum()
        vacuum_report["chunks_corrected"] = repair_report["chunks_corrected"]
        vacuum_report["orphaned_manifests_removed"] = orphan_report["removed"]
        vacuum_report["orphaned_tmp_files_removed"] = orphan_report["tmp_removed"]
        return vacuum_report

    @_changes_vault
    def prune_generation(self, label: str, generation_index: int, force: bool = False) -> dict:
        """Frees one past generation's storage, keeping the label and its other
        generations. Refuses the current tip, and a "protected" generation
        unless force=True. Returns {"freed": bool}; False if the manifest is
        still referenced elsewhere.
        """
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
        """Lowest common ancestor along primary parents."""
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
        """A manifest's ordered content hashes."""
        manifest_path = os.path.join(self.storage_root, manifest_filename)
        with open(manifest_path, "rb") as f:
            raw = self.crypto.decrypt_block(f.read(), associated_data=os.path.basename(manifest_path).encode())
        engine = FKSLookupEngine(raw_bytes=raw)
        total = engine.metadata.get("total_blocks", 0)
        return [engine.lookup(i) for i in range(total)]

    def get_generation_chunk_hashes(self, label: str, generation_index: int) -> list:
        """Generation `generation_index`'s ordered content hashes. ValueError if missing or pruned."""
        node = self.lineage.get_generation(label, generation_index)
        if node is None:
            raise ValueError(f"No generation {generation_index} recorded for '{label}'.")
        if node.manifest_filename is None:
            raise ValueError(
                f"Generation {generation_index} of '{label}' is pruned -- its content is no longer available."
            )
        return self._manifest_chunk_list(node.manifest_filename)

    @_changes_vault
    def merge_branches(self, label: str, generation_a: int, generation_b: int,
                       resolutions: Optional[Dict[int, str]] = None) -> str:
        """Merges two branches of `label` by a 3-way diff of chunk positions
        against their lowest common ancestor.

        Per position: unchanged or changed identically -> kept; changed by one
        branch -> that branch's; changed differently by both -> a conflict.
        `resolutions` ({position: "a" or "b"}) settles conflicts by taking that
        branch's chunk (or its end, if that branch ends there). Any conflict
        left unresolved raises MutationConflictError and nothing is committed.
        The result is committed as an ordinary write with generation_a as
        primary parent and generation_b as lateral parent. Returns the new
        manifest path.
        """
        resolutions = resolutions or {}
        bad = [side for side in resolutions.values() if side not in ("a", "b")]
        if bad:
            raise ValueError(f"A resolution must be 'a' or 'b', not {bad[0]!r}.")
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

        # Sentinel for "this branch has no chunk at this position": unequal to
        # any hash, and distinct from a winning choice of absence (truncation).
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
                winner = a  # both changed the same way (including both truncating)
            elif i in resolutions:
                winner = a if resolutions[i] == "a" else b
            else:
                # Changed differently by both, including truncation vs. edit.
                conflicts.append(i)
                continue

            if winner is _ABSENT:
                # Truncated here: end the merged sequence.
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
