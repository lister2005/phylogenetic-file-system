"""
One interface over both engines for pfs_gui.py: PythonEngineAdapter wraps
VaultSession, CppEngineAdapter wraps CppVaultSession. Covers what the GUI
uses: labels, metadata, lineage, the mutating operations, and file content
only through checkout()/reconstruct_current().
"""
import os
import tempfile
from contextlib import contextmanager

from clade_worker import CladeWorker, filtered_view, python_session_loader, cpp_session_loader
from reconstruct import reconstruct
from vault_session import MutationConflictError
from PhylogeneticAnalyzer import PhylogeneticAnalyzer, SIMILARITY_PROFILE
from gearhash.pipeline import release_free_memory
from gearhash import master_key_store
from gearhash.master_key_store import WrongPassphraseError
import restricted
from secret_store import MemoryFile, is_secret, read_via_memory, variable_history
from text_merge import MAX_TEXT_MERGE_CHUNKS, merge_bytes

@contextmanager
def _scratch_file(in_memory: bool):
    """Yields a path for temporary content: an in-memory file for secret
    content, an ordinary temporary file otherwise (large files would not fit
    comfortably in memory). Removed afterwards either way."""
    if in_memory:
        with MemoryFile() as mem:
            yield mem.path
        return
    fd, tmp_path = tempfile.mkstemp(prefix="pfs_gui_dup_")
    os.close(fd)
    try:
        yield tmp_path
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)


class NodeInfo:
    """A lineage node in either engine; uuids are hex strings in both."""
    __slots__ = ("node_uuid", "parent_uuid", "generation_index", "new_chunks", "total_chunks",
                 "pruned", "birth_timestamp", "manifest_filename", "label", "lateral_parent_uuids")

    def __init__(self, node_uuid, parent_uuid, generation_index, new_chunks, total_chunks,
                 pruned, birth_timestamp, manifest_filename, label, lateral_parent_uuids=()):
        """Stores one version's fields in the same shape for both engines."""
        self.node_uuid = node_uuid
        self.parent_uuid = parent_uuid
        self.generation_index = generation_index
        self.new_chunks = new_chunks
        self.total_chunks = total_chunks
        self.pruned = pruned
        self.birth_timestamp = birth_timestamp
        self.manifest_filename = manifest_filename
        self.label = label
        self.lateral_parent_uuids = list(lateral_parent_uuids)


class _CladeTracking:
    """Keeps a background clade worker (clade_worker.py) in step with changes
    made through the adapter, for the GUI's clade outlines.
    """

    _clade_worker = None
    _clade_stopped = False

    def _clade_loader(self):
        """Returns the function the clade worker uses to load a file's fingerprints (engine-specific)."""
        raise NotImplementedError

    def start_clade_worker(self) -> None:
        """Starts the background clade worker on first use, unless it was stopped for good."""
        if self._clade_worker is None and not self._clade_stopped:
            self._clade_worker = CladeWorker(self._clade_loader(), name="gui-clade-worker").start(self.labels())

    def stop_clade_worker(self) -> None:
        """Stops it for good."""
        self._clade_stopped = True
        if self._clade_worker is not None:
            self._clade_worker.stop(timeout=10)
            self._clade_worker = None

    def clade_version(self) -> int:
        """Returns the current grouping's version number, so the GUI knows when to redraw."""
        self.start_clade_worker()
        return self._clade_worker.snapshot().version if self._clade_worker else 0

    def clades(self, wait: float = 0.0):
        """(clade_to_labels, label_to_clade, version) for clades with 2+ current
        members, after waiting up to `wait` seconds for pending work.
        """
        self.start_clade_worker()
        if self._clade_worker is None:
            return {}, {}, 0
        if wait:
            self._clade_worker.wait_idle(wait)
        snapshot = self._clade_worker.snapshot()
        clade_to_labels, label_to_clade = filtered_view(snapshot, set(self.labels()), min_members=2)
        return clade_to_labels, label_to_clade, snapshot.version

    def clade_tree(self, algorithm: str, labels, wait: float = 0.0):
        """The worker's background UPGMA/NJ tree over exactly `labels`, or None
        if it isn't ready within `wait` seconds (then build it directly).
        """
        self.start_clade_worker()
        if self._clade_worker is None:
            return None
        return self._clade_worker.tree(algorithm, labels, timeout=wait)

    # ---------- secrets mode (both engines) ----------

    def is_secret(self, label: str) -> bool:
        """True if the file is tagged secret."""
        return is_secret(self.get_tags(label))

    def read_raw(self, label: str, generation_index=None) -> bytes:
        """A file's stored content (latest, or one generation), rebuilt in
        memory without touching the disk; still sealed if it is restricted."""
        if generation_index is None:
            return read_via_memory(lambda path: self.reconstruct_current(label, path))
        return read_via_memory(lambda path: self.checkout(label, generation_index, path))

    def read_bytes(self, label: str, generation_index=None) -> bytes:
        """A file's content as the current user can read it, in memory.
        restricted.NotARecipientError if it is restricted to other users."""
        return restricted.open_content(self.read_raw(label, generation_index), self.user)

    def _commit_raw(self, label: str, data: bytes) -> None:
        """Stores data, exactly as given, as the next version of label, from memory."""
        with MemoryFile() as mem:
            mem.write(data)
            self.commit_write(label, mem.path)

    def _seal_like_current(self, label: str, data: bytes) -> bytes:
        """data sealed for the same users as label's current version, if that is restricted."""
        if not self.has_label(label):
            return data
        return restricted.reseal_like(self.read_raw(label), data, self.public_keys())

    def commit_bytes(self, label: str, data: bytes) -> None:
        """Stores data as the next version of label, from memory; a restricted
        file stays restricted to the same users."""
        self._commit_raw(label, self._seal_like_current(label, data))

    def verify_passphrase(self, passphrase: str) -> bool:
        """True if the passphrase is the current user's (for the auto-lock)."""
        user = self.user
        try:
            keys = master_key_store.unlock_user(self.storage_root, passphrase, user.name if user else None)
        except (WrongPassphraseError, OSError, ValueError):
            return False
        known = self._known_kek()
        return known is None or keys.kek == known

    # ---------- users and restricted files (both engines) ----------

    @property
    def user(self):
        """Who unlocked the vault (master_key_store.UserKeys), if known."""
        return None

    def users(self) -> list:
        """The vault's user names."""
        return master_key_store.list_users(self.storage_root)

    def public_keys(self) -> dict:
        """{user name: public key}."""
        return master_key_store.public_keys(self.storage_root, self._known_kek())

    def add_user(self, name: str, passphrase: str) -> None:
        """Adds a user with their own passphrase."""
        master_key_store.add_user(self.storage_root, self._known_kek(), name, passphrase)

    def remove_user(self, name: str) -> None:
        """Removes a user; refuses the current user and the last one."""
        if self.user is not None and name == self.user.name:
            raise master_key_store.UserError("You can't remove yourself while you are using the vault.")
        master_key_store.remove_user(self.storage_root, self._known_kek(), name)

    def restriction(self, label: str):
        """The users a file is restricted to, or None if it isn't restricted."""
        raw = self.read_raw(label)
        return restricted.recipients_of(raw) if restricted.is_sealed(raw) else None

    def restrict(self, label: str, names) -> list:
        """Restricts a file's latest version to these users (plus you), as a
        new version. Earlier versions stay readable by every user until they
        are shredded. Returns the users it is restricted to."""
        content = self.read_bytes(label)
        recipients = restricted.recipients_for(names, self.public_keys(), self.user.name)
        self._commit_raw(label, restricted.seal(content, recipients))
        self.set_tag(label, "secret", True)
        self.set_tag(label, "no_graft_source", True)
        self.set_tag(label, restricted.RESTRICTED_TAG, ", ".join(sorted(recipients)))
        return sorted(recipients)

    def unrestrict(self, label: str) -> None:
        """Saves the latest version unsealed, readable by every user again (it stays secret)."""
        self._commit_raw(label, self.read_bytes(label))
        self.remove_tag(label, restricted.RESTRICTED_TAG)
        self.remove_tag(label, "no_graft_source")

    def variable_history(self, label: str):
        """Per-variable history of a secret .env file (secret_store.variable_history):
        versions the current user can't read count as unreadable."""
        history = self.get_history(label)
        generation_of = {n.node_uuid: n.generation_index for n in history}
        versions = []
        for node in history:
            content = None
            if not node.pruned:
                try:
                    content = self.read_bytes(label, node.generation_index)
                except (restricted.NotARecipientError, ValueError):
                    content = None
            versions.append((node.generation_index, generation_of.get(node.parent_uuid), node.birth_timestamp,
                             content))
        return variable_history(versions)

    def _known_kek(self):
        """The key the vault was opened with, if known (engine-specific)."""
        return None

    # ---------- line-by-line merging (both engines) ----------

    def text_merge(self, label: str, generation_a: int, generation_b: int):
        """A line-by-line merge of two branches against their common ancestor
        (text_merge.MergeResult), or None if a version isn't text or is too
        large, in which case use merge_branches(). Reads in memory only."""
        base = self.merge_base(label, generation_a, generation_b)
        sizes = {n.generation_index: n.total_chunks for n in self.get_history(label)}
        if any((sizes.get(g) or 0) > MAX_TEXT_MERGE_CHUNKS for g in (base, generation_a, generation_b)):
            return None
        raws = [self.read_raw(label, g) for g in (base, generation_a, generation_b)]
        result = merge_bytes(*(restricted.open_content(raw, self.user) for raw in raws))
        if result is None and any(restricted.is_sealed(raw) for raw in raws):
            raise ValueError("This restricted file isn't text, so it can't be merged.")
        return result

    def commit_text_merge(self, label: str, generation_a: int, generation_b: int, text: str) -> None:
        """Stores merged text as the merge of two branches, from memory."""
        with MemoryFile() as mem:
            mem.write(self._seal_like_current(label, text.encode("utf-8")))
            self.commit_merged(label, generation_a, generation_b, mem.path)
        self._clade_event("changed", label)

    def _clade_event(self, kind: str, *labels) -> None:
        # start() loads every label, so nothing to report before it.
        """Passes a file event to the clade worker, if it is running."""
        if self._clade_worker is not None:
            getattr(self._clade_worker, kind)(*labels)


class PythonEngineAdapter(_CladeTracking):
    """Wraps vault_session.VaultSession."""

    def __init__(self, session):
        """Wraps a Python-engine session and listens for changes made by other programs."""
        self._session = session
        session.add_change_listener(self._on_external_change)

    def _on_external_change(self, changed, removed) -> None:
        """Tells the clade worker about files other programs changed or removed."""
        for label in removed:
            self._clade_event("removed", label)
        for label in changed:
            self._clade_event("changed", label)

    def refresh(self) -> bool:
        """Picks up other programs' changes to the vault; True if any."""
        return self._session.refresh()

    @property
    def storage_root(self) -> str:
        """Returns the vault folder."""
        return self._session.storage_root

    @property
    def container_path(self) -> str:
        """Returns the path of the main chunk container."""
        return self._session.pipeline.container_path

    def labels(self) -> list:
        """Returns the names of the files currently in the vault."""
        return list(self._session.catalog.keys())

    def all_labels(self) -> list:
        """Returns the names of all files that have a history."""
        return self._session.lineage.all_labels()

    def has_label(self, label: str) -> bool:
        """True if a file with this name is in the vault."""
        return label in self._session.catalog

    def get_metadata(self, label: str):
        """Returns a summary of a file's latest recipe (size, chunks, type), or None."""
        manifest_filename = self._session.catalog.get(label)
        if manifest_filename is None:
            return None
        manifest_path = os.path.join(self._session.storage_root, manifest_filename)
        try:
            meta = self._session.read_manifest_metadata(manifest_path)
        except FileNotFoundError:
            return None
        return {
            "total_blocks": meta.get("total_blocks", 0),
            "duplicate_chunks_found": meta.get("duplicate_chunks_found", 0),
            "original_size": meta.get("original_size", 0),
            "phenotype_name": meta.get("phenotype_name", "Unknown Binary"),
            "similarity_fingerprint": self._session.read_similarity_fingerprint(manifest_path, meta),
            "manifest_filename": manifest_filename,
        }

    @staticmethod
    def _node_info(node) -> NodeInfo:
        """Converts a Python-engine version record into a NodeInfo."""
        return NodeInfo(node.node_uuid, node.parent_uuid, node.generation_index, node.new_chunks,
                         node.total_chunks, node.pruned, node.birth_timestamp, node.manifest_filename,
                         node.label, node.lateral_parent_uuids)

    def get_history(self, label: str) -> list:
        """Returns every version of a file, oldest first."""
        return [self._node_info(n) for n in self._session.lineage.get_history(label)]

    def get_heads(self, label: str) -> list:
        """Returns the latest version of each branch of a file."""
        return [self._node_info(n) for n in self._session.lineage.get_heads(label)]

    def get_generation(self, label: str, generation_index: int):
        """Returns one generation of a file, or None."""
        node = self._session.lineage.get_generation(label, generation_index)
        return self._node_info(node) if node else None

    def get_chunk_hashes(self, label: str, generation_index: int) -> list:
        """This generation's ordered chunk hashes (for lineage diffs)."""
        return self._session.get_generation_chunk_hashes(label, generation_index)

    def find_node_by_uuid(self, uuid_hex: str):
        """Returns (file name, version) for a version UUID, or None."""
        node = self._session.lineage.find_node_by_uuid(uuid_hex)
        return (node.label, self._node_info(node)) if node else None

    def get_node_tags(self, uuid_hex: str) -> dict:
        """Returns the tags on one version."""
        node = self._session.lineage.find_node_by_uuid(uuid_hex)
        return dict(node.epigenetic_tags) if node else {}

    def get_tags(self, label: str) -> dict:
        """Returns a file's current tags."""
        return self._session.lineage.get_tags(label)

    def set_tag(self, label: str, key: str, value) -> None:
        """Sets a tag on a file."""
        self._session.set_tag(label, key, value)

    def remove_tag(self, label: str, key: str) -> None:
        """Removes a tag from a file."""
        self._session.remove_tag(label, key)

    def commit_write(self, label: str, path: str, fork_from_generation=None) -> None:
        # Fingerprinted synchronously, like the C++ engine's write path.
        """Fingerprints the file and stores it as the next version (or a branch from an older one)."""
        fingerprint = PhylogeneticAnalyzer(SIMILARITY_PROFILE).extract_traits(path)
        manifest_path = self._session.commit_write(
            label, path, fork_from_generation=fork_from_generation, similarity_fingerprint=fingerprint)
        del fingerprint
        release_free_memory()
        self._clade_event("changed", label)
        return manifest_path

    def delete_label(self, label: str, force: bool = False) -> dict:
        """Deletes a file and its history; returns what was freed."""
        report = self._session.delete_label(label, force=force)
        self._clade_event("removed", label)
        return report

    def rename_label(self, old_label: str, new_label: str) -> None:
        """Renames a file."""
        self._session.rename_label(old_label, new_label)
        self._clade_event("renamed", old_label, new_label)

    def prune_generation(self, label: str, generation_index: int, force: bool = False) -> dict:
        """Frees one old generation's storage."""
        return self._session.prune_generation(label, generation_index, force=force)

    def merge_branches(self, label: str, generation_a: int, generation_b: int, resolutions=None) -> None:
        """Merges two branches of a file, using the user's choices for any clashing parts."""
        self._session.merge_branches(label, generation_a, generation_b, resolutions)
        self._clade_event("changed", label)

    def checkout(self, label: str, generation_index: int, out_path: str) -> None:
        """Rebuilds one generation of a file into out_path; fails if it was pruned."""
        node = self._session.lineage.get_generation(label, generation_index)
        if node is None or node.manifest_filename is None:
            raise ValueError("That generation's content is no longer available (pruned).")
        manifest_path = os.path.join(self._session.storage_root, node.manifest_filename)
        reconstruct(manifest_path, self._session.pipeline.container_path, out_path, self._session.crypto.key,
                    quiet=True)

    def reconstruct_current(self, label: str, out_path: str) -> None:
        """Rebuilds the latest version of a file into out_path."""
        manifest_path = self._session.manifest_path_for(label)
        reconstruct(manifest_path, self._session.pipeline.container_path, out_path, self._session.crypto.key,
                    quiet=True)

    def duplicate_label(self, label: str, new_label: str) -> None:
        """Makes a second file with the same content, recorded as made from the first."""
        secret = self.is_secret(label)
        with _scratch_file(secret) as tmp_path:
            self.reconstruct_current(label, tmp_path)
            fingerprint = PhylogeneticAnalyzer(SIMILARITY_PROFILE).extract_traits(tmp_path)
            self._session.commit_write(new_label, tmp_path, lateral_parent_labels=[label],
                                        similarity_fingerprint=fingerprint)
            del fingerprint
            release_free_memory()
        if secret:
            self.set_tag(new_label, "secret", True)
            source_tags = self.get_tags(label)
            for key in ("no_graft_source", restricted.RESTRICTED_TAG):  # a restricted copy stays sealed
                if key in source_tags:
                    self.set_tag(new_label, key, source_tags[key])
        self._clade_event("changed", new_label)

    def graft(self, label_a: str, label_b: str, new_label: str) -> None:
        # lateral_gene_transfer attaches its own fingerprint.
        """Makes a new file combining two files, recorded as descended from both."""
        self._session.lateral_gene_transfer(label_a, label_b, new_label)
        self._clade_event("changed", new_label)

    def _clade_loader(self):
        """Returns the fingerprint loader for a Python-engine vault."""
        return python_session_loader(self._session)

    def _known_kek(self):
        """The key the vault was opened with."""
        return self._session.crypto.key

    @property
    def user(self):
        """Who unlocked the vault."""
        return self._session.user

    def add_user(self, name: str, passphrase: str) -> None:
        """Adds a user (under the vault's write lock)."""
        self._session.add_user(name, passphrase)

    def remove_user(self, name: str) -> None:
        """Removes a user; refuses the current user and the last one (under the write lock)."""
        if name == self._session.user.name:
            raise master_key_store.UserError("You can't remove yourself while you are using the vault.")
        self._session.remove_user(name)

    def merge_base(self, label: str, generation_a: int, generation_b: int) -> int:
        """The generation two branches last had in common."""
        return self._session.merge_base(label, generation_a, generation_b)

    def commit_merged(self, label: str, generation_a: int, generation_b: int, source_path: str) -> None:
        """Commits caller-merged content as the merge of two branches."""
        self._session.commit_merged(label, generation_a, generation_b, source_path)

    def shred(self, label: str, generation_index=None, force: bool = False) -> dict:
        """Securely erases a file, or one old version (see VaultSession.shred)."""
        report = self._session.shred(label, generation_index, force=force)
        if generation_index is None:
            self._clade_event("removed", label)
        return report


class CppEngineAdapter(_CladeTracking):
    """Wraps pfs_engine_binding.CppVaultSession."""

    def __init__(self, session, kek: bytes = None, user=None):
        """Wraps a C++-engine session. kek (if given) lets the auto-lock check
        a re-entered passphrase and lets users be managed; user
        (master_key_store.UserKeys) is who unlocked it, for restricted files."""
        self._session = session
        self._kek = kek
        self._user = user

    def refresh(self) -> bool:
        """Picks up other programs' changes to the vault and tells the clade
        worker which files changed; True if any."""
        if self._clade_worker is not None and getattr(self, "_seen_view", None) is None:
            self._seen_view = self._catalog_view()  # once; later views come only after a change
        if not self._session.refresh():
            return False
        if self._clade_worker is not None:
            before, after = self._seen_view, self._catalog_view()
            for label in before.keys() - after.keys():
                self._clade_event("removed", label)
            for label, manifest in after.items():
                if before.get(label) != manifest:
                    self._clade_event("changed", label)
            self._seen_view = after
        return True

    def _catalog_view(self) -> dict:
        """label -> recipe filename, for telling what another program changed."""
        view = {}
        for label in self._session.list_labels():
            try:
                view[label] = self._session.get_manifest_info(label)["manifest_filename"]
            except Exception:  # removed meanwhile
                continue
        return view

    @property
    def storage_root(self) -> str:
        """Returns the vault folder."""
        return self._session.storage_root

    @property
    def container_path(self) -> str:
        """Returns the path of the main chunk container."""
        return self._session.container_path

    def labels(self) -> list:
        """Returns the names of the files currently in the vault."""
        return self._session.list_labels()

    def all_labels(self) -> list:
        """Returns the names of all files (the same list as labels() for this engine)."""
        return self._session.list_labels()

    def has_label(self, label: str) -> bool:
        """True if a file with this name is in the vault."""
        return label in self._session.list_labels()

    def get_metadata(self, label: str):
        """Returns a summary of a file's latest recipe (size, chunks, type), or None."""
        try:
            info = self._session.get_manifest_info(label)
        except Exception:
            return None
        fingerprint = self._session.get_fingerprint(label) if info["has_similarity_fingerprint"] else None
        return {
            "total_blocks": info["total_blocks"],
            "duplicate_chunks_found": info["duplicate_chunks_found"],
            "original_size": info["original_size"],
            "phenotype_name": info["phenotype_name"],
            "similarity_fingerprint": fingerprint,
            "manifest_filename": info["manifest_filename"],
        }

    def _node_info(self, gen_info, label: str) -> NodeInfo:
        """Converts a C++-engine version record into a NodeInfo."""
        lateral_uuids = (self._session.get_lateral_parents(gen_info.node_uuid_hex)
                         if gen_info.lateral_parent_count else [])
        return NodeInfo(gen_info.node_uuid_hex, gen_info.parent_uuid_hex, gen_info.generation_index,
                         gen_info.new_chunks, gen_info.total_chunks, gen_info.pruned,
                         gen_info.birth_timestamp, None, label, lateral_uuids)

    def get_history(self, label: str) -> list:
        """Returns every version of a file, oldest first."""
        return [self._node_info(n, label) for n in self._session.get_history(label)]

    def get_heads(self, label: str) -> list:
        """Returns the latest version of each branch of a file."""
        return [self._node_info(n, label) for n in self._session.get_heads(label)]

    def get_generation(self, label: str, generation_index: int):
        """Returns one generation of a file, or None."""
        for node in self._session.get_history(label):
            if node.generation_index == generation_index:
                return self._node_info(node, label)
        return None

    def get_chunk_hashes(self, label: str, generation_index: int) -> list:
        """This generation's ordered chunk hashes (for lineage diffs)."""
        return self._session.get_generation_chunk_hashes(label, generation_index)

    def find_node_by_uuid(self, uuid_hex: str):
        """Returns (file name, version) for a version UUID, or None."""
        found = self._session.find_node_by_uuid(uuid_hex)
        if found is None:
            return None
        label, gen_info = found
        return label, self._node_info(gen_info, label)

    def get_node_tags(self, uuid_hex: str) -> dict:
        """Returns the tags on one version."""
        return self._session.get_node_tags(uuid_hex)

    def get_tags(self, label: str) -> dict:
        """Returns a file's current tags."""
        return self._session.get_tags(label)

    def set_tag(self, label: str, key: str, value) -> None:
        """Sets a tag on a file."""
        self._session.set_tag(label, key, value)

    def remove_tag(self, label: str, key: str) -> None:
        """Removes a tag from a file."""
        self._session.remove_tag(label, key)

    def commit_write(self, label: str, path: str, fork_from_generation=None) -> None:
        """Stores a file as the next version, or as a branch from an older generation."""
        if fork_from_generation is not None:
            self._session.fork_write(label, path, fork_from_generation)
        else:
            self._session.commit_write(label, path)
        self._clade_event("changed", label)

    def delete_label(self, label: str, force: bool = False) -> dict:
        """Deletes a file and its history (shredding it if it is secret); returns what was freed."""
        if self.is_secret(label):
            return self.shred(label, None, force=force)
        report = self._session.delete_label(label, force=force)
        self._clade_event("removed", label)
        return report

    def rename_label(self, old_label: str, new_label: str) -> None:
        """Renames a file."""
        self._session.rename_label(old_label, new_label)
        self._clade_event("renamed", old_label, new_label)

    def prune_generation(self, label: str, generation_index: int, force: bool = False):
        """Frees one old generation's storage (shredding it if the file is secret)."""
        if self.is_secret(label):
            report = self.shred(label, generation_index, force=force)
            return {"freed": report["manifests_freed"] > 0, **report}
        self._session.prune_generation(label, generation_index, force=force)

    def merge_branches(self, label: str, generation_a: int, generation_b: int, resolutions=None) -> None:
        """Merges two branches of a file, using the user's choices for any clashing parts."""
        from pfs_engine_binding import PfsMergeConflictError  # only importable with the C++ engine built
        try:
            self._session.merge_branches(label, generation_a, generation_b, resolutions)
        except PfsMergeConflictError as e:
            raise MutationConflictError(e.conflicting_positions) from e
        self._clade_event("changed", label)

    def checkout(self, label: str, generation_index: int, out_path: str) -> None:
        """Rebuilds one generation of a file into out_path."""
        self._session.checkout(label, generation_index, out_path)

    def reconstruct_current(self, label: str, out_path: str) -> None:
        """Rebuilds the latest version of a file into out_path."""
        self._session.reconstruct_label(label, out_path)

    def duplicate_label(self, label: str, new_label: str) -> None:
        """Makes a second file with the same content, recorded as made from the first."""
        secret = self.is_secret(label)
        with _scratch_file(secret) as tmp_path:
            self.reconstruct_current(label, tmp_path)
            self._session.commit_write_lateral(new_label, tmp_path, label)
        if secret:
            self.set_tag(new_label, "secret", True)
            source_tags = self.get_tags(label)
            for key in ("no_graft_source", restricted.RESTRICTED_TAG):  # a restricted copy stays sealed
                if key in source_tags:
                    self.set_tag(new_label, key, source_tags[key])
        self._clade_event("changed", new_label)

    def graft(self, label_a: str, label_b: str, new_label: str) -> None:
        """Makes a new file combining two files, recorded as descended from both."""
        self._session.graft(label_a, label_b, new_label)
        self._clade_event("changed", new_label)

    def _clade_loader(self):
        """Returns the fingerprint loader for a C++-engine vault."""
        return cpp_session_loader(self._session)

    def _known_kek(self):
        """The key the vault was opened with, if it was given."""
        return self._kek

    @property
    def user(self):
        """Who unlocked the vault, if it was given."""
        return self._user

    def merge_base(self, label: str, generation_a: int, generation_b: int) -> int:
        """The generation two branches last had in common (ValueError if they can't be merged)."""
        from pfs_engine_binding import PfsEngineError  # only importable with the C++ engine built
        try:
            return self._session.merge_base(label, generation_a, generation_b)
        except PfsEngineError as e:
            raise ValueError(str(e))

    def commit_merged(self, label: str, generation_a: int, generation_b: int, source_path: str) -> None:
        """Commits caller-merged content as the merge of two branches."""
        self._session.commit_merged(label, generation_a, generation_b, source_path)

    def shred(self, label: str, generation_index=None, force: bool = False) -> dict:
        """Securely erases a file, or one old version (see VaultSession.shred)."""
        report = self._session.shred(label, generation_index, force=force)
        if generation_index is None:
            self._clade_event("removed", label)
        return report

    def close(self) -> None:
        """Stops the clade worker and closes the vault."""
        self.stop_clade_worker()
        self._session.close()
