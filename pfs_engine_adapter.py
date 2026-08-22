"""
Engine-abstraction layer for pfs_gui.py -- lets the GUI run against
either the Python engine (vault_session.VaultSession) or the compiled
C++ engine (pfs_engine_binding.CppVaultSession) without knowing which
one it's actually talking to. This exists because the two engines'
Python-facing shapes differ in real ways (VaultSession exposes
.catalog/.lineage/.pipeline/.crypto as separate objects with their own
methods; CppVaultSession is a single flat ctypes wrapper) -- pfs_gui.py
is written once against the interface below, and each adapter class
translates it into whichever engine's real calls.

Only wraps what pfs_gui.py actually uses (surveyed directly against the
GUI's own `self.session.*`/`window.session.*` call sites, not guessed):
catalog/label listing, manifest metadata, lineage history/heads/
generations/tags, and the mutating operations (write, fork, graft,
duplicate, merge, prune, delete, rename, tag/untag). Read-only file
content access always goes through checkout()/reconstruct_current(),
never raw manifest paths -- the one place the two engines' on-disk
layouts (pickle vs. the new binary formats) would otherwise leak
through this abstraction.
"""
import os
import re
import tempfile

from reconstruct import reconstruct
from vault_session import MutationConflictError
from PhylogeneticAnalyzer import PhylogeneticAnalyzer, SIMILARITY_PROFILE

_CONFLICT_POSITIONS_RE = re.compile(r"since their common ancestor:\s*([\d,\s]+)")


def _parse_conflict_positions(message: str) -> list:
    """Recovers the conflicting chunk positions from the C++ engine's
    MutationConflictError-equivalent message text (its own build_message
    in merge.hpp uses the same wording and the same first-10 truncation
    Python's own MutationConflictError does) -- lets the C++ path raise
    the SAME exception type pfs_gui.py already knows how to catch,
    rather than needing a second catch clause throughout the GUI."""
    m = _CONFLICT_POSITIONS_RE.search(message)
    if not m:
        return []
    return [int(tok) for tok in m.group(1).split(",") if tok.strip().isdigit()]


class NodeInfo:
    """Uniform lineage-node view, regardless of backend. node_uuid/
    parent_uuid are hex strings in both engines already (Python's
    LineageNode uses uuid.uuid4().hex natively; the C++ binding returns
    node_uuid_hex/parent_uuid_hex) -- no conversion needed, which is
    what makes them usable as dict keys identically either way (the GUI
    keys its node-item map by node_uuid)."""
    __slots__ = ("node_uuid", "parent_uuid", "generation_index", "new_chunks", "total_chunks",
                 "pruned", "birth_timestamp", "manifest_filename", "label", "lateral_parent_uuids")

    def __init__(self, node_uuid, parent_uuid, generation_index, new_chunks, total_chunks,
                 pruned, birth_timestamp, manifest_filename, label, lateral_parent_uuids=()):
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


class PythonEngineAdapter:
    """Wraps vault_session.VaultSession."""

    def __init__(self, session):
        self._session = session

    @property
    def storage_root(self) -> str:
        return self._session.storage_root

    @property
    def container_path(self) -> str:
        return self._session.pipeline.container_path

    def labels(self) -> list:
        return list(self._session.catalog.keys())

    def all_labels(self) -> list:
        return self._session.lineage.all_labels()

    def has_label(self, label: str) -> bool:
        return label in self._session.catalog

    def get_metadata(self, label: str):
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
            "similarity_fingerprint": meta.get("similarity_fingerprint"),
            "manifest_filename": manifest_filename,
        }

    @staticmethod
    def _node_info(node) -> NodeInfo:
        return NodeInfo(node.node_uuid, node.parent_uuid, node.generation_index, node.new_chunks,
                         node.total_chunks, node.pruned, node.birth_timestamp, node.manifest_filename,
                         node.label, node.lateral_parent_uuids)

    def get_history(self, label: str) -> list:
        return [self._node_info(n) for n in self._session.lineage.get_history(label)]

    def get_heads(self, label: str) -> list:
        return [self._node_info(n) for n in self._session.lineage.get_heads(label)]

    def get_generation(self, label: str, generation_index: int):
        node = self._session.lineage.get_generation(label, generation_index)
        return self._node_info(node) if node else None

    def get_chunk_hashes(self, label: str, generation_index: int) -> list:
        """This generation's ordered chunk-hash list (bytes, one per
        block position) -- the primitive a real lineage diff (§2.2:
        comparing two generations of the SAME label's real edit
        history, NOT the clade-clustering similarity comparison
        _show_diff_between does) is built on."""
        return self._session.get_generation_chunk_hashes(label, generation_index)

    def find_node_by_uuid(self, uuid_hex: str):
        node = self._session.lineage.find_node_by_uuid(uuid_hex)
        return (node.label, self._node_info(node)) if node else None

    def get_node_tags(self, uuid_hex: str) -> dict:
        node = self._session.lineage.find_node_by_uuid(uuid_hex)
        return dict(node.epigenetic_tags) if node else {}

    def get_tags(self, label: str) -> dict:
        return self._session.lineage.get_tags(label)

    def set_tag(self, label: str, key: str, value) -> None:
        self._session.lineage.set_tag(label, key, value)

    def remove_tag(self, label: str, key: str) -> None:
        self._session.lineage.remove_tag(label, key)

    def commit_write(self, label: str, path: str, fork_from_generation=None) -> None:
        # Computed synchronously here, matching the C++ engine's own
        # write path exactly (see pipeline.cpp) -- pfs_cli.py instead
        # backgrounds this on a thread for its own reason (a shell
        # prompt shouldn't stall on a large file), but pfs_gui.py has
        # never had ANY mechanism to attach one at all: before this
        # fix, a file written through the GUI itself (not previously
        # written via the CLI) would silently never appear in Clade
        # Tree mode, with no error -- just an empty tree. Caught by
        # testing the two engines side by side through this exact
        # adapter, not assumed.
        fingerprint = PhylogeneticAnalyzer(SIMILARITY_PROFILE).extract_traits(path)
        manifest_path = self._session.commit_write(
            label, path, fork_from_generation=fork_from_generation, similarity_fingerprint=fingerprint)
        return manifest_path

    def delete_label(self, label: str, force: bool = False) -> dict:
        return self._session.delete_label(label, force=force)

    def rename_label(self, old_label: str, new_label: str) -> None:
        self._session.catalog[new_label] = self._session.catalog.pop(old_label)
        self._session.lineage.rename_label(old_label, new_label)
        self._session.save_catalog()

    def prune_generation(self, label: str, generation_index: int, force: bool = False) -> None:
        self._session.prune_generation(label, generation_index, force=force)

    def merge_branches(self, label: str, generation_a: int, generation_b: int) -> None:
        self._session.merge_branches(label, generation_a, generation_b)

    def checkout(self, label: str, generation_index: int, out_path: str) -> None:
        node = self._session.lineage.get_generation(label, generation_index)
        if node is None or node.manifest_filename is None:
            raise ValueError("That generation's content is no longer available (pruned).")
        manifest_path = os.path.join(self._session.storage_root, node.manifest_filename)
        reconstruct(manifest_path, self._session.pipeline.container_path, out_path, self._session.crypto.key)

    def reconstruct_current(self, label: str, out_path: str) -> None:
        manifest_path = self._session.manifest_path_for(label)
        reconstruct(manifest_path, self._session.pipeline.container_path, out_path, self._session.crypto.key)

    def duplicate_label(self, label: str, new_label: str) -> None:
        fd, tmp_path = tempfile.mkstemp(prefix="pfs_gui_dup_")
        os.close(fd)
        try:
            self.reconstruct_current(label, tmp_path)
            fingerprint = PhylogeneticAnalyzer(SIMILARITY_PROFILE).extract_traits(tmp_path)
            self._session.commit_write(new_label, tmp_path, lateral_parent_labels=[label],
                                        similarity_fingerprint=fingerprint)
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    def graft(self, label_a: str, label_b: str, new_label: str) -> None:
        # lateral_gene_transfer already computes+attaches its own
        # fingerprint internally (see vault_session.py) -- no fix
        # needed here, unlike duplicate_label/commit_write above.
        self._session.lateral_gene_transfer(label_a, label_b, new_label)


class CppEngineAdapter:
    """Wraps pfs_engine_binding.CppVaultSession."""

    def __init__(self, session):
        self._session = session

    @property
    def storage_root(self) -> str:
        return self._session.storage_root

    @property
    def container_path(self) -> str:
        return self._session.container_path

    def labels(self) -> list:
        return self._session.list_labels()

    def all_labels(self) -> list:
        return self._session.list_labels()

    def has_label(self, label: str) -> bool:
        return label in self._session.list_labels()

    def get_metadata(self, label: str):
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
        lateral_uuids = (self._session.get_lateral_parents(gen_info.node_uuid_hex)
                         if gen_info.lateral_parent_count else [])
        return NodeInfo(gen_info.node_uuid_hex, gen_info.parent_uuid_hex, gen_info.generation_index,
                         gen_info.new_chunks, gen_info.total_chunks, gen_info.pruned,
                         gen_info.birth_timestamp, None, label, lateral_uuids)

    def get_history(self, label: str) -> list:
        return [self._node_info(n, label) for n in self._session.get_history(label)]

    def get_heads(self, label: str) -> list:
        return [self._node_info(n, label) for n in self._session.get_heads(label)]

    def get_generation(self, label: str, generation_index: int):
        for node in self._session.get_history(label):
            if node.generation_index == generation_index:
                return self._node_info(node, label)
        return None

    def get_chunk_hashes(self, label: str, generation_index: int) -> list:
        """This generation's ordered chunk-hash list (bytes, one per
        block position) -- see PythonEngineAdapter.get_chunk_hashes for
        why this exists as a separate primitive from the clade/
        similarity comparison _show_diff_between does."""
        return self._session.get_generation_chunk_hashes(label, generation_index)

    def find_node_by_uuid(self, uuid_hex: str):
        found = self._session.find_node_by_uuid(uuid_hex)
        if found is None:
            return None
        label, gen_info = found
        return label, self._node_info(gen_info, label)

    def get_node_tags(self, uuid_hex: str) -> dict:
        return self._session.get_node_tags(uuid_hex)

    def get_tags(self, label: str) -> dict:
        return self._session.get_tags(label)

    def set_tag(self, label: str, key: str, value) -> None:
        self._session.set_tag(label, key, value)

    def remove_tag(self, label: str, key: str) -> None:
        self._session.remove_tag(label, key)

    def commit_write(self, label: str, path: str, fork_from_generation=None) -> None:
        if fork_from_generation is not None:
            self._session.fork_write(label, path, fork_from_generation)
        else:
            self._session.commit_write(label, path)

    def delete_label(self, label: str, force: bool = False) -> dict:
        return self._session.delete_label(label, force=force)

    def rename_label(self, old_label: str, new_label: str) -> None:
        self._session.rename_label(old_label, new_label)

    def prune_generation(self, label: str, generation_index: int, force: bool = False) -> None:
        self._session.prune_generation(label, generation_index, force=force)

    def merge_branches(self, label: str, generation_a: int, generation_b: int) -> None:
        try:
            self._session.merge_branches(label, generation_a, generation_b)
        except Exception as e:
            positions = _parse_conflict_positions(str(e))
            if positions or "changed differently" in str(e):
                raise MutationConflictError(positions) from e
            raise

    def checkout(self, label: str, generation_index: int, out_path: str) -> None:
        self._session.checkout(label, generation_index, out_path)

    def reconstruct_current(self, label: str, out_path: str) -> None:
        self._session.reconstruct_label(label, out_path)

    def duplicate_label(self, label: str, new_label: str) -> None:
        fd, tmp_path = tempfile.mkstemp(prefix="pfs_gui_dup_")
        os.close(fd)
        try:
            self.reconstruct_current(label, tmp_path)
            self._session.commit_write_lateral(new_label, tmp_path, label)
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    def graft(self, label_a: str, label_b: str, new_label: str) -> None:
        self._session.graft(label_a, label_b, new_label)

    def close(self) -> None:
        self._session.close()
