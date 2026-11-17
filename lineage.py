"""
Lineage DAG: each label's real edit history (V0 -> V1 -> ...).

Separate from TreeConstructor's clade clustering, which groups different
files by similarity. Each generation references its own complete manifest
(never a delta against its parent), so any generation can be checked out,
and pruning a middle one never breaks the others: pruning clears the
node's manifest_filename but keeps the node.

- parent_uuid: the previous generation of the same label. fork_from makes
  it any past generation, creating a branch; get_heads() lists the open
  branch tips. generation_index is a per-label creation counter, not depth.
- lateral_parent_uuids: parents from other labels (graft), or the other
  branch head of a merge.
- epigenetic_tags: copied from the primary parent into every new
  generation; set_tag/remove_tag change the current tip. VaultSession
  enforces "protected" and "no_graft_source"; other keys are informational.
  Lateral parents don't pass tags on.
"""

import os
import pickle
import struct
import time
import uuid
from typing import Dict, List, Optional

LINEAGE_FILENAME = "lineage.enc"

# On disk: a magic header, then length-framed encrypted records, each a
# full SNAPSHOT or one NODE. record_version appends a NODE (O(1) per write);
# the rarer delete/prune/rename/tag rewrite a SNAPSHOT.
_LINEAGE_MAGIC = b"PFSLIN02"
_RECORD_SNAPSHOT = b"S"
_RECORD_NODE = b"N"


class LineageNode:
    """One saved version of a file: its recipe, parents, generation number, chunk counts and tags."""
    __slots__ = ("node_uuid", "parent_uuid", "lateral_parent_uuids", "label", "manifest_filename",
                 "generation_index", "birth_timestamp", "new_chunks", "total_chunks", "pruned",
                 "epigenetic_tags")

    def __init__(self, label: str, manifest_filename: Optional[str], parent_uuid: Optional[str],
                 generation_index: int, new_chunks: int, total_chunks: int,
                 node_uuid: Optional[str] = None, birth_timestamp: Optional[float] = None,
                 lateral_parent_uuids: Optional[List[str]] = None, pruned: bool = False,
                 epigenetic_tags: Optional[Dict[str, object]] = None):
        """Creates a version record; a new UUID and timestamp are made if not given."""
        self.node_uuid = node_uuid or uuid.uuid4().hex
        self.parent_uuid = parent_uuid
        self.lateral_parent_uuids = list(lateral_parent_uuids) if lateral_parent_uuids else []
        self.label = label
        self.manifest_filename = manifest_filename
        self.generation_index = generation_index
        self.birth_timestamp = birth_timestamp if birth_timestamp is not None else time.time()
        self.new_chunks = new_chunks
        self.total_chunks = total_chunks
        # Pruning is one-way: manifest_filename is None from then on; the record stays.
        self.pruned = pruned
        # Copied from the parent at creation (see record_version).
        self.epigenetic_tags = dict(epigenetic_tags) if epigenetic_tags else {}

    def to_dict(self) -> dict:
        """Converts the record to a plain dictionary for saving."""
        return {slot: getattr(self, slot) for slot in self.__slots__}

    @classmethod
    def from_dict(cls, d: dict) -> "LineageNode":
        """Rebuilds a record from a dictionary, filling in fields that older records lack."""
        return cls(d["label"], d["manifest_filename"], d["parent_uuid"], d["generation_index"],
                    d["new_chunks"], d["total_chunks"],
                    node_uuid=d["node_uuid"], birth_timestamp=d["birth_timestamp"],
                    # Older records lack these keys.
                    lateral_parent_uuids=d.get("lateral_parent_uuids", []),
                    pruned=d.get("pruned", False),
                    epigenetic_tags=d.get("epigenetic_tags", {}))


class LineageStore:
    """The vault's history: every version of every file, kept in an encrypted, append-only file."""
    def __init__(self, storage_root: str, crypto):
        """Opens the history file of a vault and loads it."""
        self.storage_root = storage_root
        self.crypto = crypto
        self.path = os.path.join(storage_root, LINEAGE_FILENAME)
        self._history: Dict[str, List[LineageNode]] = {}
        # node_uuid -> LineageNode, kept current by every method that adds or removes nodes.
        self._by_uuid: Dict[str, LineageNode] = {}
        self._load()

    def _load(self) -> None:
        """Reads and decrypts the history file, record by record, into memory."""
        self._history = {}
        self._by_uuid = {}
        if not os.path.exists(self.path):
            return
        with open(self.path, "rb") as f:
            blob = f.read()

        if not blob.startswith(_LINEAGE_MAGIC):
            # Legacy unframed file: decrypt it, then compact it into the framed format.
            raw = self.crypto.decrypt_block(blob, associated_data=b"lineage")
            stored = pickle.loads(raw)
            self._history = {
                label: [LineageNode.from_dict(d) for d in nodes]
                for label, nodes in stored.items()
            }
            self._rebuild_by_uuid()
            self._save()
            return

        offset = len(_LINEAGE_MAGIC)
        while offset < len(blob):
            record_type = blob[offset:offset + 1]
            offset += 1
            (length,) = struct.unpack(">I", blob[offset:offset + 4])
            offset += 4
            encrypted = blob[offset:offset + length]
            offset += length
            if record_type == _RECORD_SNAPSHOT:
                raw = self.crypto.decrypt_block(encrypted, associated_data=b"lineage_snapshot")
                stored = pickle.loads(raw)
                self._history = {
                    label: [LineageNode.from_dict(d) for d in nodes]
                    for label, nodes in stored.items()
                }
            elif record_type == _RECORD_NODE:
                raw = self.crypto.decrypt_block(encrypted, associated_data=b"lineage_node")
                node = LineageNode.from_dict(pickle.loads(raw))
                self._history.setdefault(node.label, []).append(node)
            else:
                raise ValueError(f"Unknown lineage record type in {self.path}: {record_type!r}")
        self._rebuild_by_uuid()

    def _rebuild_by_uuid(self) -> None:
        """Rebuilds the UUID -> version lookup table from the loaded history."""
        self._by_uuid = {
            node.node_uuid: node
            for nodes in self._history.values()
            for node in nodes
        }

    def _save(self) -> None:
        """Rewrites the file as one snapshot. Used by the rare mutating operations."""
        stored = {label: [n.to_dict() for n in nodes] for label, nodes in self._history.items()}
        raw = pickle.dumps(stored)
        encrypted = self.crypto.encrypt_block(raw, associated_data=b"lineage_snapshot")
        framed = _LINEAGE_MAGIC + _RECORD_SNAPSHOT + struct.pack(">I", len(encrypted)) + encrypted
        tmp = self.path + ".tmp"
        with open(tmp, "wb") as f:
            f.write(framed)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, self.path)

    def _append_node(self, node: "LineageNode") -> None:
        """Appends one node record. Used by record_version, the per-write path."""
        raw = pickle.dumps(node.to_dict())
        encrypted = self.crypto.encrypt_block(raw, associated_data=b"lineage_node")
        framed = _RECORD_NODE + struct.pack(">I", len(encrypted)) + encrypted
        is_new_file = not os.path.exists(self.path)
        with open(self.path, "ab") as f:
            if is_new_file:
                f.write(_LINEAGE_MAGIC)
            f.write(framed)
            f.flush()
            os.fsync(f.fileno())

    def compact(self) -> None:
        """Collapses accumulated node records into one snapshot. Manual maintenance."""
        self._save()

    def record_version(self, label: str, manifest_filename: str, new_chunks: int, total_chunks: int,
                        lateral_parent_uuids: Optional[List[str]] = None,
                        fork_from: Optional[LineageNode] = None) -> LineageNode:
        """Appends a generation of `label`.

        The primary parent is fork_from (creating a branch) or the current tip.
        Tags are copied from the primary parent.
        """
        existing = self._history.get(label, [])
        parent = fork_from if fork_from is not None else (existing[-1] if existing else None)
        node = LineageNode(
            label=label,
            manifest_filename=manifest_filename,
            parent_uuid=parent.node_uuid if parent else None,
            generation_index=len(existing),
            new_chunks=new_chunks,
            total_chunks=total_chunks,
            lateral_parent_uuids=lateral_parent_uuids,
            epigenetic_tags=parent.epigenetic_tags if parent else None,
        )
        self._history.setdefault(label, []).append(node)
        self._by_uuid[node.node_uuid] = node
        self._append_node(node)
        return node

    def get_heads(self, label: str) -> List[LineageNode]:
        """Open branch tips: nodes that aren't another node's primary parent.
        Being a lateral parent doesn't count.
        """
        nodes = self._history.get(label, [])
        claimed_as_primary_parent = {n.parent_uuid for n in nodes if n.parent_uuid is not None}
        return [n for n in nodes if n.node_uuid not in claimed_as_primary_parent]

    def get_history(self, label: str) -> List[LineageNode]:
        """Chronological, generation 0 first."""
        return list(self._history.get(label, []))

    def get_generation(self, label: str, generation_index: int) -> Optional[LineageNode]:
        """O(1) by list position; scans if that invariant ever breaks."""
        nodes = self._history.get(label)
        if not nodes:
            return None
        if 0 <= generation_index < len(nodes) and nodes[generation_index].generation_index == generation_index:
            return nodes[generation_index]
        for node in nodes:
            if node.generation_index == generation_index:
                return node
        return None

    def get_tip(self, label: str) -> Optional[LineageNode]:
        """Returns the latest version of a file, or None if it has none."""
        history = self._history.get(label, [])
        return history[-1] if history else None

    def find_node_by_uuid(self, node_uuid: str) -> Optional[LineageNode]:
        """Returns the version with this UUID, or None."""
        return self._by_uuid.get(node_uuid)

    def all_labels(self) -> List[str]:
        """Returns the names of all files that have a history."""
        return list(self._history.keys())

    def delete_label(self, label: str) -> None:
        """Removes all of label's history (full delete). No-op if it has none."""
        if label in self._history:
            for node in self._history[label]:
                self._by_uuid.pop(node.node_uuid, None)
            del self._history[label]
            self._save()

    def mark_pruned(self, label: str, generation_index: int) -> Optional[str]:
        """Clears one generation's manifest_filename, keeping the record.

        Returns the manifest_filename it had, or None if the generation doesn't
        exist or was already pruned.
        """
        for node in self._history.get(label, []):
            if node.generation_index == generation_index and not node.pruned:
                manifest_filename = node.manifest_filename
                node.pruned = True
                node.manifest_filename = None
                self._save()
                return manifest_filename
        return None

    def rename_label(self, old_label: str, new_label: str) -> None:
        """Moves label's history to new_label (rename). Appends only: the caller
        deals with any existing history under new_label first.
        """
        if old_label not in self._history:
            return
        nodes = self._history.pop(old_label)
        for node in nodes:
            node.label = new_label
        self._history.setdefault(new_label, []).extend(nodes)
        self._save()

    def get_tags(self, label: str) -> Dict[str, object]:
        """The current tip's tags; {} if the label has no history."""
        tip = self.get_tip(label)
        return dict(tip.epigenetic_tags) if tip else {}

    def set_tag(self, label: str, key: str, value: object) -> None:
        """Sets a tag on the current tip; later generations inherit it."""
        tip = self.get_tip(label)
        if tip is None:
            raise KeyError(f"'{label}' has no recorded lineage history to tag.")
        tip.epigenetic_tags[key] = value
        self._save()

    def remove_tag(self, label: str, key: str) -> bool:
        """Removes a tag from the current tip. True if it was set."""
        tip = self.get_tip(label)
        if tip is None:
            raise KeyError(f"'{label}' has no recorded lineage history to untag.")
        if key in tip.epigenetic_tags:
            del tip.epigenetic_tags[key]
            self._save()
            return True
        return False
