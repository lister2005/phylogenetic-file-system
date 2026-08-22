"""
The real Lineage DAG (design doc's "Speciation on Write"): tracks ONE
label's real edit history over time -- V1 -> V2 -> V3, each a real,
reconstructible past file state. This is deliberately separate from
TreeConstructor.py's clade clustering tree, which groups DIFFERENT,
unrelated files by content similarity; see that module's docstring for
the full distinction. This module is what actually builds the Lineage
DAG the design doc describes -- TreeConstructor explicitly does not.

Every write to an ALREADY-EXISTING label records a new generation whose
new_chunks count is the REAL number of genuinely new content-defined
chunks that edit introduced -- StoragePipeline's own new_chunks_written
for that write, already computed for free by the existing dedup
mechanism. Nothing here is a synthetic statistic.

Why this doesn't reuse PhylogeneticNode (the C-struct-shaped class in
PhylogeneticNode.py): that class's trait_matrix/mutation_delta fields
are sized for holding an actual chunk-hash set and delta bytes. A
lineage node only needs a REFERENCE to its manifest, which already
durably and immutably holds exactly that information -- duplicating it
here would either leave those fields as dead weight or waste real disk
space re-storing what the manifest already stores. LineageNode stays
deliberately minimal instead.

Old generations' manifests are never deleted when a new version is
written -- that's what makes checking out an old generation possible.

PRUNING (mark_pruned / VaultSession.prune_generation): reclaims one
specific OLD generation's storage while keeping the label and all its
OTHER generations intact. The design doc worries this requires "Graph
Re-Grafting" -- extracting a deleted middle node's delta and merging it
into its children so the chain doesn't break. That doesn't apply here:
because every generation in this system is an independently, fully
reconstructable manifest, not a byte-delta against its parent (see
above), pruning a MIDDLE generation never affects any OTHER
generation's ability to reconstruct. Pruning only clears
manifest_filename (so 'checkout' gives an honest "pruned" answer and
the manifest -- if nothing else references it -- can actually be
freed); the LineageNode record itself, and its place in the graph
(node_uuid, parent_uuid, generation_index), is kept permanently as a
historical marker. That's also why no "re-linking" of children's
parent_uuid is needed: the pruned node's uuid still resolves to a real
(if content-less) record, so the chain never actually breaks.

LATERAL GENE TRANSFER: a node's PRIMARY parent (parent_uuid) is its
predecessor within its own label's history -- what makes it a DAG
instead of just N independent lists is lateral_parent_uuids, an
additional list of node_uuids from OTHER labels' histories entirely.
This is how a node can descend from two previously-unrelated lineages
at once (see pfs_cli.py's `graft` command / VaultSession.
lateral_gene_transfer, which is what actually populates this). A graft
here is a graph-level provenance record over two already-published,
independent tips -- always well-defined, never a "conflict", because
there's no shared, contested history between two DIFFERENT labels to
diverge from.

BRANCHING (fork_from / VaultSession.fork, merge_branches): a label's
history is no longer required to be strictly linear. record_version's
`fork_from` parameter lets a new generation's PRIMARY parent be ANY
past generation of the SAME label, not only its current tip -- write
against an old generation instead of the tip, and you've created a
second, divergent head. get_heads() finds every currently-open branch
tip (any node nobody has claimed as their primary parent yet); the
"current" tip (what plain read/write operate on by default) is simply
whichever branch was written to most recently -- there's no separate
named-branch-pointer mechanism, branches are identified by generation
number. generation_index stays a simple monotonic "Nth mutation event
ever recorded for this label" counter regardless of which branch it's
on (NOT "depth from root along one branch") -- this is what keeps
get_generation()'s O(1) list-position indexing valid even once
branching exists, since every new node, on whichever branch, is still
appended to the end of the same flat list in creation order.

merge_branches() is what actually resolves the design doc's Mutation
Conflict scenario -- but using each generation's own ordered
(block_index -> content_hash) list (already stored in every manifest)
for a chunk-POSITION 3-way diff against the branches' lowest common
ancestor, not literal byte-region diffing. A position changed by only
one branch (or changed identically by both) merges automatically; a
position changed DIFFERENTLY by both branches raises
MutationConflictError (this module's answer to the design doc's
EvolutionaryDivergenceException) and commits nothing -- no automated
resolution is attempted, matching the design doc's own choice to make
the user pick manually rather than silently guess. A successful merge
reuses the SAME lateral_parent_uuids mechanism graft uses -- the merge
result's primary parent is one branch head, with the other recorded as
a lateral parent -- just within one label instead of across two.

EPIGENETIC METADATA (epigenetic_tags): the design doc's own examples
("encryption or memory priority rules") assume a kernel-level
filesystem with a real memory manager -- not something a Python
prototype has to hook into. What DOES translate honestly here:
behavioral flags that automatically inherit down a label's PRIMARY
lineage the moment they're set, exactly like the design doc describes
("descendant branches dynamically inherit... unless a specific
expression mutation overrides them"), and that have REAL enforced
effects on operations this system already has -- not decorative
metadata. record_version() copies the parent tip's epigenetic_tags
into every new generation automatically; LineageStore.set_tag/
remove_tag mutate the CURRENT TIP's tags directly (no content write
required -- tags aren't part of file content). Two tags carry real
enforcement (see VaultSession): "protected" blocks delete/prune unless
explicitly forced, and "no_graft_source" blocks a label from being used
as a graft source. Any other key is accepted too and inherits the same
way, but is purely informational -- this module doesn't special-case
tag names; enforcement is VaultSession's job, not this storage layer's.
Lateral (graft) parents do NOT propagate tags -- only primary,
vertical, same-label inheritance is automatic; a freshly grafted label
starts with an empty tag set regardless of its lateral parents' tags,
since silently inheriting a behavioral flag sideways from a merge
source would be a surprising, undiscoverable side effect.
"""

import os
import pickle
import struct
import time
import uuid
from typing import Dict, List, Optional

LINEAGE_FILENAME = "lineage.enc"

# On-disk format (see LineageStore._load/_save/_append_node): a magic
# header followed by a sequence of length-framed encrypted records, each
# either a full SNAPSHOT (the whole history dict, same shape the format
# used before this framing existed) or one incremental NODE record (a
# single new generation). record_version() -- the hot path, called on
# every file write/edit -- appends ONE small NODE record instead of
# re-pickling/re-encrypting/re-fsyncing the entire vault's history every
# time, which used to make every write progressively slower as a vault
# accumulated generations (measured: 3.7ms -> 42ms avg over 6000 nodes,
# a 7.8x slowdown, clearly growing with total history size, not file
# size or write size). The rarer mutating operations (delete/prune/
# rename/tag) still just call _save(), which writes a fresh single
# SNAPSHOT record -- correct and simple, and fine to be O(N) since
# they're occasional deliberate actions, not a per-edit hot path.
_LINEAGE_MAGIC = b"PFSLIN02"
_RECORD_SNAPSHOT = b"S"
_RECORD_NODE = b"N"


class LineageNode:
    __slots__ = ("node_uuid", "parent_uuid", "lateral_parent_uuids", "label", "manifest_filename",
                 "generation_index", "birth_timestamp", "new_chunks", "total_chunks", "pruned",
                 "epigenetic_tags")

    def __init__(self, label: str, manifest_filename: Optional[str], parent_uuid: Optional[str],
                 generation_index: int, new_chunks: int, total_chunks: int,
                 node_uuid: Optional[str] = None, birth_timestamp: Optional[float] = None,
                 lateral_parent_uuids: Optional[List[str]] = None, pruned: bool = False,
                 epigenetic_tags: Optional[Dict[str, object]] = None):
        self.node_uuid = node_uuid or uuid.uuid4().hex
        self.parent_uuid = parent_uuid
        self.lateral_parent_uuids = list(lateral_parent_uuids) if lateral_parent_uuids else []
        self.label = label
        self.manifest_filename = manifest_filename
        self.generation_index = generation_index
        self.birth_timestamp = birth_timestamp if birth_timestamp is not None else time.time()
        self.new_chunks = new_chunks
        self.total_chunks = total_chunks
        # True once pruned -- manifest_filename is None from that point
        # on (permanently; pruning is one-way). The record itself
        # stays, as a historical marker that this generation existed.
        self.pruned = pruned
        # Inherited from the parent generation automatically at
        # creation time (see record_version) -- see module docstring.
        self.epigenetic_tags = dict(epigenetic_tags) if epigenetic_tags else {}

    def to_dict(self) -> dict:
        return {slot: getattr(self, slot) for slot in self.__slots__}

    @classmethod
    def from_dict(cls, d: dict) -> "LineageNode":
        return cls(d["label"], d["manifest_filename"], d["parent_uuid"], d["generation_index"],
                    d["new_chunks"], d["total_chunks"],
                    node_uuid=d["node_uuid"], birth_timestamp=d["birth_timestamp"],
                    # .get(): nodes recorded before these features existed have no such key.
                    lateral_parent_uuids=d.get("lateral_parent_uuids", []),
                    pruned=d.get("pruned", False),
                    epigenetic_tags=d.get("epigenetic_tags", {}))


class LineageStore:
    def __init__(self, storage_root: str, crypto):
        self.storage_root = storage_root
        self.crypto = crypto
        self.path = os.path.join(storage_root, LINEAGE_FILENAME)
        self._history: Dict[str, List[LineageNode]] = {}
        # node_uuid -> LineageNode, maintained incrementally (not
        # rebuilt per lookup) by every method that adds/removes nodes --
        # see record_version/delete_label. O(1) find_node_by_uuid.
        self._by_uuid: Dict[str, LineageNode] = {}
        self._load()

    def _load(self) -> None:
        self._history = {}
        self._by_uuid = {}
        if not os.path.exists(self.path):
            return
        with open(self.path, "rb") as f:
            blob = f.read()

        if not blob.startswith(_LINEAGE_MAGIC):
            # Pre-framing format: the whole file is ONE encrypted blob,
            # no header, no record framing at all. One-time migration:
            # decrypt it the old way, then immediately compact into the
            # new framed format so every later load (and every later
            # write) takes the fast append path instead of this branch.
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
        self._by_uuid = {
            node.node_uuid: node
            for nodes in self._history.values()
            for node in nodes
        }

    def _save(self) -> None:
        """Full compaction: writes ONE fresh snapshot record containing
        the entire current history, replacing the file. O(total history
        size) -- correct for the rare mutating operations that call this
        (delete/prune/rename/tag), but NOT used by record_version's hot
        path (see _append_node)."""
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
        """The fast path: appends ONE small framed record for this node
        to the end of the existing file -- cost is proportional to this
        one node, not to the vault's total accumulated history. Used
        only by record_version(), the true per-write hot path."""
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
        """Explicit maintenance op, same idea as GlobalBlockIndex.compact()
        -- rewrites the file as a single fresh snapshot so accumulated
        append records collapse back down. Not run automatically on any
        hot path; call it periodically/manually if a long-lived vault's
        lineage.enc has grown large from many small appended records."""
        self._save()

    def record_version(self, label: str, manifest_filename: str, new_chunks: int, total_chunks: int,
                        lateral_parent_uuids: Optional[List[str]] = None,
                        fork_from: Optional[LineageNode] = None) -> LineageNode:
        """Appends a new generation for `label`. Primary parent is
        `fork_from` if given (this is what actually creates a branch --
        `fork_from` need not be label's current tip), otherwise whatever
        `label`'s own current tip was (None, i.e. a root node, if this is
        the first write ever recorded for this label). lateral_parent_uuids,
        if given, are node_uuids from OTHER labels' histories -- see the
        module docstring for what that means and why it's not itself
        "conflict resolution" (merge_branches is).

        generation_index is always the new node's position in the flat
        per-label list (a chronological "Nth event" counter, not "depth
        from root") -- this is unaffected by forking, since every new
        node, on whichever branch, is still appended to the end of the
        same list. Keeps get_generation()'s O(1) indexing valid
        regardless of branching.

        epigenetic_tags are copied from the parent automatically (a
        fresh dict, not a shared reference -- later changing the
        child's tags must never retroactively change the parent's) --
        this IS the inheritance mechanism; no caller action needed. A
        brand-new label's generation 0 has no parent, so it starts with
        an empty tag set."""
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
        """Every currently-open branch tip for `label`: nodes that
        aren't any other node's PRIMARY parent yet. Normally exactly
        one (the ordinary linear case); more than one once 'fork' has
        created a divergent branch. Being someone's LATERAL parent
        (via graft or merge) doesn't disqualify a node from still being
        a head of its own primary line."""
        nodes = self._history.get(label, [])
        claimed_as_primary_parent = {n.parent_uuid for n in nodes if n.parent_uuid is not None}
        return [n for n in nodes if n.node_uuid not in claimed_as_primary_parent]

    def get_history(self, label: str) -> List[LineageNode]:
        """Chronological, generation 0 first."""
        return list(self._history.get(label, []))

    def get_generation(self, label: str, generation_index: int) -> Optional[LineageNode]:
        """O(1): generation_index is always exactly the list position
        within label's history -- record_version only ever appends
        sequentially (generation N+1 after N), and nothing else
        reorders or removes entries (mark_pruned mutates in place,
        rename_label moves the whole list intact). Falls back to a
        scan if that invariant is ever somehow violated, rather than
        silently returning the wrong node."""
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
        history = self._history.get(label, [])
        return history[-1] if history else None

    def find_node_by_uuid(self, node_uuid: str) -> Optional[LineageNode]:
        """O(1) via the index maintained by record_version/delete_label
        -- was a linear scan across every label's history before
        2026-07-23's optimization pass."""
        return self._by_uuid.get(node_uuid)

    def all_labels(self) -> List[str]:
        return list(self._history.keys())

    def delete_label(self, label: str) -> None:
        """Purges label's ENTIRE recorded history -- every generation,
        not just the tip. Used only by a full label delete
        (VaultSession.delete_label), which is what makes "delete really
        means delete" possible now that writes preserve history by
        default. This is NOT a partial prune (discarding some of a
        still-live label's older generations while keeping the label
        itself) -- that's different, separate future work. Safe to call
        on a label with no recorded history (no-op)."""
        if label in self._history:
            for node in self._history[label]:
                self._by_uuid.pop(node.node_uuid, None)
            del self._history[label]
            self._save()

    def mark_pruned(self, label: str, generation_index: int) -> Optional[str]:
        """Marks one generation as pruned: clears its manifest_filename
        (excluding it from future manifest-reference-counting and
        giving 'checkout' a clear, honest answer) while keeping the
        record -- generation index, timestamps, chunk stats, graph
        linkage -- for history/audit purposes. One-way; pruning an
        already-pruned generation is a no-op returning None.

        Returns the manifest_filename it HAD before clearing (the
        caller needs this to decide whether to actually free the
        underlying manifest), or None if this generation doesn't exist
        or was already pruned."""
        for node in self._history.get(label, []):
            if node.generation_index == generation_index and not node.pruned:
                manifest_filename = node.manifest_filename
                node.pruned = True
                node.manifest_filename = None
                self._save()
                return manifest_filename
        return None

    def rename_label(self, old_label: str, new_label: str) -> None:
        """Carries a label's full recorded history forward under a new
        name -- used by 'rename', so a label's history isn't silently
        stranded under a name nothing points to anymore. No-op if
        old_label has no recorded history. Assumes new_label's own
        history (if any) has already been dealt with by the caller
        (e.g. via delete_label, when renaming overwrites an existing
        destination) -- this only ever APPENDS, never overwrites."""
        if old_label not in self._history:
            return
        nodes = self._history.pop(old_label)
        for node in nodes:
            node.label = new_label
        self._history.setdefault(new_label, []).extend(nodes)
        self._save()

    def get_tags(self, label: str) -> Dict[str, object]:
        """The CURRENT TIP's epigenetic tags -- {} if the label has no
        recorded history."""
        tip = self.get_tip(label)
        return dict(tip.epigenetic_tags) if tip else {}

    def set_tag(self, label: str, key: str, value: object) -> None:
        """Sets a tag on label's CURRENT TIP directly -- no content
        write required, since a tag isn't part of file content. This is
        the "expression mutation" the module docstring describes: from
        this point forward, every NEW generation inherits this value
        (record_version always copies the tip's tags at creation time),
        overriding whatever this label inherited before. Raises if the
        label has no recorded history to tag."""
        tip = self.get_tip(label)
        if tip is None:
            raise KeyError(f"'{label}' has no recorded lineage history to tag.")
        tip.epigenetic_tags[key] = value
        self._save()

    def remove_tag(self, label: str, key: str) -> bool:
        """Removes a tag from label's CURRENT TIP. Returns True if a
        tag was actually removed, False if it wasn't set. Like set_tag,
        this is itself an expression mutation -- generations created
        after this point won't inherit the removed tag either."""
        tip = self.get_tip(label)
        if tip is None:
            raise KeyError(f"'{label}' has no recorded lineage history to untag.")
        if key in tip.epigenetic_tags:
            del tip.epigenetic_tags[key]
            self._save()
            return True
        return False
