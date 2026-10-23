"""
Background clade clustering -- manual.txt PART 8 item #6.

Clades (connected components of "Jaccard distance <= threshold" between
files' similarity fingerprints -- exactly TreeConstructor.compute_clades)
used to be recomputed from scratch, on demand, after any change: every
manifest decrypted, every pair compared, O(n^2), on the path of whatever
asked (a FUSE path lookup, the GUI's next refresh). A CladeWorker keeps
the partition up to date on a background thread instead:

  - The front end reports changes -- changed(label) once a label's
    fingerprint exists or changes, removed(label), renamed(old, new) --
    and never waits for the work.
  - Recomputing is incremental: the worker keeps each label's set of
    related labels (distance <= threshold), so a change only compares
    the CHANGED labels against everyone else (O(n) for one change, not
    O(n^2)), then re-runs the cheap union-find over those edges.
  - Readers call snapshot(): the last complete partition, immediately.
    It can briefly lag the vault; filtered_view() drops labels that no
    longer exist, so a deleted or renamed label never surfaces from a
    stale snapshot. A label not yet in any snapshot simply isn't in a
    clade yet. Readers that want a fresh answer call wait_idle() first.

It runs inside the process that holds the vault, as a thread, not as a
separate daemon process: the vault lock (vault_lock.py) admits one
process per vault, so a separate process would lock out the CLI, GUI
and mount it's meant to serve.

Fingerprints come from a loader the front end supplies, called ONLY on
the worker thread; it must be safe to call from there (see each front
end). They're cached in memory packed (gearhash/fingerprint.py), 32
bytes per trait -- roughly a tenth of the vault's unique stored data --
and unpacked one comparison block at a time, so memory stays bounded.

The C++ FUSE driver has its own port of this (cpp_engine/src/
pfs_fuse_cpp.cpp, CladeWorker); same algorithm, same semantics.
"""
import sys
import threading
from typing import Callable, Dict, Iterable, List, Optional, Set

from gearhash import fingerprint as stored_fingerprint
from PhylogeneticAnalyzer import PhylogeneticAnalyzer, SIMILARITY_PROFILE
from TreeConstructor import TreeConstructor

DEFAULT_CLADE_THRESHOLD = TreeConstructor.DEFAULT_CLADE_THRESHOLD

# How many changed labels' trait sets are held unpacked at once while
# they're compared against everyone else. Bounds memory during a big
# batch (e.g. the initial build) at the cost of one extra pass over the
# cached fingerprints per block.
COMPARE_BLOCK = 64


class CladeSnapshot:
    """One complete, immutable partition. clade_to_labels maps each
    clade's representative (its lexicographically-smallest member) to its
    sorted members -- singletons included, exactly like compute_clades();
    label_to_clade maps every member to its representative. Only labels
    that had a fingerprint when it was computed appear at all.

    version counts published snapshots (0 = nothing computed yet);
    pending is True if changes were queued or in progress when it was
    taken, i.e. the vault may already differ from it."""

    __slots__ = ("clade_to_labels", "label_to_clade", "version", "pending")

    def __init__(self, clade_to_labels, label_to_clade, version, pending):
        self.clade_to_labels = clade_to_labels
        self.label_to_clade = label_to_clade
        self.version = version
        self.pending = pending


def filtered_view(snapshot: CladeSnapshot, live_labels, min_members: int = 1):
    """(clade_to_labels, label_to_clade) restricted to labels that still
    exist, re-keyed by each clade's smallest SURVIVING member, keeping
    only clades with at least min_members survivors. This is what lets a
    reader use a slightly stale snapshot safely: a label deleted or
    renamed since it was computed never shows up."""
    live = live_labels if isinstance(live_labels, (set, frozenset, dict)) else set(live_labels)
    clade_to_labels = {}
    for members in snapshot.clade_to_labels.values():
        surviving = [m for m in members if m in live]
        if len(surviving) >= min_members:
            clade_to_labels[surviving[0]] = surviving  # members are sorted, so [0] is the smallest
    label_to_clade = {m: name for name, members in clade_to_labels.items() for m in members}
    return clade_to_labels, label_to_clade


def python_session_loader(session) -> Callable[[str], Optional[Set[bytes]]]:
    """Fingerprint loader for a vault_session.VaultSession. Safe on the
    worker thread: it only reads and decrypts one manifest file -- no
    SQLite, nothing the front end mutates in place (a dict lookup on the
    catalog is atomic). A label deleted meanwhile loads as None."""
    import os

    def load(label: str):
        manifest_filename = session.catalog.get(label)
        if manifest_filename is None:
            return None
        try:
            meta = session.read_manifest_metadata(os.path.join(session.storage_root, manifest_filename))
        except FileNotFoundError:
            return None
        return stored_fingerprint.unpack(meta.get("similarity_fingerprint"))
    return load


def cpp_session_loader(session) -> Callable[[str], Optional[Set[bytes]]]:
    """Fingerprint loader for a pfs_engine_binding.CppVaultSession. Safe
    on the worker thread because the binding serializes every call into
    one session (pfs_engine_binding._serialize_calls). A label that no
    longer exists loads as None; one with an EMPTY stored fingerprint
    (an empty file) loads as an empty set, so it still counts as a
    clade of one, exactly as compute_clades() treats it."""
    def load(label: str):
        # Held across both calls, and the same lock close() takes: a session
        # closed meanwhile is seen here, never called with a dead handle.
        with session._call_lock:
            if session._handle is None:
                return None
            try:
                if not session.get_manifest_info(label)["has_similarity_fingerprint"]:
                    return None
                return session.get_fingerprint(label)
            except Exception:
                return None
    return load


class CladeWorker:
    def __init__(self, load_traits: Callable[[str], Optional[Set[bytes]]],
                 threshold: float = DEFAULT_CLADE_THRESHOLD,
                 distance: Optional[Callable[[set, set], float]] = None,
                 name: str = "clade-worker"):
        self._load_traits = load_traits
        self._threshold = threshold
        self._distance = distance or PhylogeneticAnalyzer(SIMILARITY_PROFILE).calculate_distance
        self._name = name

        self._cond = threading.Condition()
        self._events: List[tuple] = []   # guarded by _cond
        self._busy = False               # guarded by _cond: a batch is being processed
        self._stopping = False           # guarded by _cond
        self._snapshot = CladeSnapshot({}, {}, 0, False)
        self._thread: Optional[threading.Thread] = None
        self.last_error: Optional[str] = None

        # Worker-thread-only state.
        self._traits: Dict[str, bytes] = {}       # label -> packed fingerprint
        self._neighbors: Dict[str, Set[str]] = {}  # label -> labels within threshold

    # ---------- front-end API (any thread) ----------

    def start(self, labels: Iterable[str] = ()) -> "CladeWorker":
        """Queues every existing label and starts the thread. The first
        snapshot lands once the initial build finishes."""
        with self._cond:
            self._events.extend(("changed", label) for label in labels)
        self._thread = threading.Thread(target=self._run, name=self._name, daemon=True)
        self._thread.start()
        return self

    def changed(self, label: str) -> None:
        self._post(("changed", label))

    def removed(self, label: str) -> None:
        self._post(("removed", label))

    def renamed(self, old: str, new: str) -> None:
        self._post(("renamed", old, new))

    def snapshot(self) -> CladeSnapshot:
        with self._cond:
            snap = self._snapshot
            pending = bool(self._events) or self._busy
        if pending == snap.pending:
            return snap
        return CladeSnapshot(snap.clade_to_labels, snap.label_to_clade, snap.version, pending)

    def wait_idle(self, timeout: Optional[float] = None) -> bool:
        """Blocks until every change reported so far is reflected in
        snapshot(). False if the timeout ran out first."""
        with self._cond:
            return self._cond.wait_for(lambda: not self._events and not self._busy, timeout)

    def stop(self, timeout: Optional[float] = None) -> None:
        with self._cond:
            self._stopping = True
            self._cond.notify_all()
        if self._thread is not None:
            self._thread.join(timeout)

    def _post(self, event: tuple) -> None:
        with self._cond:
            self._events.append(event)
            self._cond.notify_all()

    # ---------- worker thread ----------

    def _run(self) -> None:
        while True:
            with self._cond:
                self._cond.wait_for(lambda: self._events or self._stopping)
                if self._stopping:
                    return
                events, self._events = self._events, []
                self._busy = True
            try:
                self._process(events)
            except Exception as e:  # never let the thread die; report and keep serving
                self.last_error = f"{type(e).__name__}: {e}"
                sys.stderr.write(f"[{self._name}] clustering pass failed: {self.last_error}\n")
            finally:
                with self._cond:
                    self._busy = bool(self._events)  # more may have arrived meanwhile
                    self._cond.notify_all()

    def _drop(self, label: str) -> None:
        self._traits.pop(label, None)
        for other in self._neighbors.pop(label, ()):
            self._neighbors[other].discard(label)

    def _process(self, events: List[tuple]) -> None:
        dirty: Set[str] = set()
        for event in events:
            kind = event[0]
            if kind == "changed":
                dirty.add(event[1])
            elif kind == "removed":
                self._drop(event[1])
                dirty.discard(event[1])
            elif kind == "renamed":
                old, new = event[1], event[2]
                if old == new:
                    continue
                self._drop(new)  # a rename over an existing label replaces it
                dirty.discard(new)
                if old in self._traits:
                    self._traits[new] = self._traits.pop(old)
                    neighbors = self._neighbors.pop(old)
                    self._neighbors[new] = neighbors
                    for other in neighbors:
                        self._neighbors[other].discard(old)
                        self._neighbors[other].add(new)
                if old in dirty:
                    dirty.discard(old)
                    dirty.add(new)

        # Reload each dirty label's fingerprint and drop its old edges.
        loaded: Dict[str, bytes] = {}
        for label in sorted(dirty):
            self._drop(label)
            try:
                traits = self._load_traits(label)
            except Exception as e:
                self.last_error = f"loading '{label}': {type(e).__name__}: {e}"
                traits = None
            if traits is not None:
                loaded[label] = stored_fingerprint.pack(traits)

        # Compare the newly loaded labels, a block at a time, against (1)
        # every label already known, (2) new labels in LATER blocks, and
        # (3) each other within the block -- every unordered pair exactly
        # once, with at most one block plus one other label unpacked.
        new_labels = sorted(loaded)
        for start in range(0, len(new_labels), COMPARE_BLOCK):
            names = new_labels[start:start + COMPARE_BLOCK]
            block = {label: stored_fingerprint.unpack(loaded[label]) for label in names}
            others = [(label, self._traits[label]) for label in self._traits]
            others += [(label, loaded[label]) for label in new_labels[start + COMPARE_BLOCK:]]
            for other, packed in others:
                other_traits = stored_fingerprint.unpack(packed)
                for label in names:
                    self._maybe_link(label, block[label], other, other_traits)
            for i, a in enumerate(names):
                for b in names[i + 1:]:
                    self._maybe_link(a, block[a], b, block[b])
        for label in new_labels:
            self._traits[label] = loaded[label]
            self._neighbors.setdefault(label, set())

        self._publish()

    def _maybe_link(self, a: str, traits_a: set, b: str, traits_b: set) -> None:
        if self._distance(traits_a, traits_b) <= self._threshold:
            self._neighbors.setdefault(a, set()).add(b)
            self._neighbors.setdefault(b, set()).add(a)

    def _publish(self) -> None:
        parent = {label: label for label in self._traits}

        def find(x):
            while parent[x] != x:
                parent[x] = parent[parent[x]]
                x = parent[x]
            return x

        for label, neighbors in self._neighbors.items():
            for other in neighbors:
                ra, rb = find(label), find(other)
                if ra != rb:
                    parent[ra] = rb

        groups: Dict[str, List[str]] = {}
        for label in self._traits:
            groups.setdefault(find(label), []).append(label)
        clade_to_labels = {}
        for members in groups.values():
            members.sort()
            clade_to_labels[members[0]] = members
        label_to_clade = {m: name for name, members in clade_to_labels.items() for m in members}

        with self._cond:
            self._snapshot = CladeSnapshot(clade_to_labels, label_to_clade,
                                           self._snapshot.version + 1, False)
