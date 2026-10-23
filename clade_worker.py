"""
Background, incremental clade clustering (TreeConstructor.compute_clades's
partition) for the FUSE mount, the CLI and the GUI.

Front ends report changed(label), removed(label) and renamed(old, new),
never waiting. The worker keeps each label's related labels, so a change
compares only the changed labels against the rest (O(n), not O(n^2)).
snapshot() returns the last complete partition at once; filtered_view()
hides labels that no longer exist; wait_idle() waits for a fresh one.

A thread in the process holding the vault, not a separate process: the
vault lock admits one process per vault. Fingerprints come from a loader
called only on the worker thread, and are cached packed (32 bytes per
trait). The C++ FUSE driver uses the port in clade_worker.hpp.
"""
import sys
import threading
from typing import Callable, Dict, Iterable, List, Optional, Set

from gearhash import fingerprint as stored_fingerprint
from PhylogeneticAnalyzer import PhylogeneticAnalyzer, SIMILARITY_PROFILE
from TreeConstructor import TreeConstructor

DEFAULT_CLADE_THRESHOLD = TreeConstructor.DEFAULT_CLADE_THRESHOLD

# Changed labels held unpacked at once; bounds memory in big batches.
COMPARE_BLOCK = 64


class CladeSnapshot:
    """An immutable partition. clade_to_labels: representative (smallest
    member) -> sorted members, singletons included; label_to_clade: member ->
    representative. version counts snapshots (0 = none yet); pending means
    changes were queued when it was taken.
    """

    __slots__ = ("clade_to_labels", "label_to_clade", "version", "pending")

    def __init__(self, clade_to_labels, label_to_clade, version, pending):
        self.clade_to_labels = clade_to_labels
        self.label_to_clade = label_to_clade
        self.version = version
        self.pending = pending


def filtered_view(snapshot: CladeSnapshot, live_labels, min_members: int = 1):
    """(clade_to_labels, label_to_clade) for labels still in live_labels,
    re-keyed by the smallest survivor, keeping clades with min_members+.
    """
    live = live_labels if isinstance(live_labels, (set, frozenset, dict)) else set(live_labels)
    clade_to_labels = {}
    for members in snapshot.clade_to_labels.values():
        surviving = [m for m in members if m in live]
        if len(surviving) >= min_members:
            clade_to_labels[surviving[0]] = surviving  # members are sorted
    label_to_clade = {m: name for name, members in clade_to_labels.items() for m in members}
    return clade_to_labels, label_to_clade


def python_session_loader(session) -> Callable[[str], Optional[Set[bytes]]]:
    """Loader for a VaultSession: reads and decrypts one fingerprint file (no
    SQLite), so it's safe on the worker thread. Deleted labels load as None.
    """
    import os

    def load(label: str):
        manifest_filename = session.catalog.get(label)
        if manifest_filename is None:
            return None
        return session.read_similarity_fingerprint(os.path.join(session.storage_root, manifest_filename))
    return load


def cpp_session_loader(session) -> Callable[[str], Optional[Set[bytes]]]:
    """Loader for a CppVaultSession (calls are serialized by the binding).
    Missing labels load as None; an empty fingerprint loads as an empty set,
    a clade of one, as in compute_clades().
    """
    def load(label: str):
        # Hold the session lock across both calls; close() takes it too.
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
        self._busy = False  # guarded by _cond
        self._stopping = False           # guarded by _cond
        self._snapshot = CladeSnapshot({}, {}, 0, False)
        self._thread: Optional[threading.Thread] = None
        self.last_error: Optional[str] = None

        # Worker-thread state.
        self._traits: Dict[str, bytes] = {}       # label -> packed fingerprint
        self._neighbors: Dict[str, Set[str]] = {}  # label -> labels within threshold

    # ---------- front-end API (any thread) ----------

    def start(self, labels: Iterable[str] = ()) -> "CladeWorker":
        """Queues every label and starts the thread."""
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
        """Waits until every change posted so far is in snapshot(). False on timeout."""
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
            except Exception as e:  # keep serving
                self.last_error = f"{type(e).__name__}: {e}"
                sys.stderr.write(f"[{self._name}] clustering pass failed: {self.last_error}\n")
            finally:
                with self._cond:
                    self._busy = bool(self._events)  # more may have arrived
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

        # Compare new labels, a block at a time, with (1) known labels, (2) new
        # labels in later blocks, (3) each other -- every pair once.
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
