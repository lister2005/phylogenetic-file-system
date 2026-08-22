"""
Builds a phylogenetic tree from a set of files, using either UPGMA or
Neighbor-Joining. Both start from the same pairwise Jaccard distance
matrix (via the analyzer's SIMILARITY_PROFILE) but merge nodes with
different criteria and produce different branch-length semantics --
see each method's docstring.

Two ways to get leaves in:
- build_tree_upgma(file_paths) / build_tree_nj(file_paths): reads and
  fingerprints files directly. Useful for ad-hoc comparisons of files
  not yet in the vault.
- build_tree_upgma_from_traits(named_traits) / build_tree_nj_from_traits
  (named_traits): starts from ALREADY-COMPUTED trait sets (e.g. read
  back from encrypted manifest metadata via the storage pipeline). This
  is what the CLI's `tree` command uses -- it never needs to re-read or
  re-decrypt original file content just to see the tree.

IMPORTANT DISTINCTION (per text.txt): this builds the CLADE CLUSTERING
TREE, not the LINEAGE DAG. These are two different structures text.txt
describes, and they must not be conflated:

- The Lineage DAG (text.txt's "Speciation on Write"): tracks ONE file's
  real edit history over time (V1 -> V2 -> V3...). Every node is a real,
  reconstructible file state. Parent->child here has a REAL
  mutation_delta -- the actual new chunk bytes introduced by a real
  edit, computed by comparing the new version's STORAGE_PROFILE chunk
  hashes against the parent's. This already exists: it's exactly what
  StoragePipeline's dedup mechanism does on every write
  (new_chunks_written vs duplicate_chunks_found in the manifest). This
  file does not build that structure.

- The Clade Clustering Tree (this file, UPGMA/NJ): groups UNRELATED,
  previously-unlinked files by content similarity for discovery and
  organization -- text.txt's "background clustering daemon... to build
  the file matrix". Internal nodes here are SYNTHETIC clusters with no
  real byte content (they're the union of their children's trait sets),
  so they cannot have a real mutation_delta. leaf_count/branch_signature
  are meaningful here; mutation_delta/delta_size are left at their
  defaults (0 / empty) on internal nodes, since populating them with
  anything would misleadingly imply real storage bytes that don't exist.
"""

from typing import List, Dict, Optional
from PhylogeneticNode import PhylogeneticNode


class TreeConstructor:
    def __init__(self, analyzer):
        self.analyzer = analyzer

    # ---------- leaf construction (two front-ends, same downstream core) ----------

    def _make_leaves_from_files(self, file_paths: List[str]) -> List[PhylogeneticNode]:
        leaves = []
        for path in file_paths:
            node = PhylogeneticNode()
            node.trait_matrix = self.analyzer.extract_traits(path)
            node.metadata_name = path
            leaves.append(node)
        return self._assign_branch_signatures(leaves)

    def _make_leaves_from_traits(self, named_traits: Dict[str, set]) -> List[PhylogeneticNode]:
        """named_traits: {label: set_of_trait_hashes}, e.g. read back from
        each file's already-computed, already-stored fingerprint. No file
        I/O, no re-chunking -- just builds leaf nodes directly."""
        leaves = []
        for label, traits in named_traits.items():
            node = PhylogeneticNode()
            node.trait_matrix = set(traits)
            node.metadata_name = label
            leaves.append(node)
        return self._assign_branch_signatures(leaves)

    def _assign_branch_signatures(self, leaves: List[PhylogeneticNode]) -> List[PhylogeneticNode]:
        # branch_signature is a uint32_t bitmask in the C struct -- one
        # bit per ORIGINAL leaf, OR'd together as clusters merge, so any
        # node's signature tells you which original files are its
        # descendants via simple bit tests. This caps out at 32 leaves;
        # beyond that, signature is left at 0 for the overflow leaves --
        # documented limitation, not a silent wraparound bug. A real fix
        # for large N would need a wider or probabilistic (Bloom-filter
        # style) signature scheme instead of a fixed 32-bit mask.
        for i, leaf in enumerate(leaves):
            leaf.branch_signature = (1 << i) if i < 32 else 0
        return leaves

    def _initial_distances(self, leaves: List[PhylogeneticNode]) -> Dict:
        distances = {leaf: {} for leaf in leaves}
        for i in range(len(leaves)):
            for j in range(i + 1, len(leaves)):
                a, b = leaves[i], leaves[j]
                d = self.analyzer.calculate_distance(a.trait_matrix, b.trait_matrix)
                distances[a][b] = d
                distances[b][a] = d
        return distances

    # ---------- public entry points ----------

    def build_tree_upgma(self, file_paths: List[str]) -> List[PhylogeneticNode]:
        """UPGMA from files read directly off disk."""
        return self._upgma_merge(self._make_leaves_from_files(file_paths))

    def build_tree_upgma_from_traits(self, named_traits: Dict[str, set]) -> List[PhylogeneticNode]:
        """UPGMA from already-computed trait sets -- no file I/O."""
        return self._upgma_merge(self._make_leaves_from_traits(named_traits))

    def build_tree_nj(self, file_paths: List[str]) -> List[PhylogeneticNode]:
        """Neighbor-Joining from files read directly off disk."""
        return self._nj_merge(self._make_leaves_from_files(file_paths))

    def build_tree_nj_from_traits(self, named_traits: Dict[str, set]) -> List[PhylogeneticNode]:
        """Neighbor-Joining from already-computed trait sets -- no file I/O."""
        return self._nj_merge(self._make_leaves_from_traits(named_traits))

    # ---------- UPGMA core ----------

    def _upgma_merge(self, leaves: List[PhylogeneticNode]) -> List[PhylogeneticNode]:
        """Unweighted Pair Group Method with Arithmetic mean. Assumes a
        constant mutation rate across all lineages (produces an
        ULTRAMETRIC tree -- every leaf is the same total height from the
        root). At each step, merges the two clusters with the smallest
        distance, then updates the new cluster's distance to everyone
        else via the size-weighted average of the two merged clusters'
        distances -- this is the "arithmetic mean" the name refers to,
        and it's what makes this UPGMA rather than just greedy nearest-
        neighbor clustering.

        Returns ALL nodes created (leaves + internal), not just the
        root, so the full tree is available for visualization/export.
        """
        if len(leaves) <= 1:
            return leaves

        active = list(leaves)
        distances = self._initial_distances(leaves)
        all_nodes = list(leaves)

        while len(active) > 1:
            best_pair = None
            min_dist = float("inf")
            for i in range(len(active)):
                for j in range(i + 1, len(active)):
                    a, b = active[i], active[j]
                    d = distances[a][b]
                    if d < min_dist:
                        min_dist = d
                        best_pair = (a, b)

            a, b = best_pair
            parent = PhylogeneticNode()
            parent.trait_matrix = a.trait_matrix.union(b.trait_matrix)
            parent.generation_index = max(a.generation_index, b.generation_index) + 1
            parent.leaf_count = a.leaf_count + b.leaf_count
            parent.branch_signature = a.branch_signature | b.branch_signature
            parent.height = min_dist / 2.0  # ultrametric midpoint
            # Trait-count proxy for divergence at this split -- traits
            # that distinguish the two children from each other. NOT the
            # actual byte-level mutation delta (that's a separate delta-
            # synthesis phase against real file content, not built yet).
            parent.trait_divergence_count = len(a.trait_matrix.symmetric_difference(b.trait_matrix))

            a.parent_uuid = parent.node_uuid
            b.parent_uuid = parent.node_uuid
            a.branch_length = max(0.0, parent.height - a.height)
            b.branch_length = max(0.0, parent.height - b.height)

            # UPGMA's actual update rule: size-weighted average of the
            # two merged clusters' distances to everyone else.
            new_row = {}
            for other in active:
                if other is a or other is b:
                    continue
                d_new = (a.leaf_count * distances[a][other] + b.leaf_count * distances[b][other]) \
                        / (a.leaf_count + b.leaf_count)
                new_row[other] = d_new
                distances[other][parent] = d_new
                del distances[other][a]
                del distances[other][b]
            distances[parent] = new_row
            del distances[a]
            del distances[b]

            active = [x for x in active if x is not a and x is not b]
            active.append(parent)
            all_nodes.append(parent)

        return all_nodes

    # ---------- Neighbor-Joining core ----------

    def _nj_merge(self, leaves: List[PhylogeneticNode]) -> List[PhylogeneticNode]:
        """Neighbor-Joining. Does NOT assume a constant mutation rate --
        useful here because different files/file types plausibly get
        edited at very different rates, which would distort an UPGMA
        tree's ultrametric assumption. Produces asymmetric branch
        lengths per child instead of a single midpoint height.

        Classic NJ produces an unrooted tree (the last three active
        nodes form a trifurcation with no natural root). For a
        browsable lineage tree we still want a root, so this roots at
        the final join of the last two active nodes -- a standard,
        simple choice, not the only valid one (midpoint or outgroup
        rooting are alternatives if you need something more principled
        later).

        Returns ALL nodes created (leaves + internal).
        """
        if len(leaves) <= 1:
            return leaves

        active = list(leaves)
        distances = self._initial_distances(leaves)
        all_nodes = list(leaves)

        while len(active) > 2:
            n = len(active)
            total = {
                node: sum(distances[node][other] for other in active if other is not node)
                for node in active
            }

            best_pair = None
            min_q = float("inf")
            for i in range(n):
                for j in range(i + 1, n):
                    a, b = active[i], active[j]
                    q = (n - 2) * distances[a][b] - total[a] - total[b]
                    if q < min_q:
                        min_q = q
                        best_pair = (a, b)

            a, b = best_pair
            d_ab = distances[a][b]
            branch_a = 0.5 * d_ab + (total[a] - total[b]) / (2 * (n - 2))
            branch_b = d_ab - branch_a
            # Floating point can push these fractionally negative for
            # near-zero distances -- clamp rather than let a cosmetic
            # rounding error look like a real negative branch length.
            branch_a = max(0.0, branch_a)
            branch_b = max(0.0, branch_b)

            parent = PhylogeneticNode()
            parent.trait_matrix = a.trait_matrix.union(b.trait_matrix)
            parent.generation_index = max(a.generation_index, b.generation_index) + 1
            parent.leaf_count = a.leaf_count + b.leaf_count
            parent.branch_signature = a.branch_signature | b.branch_signature
            parent.trait_divergence_count = len(a.trait_matrix.symmetric_difference(b.trait_matrix))

            a.parent_uuid = parent.node_uuid
            b.parent_uuid = parent.node_uuid
            a.branch_length = branch_a
            b.branch_length = branch_b

            new_row = {}
            for other in active:
                if other is a or other is b:
                    continue
                d_new = max(0.0, 0.5 * (distances[a][other] + distances[b][other] - d_ab))
                new_row[other] = d_new
                distances[other][parent] = d_new
                del distances[other][a]
                del distances[other][b]
            distances[parent] = new_row
            del distances[a]
            del distances[b]

            active = [x for x in active if x is not a and x is not b]
            active.append(parent)
            all_nodes.append(parent)

        # Final step: exactly two active nodes left -- join directly.
        a, b = active[0], active[1]
        d_ab = distances[a][b]
        root = PhylogeneticNode()
        root.trait_matrix = a.trait_matrix.union(b.trait_matrix)
        root.generation_index = max(a.generation_index, b.generation_index) + 1
        root.leaf_count = a.leaf_count + b.leaf_count
        root.branch_signature = a.branch_signature | b.branch_signature
        root.trait_divergence_count = len(a.trait_matrix.symmetric_difference(b.trait_matrix))
        a.parent_uuid = root.node_uuid
        b.parent_uuid = root.node_uuid
        a.branch_length = d_ab / 2.0
        b.branch_length = d_ab / 2.0
        all_nodes.append(root)

        return all_nodes

    # ---------- clade partitioning (connected components, not the tree) ----------

    # Design doc's own recommendation ("The absolute optimal threshold
    # for your system is D<=0.80"): files sharing at least 20% of their
    # content-defined chunks are considered the same clade.
    DEFAULT_CLADE_THRESHOLD = 0.80

    def compute_clades(self, named_traits: Dict[str, set], threshold: float = DEFAULT_CLADE_THRESHOLD) -> Dict[str, List[str]]:
        """Partitions files into clades: connected components of the
        graph where an edge connects any two labels whose Jaccard
        distance is <= threshold. Deliberately NOT the UPGMA/NJ tree
        above (which always produces a single tree spanning everyone,
        with no notion of "these are unrelated") -- a clade here is
        "the group of files close enough to call related", matching the
        design doc's own definition verbatim: "If D(A,B) < Threshold,
        they are assigned to the same Clade."

        Returns {representative_label: [member_labels, ...]}, keyed by
        each clade's lexicographically-smallest member so a caller using
        this for directory names gets a name that's stable across
        recomputation as long as membership doesn't change. Singleton
        clades (no neighbor within threshold) are included too, as a
        clade of one -- callers that only want multi-member clades
        (e.g. "only show a subdirectory when there's actually a group")
        should filter those out themselves."""
        labels = list(named_traits.keys())
        parent = {label: label for label in labels}

        def find(x):
            while parent[x] != x:
                parent[x] = parent[parent[x]]
                x = parent[x]
            return x

        def union(a, b):
            ra, rb = find(a), find(b)
            if ra != rb:
                parent[ra] = rb

        for i in range(len(labels)):
            for j in range(i + 1, len(labels)):
                a, b = labels[i], labels[j]
                d = self.analyzer.calculate_distance(named_traits[a], named_traits[b])
                if d <= threshold:
                    union(a, b)

        groups: Dict[str, List[str]] = {}
        for label in labels:
            root = find(label)
            groups.setdefault(root, []).append(label)

        result: Dict[str, List[str]] = {}
        for members in groups.values():
            members.sort()
            result[members[0]] = members
        return result

    # ---------- visualization ----------

    def visualize_tree(self, all_nodes: List[PhylogeneticNode]) -> None:
        """ASCII tree, working recursively via a parent->children map
        built from the full node list."""
        by_uuid = {n.node_uuid: n for n in all_nodes}
        children: Dict[bytes, List[PhylogeneticNode]] = {n.node_uuid: [] for n in all_nodes}
        roots = []
        for n in all_nodes:
            if n.parent_uuid is not None and n.parent_uuid in by_uuid:
                children[n.parent_uuid].append(n)
            else:
                roots.append(n)

        def _print(node: PhylogeneticNode, prefix: str, is_last: bool):
            connector = "└── " if is_last else "├── "
            label = node.metadata_name or f"internal({node.uuid_hex()[:8]})"
            print(f"{prefix}{connector}{label}  "
                  f"[gen={node.generation_index}, branch_len={node.branch_length:.4f}, "
                  f"leaves={node.leaf_count}]")
            kids = children[node.node_uuid]
            new_prefix = prefix + ("    " if is_last else "│   ")
            for i, child in enumerate(kids):
                _print(child, new_prefix, i == len(kids) - 1)

        for i, root in enumerate(roots):
            label = root.metadata_name or f"ROOT({root.uuid_hex()[:8]})"
            print(f"{label}  [gen={root.generation_index}, leaves={root.leaf_count}]")
            kids = children[root.node_uuid]
            for j, child in enumerate(kids):
                _print(child, "", j == len(kids) - 1)
