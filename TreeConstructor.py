"""
Clade clustering: UPGMA and Neighbor-Joining trees, and the clade
partition (compute_clades), from pairwise Jaccard distances between
SIMILARITY_PROFILE fingerprints.

Leaves come from files (build_tree_*(file_paths)) or from stored
fingerprints (build_tree_*_from_traits), which is what the CLI uses.

This groups different files by similarity. It is not the lineage DAG
(lineage.py), which records one file's real edit history: internal nodes
here are synthetic, so they carry no mutation delta.
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
        """named_traits: {label: set_of_trait_hashes}. No file I/O."""
        leaves = []
        for label, traits in named_traits.items():
            node = PhylogeneticNode()
            node.trait_matrix = set(traits)
            node.metadata_name = label
            leaves.append(node)
        return self._assign_branch_signatures(leaves)

    def _assign_branch_signatures(self, leaves: List[PhylogeneticNode]) -> List[PhylogeneticNode]:
        # branch_signature: one bit per original leaf, OR'd on merge. 32 bits, so
        # leaves past the 32nd get 0.
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
        """UPGMA from stored trait sets."""
        return self._upgma_merge(self._make_leaves_from_traits(named_traits))

    def build_tree_nj(self, file_paths: List[str]) -> List[PhylogeneticNode]:
        """Neighbor-Joining from files read directly off disk."""
        return self._nj_merge(self._make_leaves_from_files(file_paths))

    def build_tree_nj_from_traits(self, named_traits: Dict[str, set]) -> List[PhylogeneticNode]:
        """Neighbor-Joining from stored trait sets."""
        return self._nj_merge(self._make_leaves_from_traits(named_traits))

    # ---------- UPGMA core ----------

    def _upgma_merge(self, leaves: List[PhylogeneticNode]) -> List[PhylogeneticNode]:
        """UPGMA: repeatedly merges the closest pair, updating distances by the
        size-weighted average. Assumes a constant rate (ultrametric tree).
        Returns every node, leaves and internal.
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
            # Traits distinguishing the two children: a divergence proxy, not a byte delta.
            parent.trait_divergence_count = len(a.trait_matrix.symmetric_difference(b.trait_matrix))

            a.parent_uuid = parent.node_uuid
            b.parent_uuid = parent.node_uuid
            a.branch_length = max(0.0, parent.height - a.height)
            b.branch_length = max(0.0, parent.height - b.height)

            # Size-weighted average distance to every other cluster.
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
        """Neighbor-Joining: no constant-rate assumption, so branch lengths differ
        per child. Rooted at the final join of the last two nodes. Returns every
        node, leaves and internal.
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
            # Clamp rounding noise below zero.
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

        # Two nodes left: join them.
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

    # Distance <= 0.80 (at least 20% shared chunks) means the same clade.
    DEFAULT_CLADE_THRESHOLD = 0.80

    def compute_clades(self, named_traits: Dict[str, set], threshold: float = DEFAULT_CLADE_THRESHOLD) -> Dict[str, List[str]]:
        """Clades: connected components of "Jaccard distance <= threshold",
        unlike the trees, which always span everything.

        Returns {representative: [members]} keyed by each clade's smallest
        member; singletons are included.
        """
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
        """ASCII rendering of the tree."""
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
