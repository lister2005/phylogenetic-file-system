import pickle
import random
from typing import List, Tuple, Any, Optional

FKS_PRIME = 18446744073709551629

class FKSIndexBuilder:
    def __init__(self, key_value_pairs: List[Tuple[int, Any]], metadata: dict = None):
        unique_mappings = {}
        for k, v in key_value_pairs:
            unique_mappings[int(k)] = v
            
        self.raw_data = list(unique_mappings.items())
        self.n_total = len(self.raw_data)
        self.m1 = max(1, self.n_total)
        self.a1 = 0
        self.buckets = {i: [] for i in range(self.m1)}
        
        self.a2_multipliers = [0] * self.m1
        self.m2_sizes = [0] * self.m1
        self.secondary_tables = [[] for _ in range(self.m1)]
        self.metadata = metadata or {}

    def _hash(self, key: int, a: int, m: int) -> int:
        return ((a * key) % FKS_PRIME) % m

    def build(self) -> None:
        rng = random.Random()  # OS entropy: not deterministic
        
        while True:
            self.a1 = rng.randint(1, FKS_PRIME - 1)
            for i in range(self.m1):
                self.buckets[i].clear()
                
            for k, v in self.raw_data:
                idx = self._hash(k, self.a1, self.m1)
                self.buckets[idx].append((k, v))
                
            sum_n_squared = sum(len(self.buckets[i]) ** 2 for i in range(self.m1))
            if sum_n_squared <= 4 * self.n_total + 2:
                break

        for i in range(self.m1):
            bucket_items = self.buckets[i]
            n = len(bucket_items)
            if n == 0:
                continue
                
            m2 = n * n
            self.m2_sizes[i] = m2
            self.secondary_tables[i] = [None] * m2
            
            if n == 1:
                self.a2_multipliers[i] = 1
                idx = self._hash(bucket_items[0][0], 1, m2)
                self.secondary_tables[i][idx] = bucket_items[0]
                continue

            while True:
                a2 = rng.randint(1, FKS_PRIME - 1)
                temp_table = [None] * m2
                collision = False
                
                for k, v in bucket_items:
                    idx = self._hash(k, a2, m2)
                    if temp_table[idx] is not None:
                        collision = True
                        break
                    temp_table[idx] = (k, v)
                    
                if not collision:
                    self.a2_multipliers[i] = a2
                    self.secondary_tables[i] = temp_table
                    break

    def serialize(self) -> bytes:
        """The pickled state as bytes; callers encrypt it themselves."""
        state = {
            "m1": self.m1,
            "a1": self.a1,
            "a2_multipliers": self.a2_multipliers,
            "m2_sizes": self.m2_sizes,
            "secondary_tables": self.secondary_tables,
            "n_total": self.n_total,
            "metadata": self.metadata,
        }
        return pickle.dumps(state)

    def save_to_file(self, filepath: str) -> None:
        """Unencrypted save; sensitive data should use serialize() and encrypt."""
        with open(filepath, "wb") as f:
            f.write(self.serialize())


class FKSLookupEngine:
    def __init__(self, filepath: str = None, raw_bytes: bytes = None) -> None:
        if raw_bytes is None:
            with open(filepath, "rb") as f:
                raw_bytes = f.read()
        state = pickle.loads(raw_bytes)
            
        self.m1 = state["m1"]
        self.a1 = state["a1"]
        self.a2_multipliers = state["a2_multipliers"]
        self.m2_sizes = state["m2_sizes"]
        self.secondary_tables = state["secondary_tables"]
        self.n_total = state.get("n_total")
        self.metadata = state.get("metadata", {})

    def _hash(self, key: int, a: int, m: int) -> int:
        return ((a * key) % FKS_PRIME) % m

    def lookup(self, key: int) -> Optional[Any]:
        int_key = int(key)
        idx1 = self._hash(int_key, self.a1, self.m1)
        m2 = self.m2_sizes[idx1]
        if m2 == 0:
            return None
            
        a2 = self.a2_multipliers[idx1]
        idx2 = self._hash(int_key, a2, m2)
        
        entry = self.secondary_tables[idx1][idx2]
        if entry is not None and entry[0] == int_key:
            return entry[1]
        return None

    def enumerate_all(self):
        """Yields every stored (key, value)."""
        for bucket in self.secondary_tables:
            for entry in bucket:
                if entry is not None:
                    yield entry