#include <stdint.h>
#include <stddef.h>

// Original single-chunk scanner kept for compatibility
size_t scan_chunk_c(const uint8_t* data, size_t data_len, size_t cursor, uint64_t* current_hash, uint64_t mask, size_t min_size, size_t max_size, const uint64_t* gear_table) {
    size_t start = cursor;
    size_t max_limit = (start + max_size > data_len) ? data_len : start + max_size;
    size_t min_limit = (start + min_size > data_len) ? data_len : start + min_size;

    while (cursor < min_limit) { *current_hash = ((*current_hash << 1) + gear_table[data[cursor++]]); }
    while (cursor < max_limit) {
        *current_hash = ((*current_hash << 1) + gear_table[data[cursor++]]);
        if ((*current_hash & mask) == 0) break;
    }
    return cursor - start;
}

// Like scan_chunk_c, for storage chunking: when no natural cut appears before
// max_size and the data goes on, cuts after the candidate position (one
// that a natural cut could have used) with the lowest hash, the earliest on
// a tie, instead of exactly at max_size. That position depends on the
// content, so cuts still move with an edit: in data that repeats (padding,
// silence, repeated lines) it falls at the same point of the pattern every
// time, and the chunks after an insertion line up with the old ones again.
// *current_hash is left as it was at the cut.
size_t scan_chunk_anchored_c(const uint8_t* data, size_t data_len, size_t cursor, uint64_t* current_hash, uint64_t mask, size_t min_size, size_t max_size, const uint64_t* gear_table) {
    size_t start = cursor;
    if (start + max_size > data_len) {
        // The end of the data: nothing comes after it to line up with.
        return scan_chunk_c(data, data_len, cursor, current_hash, mask, min_size, max_size, gear_table);
    }
    size_t min_limit = start + min_size;
    size_t max_limit = start + max_size;
    uint64_t hash = *current_hash;
    while (cursor < min_limit) { hash = (hash << 1) + gear_table[data[cursor++]]; }
    uint64_t best_hash = UINT64_MAX;
    size_t best_end = max_limit;
    while (cursor < max_limit) {
        hash = (hash << 1) + gear_table[data[cursor++]];
        if ((hash & mask) == 0) {
            *current_hash = hash;
            return cursor - start;
        }
        if (hash < best_hash) {  // strictly lower: the earliest position wins a tie
            best_hash = hash;
            best_end = cursor;
        }
    }
    *current_hash = best_hash;
    return best_end - start;
}

// NEW: Vectorized Batch Scanner
// Fills results array with [length1, length2, length3...]
// Returns number of chunks found
int scan_batch_c(const uint8_t* data, size_t data_len, uint64_t* hash_ptr, uint64_t mask, size_t min_size, size_t max_size, const uint64_t* gear_table, int* results, int max_chunks) {
    size_t cursor = 0;
    int chunks_found = 0;
    
    while (cursor < data_len && chunks_found < max_chunks) {
        size_t start = cursor;
        size_t max_limit = (start + max_size > data_len) ? data_len : start + max_size;
        size_t min_limit = (start + min_size > data_len) ? data_len : start + min_size;

        // Min size phase
        while (cursor < min_limit) { *hash_ptr = ((*hash_ptr << 1) + gear_table[data[cursor++]]); }
        
        // Max size phase
        while (cursor < max_limit) {
            *hash_ptr = ((*hash_ptr << 1) + gear_table[data[cursor++]]);
            if ((*hash_ptr & mask) == 0) break;
        }
        
        results[chunks_found++] = (int)(cursor - start);
    }
    return chunks_found;
}