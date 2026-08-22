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