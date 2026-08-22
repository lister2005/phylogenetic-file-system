#pragma once
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// Declarations for the functions in gearhash_core.c -- copied verbatim
// from gearhash/gearhash_core.c (the same file the Python engine already
// compiles into libgearhash.so), not reimplemented, so chunk-boundary
// behavior is guaranteed identical to what Python already writes.
size_t scan_chunk_c(const uint8_t* data, size_t data_len, size_t cursor,
                     uint64_t* current_hash, uint64_t mask,
                     size_t min_size, size_t max_size,
                     const uint64_t* gear_table);

int scan_batch_c(const uint8_t* data, size_t data_len, uint64_t* hash_ptr,
                  uint64_t mask, size_t min_size, size_t max_size,
                  const uint64_t* gear_table, int* results, int max_chunks);

#ifdef __cplusplus
}
#endif
