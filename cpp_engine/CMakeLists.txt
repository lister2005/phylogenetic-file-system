cmake_minimum_required(VERSION 3.16)
project(pfs_cpp_engine LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_STANDARD 11)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()
set(CMAKE_CXX_FLAGS_RELEASE "-O2")
set(CMAKE_C_FLAGS_RELEASE "-O2")

# Every static lib in this project needs to be linkable into the
# pfs_engine_capi SHARED library (the Python/ctypes boundary) -- that
# requires position-independent code throughout, not just in the .so
# target itself. Negligible cost for the plain executables/test
# binaries that don't strictly need it.
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

find_package(OpenSSL REQUIRED)
find_package(SQLite3 REQUIRED)

include_directories(include)

# FUSE3: the runtime library (libfuse3.so.3) is a normal system package
# on most Linux distros, but the -dev package (headers + unversioned
# .so symlink) may not be installed and needs root to add. Rather than
# require that, this vendors just the -dev package's CONTENTS (headers
# + .pc file + the .so symlink, all under third_party/fuse3/, extracted
# via `apt-get download` + `dpkg -x` -- no system changes, no root)
# checked into this repo -- see third_party/fuse3/README (if present)
# or cpp_port_plan.txt for how it got there. Falls back to a normal
# system find_package/pkg-config lookup first, in case the -dev package
# genuinely is installed on whatever machine builds this next.
set(FUSE3_VENDORED_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/third_party/fuse3/usr")
find_path(FUSE3_INCLUDE_DIR NAMES fuse3/fuse.h
    PATHS /usr/include ${FUSE3_VENDORED_ROOT}/include)
find_library(FUSE3_LIBRARY NAMES fuse3
    PATHS /usr/lib/x86_64-linux-gnu ${FUSE3_VENDORED_ROOT}/lib/x86_64-linux-gnu)
if(FUSE3_INCLUDE_DIR AND FUSE3_LIBRARY)
    message(STATUS "FUSE3 found: ${FUSE3_INCLUDE_DIR}, ${FUSE3_LIBRARY}")
    set(FUSE3_FOUND TRUE)
else()
    message(WARNING "FUSE3 not found -- pfs_fuse target will be skipped")
    set(FUSE3_FOUND FALSE)
endif()

# The chunk-boundary core, compiled from the SAME source file the Python
# engine already ships (gearhash/gearhash_core.c) -- not reimplemented.
add_library(gearhash_core STATIC src/gearhash_core.c)

# Shared crypto primitives (SHA-256, HMAC, HKDF, AES-256-GCM) -- used by
# both the dedup index and the manifest module. See crypto_utils.hpp for
# why each one exists and what Python code it's matched against.
add_library(crypto_utils STATIC src/crypto_utils.cpp)
target_link_libraries(crypto_utils PUBLIC OpenSSL::Crypto)

# Phase 1 prototype: chunk + hash + encrypt + persist, one native loop,
# no per-chunk Python/FFI crossing. Deliberately does NOT yet integrate
# the dedup index, manifest, or keyring -- see cpp_port_plan.txt for why
# (those need new portable formats; this benchmark isolates and measures
# the specific per-chunk-interpreter-overhead hypothesis first, per the
# plan's own "prototype and benchmark before building further" rule).
add_executable(engine_write_bench bench/engine_write_bench.cpp)
target_link_libraries(engine_write_bench PRIVATE gearhash_core OpenSSL::Crypto)

add_executable(dump_chunk_lengths bench/dump_chunk_lengths.cpp)
target_link_libraries(dump_chunk_lengths PRIVATE gearhash_core)

add_executable(hkdf_check bench/hkdf_check.cpp)
target_link_libraries(hkdf_check PRIVATE OpenSSL::Crypto)

add_library(dedup_index STATIC src/dedup_index.cpp)
target_link_libraries(dedup_index PUBLIC crypto_utils SQLite::SQLite3)

add_executable(dedup_index_tool bench/dedup_index_tool.cpp)
target_link_libraries(dedup_index_tool PRIVATE dedup_index)

add_executable(dedup_index_bench bench/dedup_index_bench.cpp)
target_link_libraries(dedup_index_bench PRIVATE dedup_index)

add_executable(engine_write_bench_v2 bench/engine_write_bench_v2.cpp)
target_link_libraries(engine_write_bench_v2 PRIVATE gearhash_core dedup_index OpenSSL::Crypto)

add_library(manifest STATIC src/manifest.cpp)
target_link_libraries(manifest PUBLIC crypto_utils)

add_executable(manifest_roundtrip_test bench/manifest_roundtrip_test.cpp)
target_link_libraries(manifest_roundtrip_test PRIVATE manifest)

add_executable(engine_write_read_bench bench/engine_write_read_bench.cpp)
target_link_libraries(engine_write_read_bench PRIVATE gearhash_core dedup_index manifest crypto_utils)

add_library(immutability STATIC src/immutability.cpp)

add_library(keyring STATIC src/keyring.cpp)
target_link_libraries(keyring PUBLIC crypto_utils immutability)

add_executable(keyring_test bench/keyring_test.cpp)
target_link_libraries(keyring_test PRIVATE keyring)

add_executable(keyring_wrap_check bench/keyring_wrap_check.cpp)
target_link_libraries(keyring_wrap_check PRIVATE crypto_utils)

add_executable(engine_write_read_bench_v2 bench/engine_write_read_bench_v2.cpp)
target_link_libraries(engine_write_read_bench_v2 PRIVATE gearhash_core dedup_index manifest keyring crypto_utils)

add_executable(keyring_rotation_test bench/keyring_rotation_test.cpp)
target_link_libraries(keyring_rotation_test PRIVATE gearhash_core dedup_index manifest keyring crypto_utils)

# The actual engine entry points (write a file, read a file back),
# consolidating what several bench files above had been duplicating,
# and including Ancestral Hardening mirroring -- see pipeline.hpp.
# Clade clustering (PhylogeneticAnalyzer.py + TreeConstructor.py port) --
# deliberately independent of lineage_store (see phylo.hpp's own
# docstring for why the two must not be conflated). Declared here,
# before StoragePipeline, since secure_and_persist_file() computes a
# similarity fingerprint at write time using it.
add_library(phenotype STATIC src/phenotype.cpp)

# The repo root (parent of cpp_engine/), baked into the two tests that
# shell out to the REAL Python modules for cross-verification, so they
# follow the project wherever it lives instead of a hardcoded path.
get_filename_component(PFS_REPO_ROOT "${CMAKE_CURRENT_SOURCE_DIR}" DIRECTORY)

add_executable(phenotype_test bench/phenotype_test.cpp)
target_link_libraries(phenotype_test PRIVATE phenotype)
target_compile_definitions(phenotype_test PRIVATE PFS_REPO_ROOT="${PFS_REPO_ROOT}")

add_library(phylo STATIC src/phylo.cpp)
target_link_libraries(phylo PUBLIC crypto_utils gearhash_core)

add_library(pipeline STATIC src/pipeline.cpp)
target_link_libraries(pipeline PUBLIC gearhash_core dedup_index manifest keyring crypto_utils phylo phenotype)

add_executable(pipeline_test bench/pipeline_test.cpp)
target_link_libraries(pipeline_test PRIVATE pipeline)

add_executable(pipeline_mirroring_test bench/pipeline_mirroring_test.cpp)
target_link_libraries(pipeline_mirroring_test PRIVATE pipeline)

add_executable(manifest_reader_test bench/manifest_reader_test.cpp)
target_link_libraries(manifest_reader_test PRIVATE pipeline)

add_executable(vacuum_fsck_test bench/vacuum_fsck_test.cpp)
target_link_libraries(vacuum_fsck_test PRIVATE pipeline)

add_executable(delete_prune_test bench/delete_prune_test.cpp)
target_link_libraries(delete_prune_test PRIVATE vault_session)

add_executable(graft_test bench/graft_test.cpp)
target_link_libraries(graft_test PRIVATE vault_session)

# Clade clustering (PhylogeneticAnalyzer.py + TreeConstructor.py port) --
# deliberately independent of lineage_store (see phylo.hpp's own
# docstring for why the two must not be conflated).
add_executable(phylo_test bench/phylo_test.cpp)
target_link_libraries(phylo_test PRIVATE phylo)
target_compile_definitions(phylo_test PRIVATE PFS_REPO_ROOT="${PFS_REPO_ROOT}")

add_library(clade_worker STATIC src/clade_worker.cpp)
target_link_libraries(clade_worker PUBLIC phylo)
find_package(Threads REQUIRED)
target_link_libraries(clade_worker PUBLIC Threads::Threads)

add_executable(clade_worker_test bench/clade_worker_test.cpp)
target_link_libraries(clade_worker_test PRIVATE clade_worker)

add_executable(migration_verify_test bench/migration_verify_test.cpp)
target_link_libraries(migration_verify_test PRIVATE pipeline)

# Component 2: the lineage store (per-label edit history DAG).
add_library(lineage_store STATIC src/lineage_store.cpp)
target_link_libraries(lineage_store PUBLIC crypto_utils)

add_executable(lineage_store_test bench/lineage_store_test.cpp)
target_link_libraries(lineage_store_test PRIVATE lineage_store)

add_executable(lineage_scaling_bench bench/lineage_scaling_bench.cpp)
target_link_libraries(lineage_scaling_bench PRIVATE lineage_store)

add_executable(lineage_migration_verify bench/lineage_migration_verify.cpp)
target_link_libraries(lineage_migration_verify PRIVATE lineage_store)

# merge_branches -- cross-cutting over StoragePipeline + LineageStore.
add_library(merge STATIC src/merge.cpp)
target_link_libraries(merge PUBLIC pipeline lineage_store manifest)

add_executable(merge_test bench/merge_test.cpp)
target_link_libraries(merge_test PRIVATE merge)

add_library(catalog STATIC src/catalog.cpp)
target_link_libraries(catalog PUBLIC crypto_utils immutability)

add_executable(catalog_test bench/catalog_test.cpp)
target_link_libraries(catalog_test PRIVATE catalog)

add_library(vault_session STATIC src/vault_session.cpp src/vault_lock.cpp)
target_link_libraries(vault_session PUBLIC pipeline lineage_store catalog merge)

add_executable(vault_session_test bench/vault_session_test.cpp)
target_link_libraries(vault_session_test PRIVATE vault_session)

# Component 3: the real FUSE mount. Flat presentation (see
# pfs_fuse_cpp.cpp's own header comment for exactly what's in and out
# of scope for this pass).
if(FUSE3_FOUND)
    add_executable(pfs_fuse_cpp src/pfs_fuse_cpp.cpp)
    target_include_directories(pfs_fuse_cpp PRIVATE ${FUSE3_INCLUDE_DIR})
    target_link_libraries(pfs_fuse_cpp PRIVATE vault_session manifest clade_worker ${FUSE3_LIBRARY})
    target_compile_definitions(pfs_fuse_cpp PRIVATE _FILE_OFFSET_BITS=64)
endif()

add_executable(big_file_bench bench/big_file_bench.cpp)
target_link_libraries(big_file_bench PRIVATE vault_session manifest)

add_executable(big_file_profile bench/big_file_profile.cpp)
target_link_libraries(big_file_profile PRIVATE gearhash_core dedup_index keyring crypto_utils)

# PART 8 item #1 before/after measurement -- same fixture/phase-timer
# methodology as big_file_profile, batched dedup-index calls instead of
# one lookup()/register_new() per chunk. See bench/big_file_profile_batched.cpp.
add_executable(big_file_profile_batched bench/big_file_profile_batched.cpp)
target_link_libraries(big_file_profile_batched PRIVATE gearhash_core dedup_index keyring crypto_utils)

# The Python<->C++ binding boundary: a shared library exposing only the
# plain-C API in include/c_api.h, for ctypes to dlopen. See
# pfs_engine_binding.py (repo root) for the Python-side wrapper.
add_library(pfs_engine_capi SHARED src/c_api.cpp)
target_link_libraries(pfs_engine_capi PRIVATE vault_session manifest)
set_target_properties(pfs_engine_capi PROPERTIES OUTPUT_NAME "pfs_engine_capi")
