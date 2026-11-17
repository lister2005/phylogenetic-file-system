# Authorship

PFS (the Phylogenetic File System) is a project by **Kudi Aye Lordlister**.

This document sets out who did what, how AI tools were used, and whose work
PFS builds on. The full story of the project, from the original idea to the
finished system, is in [DOCUMENTATION.md](DOCUMENTATION.md).

## My role

### The idea

I came up with the idea of treating files like genes while studying how the
distance and relatedness between genes are calculated, in a bioinformatics
course on MIT OpenCourseWare. I then researched how to make the idea work in
practice, which led me to content-defined chunking, Jaccard distance, and the
Neighbour-Joining and UPGMA tree-building methods.

### Design decisions

The most important decision was what PFS should be and do. Once I realised
that such a system would need neither folders nor file extensions, because
files can organise themselves by their content and ancestry, I had to decide
on the details that make this possible: the chunk size, the hashing
algorithms, and the content-chunking methods and concepts to implement.

### Architecture

I designed the architecture of the system:

- chunked, deduplicated and encrypted storage;
- a version history that can branch and merge;
- grouping of files by similarity;
- two interchangeable storage engines;
- three ways in: a desktop app, a command shell and a mounted folder.

### Trade-offs

Building PFS involved many trade-offs and errors. One example is chunk size
against read and write time: I had to find the balance that I judged to be
the best chunk size for keeping read and write latency low.

## Use of AI tools

AI coding agents, mainly Anthropic's Claude Code, wrote most of the code and
the automated tests, helped with testing and debugging, and wrote the
documentation, working to my direction. I set the goals for each stage,
reviewed their solutions and code in detail, tested the results, and decided
what was kept, changed or dropped.

## Built on the work of others

### Research

- **FastCDC.** Wen Xia, Hong Jiang, Dan Feng, Lei Tian, Min Fu and Yukun
  Zhou, "FastCDC: a Fast and Efficient Content-Defined Chunking Approach for
  Data Deduplication", 2016 USENIX Annual Technical Conference. PFS's
  chunking is based on this paper.
- **Neighbour-Joining.** Naruya Saitou and Masatoshi Nei, *Molecular Biology
  and Evolution*, 1987.
- **UPGMA.** Robert Sokal and Charles Michener, 1958.
- **Jaccard index.** Paul Jaccard, 1901.

### Code

- **rust-gearhash** by Sam Rijs and contributors
  (https://github.com/srijs/rust-gearhash, MIT or Apache-2.0). PFS's Gear
  hash table and hasher (`gearhash/table.py`, `gearhash/hasher.py`) were
  ported from this library, and the same table is used by the C++ engine and
  the kernel modules. Its license notice is reproduced in `LICENSE`.
- **FastCDC implementations studied while building PFS's chunker:**
  fastcdc-go (https://github.com/jotfs/fastcdc-go, Apache-2.0) and
  fastcdc-rs by Nathan Fiedler (https://github.com/nlfiedler/fastcdc-rs,
  MIT).

### Courses (MIT OpenCourseWare)

- **7.91J** *Foundations of Computational and Systems Biology*: the
  bioinformatics course where the idea began.
- **9.40** *Introduction to Neural Computation*: inspired the idea further.
- **6.046J / 18.410J** *Design and Analysis of Algorithms* and **6.851**
  *Advanced Data Structures*: helped develop the design.

### Software

Python, PySide6 (Qt), the `cryptography` library, NetworkX, fusepy, libfuse,
SQLite and OpenSSL. The libfuse3 development files in
`cpp_engine/third_party/fuse3/` are third-party code under their own license.

## License

PFS is released under the MIT License (see `LICENSE`). The Linux kernel
modules in `kernel_module/` are GPL-2.0.
