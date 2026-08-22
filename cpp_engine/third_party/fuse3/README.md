# Vendored libfuse3 development headers

This directory is the extracted **contents** of the `libfuse3-dev` Ubuntu
package (headers, `fuse3.pc`, and the unversioned `libfuse3.so` symlink) —
not a system install. It was fetched like this, with no root access:

```sh
apt-get download libfuse3-dev          # downloads the .deb, no sudo needed
dpkg -x libfuse3-dev_*.deb third_party/fuse3   # extracts it locally, installs nothing
```

## Why this exists

The runtime library (`libfuse3.so.3`) is a normal, already-installed system
package on most Linux boxes — but the matching `-dev` package (headers +
the unversioned `.so` symlink compilers/linkers look for) often isn't, and
installing it system-wide needs root. This build doesn't require that: it
extracts just the dev package's files into the repo instead.

**Version pinned to what was already installed at extraction time**
(3.14.0), specifically so the vendored headers stay ABI-compatible with
whatever `libfuse3.so.3` is actually loaded at link/run time — verified
directly (not assumed) with a trivial `fuse_version()` call before
anything else in `cpp_engine/` was built against these headers.

`CMakeLists.txt` looks for a normal system `libfuse3-dev` install first
(via `find_path`/`find_library`) and only falls back to this vendored copy
if that's not found — so a machine that already has the dev package
installed doesn't need this directory at all.

## If this ever needs updating

Re-run the two commands above with whatever `libfuse3-dev` version matches
the target system's installed `libfuse3.so.3`, then replace this
directory's contents.
