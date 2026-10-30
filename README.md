# PFS — Phylogenetic File System

A filesystem that replaces directory hierarchies with a biology-inspired
lineage graph. Every save is a new generation, not an overwrite. Content is
split into variable-length chunks (FastCDC / Gear hash), deduplicated across
the whole vault, and encrypted with AES-256-GCM under rotating keys.
Separately, unrelated files are grouped into similarity "clades" (UPGMA /
Neighbor-Joining over chunk overlap).

There are two interchangeable storage engines — the original Python engine
and a compiled C++ port — each with a CLI shell, a desktop GUI and a FUSE
mount. A vault belongs to the engine that created it; the other engine
refuses to open it.

## Setup (Linux)

```sh
python3 -m venv .venv                          # Python 3.12
.venv/bin/python3 -m pip install -r requirements.txt

# C++ engine: needs cmake, g++, libssl-dev, libsqlite3-dev
# (FUSE headers are vendored in cpp_engine/third_party/fuse3)
cmake -S cpp_engine -B cpp_engine/build -DCMAKE_BUILD_TYPE=Release
cmake --build cpp_engine/build -j4
```

Run everything from this directory with `.venv/bin/python3`, and never with
`sudo` — nothing needs root, and `sudo` silently switches to the system
Python.

## Using it

```sh
.venv/bin/python3 pfs_cli.py my_vault                  # Python-engine shell
.venv/bin/python3 pfs_cli.py --engine cpp my_vault_cpp # C++-engine shell
.venv/bin/python3 pfs_gui.py my_vault                  # GUI ("Cosmic Web" view)
```

Inside a shell, `help` lists every command. Put a label or path containing
spaces in quotes: `write "/home/me/Q3 report.pdf" "q3 report"`. After you
re-enter the passphrase once, vault commands run without asking again for
5 minutes; `delete` and `panic` always ask.

## Documentation

| Read | For |
|---|---|
| `manual.pdf` | Every command, both engines, security posture, known limitations |
| `gui_manual.pdf` | Using the desktop app, with screenshots and troubleshooting |

Vault directories (`pfs_storage_vault*/`) hold real key material and are
kept out of git.
