# PFS-LKM -- Linux Kernel Module feasibility proof-of-concept

## What this is

This is a **small, deliberately toy-scoped proof-of-concept**, built to
answer one narrow question raised by this project's original design brief
(its section on a Linux kernel module and a hybrid architecture): *is it actually feasible to intercept file operations at
the Linux VFS layer via a `struct file_operations` table, the way a real
"Phase 3" PFS kernel driver eventually would?*

It is **NOT**:

- A production filesystem. It does not implement a superblock, inodes, or
  directory entries, and cannot be `mount`ed anywhere.
- Integrated with the real PFS storage engine in any way. It does not do
  FastCDC chunking, block deduplication, lineage-graph bookkeeping, or any
  encryption -- none of that is reasonable to reimplement inside kernel
  space for a proof-of-concept (kernel code can't link against the
  `cryptography` package or open a catalog file with ordinary libc calls,
  and generally must avoid the kind of blocking/allocation patterns
  userspace storage code uses freely). The real, working PFS engines are
  the Python engine, the C++ engine, and the existing FUSE mount
  (`pfs_fuse.py`, `pfs_fuse_cpp.cpp`) described in `user_manual.pdf` -- this
  module does not touch or replace any of that.

What it **does** demonstrate for real: a loadable kernel module that
registers a character device (`/dev/pfs_lkm`), wires it to a real
`struct file_operations` table with real `.open`/`.read`/`.write`/
`.release` function pointers (exactly the mechanism the design brief
proposed), and logs via `printk` every single
time the kernel calls into one of those functions -- using this project's
own "speciation event" / "delta synthesis" vocabulary in the log lines, so
the tie-back to the rest of PFS's design language is explicit rather than
generic kernel-module boilerplate. Everywhere the real userspace PFS engine
would actually do its work (chunk, hash, dedupe, record a new lineage
generation), the code has an explicit comment saying so, backed by a small
in-kernel memory buffer standing in for real storage just so a `read()`
after a `write()` has something real to hand back.


## Build status: compiles cleanly to a real `.ko`

This module **was successfully compiled** on this machine. Kernel headers
for the exact running kernel (`7.0.0-29-generic`) were already installed
system-wide (`/lib/modules/7.0.0-29-generic/build` -> a valid
`linux-headers-7.0.0-29-generic` tree), so the non-root
`apt-get download` + `dpkg -x` vendoring workaround used for the C++
engine's `libfuse3-dev` headers (see `cpp_engine/third_party/fuse3/README.md`)
was not needed here.

```
$ make
make -C /lib/modules/7.0.0-29-generic/build M=/home/lister/PFS/FastCDC/kernel_module modules
...
  CC [M]  pfs_lkm.o
  MODPOST Module.symvers
  CC [M]  pfs_lkm.mod.o
  CC [M]  .module-common.o
  LD [M]  pfs_lkm.ko
  BTF [M] pfs_lkm.ko
Skipping BTF generation for pfs_lkm.ko due to unavailability of vmlinux
```

(Two harmless warnings appear about the pahole/compiler versions differing
slightly from whatever exactly built the stock kernel package -- these are
routine on any dev machine building an out-of-tree module and do not affect
the result. BTF generation is skipped because no `vmlinux` with debug
symbols is present -- also routine, and does not affect module
functionality.)

`modinfo pfs_lkm.ko` on the result confirms a real, correctly-tagged
module:

```
filename:       pfs_lkm.ko
version:        0.1
description:    PFS-LKM: toy character device demonstrating VFS file_operations interception as a feasibility proof for PFS's 'Phase 3' design. NOT a production filesystem.
license:        GPL
name:           pfs_lkm
vermagic:       7.0.0-29-generic SMP preempt mod_unload modversions
```

The `vermagic` line matches this machine's running kernel (`uname -r`)
exactly, which is required for `insmod` to accept the module at all.

To rebuild from scratch:

```
cd kernel_module
make clean   # removes pfs_lkm.o / pfs_lkm.mod.* / pfs_lkm.ko / build litter
make         # rebuilds pfs_lkm.ko
```

## !! Loading this module carries real risk -- read before doing it !!

Everything below this line involves **actually loading code into the
running kernel**. Unlike ordinary userspace bugs, a kernel module bug
(a bad pointer dereference, a deadlock, an unbalanced lock) can crash or
destabilize the **entire machine**, not just this one program -- there is
no process sandbox around code running in kernel space.

**This module has only ever been compiled, never loaded.** No `insmod`,
`modprobe`, or `rmmod` was run against it while building it, and none of
the commands below were executed as part of writing this proof-of-concept.
That was a deliberate safety decision, not an oversight -- loading a kernel
module is exactly the kind of irreversible, whole-machine-blast-radius
action that should be a **human's own deliberate choice**, run
interactively, on a machine they're prepared to reboot if something goes
wrong (a disposable VM or a machine you can tolerate a hard reset on is the
safer choice over doing this on your only/primary machine) -- never
something run unattended or by an automated tool.

If a human operator wants to try it themselves, here is exactly what that
would involve:

### 1. Load the module (requires root)

```
sudo insmod pfs_lkm.ko
```

If this succeeds there is no output on success (that's normal `insmod`
behavior) -- check the kernel log to confirm:

```
dmesg | tail
```

Expect a line like:

```
PFS-LKM: module loaded. /dev/pfs_lkm is live -- PFS Phylogenetic File
System VFS-interception feasibility proof-of-concept, NOT a production
filesystem. Every open/read/write/release against this device will now be
logged here as it is intercepted.
```

Confirm it's really listed as loaded:

```
lsmod | grep pfs_lkm
```

### 2. Confirm the device node exists

The module uses `misc_register()` with `MISC_DYNAMIC_MINOR`, so on a normal
desktop/server Linux system with `udev` running, `/dev/pfs_lkm` should be
created automatically the moment `insmod` succeeds:

```
ls -l /dev/pfs_lkm
```

If, on some minimal/non-udev system, the node does **not** appear
automatically, find the minor number the kernel actually assigned and
create it manually:

```
grep pfs_lkm /proc/misc
# e.g. "58 pfs_lkm" -- 58 is the minor number, MISC major is always 10
sudo mknod /dev/pfs_lkm c 10 58
sudo chmod 666 /dev/pfs_lkm
```

### 3. Trigger the intercepted operations

Any ordinary write into the device triggers `.open`, `.write`, and
`.release`:

```
echo "hello from a speciation event" > /dev/pfs_lkm
```

Reading it back triggers `.open`, `.read`, and `.release`:

```
cat /dev/pfs_lkm
```

### 4. Watch the interception log

```
dmesg | tail -20
```

Expect to see the real interception log lines, e.g.:

```
PFS-LKM: open() intercepted -- this is the VFS entry point where a real
PFS driver would locate/open a lineage node's current tip generation.
PFS-LKM: write() intercepted, 32 bytes -- this is the speciation-event
hook point (event #1). The real userspace PFS engine would be invoked
here: FastCDC-chunk these bytes, hash + dedupe each chunk against the
global block index, and commit a brand-new lineage generation instead of
overwriting in place. [toy buffer now holds 32/65536 bytes]
PFS-LKM: release() intercepted -- file closed; a real PFS driver would
finalize/commit any pending speciation event here.
PFS-LKM: open() intercepted -- ...
PFS-LKM: read() intercepted, 32 bytes requested at offset 0 -- this is the
delta-synthesis hook point (event #1). The real userspace PFS engine would
be invoked here: walk the ancestral generation chain and stitch
chunks/deltas into one reconstructed byte stream before handing it back.
PFS-LKM: release() intercepted -- ...
```

(You can also watch these live in a second terminal with
`sudo dmesg -w` while triggering operations in the first.)

### 5. Unload the module (requires root)

```
sudo rmmod pfs_lkm
```

Check `dmesg | tail` again for the unload confirmation line (includes a
final tally of how many write/read interceptions happened during that
load):

```
PFS-LKM: module unloaded. Final tally this load: 1 write() interceptions
(speciation-event hook points), 1 read() interceptions (delta-synthesis
hook points). /dev/pfs_lkm is gone.
```

Confirm it's really gone:

```
lsmod | grep pfs_lkm   # should print nothing
ls /dev/pfs_lkm        # should say "No such file or directory"
```

## Files in this directory

- `pfs_lkm.c` -- the module source. Heavily commented (see the file's own
  top-of-file note on why the comment density here is unusually high for
  this codebase).
- `Makefile` -- standard out-of-tree Kbuild-style module Makefile
  (`obj-m`, `KDIR := /lib/modules/$(shell uname -r)/build`, delegates the
  real build to `make -C $(KDIR) M=$(PWD) modules`).
- `pfs_lkm.ko` -- the compiled module (present after a successful `make`;
  removed by `make clean`).
- `README.md` -- this file.

---

# pfsfs.ko -- PFS's storage model as a mountable filesystem

**Status: written and compiled against kernel 7.0.0-38 headers (clean,
including `make W=1`); never loaded or run. Unverified.**

`pfsfs.c` is a second, separate module. Unlike `pfs_lkm`, it is a real
filesystem you can mount:

- A file's working copy lives in the page cache (ramfs's `ram_aops`).
- When a file that was written is closed (or truncated with no writer
  open), it gets a new **generation**: its content is cut into
  content-defined chunks with the same Gear table (`pfs_gear_table.h`,
  generated from `gearhash/table.py`) and parameters (mask `0x1FFF`,
  4–16 KiB) as the userspace engines, each chunk is SHA-256 hashed, and
  each distinct chunk is stored once per mount. A byte-identical resave
  adds no generation. Deleting a file drops its whole history.
- `.pfs_lineage` (read-only) lists every file's generations and the dedup
  totals. `.pfs_checkout`: write `"<name> <generation>"`, then read back
  that generation, rebuilt from its chunks with every chunk's hash
  re-checked (generations up to 64 MiB).
- Flat namespace (no subdirectories). No encryption, no persistence
  (unmount discards everything), no clade clustering -- those stay in
  userspace.

## Testing it (on a disposable machine or VM)

```sh
make
sudo insmod pfsfs.ko
sudo mkdir -p /mnt/pfs && sudo mount -t pfsfs none /mnt/pfs
head -c 200000 /dev/urandom | sudo tee /mnt/pfs/a > /dev/null
sudo cp /mnt/pfs/a /mnt/pfs/b               # same content: no new chunks
echo edit | sudo tee -a /mnt/pfs/a > /dev/null
cat /mnt/pfs/.pfs_lineage                   # a: generations 0 and 1; b: 0
# generation 0 of a, rebuilt from its chunks, must equal a's first 200000 bytes
sudo python3 -c '
f = open("/mnt/pfs/.pfs_checkout", "r+b", buffering=0)
f.write(b"a 0"); f.seek(0); old = f.read()
print(old == open("/mnt/pfs/a", "rb").read(200000))'
sudo umount /mnt/pfs && sudo rmmod pfsfs
```

`.pfs_checkout` keeps the rebuilt generation per open file, so the
request and the read must use the same open file, as above.

## Where it is most likely to be wrong

The compile checks names, types and exported symbols, not behaviour.
Places that depend on kernel-version semantics this machine couldn't
check (only headers were available, no kernel sources):

- Kernel 7.0's persistent-dentry API: `d_make_persistent()` in create and
  for the two control files (with `simple_start_creating()` /
  `simple_done_creating()`), `simple_unlink()` making the dentry
  discardable again, and `kill_anon_super()` cleaning up persistent
  dentries at unmount (it replaced `kill_litter_super()`).
- `pfs_setattr()` speciates when `i_writecount` shows no writer; the
  O_TRUNC open path is expected to see the opener counted already.
- `pfs_speciate()` reads the page cache with `read_mapping_folio()` while
  holding the mount's mutex.
