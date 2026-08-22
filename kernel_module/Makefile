# Makefile for pfs_lkm.ko -- standard out-of-tree kernel module build.
#
# This follows the conventional "Kbuild" pattern every out-of-tree Linux
# kernel module uses: this Makefile does NOT compile pfs_lkm.c itself.
# Instead, `make` re-invokes the running kernel's OWN build system (found
# under /lib/modules/$(uname -r)/build, which is normally a symlink into the
# matching linux-headers-* package) with M=$(PWD), telling that build system
# "come build the module described by THIS directory's Kbuild rules, and
# drop the output back here." That's why kernel modules must be built against
# headers matching the exact running kernel version -- the kernel's internal
# structures/ABI are not stable across versions the way userspace libraries
# are.
#
# obj-m says "pfs_lkm.o should be built as a loadable module" (as opposed to
# obj-y, which the real kernel tree uses for things built directly into the
# kernel image). Because the module is named pfs_lkm, Kbuild automatically
# compiles pfs_lkm.c into pfs_lkm.o and then links that into pfs_lkm.ko --
# no explicit compile rule needed, this is Kbuild's own naming convention.
obj-m += pfs_lkm.o

# KDIR points at the running kernel's build directory (headers + Kbuild
# infrastructure matching `uname -r` exactly). This must exist -- it comes
# from installing the matching linux-headers-$(uname -r) package.
KDIR := /lib/modules/$(shell uname -r)/build

# PWD is this directory -- passed as M= so the kernel build system knows
# where to find pfs_lkm.c and where to drop pfs_lkm.ko.
PWD := $(shell pwd)

# Default target: delegate the actual build to the kernel's own Makefile.
all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

# Standard matching clean target -- also delegates to the kernel build
# system so it can remove exactly the intermediate files it generated
# (pfs_lkm.o, pfs_lkm.mod.c, pfs_lkm.mod.o, .pfs_lkm.*.cmd, etc), not just a
# hand-guessed file list.
clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

.PHONY: all clean
