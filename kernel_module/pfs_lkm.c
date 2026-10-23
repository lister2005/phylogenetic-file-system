/*
 * pfs_lkm: proof of concept for intercepting file operations in the kernel
 * through a struct file_operations table, as Project_idea.txt section 4
 * proposes for a kernel-level PFS.
 *
 * A character device, /dev/pfs_lkm, whose open/read/write/release log each
 * call with printk. Writes append to a 64 KiB in-kernel buffer that reads
 * serve back. Not a filesystem and not connected to the PFS engine; see
 * pfsfs.c for the storage model in kernel space.
 *
 * Never loaded into a running kernel: see README.md before loading it.
 */

/*
 * miscdevice.h: misc_register(), the simplest way to expose one device
 * node. uaccess.h: copy_to_user()/copy_from_user(), the only safe way to
 * cross the user/kernel boundary.
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/mutex.h>    /* protects the buffer below */

MODULE_LICENSE("GPL");
MODULE_AUTHOR("PFS project (Phylogenetic File System) -- proof-of-concept");
MODULE_DESCRIPTION(
	"PFS-LKM: toy character device demonstrating VFS file_operations "
	"interception as a feasibility proof for PFS's 'Phase 3' design, "
	"per Project_idea.txt section 4. NOT a production filesystem.");
MODULE_VERSION("0.1");

/*
 * Stand-in for PFS storage: a fixed buffer that write() appends to and
 * read() serves from. Not chunked, hashed or versioned.
 */
#define PFS_LKM_BUF_SIZE (64 * 1024)   /* 64 KiB */

static char *pfs_lkm_buffer;           /* allocated in pfs_lkm_init() */
static size_t pfs_lkm_buffer_len;      /* bytes stored */
static DEFINE_MUTEX(pfs_lkm_lock);     /* serializes concurrent open()ers   */

/* Event counters for the log lines. */
static unsigned long pfs_lkm_write_events;
static unsigned long pfs_lkm_read_events;

/* open: logs the call. All opens share the one buffer. */
static int pfs_lkm_open(struct inode *inode, struct file *file)
{
	printk(KERN_INFO
	       "PFS-LKM: open() intercepted -- this is the VFS entry point "
	       "where a real PFS driver would locate/open a lineage node's "
	       "current tip generation.\n");
	return 0;
}

/* release: called when the last reference to an open file goes away; logs it. */
static int pfs_lkm_release(struct inode *inode, struct file *file)
{
	printk(KERN_INFO
	       "PFS-LKM: release() intercepted -- file closed; a real PFS "
	       "driver would finalize/commit any pending speciation event "
	       "here.\n");
	return 0;
}

/*
 * write: where PFS would turn each write into a new generation (chunk,
 * hash, dedup, record). Here the bytes are appended to the buffer.
 */
static ssize_t pfs_lkm_write(struct file *file, const char __user *user_buf,
			      size_t count, loff_t *offset)
{
	size_t space_left;
	size_t to_copy;

	mutex_lock(&pfs_lkm_lock);

	/* Only as much as fits in the buffer. */
	space_left = PFS_LKM_BUF_SIZE - pfs_lkm_buffer_len;
	to_copy = count < space_left ? count : space_left;

	if (to_copy > 0) {
		/* user_buf points into the caller's address space: copy, never dereference. */
		if (copy_from_user(pfs_lkm_buffer + pfs_lkm_buffer_len,
				    user_buf, to_copy)) {
			mutex_unlock(&pfs_lkm_lock);
			return -EFAULT;
		}
		pfs_lkm_buffer_len += to_copy;
	}

	pfs_lkm_write_events++;

	printk(KERN_INFO
	       "PFS-LKM: write() intercepted, %zu bytes -- this is the "
	       "speciation-event hook point (event #%lu). The real userspace "
	       "PFS engine would be invoked here: FastCDC-chunk these bytes, "
	       "hash + dedupe each chunk against the global block index, and "
	       "commit a brand-new lineage generation instead of overwriting "
	       "in place. [toy buffer now holds %zu/%d bytes]\n",
	       to_copy, pfs_lkm_write_events, pfs_lkm_buffer_len,
	       PFS_LKM_BUF_SIZE);

	mutex_unlock(&pfs_lkm_lock);

	/* Return the bytes actually accepted; a full buffer is reported, not hidden. */
	if (to_copy == 0 && count > 0)
		return -ENOSPC;

	return to_copy;
}

/* read: serves the buffer from the file offset (PFS would reconstruct a generation here). */
static ssize_t pfs_lkm_read(struct file *file, char __user *user_buf,
			     size_t count, loff_t *offset)
{
	size_t available;
	size_t to_copy;

	mutex_lock(&pfs_lkm_lock);

	if (*offset >= pfs_lkm_buffer_len) {
		/* At or past the end: EOF. */
		mutex_unlock(&pfs_lkm_lock);
		return 0;
	}

	available = pfs_lkm_buffer_len - *offset;
	to_copy = count < available ? count : available;

	if (copy_to_user(user_buf, pfs_lkm_buffer + *offset, to_copy)) {
		mutex_unlock(&pfs_lkm_lock);
		return -EFAULT;
	}

	*offset += to_copy;
	pfs_lkm_read_events++;

	printk(KERN_INFO
	       "PFS-LKM: read() intercepted, %zu bytes requested at offset "
	       "%lld -- this is the delta-synthesis hook point (event #%lu). "
	       "The real userspace PFS engine would be invoked here: walk "
	       "the ancestral generation chain and stitch chunks/deltas into "
	       "one reconstructed byte stream before handing it back.\n",
	       to_copy, (long long)(*offset - to_copy), pfs_lkm_read_events);

	mutex_unlock(&pfs_lkm_lock);
	return to_copy;
}

/* The file_operations table the VFS dispatches to once the device is registered. */
static const struct file_operations pfs_lkm_fops = {
	.owner   = THIS_MODULE,
	.open    = pfs_lkm_open,
	.read    = pfs_lkm_read,
	.write   = pfs_lkm_write,
	.release = pfs_lkm_release,
};

/* A misc device with a dynamic minor; udev creates /dev/pfs_lkm. */
static struct miscdevice pfs_lkm_device = {
	.minor = MISC_DYNAMIC_MINOR,
	.name  = "pfs_lkm",
	.fops  = &pfs_lkm_fops,
	.mode  = 0666,   /* rw-rw-rw- */
};

/* Load: allocate the buffer and register the device. */
static int __init pfs_lkm_init(void)
{
	int ret;

	pfs_lkm_buffer = kmalloc(PFS_LKM_BUF_SIZE, GFP_KERNEL);
	if (!pfs_lkm_buffer) {
		printk(KERN_ERR "PFS-LKM: failed to allocate toy buffer, "
				"aborting load.\n");
		return -ENOMEM;
	}
	pfs_lkm_buffer_len = 0;
	pfs_lkm_write_events = 0;
	pfs_lkm_read_events = 0;

	/* From here on, /dev/pfs_lkm's operations go through the functions above. */
	ret = misc_register(&pfs_lkm_device);
	if (ret) {
		printk(KERN_ERR "PFS-LKM: misc_register failed (%d), "
				"aborting load.\n", ret);
		kfree(pfs_lkm_buffer);
		pfs_lkm_buffer = NULL;
		return ret;
	}

	printk(KERN_INFO
	       "PFS-LKM: module loaded. /dev/%s is live -- "
	       "PFS Phylogenetic File System VFS-interception feasibility "
	       "proof-of-concept, NOT a production filesystem. "
	       "Every open/read/write/release against this device will now "
	       "be logged here as it is intercepted.\n",
	       pfs_lkm_device.name);

	return 0;
}

/* Unload: unregister first (no new opens), then free the buffer. */
static void __exit pfs_lkm_exit(void)
{
	misc_deregister(&pfs_lkm_device);

	kfree(pfs_lkm_buffer);
	pfs_lkm_buffer = NULL;

	printk(KERN_INFO
	       "PFS-LKM: module unloaded. Final tally this load: %lu "
	       "write() interceptions (speciation-event hook points), %lu "
	       "read() interceptions (delta-synthesis hook points). "
	       "/dev/%s is gone.\n",
	       pfs_lkm_write_events, pfs_lkm_read_events,
	       pfs_lkm_device.name);
}

module_init(pfs_lkm_init);
module_exit(pfs_lkm_exit);
