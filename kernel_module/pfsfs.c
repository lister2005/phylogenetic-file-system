// SPDX-License-Identifier: GPL-2.0
/*
 * pfsfs -- a mountable, in-memory filesystem applying PFS's storage model
 * inside the kernel (manual.txt PART 8 item #8).
 *
 *   mount -t pfsfs none /mnt/pfs
 *
 * A file's working copy lives in the page cache, as in ramfs. When a
 * file that was written is closed, pfsfs "speciates" it: the content is
 * cut into content-defined chunks (Gear hash, same table and parameters
 * as the userspace engines), each chunk is SHA-256 hashed and stored
 * once per mount however many files or generations share it, and the
 * file gains a new generation -- unless it's byte-identical to its
 * current one. Two read-only/control files at the root expose this:
 *
 *   .pfs_lineage   every file's generations, plus dedup totals
 *   .pfs_checkout  write "<name> <generation>", then read that past
 *                  generation back, rebuilt from its chunks (each chunk's
 *                  hash re-checked)
 *
 * Not here (userspace only): encryption, persistence (everything is lost
 * on unmount), clade clustering, merge/fork. The namespace is flat, like
 * PFS labels: no subdirectories.
 *
 * Written against kernel 7.0 headers and compiled; never loaded or run.
 */
#include <linux/fs.h>
#include <linux/fs_context.h>
#include <linux/hashtable.h>
#include <linux/highmem.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/pagemap.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/timekeeping.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>
#include <crypto/sha2.h>

#include "pfs_gear_table.h"

#define PFSFS_MAGIC 0x50465331 /* "PFS1" */

/* Storage chunking profile, matching gearhash/pipeline.py and pipeline.cpp. */
#define PFS_CHUNK_MASK 0x1FFFULL
#define PFS_CHUNK_MIN 4096
#define PFS_CHUNK_MAX 16384

#define PFS_LINEAGE_NAME ".pfs_lineage"
#define PFS_CHECKOUT_NAME ".pfs_checkout"
#define PFS_RESERVED_PREFIX ".pfs_"
#define PFS_CHECKOUT_MAX (64UL << 20) /* largest generation .pfs_checkout rebuilds */
#define PFS_CHECKOUT_REQUEST_MAX 512

enum pfs_kind { PFS_DIR, PFS_FILE, PFS_LINEAGE, PFS_CHECKOUT };

struct pfs_chunk {
	struct hlist_node node;
	u8 hash[SHA256_DIGEST_SIZE];
	u32 len;
	u32 refs; /* generations referencing it */
	u8 data[];
};

struct pfs_generation {
	struct list_head node;
	u32 index;
	u32 nchunks;
	u32 new_chunks; /* chunks that weren't already stored */
	u64 size;
	time64_t birth;
	struct pfs_chunk **chunks;
};

struct pfs_inode {
	struct inode vfs_inode;
	enum pfs_kind kind;
	bool dirty;                   /* working copy changed since the last generation */
	char *label;                  /* current name (PFS_FILE) */
	struct list_head generations; /* oldest first */
	u32 ngenerations;
	struct list_head files;       /* entry in pfs_sb.files */
};

/* Per mount. `lock` guards everything here and every pfs_inode's label,
 * generations and files entry. */
struct pfs_sb {
	struct mutex lock;
	DECLARE_HASHTABLE(chunks, 12);
	struct list_head files;
	u64 unique_chunks;
	u64 unique_bytes;
};

static struct kmem_cache *pfs_inode_cachep;

static inline struct pfs_inode *PFS_I(struct inode *inode)
{
	return container_of(inode, struct pfs_inode, vfs_inode);
}

static inline struct pfs_sb *PFS_SB(struct super_block *sb)
{
	return sb->s_fs_info;
}

/* ---------- chunk store ---------- */

static struct pfs_chunk *pfs_chunk_get(struct pfs_sb *sbi, const u8 *data, u32 len, bool *is_new)
{
	u8 hash[SHA256_DIGEST_SIZE];
	struct pfs_chunk *c;
	u64 key;

	sha256(data, len, hash);
	memcpy(&key, hash, sizeof(key));
	hash_for_each_possible(sbi->chunks, c, node, key) {
		if (!memcmp(c->hash, hash, SHA256_DIGEST_SIZE)) {
			c->refs++;
			*is_new = false;
			return c;
		}
	}
	c = kmalloc(struct_size(c, data, len), GFP_KERNEL);
	if (!c)
		return NULL;
	memcpy(c->hash, hash, SHA256_DIGEST_SIZE);
	memcpy(c->data, data, len);
	c->len = len;
	c->refs = 1;
	hash_add(sbi->chunks, &c->node, key);
	sbi->unique_chunks++;
	sbi->unique_bytes += len;
	*is_new = true;
	return c;
}

static void pfs_chunk_put(struct pfs_sb *sbi, struct pfs_chunk *c)
{
	if (--c->refs)
		return;
	hash_del(&c->node);
	sbi->unique_chunks--;
	sbi->unique_bytes -= c->len;
	kfree(c);
}

static void pfs_generation_free(struct pfs_sb *sbi, struct pfs_generation *gen)
{
	u32 i;

	for (i = 0; i < gen->nchunks; i++)
		pfs_chunk_put(sbi, gen->chunks[i]);
	kvfree(gen->chunks);
	kfree(gen);
}

/* ---------- speciation: working copy -> new generation ---------- */

struct pfs_chunker {
	struct pfs_sb *sbi;
	u64 hash; /* never reset between chunks, like the userspace chunker */
	u8 *buf;
	u32 len;
	struct pfs_chunk **chunks;
	u32 nchunks;
	u32 cap;
	u32 new_chunks;
};

static int pfs_chunker_emit(struct pfs_chunker *ck)
{
	struct pfs_chunk *c;
	bool is_new;

	if (ck->nchunks == ck->cap) {
		u32 cap = ck->cap ? ck->cap * 2 : 64;
		struct pfs_chunk **grown = kvmalloc_array(cap, sizeof(*grown), GFP_KERNEL);

		if (!grown)
			return -ENOMEM;
		if (ck->nchunks)
			memcpy(grown, ck->chunks, ck->nchunks * sizeof(*grown));
		kvfree(ck->chunks);
		ck->chunks = grown;
		ck->cap = cap;
	}
	c = pfs_chunk_get(ck->sbi, ck->buf, ck->len, &is_new);
	if (!c)
		return -ENOMEM;
	ck->chunks[ck->nchunks++] = c;
	ck->new_chunks += is_new;
	ck->len = 0;
	return 0;
}

/* Same boundary rule as gearhash_core.c's scan_chunk_c(): the first
 * PFS_CHUNK_MIN bytes of a chunk are hashed but never cut; after that, a
 * chunk ends right after any byte leaving (hash & mask) == 0, and always
 * at PFS_CHUNK_MAX. */
static int pfs_chunker_feed(struct pfs_chunker *ck, const u8 *data, size_t n)
{
	size_t i;
	int err;

	for (i = 0; i < n; i++) {
		ck->hash = (ck->hash << 1) + pfs_gear_table[data[i]];
		ck->buf[ck->len++] = data[i];
		if ((ck->len > PFS_CHUNK_MIN && !(ck->hash & PFS_CHUNK_MASK)) || ck->len == PFS_CHUNK_MAX) {
			err = pfs_chunker_emit(ck);
			if (err)
				return err;
		}
	}
	return 0;
}

static void pfs_chunker_abort(struct pfs_chunker *ck)
{
	u32 i;

	for (i = 0; i < ck->nchunks; i++)
		pfs_chunk_put(ck->sbi, ck->chunks[i]);
	kvfree(ck->chunks);
}

static bool pfs_same_chunks(const struct pfs_generation *gen, const struct pfs_chunker *ck)
{
	return gen->nchunks == ck->nchunks &&
	       !memcmp(gen->chunks, ck->chunks, ck->nchunks * sizeof(*ck->chunks));
}

/* Records the inode's current content as a new generation. Caller holds
 * the inode lock. Streams the page cache a page at a time. */
static int pfs_speciate(struct inode *inode)
{
	struct pfs_inode *pi = PFS_I(inode);
	struct pfs_sb *sbi = PFS_SB(inode->i_sb);
	struct pfs_chunker ck = { .sbi = sbi };
	struct pfs_generation *tip, *gen;
	loff_t size = i_size_read(inode);
	loff_t pos = 0;
	int err = 0;

	ck.buf = kmalloc(PFS_CHUNK_MAX, GFP_KERNEL);
	if (!ck.buf)
		return -ENOMEM;

	mutex_lock(&sbi->lock);
	while (pos < size && !err) {
		struct folio *folio = read_mapping_folio(inode->i_mapping, pos >> PAGE_SHIFT, NULL);
		size_t offset, end;

		if (IS_ERR(folio)) {
			err = PTR_ERR(folio);
			break;
		}
		offset = offset_in_folio(folio, pos);
		end = min_t(loff_t, folio_size(folio), offset + (size - pos));
		while (offset < end && !err) {
			size_t n = min_t(size_t, end - offset, PAGE_SIZE - offset_in_page(offset));
			u8 *addr = kmap_local_folio(folio, offset);

			err = pfs_chunker_feed(&ck, addr, n);
			kunmap_local(addr);
			offset += n;
			pos += n;
		}
		folio_put(folio);
	}
	if (!err && ck.len)
		err = pfs_chunker_emit(&ck);
	if (err) {
		pfs_chunker_abort(&ck);
		goto out;
	}

	tip = list_last_entry_or_null(&pi->generations, struct pfs_generation, node);
	if (tip && pfs_same_chunks(tip, &ck)) {
		pfs_chunker_abort(&ck); /* byte-identical resave: no new generation */
		pi->dirty = false;
		goto out;
	}
	gen = kzalloc(sizeof(*gen), GFP_KERNEL);
	if (!gen) {
		pfs_chunker_abort(&ck);
		err = -ENOMEM;
		goto out;
	}
	gen->index = pi->ngenerations++;
	gen->nchunks = ck.nchunks;
	gen->new_chunks = ck.new_chunks;
	gen->size = size;
	gen->birth = ktime_get_real_seconds();
	gen->chunks = ck.chunks;
	list_add_tail(&gen->node, &pi->generations);
	pi->dirty = false;
out:
	mutex_unlock(&sbi->lock);
	kfree(ck.buf);
	return err;
}

/* ---------- regular files ---------- */

static ssize_t pfs_write_iter(struct kiocb *iocb, struct iov_iter *from)
{
	ssize_t ret = generic_file_write_iter(iocb, from);

	if (ret > 0)
		PFS_I(file_inode(iocb->ki_filp))->dirty = true;
	return ret;
}

/* Speciation on close: the file's last writer closing is the commit point,
 * as in the FUSE drivers. */
static int pfs_file_release(struct inode *inode, struct file *file)
{
	int err = 0;

	if ((file->f_mode & FMODE_WRITE) && PFS_I(inode)->dirty) {
		inode_lock(inode);
		if (PFS_I(inode)->dirty)
			err = pfs_speciate(inode);
		inode_unlock(inode);
	}
	if (err)
		pr_warn("pfsfs: recording a generation of '%s' failed: %d\n", PFS_I(inode)->label, err);
	return 0;
}

static int pfs_setattr(struct mnt_idmap *idmap, struct dentry *dentry, struct iattr *attr)
{
	struct inode *inode = d_inode(dentry);
	int err = simple_setattr(idmap, dentry, attr);

	if (err || !(attr->ia_valid & ATTR_SIZE))
		return err;
	PFS_I(inode)->dirty = true;
	/* A truncate with no writer open has no close to wait for. The VFS
	 * holds the inode lock around setattr. */
	if (atomic_read(&inode->i_writecount) <= 0)
		err = pfs_speciate(inode);
	return err;
}

static const struct file_operations pfs_file_operations = {
	.read_iter = generic_file_read_iter,
	.write_iter = pfs_write_iter,
	.llseek = generic_file_llseek,
	.fsync = noop_fsync,
	.release = pfs_file_release,
};

static const struct inode_operations pfs_file_inode_operations = {
	.setattr = pfs_setattr,
	.getattr = simple_getattr,
};

/* ---------- .pfs_lineage ---------- */

struct pfs_text {
	char *data;
	size_t len;
};

static int pfs_lineage_open(struct inode *inode, struct file *file)
{
	struct pfs_sb *sbi = PFS_SB(inode->i_sb);
	struct pfs_inode *pi;
	struct pfs_generation *gen;
	struct pfs_text *text;
	size_t cap = 512, len = 0;
	u64 files = 0, generations = 0, logical = 0;

	text = kzalloc(sizeof(*text), GFP_KERNEL);
	if (!text)
		return -ENOMEM;

	mutex_lock(&sbi->lock);
	list_for_each_entry(pi, &sbi->files, files)
		cap += (size_t)(pi->ngenerations + 1) * (strlen(pi->label) + 96);
	text->data = kvmalloc(cap, GFP_KERNEL);
	if (!text->data) {
		mutex_unlock(&sbi->lock);
		kfree(text);
		return -ENOMEM;
	}
	len += scnprintf(text->data + len, cap - len, "name\tgeneration\tsize\tchunks\tnew_chunks\tbirth\n");
	list_for_each_entry(pi, &sbi->files, files) {
		files++;
		list_for_each_entry(gen, &pi->generations, node) {
			generations++;
			logical += gen->size;
			len += scnprintf(text->data + len, cap - len, "%s\t%u\t%llu\t%u\t%u\t%lld\n",
					 pi->label, gen->index, gen->size, gen->nchunks,
					 gen->new_chunks, (long long)gen->birth);
		}
	}
	len += scnprintf(text->data + len, cap - len,
			 "# %llu files, %llu generations, %llu bytes across all generations, "
			 "%llu unique chunks holding %llu bytes\n",
			 files, generations, logical, sbi->unique_chunks, sbi->unique_bytes);
	mutex_unlock(&sbi->lock);

	text->len = len;
	file->private_data = text;
	return 0;
}

static ssize_t pfs_text_read(struct file *file, char __user *buf, size_t count, loff_t *ppos)
{
	struct pfs_text *text = file->private_data;

	return simple_read_from_buffer(buf, count, ppos, text->data, text->len);
}

static int pfs_text_release(struct inode *inode, struct file *file)
{
	struct pfs_text *text = file->private_data;

	if (text) {
		kvfree(text->data);
		kfree(text);
	}
	return 0;
}

static const struct file_operations pfs_lineage_operations = {
	.open = pfs_lineage_open,
	.read = pfs_text_read,
	.llseek = default_llseek,
	.release = pfs_text_release,
};

/* ---------- .pfs_checkout ---------- */

static int pfs_checkout_open(struct inode *inode, struct file *file)
{
	file->private_data = kzalloc(sizeof(struct pfs_text), GFP_KERNEL);
	return file->private_data ? 0 : -ENOMEM;
}

/* Rebuilds `gen` from its chunks, re-checking every chunk's hash. Caller
 * holds sbi->lock. */
static int pfs_rebuild(const struct pfs_generation *gen, struct pfs_text *out)
{
	u8 hash[SHA256_DIGEST_SIZE];
	size_t pos = 0;
	u32 i;

	if (gen->size > PFS_CHECKOUT_MAX)
		return -EFBIG;
	out->data = kvmalloc(max_t(size_t, gen->size, 1), GFP_KERNEL);
	if (!out->data)
		return -ENOMEM;
	for (i = 0; i < gen->nchunks; i++) {
		const struct pfs_chunk *c = gen->chunks[i];

		sha256(c->data, c->len, hash);
		if (memcmp(hash, c->hash, SHA256_DIGEST_SIZE) || pos + c->len > gen->size) {
			kvfree(out->data);
			out->data = NULL;
			return -EIO;
		}
		memcpy(out->data + pos, c->data, c->len);
		pos += c->len;
	}
	out->len = pos;
	return pos == gen->size ? 0 : -EIO;
}

static ssize_t pfs_checkout_write(struct file *file, const char __user *buf, size_t count, loff_t *ppos)
{
	struct pfs_sb *sbi = PFS_SB(file_inode(file)->i_sb);
	struct pfs_text *text = file->private_data;
	struct pfs_inode *pi;
	struct pfs_generation *gen;
	char *request, *space;
	unsigned int index;
	int err = -ENOENT;

	if (count == 0 || count > PFS_CHECKOUT_REQUEST_MAX)
		return -EINVAL;
	request = memdup_user_nul(buf, count);
	if (IS_ERR(request))
		return PTR_ERR(request);
	strim(request);
	space = strrchr(request, ' ');
	if (!space || kstrtouint(space + 1, 10, &index)) {
		kfree(request);
		return -EINVAL;
	}
	*space = '\0';

	kvfree(text->data);
	text->data = NULL;
	text->len = 0;
	mutex_lock(&sbi->lock);
	list_for_each_entry(pi, &sbi->files, files) {
		if (strcmp(pi->label, request))
			continue;
		list_for_each_entry(gen, &pi->generations, node) {
			if (gen->index == index) {
				err = pfs_rebuild(gen, text);
				break;
			}
		}
		break;
	}
	mutex_unlock(&sbi->lock);
	kfree(request);
	*ppos = 0;
	return err ? err : count;
}

static ssize_t pfs_checkout_read(struct file *file, char __user *buf, size_t count, loff_t *ppos)
{
	struct pfs_text *text = file->private_data;

	if (!text->data)
		return 0;
	return simple_read_from_buffer(buf, count, ppos, text->data, text->len);
}

static const struct file_operations pfs_checkout_operations = {
	.open = pfs_checkout_open,
	.read = pfs_checkout_read,
	.write = pfs_checkout_write,
	.llseek = default_llseek,
	.release = pfs_text_release,
};

/* ---------- inodes ---------- */

static const struct inode_operations pfs_dir_inode_operations;

static struct inode *pfs_new_inode(struct super_block *sb, struct inode *dir, umode_t mode,
				   enum pfs_kind kind)
{
	struct inode *inode = new_inode(sb);

	if (!inode)
		return NULL;
	inode->i_ino = get_next_ino();
	inode_init_owner(&nop_mnt_idmap, inode, dir, mode);
	simple_inode_init_ts(inode);
	PFS_I(inode)->kind = kind;
	switch (kind) {
	case PFS_DIR:
		inode->i_op = &pfs_dir_inode_operations;
		inode->i_fop = &simple_dir_operations;
		inc_nlink(inode);
		break;
	case PFS_FILE:
		inode->i_op = &pfs_file_inode_operations;
		inode->i_fop = &pfs_file_operations;
		inode->i_mapping->a_ops = &ram_aops;
		mapping_set_gfp_mask(inode->i_mapping, GFP_HIGHUSER);
		mapping_set_unevictable(inode->i_mapping);
		break;
	case PFS_LINEAGE:
		inode->i_fop = &pfs_lineage_operations;
		break;
	case PFS_CHECKOUT:
		inode->i_fop = &pfs_checkout_operations;
		break;
	}
	return inode;
}

static bool pfs_reserved_name(const struct dentry *dentry)
{
	return !strncmp(dentry->d_name.name, PFS_RESERVED_PREFIX, strlen(PFS_RESERVED_PREFIX));
}

static int pfs_create(struct mnt_idmap *idmap, struct inode *dir, struct dentry *dentry,
		      umode_t mode, bool excl)
{
	struct pfs_sb *sbi = PFS_SB(dir->i_sb);
	struct inode *inode;
	char *label;

	if (pfs_reserved_name(dentry))
		return -EPERM;
	label = kstrndup(dentry->d_name.name, dentry->d_name.len, GFP_KERNEL);
	if (!label)
		return -ENOMEM;
	inode = pfs_new_inode(dir->i_sb, dir, S_IFREG | (mode & 0777), PFS_FILE);
	if (!inode) {
		kfree(label);
		return -ENOSPC;
	}
	mutex_lock(&sbi->lock);
	PFS_I(inode)->label = label;
	list_add_tail(&PFS_I(inode)->files, &sbi->files);
	mutex_unlock(&sbi->lock);
	d_make_persistent(dentry, inode);
	inode_set_mtime_to_ts(dir, inode_set_ctime_current(dir));
	return 0;
}

static int pfs_unlink(struct inode *dir, struct dentry *dentry)
{
	if (PFS_I(d_inode(dentry))->kind != PFS_FILE)
		return -EPERM;
	return simple_unlink(dir, dentry);
}

static int pfs_set_label(struct pfs_sb *sbi, struct inode *inode, const struct qstr *name)
{
	char *label = kstrndup(name->name, name->len, GFP_KERNEL);

	if (!label)
		return -ENOMEM;
	mutex_lock(&sbi->lock);
	swap(PFS_I(inode)->label, label);
	mutex_unlock(&sbi->lock);
	kfree(label);
	return 0;
}

static int pfs_rename(struct mnt_idmap *idmap, struct inode *old_dir, struct dentry *old_dentry,
		      struct inode *new_dir, struct dentry *new_dentry, unsigned int flags)
{
	struct pfs_sb *sbi = PFS_SB(old_dir->i_sb);
	struct inode *old_inode = d_inode(old_dentry);
	struct inode *new_inode = d_inode(new_dentry);
	struct qstr old_name = QSTR_INIT(old_dentry->d_name.name, old_dentry->d_name.len);
	char *saved_old_name;
	int err;

	if (PFS_I(old_inode)->kind != PFS_FILE || pfs_reserved_name(new_dentry) ||
	    (new_inode && PFS_I(new_inode)->kind != PFS_FILE))
		return -EPERM;
	saved_old_name = kstrndup(old_name.name, old_name.len, GFP_KERNEL);
	if (!saved_old_name)
		return -ENOMEM;
	old_name.name = saved_old_name;

	err = simple_rename(idmap, old_dir, old_dentry, new_dir, new_dentry, flags);
	if (!err)
		err = pfs_set_label(sbi, old_inode, &new_dentry->d_name);
	if (!err && (flags & RENAME_EXCHANGE) && new_inode)
		err = pfs_set_label(sbi, new_inode, &old_name);
	kfree(saved_old_name);
	return err;
}

static const struct inode_operations pfs_dir_inode_operations = {
	.create = pfs_create,
	.lookup = simple_lookup,
	.unlink = pfs_unlink,
	.rename = pfs_rename,
};

/* ---------- superblock ---------- */

static struct inode *pfs_alloc_inode(struct super_block *sb)
{
	struct pfs_inode *pi = alloc_inode_sb(sb, pfs_inode_cachep, GFP_KERNEL);

	if (!pi)
		return NULL;
	pi->kind = PFS_DIR;
	pi->dirty = false;
	pi->label = NULL;
	pi->ngenerations = 0;
	INIT_LIST_HEAD(&pi->generations);
	INIT_LIST_HEAD(&pi->files);
	return &pi->vfs_inode;
}

static void pfs_free_inode(struct inode *inode)
{
	kmem_cache_free(pfs_inode_cachep, PFS_I(inode));
}

/* A deleted file's whole history goes with it, as `delete` does in the
 * userspace engines; chunks other files still use stay. */
static void pfs_evict_inode(struct inode *inode)
{
	struct pfs_inode *pi = PFS_I(inode);
	struct pfs_sb *sbi = PFS_SB(inode->i_sb);
	struct pfs_generation *gen, *next;

	truncate_inode_pages_final(&inode->i_data);
	clear_inode(inode);
	if (pi->kind != PFS_FILE)
		return;
	mutex_lock(&sbi->lock);
	list_for_each_entry_safe(gen, next, &pi->generations, node) {
		list_del(&gen->node);
		pfs_generation_free(sbi, gen);
	}
	list_del_init(&pi->files);
	mutex_unlock(&sbi->lock);
	kfree(pi->label);
	pi->label = NULL;
}

static const struct super_operations pfs_super_operations = {
	.alloc_inode = pfs_alloc_inode,
	.free_inode = pfs_free_inode,
	.evict_inode = pfs_evict_inode,
	.statfs = simple_statfs,
};

static int pfs_add_control_file(struct super_block *sb, const char *name, umode_t mode, enum pfs_kind kind)
{
	struct inode *inode = pfs_new_inode(sb, d_inode(sb->s_root), S_IFREG | mode, kind);
	struct dentry *dentry;

	if (!inode)
		return -ENOMEM;
	dentry = simple_start_creating(sb->s_root, name);
	if (IS_ERR(dentry)) {
		iput(inode);
		return PTR_ERR(dentry);
	}
	d_make_persistent(dentry, inode);
	simple_done_creating(dentry);
	return 0;
}

static int pfs_fill_super(struct super_block *sb, struct fs_context *fc)
{
	struct pfs_sb *sbi = kzalloc(sizeof(*sbi), GFP_KERNEL);
	struct inode *root;
	int err;

	if (!sbi)
		return -ENOMEM;
	mutex_init(&sbi->lock);
	hash_init(sbi->chunks);
	INIT_LIST_HEAD(&sbi->files);
	sb->s_fs_info = sbi;
	sb->s_maxbytes = MAX_LFS_FILESIZE;
	sb->s_blocksize = PAGE_SIZE;
	sb->s_blocksize_bits = PAGE_SHIFT;
	sb->s_magic = PFSFS_MAGIC;
	sb->s_op = &pfs_super_operations;
	sb->s_time_gran = 1;

	root = pfs_new_inode(sb, NULL, S_IFDIR | 0755, PFS_DIR);
	sb->s_root = d_make_root(root);
	if (!sb->s_root)
		return -ENOMEM;
	err = pfs_add_control_file(sb, PFS_LINEAGE_NAME, 0444, PFS_LINEAGE);
	if (!err)
		err = pfs_add_control_file(sb, PFS_CHECKOUT_NAME, 0644, PFS_CHECKOUT);
	return err;
}

static int pfs_get_tree(struct fs_context *fc)
{
	return get_tree_nodev(fc, pfs_fill_super);
}

static const struct fs_context_operations pfs_context_operations = {
	.get_tree = pfs_get_tree,
};

static int pfs_init_fs_context(struct fs_context *fc)
{
	fc->ops = &pfs_context_operations;
	return 0;
}

static void pfs_kill_sb(struct super_block *sb)
{
	struct pfs_sb *sbi = PFS_SB(sb);

	kill_anon_super(sb); /* evicts every inode, which releases every chunk */
	if (sbi) {
		WARN_ON(!hash_empty(sbi->chunks));
		kfree(sbi);
	}
}

static struct file_system_type pfs_fs_type = {
	.owner = THIS_MODULE,
	.name = "pfsfs",
	.init_fs_context = pfs_init_fs_context,
	.kill_sb = pfs_kill_sb,
};

static void pfs_inode_init_once(void *obj)
{
	inode_init_once(&((struct pfs_inode *)obj)->vfs_inode);
}

static int __init pfsfs_init(void)
{
	int err;

	pfs_inode_cachep = kmem_cache_create("pfsfs_inode", sizeof(struct pfs_inode), 0,
					     SLAB_RECLAIM_ACCOUNT | SLAB_ACCOUNT, pfs_inode_init_once);
	if (!pfs_inode_cachep)
		return -ENOMEM;
	err = register_filesystem(&pfs_fs_type);
	if (err)
		kmem_cache_destroy(pfs_inode_cachep);
	return err;
}

static void __exit pfsfs_exit(void)
{
	unregister_filesystem(&pfs_fs_type);
	rcu_barrier(); /* free_inode runs after an RCU grace period */
	kmem_cache_destroy(pfs_inode_cachep);
}

module_init(pfsfs_init);
module_exit(pfsfs_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("PFS storage model as an in-memory filesystem: content-defined chunking, "
		   "global dedup, a generation per write");
MODULE_ALIAS_FS("pfsfs");
