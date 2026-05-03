// SPDX-License-Identifier: GPL-2.0+
/*
 * Read-only F2FS support for U-Boot's generic filesystem layer.
 *
 * This is a bootloader-oriented reader.  It is deliberately conservative:
 * - reads only a clean checkpoint pack;
 * - supports normal files, directories, inline data and inline dentries;
 * - supports inode/direct/single/double indirect block mapping;
 * - does not write, replay checkpoints, decrypt, casefold, or decompress.
 *
 * The on-disk definitions below are derived from Linux's GPL-2.0 F2FS
 * format headers, with only the fields needed by this reader kept here.
 */

#include <blk.h>
#include <errno.h>
#include <fs.h>
#include <f2fs.h>
#include <linux/bitops.h>
#include <asm/byteorder.h>
#include <linux/compiler.h>
#include <linux/stat.h>
#include <linux/types.h>
#include <malloc.h>
#include <part.h>
#include <stdio.h>
#include <vsprintf.h>
#include <string.h>

#ifndef FS_DT_UNKNOWN
#define FS_DT_UNKNOWN 0
#endif

#ifndef __packed
#define __packed __attribute__((packed))
#endif

#ifndef BIT
#define BIT(nr) (1UL << (nr))
#endif

#ifndef DIV_ROUND_UP
#define DIV_ROUND_UP(n, d) (((n) + (d) - 1) / (d))
#endif

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#endif

#define F2FS_SUPER_MAGIC	0xF2F52010U
#define F2FS_SUPER_OFFSET	1024ULL
#define F2FS_SUPER0_OFFSET	F2FS_SUPER_OFFSET
#define F2FS_SUPER1_OFFSET	(F2FS_BLKSIZE + F2FS_SUPER_OFFSET)
#define F2FS_BLKSIZE		4096U
#define F2FS_LOG_BLOCK_SIZE	12U
#define F2FS_MAX_NAME_LEN	255U
#define F2FS_SLOT_LEN		8U
#define F2FS_DIR_ENTRY_SIZE	11U
#define F2FS_NR_DENTRY_IN_BLOCK	214U
#define F2FS_DENTRY_BITMAP_BYTES	27U
#define F2FS_INLINE_RESERVED_ADDRS 1U
#define F2FS_DEFAULT_INLINE_XATTR_ADDRS 50U
#define F2FS_MAX_LINK_DEPTH	8U
#define F2FS_MAX_ACTIVE_LOGS	16U
#define F2FS_MAX_ACTIVE_NODE_LOGS	8U
#define F2FS_MAX_ACTIVE_DATA_LOGS	8U

#define NULL_ADDR		0x0U
#define NEW_ADDR		0xffffffffU
#define COMPRESS_ADDR		0xfffffffeU

#define F2FS_INLINE_XATTR	0x01
#define F2FS_INLINE_DATA	0x02
#define F2FS_INLINE_DENTRY	0x04
#define F2FS_DATA_EXIST		0x08
#define F2FS_INLINE_DOTS	0x10
#define F2FS_EXTRA_ATTR		0x20

#define F2FS_FEATURE_ENCRYPT		0x0001
#define F2FS_FEATURE_BLKZONED		0x0002
#define F2FS_FEATURE_EXTRA_ATTR		0x0008
#define F2FS_FEATURE_PROJECT_QUOTA	0x0020
#define F2FS_FEATURE_INODE_CHKSUM	0x0800
#define F2FS_FEATURE_CASEFOLD		0x1000
#define F2FS_FEATURE_COMPRESSION		0x2000
#define F2FS_FEATURE_FLEXIBLE_INLINE_XATTR	0x0040

#define CP_UMOUNT_FLAG		0x00000001
#define CP_COMPACT_SUM_FLAG	0x00000004
#define CP_ERROR_FLAG		0x00000008
#define CP_FSCK_FLAG		0x00000010
#define CP_DISABLED_FLAG	0x00001000

#define NODE_DIR1_BLOCK		0
#define NODE_DIR2_BLOCK		1
#define NODE_IND1_BLOCK		2
#define NODE_IND2_BLOCK		3
#define NODE_DIND_BLOCK		4

#define DEF_ADDRS_PER_INODE	923U
#define DEF_ADDRS_PER_BLOCK	1018U
#define NAT_ENTRY_PER_BLOCK	455U
#define NIDS_PER_BLOCK		1018U

#define F2FS_SUMMARY_SIZE	7U
#define F2FS_ENTRIES_IN_SUM	512U
#define F2FS_SUM_FOOTER_SIZE	5U
#define F2FS_SUM_JOURNAL_SIZE	(F2FS_BLKSIZE - F2FS_SUM_FOOTER_SIZE - \
					 F2FS_SUMMARY_SIZE * F2FS_ENTRIES_IN_SUM)

struct f2fs_super_block {
	__le32 magic;
	__le16 major_ver;
	__le16 minor_ver;
	__le32 log_sectorsize;
	__le32 log_sectors_per_block;
	__le32 log_blocksize;
	__le32 log_blocks_per_seg;
	__le32 segs_per_sec;
	__le32 secs_per_zone;
	__le32 checksum_offset;
	__le64 block_count;
	__le32 section_count;
	__le32 segment_count;
	__le32 segment_count_ckpt;
	__le32 segment_count_sit;
	__le32 segment_count_nat;
	__le32 segment_count_ssa;
	__le32 segment_count_main;
	__le32 segment0_blkaddr;
	__le32 cp_blkaddr;
	__le32 sit_blkaddr;
	__le32 nat_blkaddr;
	__le32 ssa_blkaddr;
	__le32 main_blkaddr;
	__le32 root_ino;
	__le32 node_ino;
	__le32 meta_ino;
	__u8 uuid[16];
	__le16 volume_name[512];
	__le32 extension_count;
	__u8 extension_list[64][8];
	__le32 cp_payload;
	__u8 version[256];
	__u8 init_version[256];
	__le32 feature;
	__u8 encryption_level;
	__u8 encrypt_pw_salt[16];
	__le32 qf_ino[3];
	__le32 hot_ext_count;
	__le16 s_encoding;
	__le16 s_encoding_flags;
	__u8 reserved[306];
} __packed;

struct f2fs_checkpoint {
	__le64 checkpoint_ver;
	__le64 user_block_count;
	__le64 valid_block_count;
	__le32 rsvd_segment_count;
	__le32 overprov_segment_count;
	__le32 free_segment_count;
	__le32 cur_node_segno[F2FS_MAX_ACTIVE_NODE_LOGS];
	__le16 cur_node_blkoff[F2FS_MAX_ACTIVE_NODE_LOGS];
	__le32 cur_data_segno[F2FS_MAX_ACTIVE_DATA_LOGS];
	__le16 cur_data_blkoff[F2FS_MAX_ACTIVE_DATA_LOGS];
	__le32 ckpt_flags;
	__le32 cp_pack_total_block_count;
	__le32 cp_pack_start_sum;
	__le32 valid_node_count;
	__le32 valid_inode_count;
	__le32 next_free_nid;
	__le32 sit_ver_bitmap_bytesize;
	__le32 nat_ver_bitmap_bytesize;
	__le32 checksum_offset;
	__le64 elapsed_time;
	__u8 alloc_type[F2FS_MAX_ACTIVE_LOGS];
	__u8 sit_nat_version_bitmap[1];
} __packed;

struct f2fs_extent {
	__le32 fofs;
	__le32 blk;
	__le32 len;
} __packed;

struct f2fs_inode {
	__le16 i_mode;
	__u8 i_advise;
	__u8 i_inline;
	__le32 i_uid;
	__le32 i_gid;
	__le32 i_links;
	__le64 i_size;
	__le64 i_blocks;
	__le64 i_atime;
	__le64 i_ctime;
	__le64 i_mtime;
	__le32 i_atime_nsec;
	__le32 i_ctime_nsec;
	__le32 i_mtime_nsec;
	__le32 i_generation;
	__le32 i_current_depth;
	__le32 i_xattr_nid;
	__le32 i_flags;
	__le32 i_pino;
	__le32 i_namelen;
	__u8 i_name[F2FS_MAX_NAME_LEN];
	__u8 i_dir_level;
	struct f2fs_extent i_ext;
	union {
		struct {
			__le16 i_extra_isize;
			__le16 i_inline_xattr_size;
			__le32 i_projid;
			__le32 i_inode_checksum;
			__le64 i_crtime;
			__le32 i_crtime_nsec;
			__le64 i_compr_blocks;
			__u8 i_compress_algorithm;
			__u8 i_log_cluster_size;
			__le16 i_compress_flag;
			__le32 i_extra_end[0];
		} __packed;
		__le32 i_addr[DEF_ADDRS_PER_INODE];
	};
	__le32 i_nid[5];
} __packed;

struct f2fs_node_footer {
	__le32 nid;
	__le32 ino;
	__le32 flag;
	__le64 cp_ver;
	__le32 next_blkaddr;
} __packed;

struct f2fs_direct_node {
	__le32 addr[DEF_ADDRS_PER_BLOCK];
} __packed;

struct f2fs_indirect_node {
	__le32 nid[NIDS_PER_BLOCK];
} __packed;

struct f2fs_node {
	union {
		struct f2fs_inode i;
		struct f2fs_direct_node dn;
		struct f2fs_indirect_node in;
		__u8 raw[F2FS_BLKSIZE - sizeof(struct f2fs_node_footer)];
	};
	struct f2fs_node_footer footer;
} __packed;

struct f2fs_nat_entry {
	__u8 version;
	__le32 ino;
	__le32 block_addr;
} __packed;

struct f2fs_nat_block {
	struct f2fs_nat_entry entries[NAT_ENTRY_PER_BLOCK];
	__u8 reserved[F2FS_BLKSIZE - NAT_ENTRY_PER_BLOCK * sizeof(struct f2fs_nat_entry)];
} __packed;

struct f2fs_summary {
	__le32 nid;
	union {
		__u8 reserved[3];
		struct {
			__u8 version;
			__le16 ofs_in_node;
		} __packed;
	};
} __packed;

struct f2fs_nat_journal_entry {
	__le32 nid;
	struct f2fs_nat_entry ne;
} __packed;

#define F2FS_NAT_JOURNAL_ENTRIES \
	((F2FS_SUM_JOURNAL_SIZE - sizeof(__le16)) / sizeof(struct f2fs_nat_journal_entry))

struct f2fs_journal {
	union {
		__le16 n_nats;
		__le16 n_sits;
	};
	__u8 payload[F2FS_SUM_JOURNAL_SIZE - sizeof(__le16)];
} __packed;

struct f2fs_summary_block {
	struct f2fs_summary entries[F2FS_ENTRIES_IN_SUM];
	struct f2fs_journal journal;
	__u8 footer[F2FS_SUM_FOOTER_SIZE];
} __packed;

struct f2fs_dir_entry {
	__le32 hash_code;
	__le32 ino;
	__le16 name_len;
	__u8 file_type;
} __packed;

struct f2fs_dentry_block {
	__u8 dentry_bitmap[F2FS_DENTRY_BITMAP_BYTES];
	__u8 reserved[3];
	struct f2fs_dir_entry dentry[F2FS_NR_DENTRY_IN_BLOCK];
	__u8 filename[F2FS_NR_DENTRY_IN_BLOCK][F2FS_SLOT_LEN];
} __packed;

struct f2fs_ctx {
	struct blk_desc *desc;
	struct disk_partition part;
	struct f2fs_super_block sb;
	struct f2fs_checkpoint *cp;
	unsigned int sector_size;
	unsigned int sectors_per_block;
	unsigned int blocks_per_seg;
	unsigned int nat_bitmap_bytes;
	__u8 *nat_bitmap;
	u32 cp_start_blk;
	unsigned int nat_journal_count;
	struct f2fs_nat_journal_entry nat_journal[F2FS_NAT_JOURNAL_ENTRIES];
};

struct f2fs_dir_stream_priv {
	struct fs_dir_stream fs;
	struct f2fs_node dir;
	u32 nid;
	u64 index;
	u64 max_index;
	unsigned int inline_count;
	struct fs_dirent dent;
};

struct f2fs_lookup_res {
	u32 nid;
	u16 mode;
	u8 type;
	u64 size;
};

static struct f2fs_ctx gctx;

static int f2fs_get_bit(const __u8 *bitmap, unsigned int bit)
{
	return !!(bitmap[bit >> 3] & BIT(bit & 7));
}

static unsigned int f2fs_slots(unsigned int name_len)
{
	return DIV_ROUND_UP(name_len, F2FS_SLOT_LEN);
}

static int f2fs_mode_to_fs_dt(u16 mode)
{
	switch (mode & S_IFMT) {
	case S_IFDIR:
		return FS_DT_DIR;
	case S_IFLNK:
		return FS_DT_LNK;
	case S_IFREG:
		return FS_DT_REG;
	default:
		return FS_DT_UNKNOWN;
	}
}

static int f2fs_read_bytes(u64 off, void *buf, size_t len)
{
	unsigned int ss = gctx.sector_size;
	__u8 *bounce;
	u64 start;
	u64 end;
	lbaint_t lba;
	lbaint_t cnt;
	size_t skip;
	int ret = 0;

	if (!len)
		return 0;

	if (!gctx.desc || !ss)
		return -ENODEV;

	start = off / ss;
	end = DIV_ROUND_UP(off + len, ss);
	cnt = end - start;
	skip = off - start * ss;

	bounce = malloc(cnt * ss);
	if (!bounce)
		return -ENOMEM;

	lba = gctx.part.start + start;
	if (blk_dread(gctx.desc, lba, cnt, bounce) != cnt)
		ret = -EIO;
	else
		memcpy(buf, bounce + skip, len);

	free(bounce);
	return ret;
}

static int f2fs_read_block(u32 blkaddr, void *buf)
{
	return f2fs_read_bytes((u64)blkaddr * F2FS_BLKSIZE, buf, F2FS_BLKSIZE);
}

static int f2fs_check_super(struct f2fs_super_block *sb)
{
	u32 feature;

	if (le32_to_cpu(sb->magic) != F2FS_SUPER_MAGIC)
		return -EINVAL;

	if (le32_to_cpu(sb->log_blocksize) != F2FS_LOG_BLOCK_SIZE)
		return -EINVAL;

	if (le32_to_cpu(sb->log_sectors_per_block) == 0)
		return -EINVAL;

	if (!le32_to_cpu(sb->segment_count_nat) || !le32_to_cpu(sb->log_blocks_per_seg))
		return -EINVAL;

	feature = le32_to_cpu(sb->feature);
	if (feature & (F2FS_FEATURE_ENCRYPT | F2FS_FEATURE_CASEFOLD |
		       F2FS_FEATURE_BLKZONED))
		return -ENOTSUPP;

	return 0;
}

static int f2fs_read_super(void)
{
	struct f2fs_super_block *sb;
	int ret;

	sb = malloc(sizeof(*sb));
	if (!sb)
		return -ENOMEM;

	ret = f2fs_read_bytes(F2FS_SUPER0_OFFSET, sb, sizeof(*sb));
	if (ret || f2fs_check_super(sb)) {
		ret = f2fs_read_bytes(F2FS_SUPER1_OFFSET, sb, sizeof(*sb));
		if (ret || f2fs_check_super(sb)) {
			free(sb);
			return -EINVAL;
		}
	}

	memcpy(&gctx.sb, sb, sizeof(*sb));
	free(sb);
	gctx.blocks_per_seg = 1U << le32_to_cpu(gctx.sb.log_blocks_per_seg);
	gctx.sectors_per_block = 1U << le32_to_cpu(gctx.sb.log_sectors_per_block);
	return 0;
}

static int f2fs_read_checkpoint_pack(u32 start_blk, struct f2fs_checkpoint **cpp,
				     u64 *versionp)
{
	struct f2fs_checkpoint *cp;
	u32 total;
	u32 bytes;
	int ret;

	cp = malloc(F2FS_BLKSIZE);
	if (!cp)
		return -ENOMEM;

	ret = f2fs_read_block(start_blk, cp);
	if (ret)
		goto fail;

	total = le32_to_cpu(cp->cp_pack_total_block_count);
	if (!total || total > gctx.blocks_per_seg * 2) {
		ret = -EINVAL;
		goto fail;
	}

	bytes = total * F2FS_BLKSIZE;
	free(cp);
	cp = malloc(bytes);
	if (!cp)
		return -ENOMEM;

	ret = f2fs_read_bytes((u64)start_blk * F2FS_BLKSIZE, cp, bytes);
	if (ret)
		goto fail;

	*versionp = le64_to_cpu(cp->checkpoint_ver);
	*cpp = cp;
	return 0;

fail:
	free(cp);
	return ret;
}


static int f2fs_load_nat_journal(void)
{
	struct f2fs_summary_block *sum;
	struct f2fs_journal *jnl;
	struct f2fs_nat_journal_entry *entries;
	u32 blkaddr;
	u32 flags;
	u16 nats;
	int ret;

	gctx.nat_journal_count = 0;

	if (!gctx.cp)
		return -EINVAL;

	/*
	 * The hot-data current summary carries the NAT journal.  With compacted
	 * summaries the first checkpoint summary block starts directly with the
	 * hot-data journal; otherwise it is a normal summary block and the
	 * journal follows ENTRIES_IN_SUM summary entries.
	 */
	blkaddr = gctx.cp_start_blk + le32_to_cpu(gctx.cp->cp_pack_start_sum);
	flags = le32_to_cpu(gctx.cp->ckpt_flags);

	sum = malloc(F2FS_BLKSIZE);
	if (!sum)
		return -ENOMEM;

	ret = f2fs_read_block(blkaddr, sum);
	if (ret)
		goto out;

	if (flags & CP_COMPACT_SUM_FLAG)
		jnl = (struct f2fs_journal *)sum;
	else
		jnl = &sum->journal;

	nats = le16_to_cpu(jnl->n_nats);
	if (nats > F2FS_NAT_JOURNAL_ENTRIES)
		nats = F2FS_NAT_JOURNAL_ENTRIES;

	entries = (struct f2fs_nat_journal_entry *)jnl->payload;
	memcpy(gctx.nat_journal, entries, nats * sizeof(*entries));
	gctx.nat_journal_count = nats;

out:
	free(sum);
	return ret;
}

static int f2fs_read_checkpoint(void)
{
	struct f2fs_checkpoint *cp0 = NULL, *cp1 = NULL;
	u64 ver0 = 0, ver1 = 0;
	u32 cp_blk = le32_to_cpu(gctx.sb.cp_blkaddr);
	u32 flags;
	int ret0, ret1;

	ret0 = f2fs_read_checkpoint_pack(cp_blk, &cp0, &ver0);
	ret1 = f2fs_read_checkpoint_pack(cp_blk + gctx.blocks_per_seg, &cp1, &ver1);

	if (ret0 && ret1)
		return -EINVAL;

	if (!ret1 && (ret0 || ver1 > ver0)) {
		free(cp0);
		gctx.cp = cp1;
		gctx.cp_start_blk = cp_blk + gctx.blocks_per_seg;
	} else {
		free(cp1);
		gctx.cp = cp0;
		gctx.cp_start_blk = cp_blk;
	}

	flags = le32_to_cpu(gctx.cp->ckpt_flags);
	if (!(flags & CP_UMOUNT_FLAG) ||
	    (flags & (CP_ERROR_FLAG | CP_FSCK_FLAG | CP_DISABLED_FLAG)))
		return -EINVAL;

	gctx.nat_bitmap_bytes = le32_to_cpu(gctx.cp->nat_ver_bitmap_bytesize);
	gctx.nat_bitmap = gctx.cp->sit_nat_version_bitmap +
		le32_to_cpu(gctx.cp->sit_ver_bitmap_bytesize);
	if (!gctx.nat_bitmap_bytes)
		return -EINVAL;

	return f2fs_load_nat_journal();
}

static int f2fs_read_nat_entry(u32 nid, struct f2fs_nat_entry *entry)
{
	struct f2fs_nat_block *blk;
	u32 block_off = nid / NAT_ENTRY_PER_BLOCK;
	u32 entry_off = nid % NAT_ENTRY_PER_BLOCK;
	u32 nat_blocks = le32_to_cpu(gctx.sb.segment_count_nat) * gctx.blocks_per_seg;
	u32 nat_blocks_per_set = nat_blocks / 2;
	u32 set = 0;
	u32 blkaddr;
	unsigned int i;
	int ret;

	for (i = gctx.nat_journal_count; i > 0; i--) {
		const struct f2fs_nat_journal_entry *je = &gctx.nat_journal[i - 1];

		if (le32_to_cpu(je->nid) == nid) {
			memcpy(entry, &je->ne, sizeof(*entry));
			return 0;
		}
	}

	if (!nat_blocks_per_set || block_off >= nat_blocks_per_set)
		return -EINVAL;

	if (block_off / 8 < gctx.nat_bitmap_bytes &&
	    f2fs_get_bit(gctx.nat_bitmap, block_off))
		set = 1;

	blkaddr = le32_to_cpu(gctx.sb.nat_blkaddr) + set * nat_blocks_per_set + block_off;
	blk = malloc(sizeof(*blk));
	if (!blk)
		return -ENOMEM;

	ret = f2fs_read_block(blkaddr, blk);
	if (!ret)
		memcpy(entry, &blk->entries[entry_off], sizeof(*entry));

	free(blk);
	return ret;
}

static int f2fs_read_node(u32 nid, struct f2fs_node *node)
{
	struct f2fs_nat_entry nat;
	u32 blkaddr;
	int ret;

	if (!nid)
		return -ENOENT;

	ret = f2fs_read_nat_entry(nid, &nat);
	if (ret)
		return ret;

	blkaddr = le32_to_cpu(nat.block_addr);
	if (blkaddr == NULL_ADDR || blkaddr == NEW_ADDR || blkaddr == COMPRESS_ADDR)
		return -ENOENT;

	ret = f2fs_read_block(blkaddr, node);
	if (ret)
		return ret;

	if (le32_to_cpu(node->footer.nid) != nid)
		return -EINVAL;

	return 0;
}

static unsigned int f2fs_inode_extra_words(const struct f2fs_inode *inode)
{
	unsigned int words = 0;

	if (inode->i_inline & F2FS_EXTRA_ATTR)
		words = le16_to_cpu(inode->i_extra_isize) / sizeof(__le32);

	if (words > DEF_ADDRS_PER_INODE - F2FS_INLINE_RESERVED_ADDRS)
		words = DEF_ADDRS_PER_INODE - F2FS_INLINE_RESERVED_ADDRS;

	return words;
}

static unsigned int f2fs_inode_xattr_words(const struct f2fs_inode *inode)
{
	u32 feature = le32_to_cpu(gctx.sb.feature);
	unsigned int words = 0;

	if (feature & F2FS_FEATURE_FLEXIBLE_INLINE_XATTR)
		words = le16_to_cpu(inode->i_inline_xattr_size);
	else if (inode->i_inline & (F2FS_INLINE_XATTR | F2FS_INLINE_DENTRY))
		words = F2FS_DEFAULT_INLINE_XATTR_ADDRS;

	if (words > DEF_ADDRS_PER_INODE)
		words = 0;

	return words;
}

static const __le32 *f2fs_inode_addr_base(const struct f2fs_inode *inode,
					  unsigned int *countp)
{
	unsigned int extra = f2fs_inode_extra_words(inode);
	unsigned int xattr = f2fs_inode_xattr_words(inode);
	unsigned int count = DEF_ADDRS_PER_INODE;

	if (extra < count) {
		count -= extra;
	} else {
		*countp = 0;
		return inode->i_addr;
	}

	if (xattr < count)
		count -= xattr;
	else
		count = 0;

	*countp = count;
	return &inode->i_addr[extra];
}

static int f2fs_file_block(const struct f2fs_node *inode_node, u64 lblock,
			   u32 *blkaddrp)
{
	const struct f2fs_inode *inode = &inode_node->i;
	const __le32 *addr;
	struct f2fs_node n1, n2;
	unsigned int addrs;
	u32 nid;
	u64 idx;
	int ret;

	addr = f2fs_inode_addr_base(inode, &addrs);
	if (lblock < addrs) {
		*blkaddrp = le32_to_cpu(addr[lblock]);
		return 0;
	}
	lblock -= addrs;

	if (lblock < DEF_ADDRS_PER_BLOCK * 2ULL) {
		int which = lblock / DEF_ADDRS_PER_BLOCK;
		idx = lblock % DEF_ADDRS_PER_BLOCK;
		nid = le32_to_cpu(inode->i_nid[which]);
		ret = f2fs_read_node(nid, &n1);
		if (ret)
			return ret;
		*blkaddrp = le32_to_cpu(n1.dn.addr[idx]);
		return 0;
	}
	lblock -= DEF_ADDRS_PER_BLOCK * 2ULL;

	if (lblock < DEF_ADDRS_PER_BLOCK * (u64)NIDS_PER_BLOCK * 2ULL) {
		int which = lblock / (DEF_ADDRS_PER_BLOCK * (u64)NIDS_PER_BLOCK);
		u64 rem = lblock % (DEF_ADDRS_PER_BLOCK * (u64)NIDS_PER_BLOCK);

		idx = rem / DEF_ADDRS_PER_BLOCK;
		nid = le32_to_cpu(inode->i_nid[NODE_IND1_BLOCK + which]);
		ret = f2fs_read_node(nid, &n1);
		if (ret)
			return ret;

		nid = le32_to_cpu(n1.in.nid[idx]);
		ret = f2fs_read_node(nid, &n2);
		if (ret)
			return ret;

		*blkaddrp = le32_to_cpu(n2.dn.addr[rem % DEF_ADDRS_PER_BLOCK]);
		return 0;
	}
	lblock -= DEF_ADDRS_PER_BLOCK * (u64)NIDS_PER_BLOCK * 2ULL;

	/* Double-indirect node. */
	idx = lblock / (DEF_ADDRS_PER_BLOCK * (u64)NIDS_PER_BLOCK);
	if (idx >= NIDS_PER_BLOCK)
		return -EFBIG;

	nid = le32_to_cpu(inode->i_nid[NODE_DIND_BLOCK]);
	ret = f2fs_read_node(nid, &n1);
	if (ret)
		return ret;

	nid = le32_to_cpu(n1.in.nid[idx]);
	ret = f2fs_read_node(nid, &n1);
	if (ret)
		return ret;

	lblock %= DEF_ADDRS_PER_BLOCK * (u64)NIDS_PER_BLOCK;
	nid = le32_to_cpu(n1.in.nid[lblock / DEF_ADDRS_PER_BLOCK]);
	ret = f2fs_read_node(nid, &n2);
	if (ret)
		return ret;

	*blkaddrp = le32_to_cpu(n2.dn.addr[lblock % DEF_ADDRS_PER_BLOCK]);
	return 0;
}

static const __u8 *f2fs_inline_data_ptr(const struct f2fs_inode *inode,
					unsigned int *lenp)
{
	unsigned int addrs;
	const __le32 *base = f2fs_inode_addr_base(inode, &addrs);

	if (addrs <= F2FS_INLINE_RESERVED_ADDRS) {
		*lenp = 0;
		return NULL;
	}

	*lenp = (addrs - F2FS_INLINE_RESERVED_ADDRS) * sizeof(__le32);
	return (const __u8 *)&base[F2FS_INLINE_RESERVED_ADDRS];
}

static int f2fs_read_inode_data(const struct f2fs_node *node, void *buf,
				loff_t offset, loff_t len, loff_t *actread)
{
	const struct f2fs_inode *inode = &node->i;
	u64 size = le64_to_cpu(inode->i_size);
	__u8 *dst = buf;
	loff_t done = 0;
	int ret = 0;

	if (offset < 0 || len < 0)
		return -EINVAL;

	if ((u64)offset >= size) {
		if (actread)
			*actread = 0;
		return 0;
	}

	if (!len || (u64)len > size - offset)
		len = size - offset;

	if (inode->i_inline & F2FS_INLINE_DATA) {
		const __u8 *idata;
		unsigned int ilen;

		idata = f2fs_inline_data_ptr(inode, &ilen);
		if (!idata || (u64)offset >= ilen)
			return -EINVAL;
		if ((u64)len > ilen - offset)
			len = ilen - offset;
		memcpy(dst, idata + offset, len);
		if (actread)
			*actread = len;
		return 0;
	}

	while (done < len) {
		u64 pos = offset + done;
		u64 lblock = pos / F2FS_BLKSIZE;
		u32 off = pos % F2FS_BLKSIZE;
		u32 blkaddr;
		u32 chunk = F2FS_BLKSIZE - off;
		__u8 *block;

		if (chunk > len - done)
			chunk = len - done;

		ret = f2fs_file_block(node, lblock, &blkaddr);
		if (ret)
			break;

		if (blkaddr == NULL_ADDR || blkaddr == NEW_ADDR) {
			memset(dst + done, 0, chunk);
			done += chunk;
			continue;
		}

		if (blkaddr == COMPRESS_ADDR) {
			ret = -ENOTSUPP;
			break;
		}

		block = malloc(F2FS_BLKSIZE);
		if (!block) {
			ret = -ENOMEM;
			break;
		}

		ret = f2fs_read_block(blkaddr, block);
		if (!ret)
			memcpy(dst + done, block + off, chunk);
		free(block);
		if (ret)
			break;

		done += chunk;
	}

	if (actread)
		*actread = done;
	return ret;
}

static int f2fs_dentry_name_match(const __u8 *name, u16 name_len,
				  const char *want, unsigned int want_len)
{
	return name_len == want_len && !memcmp(name, want, want_len);
}

static int f2fs_lookup_regular_dir(const struct f2fs_node *dir, const char *name,
				   unsigned int name_len, struct f2fs_lookup_res *res)
{
	u64 size = le64_to_cpu(dir->i.i_size);
	u64 blocks = DIV_ROUND_UP(size, F2FS_BLKSIZE);
	struct f2fs_dentry_block *dblk;
	u64 b;
	int ret = -ENOENT;

	dblk = malloc(sizeof(*dblk));
	if (!dblk)
		return -ENOMEM;

	for (b = 0; b < blocks; b++) {
		u32 blkaddr;
		unsigned int i;

		ret = f2fs_file_block(dir, b, &blkaddr);
		if (ret)
			goto out;
		if (blkaddr == NULL_ADDR || blkaddr == NEW_ADDR)
			continue;
		if (blkaddr == COMPRESS_ADDR) {
			ret = -ENOTSUPP;
			goto out;
		}

		ret = f2fs_read_block(blkaddr, dblk);
		if (ret)
			goto out;

		for (i = 0; i < F2FS_NR_DENTRY_IN_BLOCK; ) {
			struct f2fs_dir_entry *de = &dblk->dentry[i];
			u16 len;

			if (!f2fs_get_bit(dblk->dentry_bitmap, i)) {
				i++;
				continue;
			}

			len = le16_to_cpu(de->name_len);
			if (len && len <= F2FS_MAX_NAME_LEN &&
			    f2fs_dentry_name_match(&dblk->filename[i][0], len, name, name_len)) {
				res->nid = le32_to_cpu(de->ino);
				res->type = de->file_type;
				ret = 0;
				goto out;
			}

			i += f2fs_slots(len ? len : 1);
		}
	}

	ret = -ENOENT;
out:
	free(dblk);
	return ret;
}

static int f2fs_inline_dentry_params(const struct f2fs_inode *inode,
				     const __u8 **bitmapp,
				     const struct f2fs_dir_entry **dentryp,
				     const __u8 **namesp,
				     unsigned int *nrp)
{
	const __u8 *base;
	unsigned int bytes;
	unsigned int nr;
	unsigned int bitmap_bytes;
	unsigned int reserved;

	base = f2fs_inline_data_ptr(inode, &bytes);
	if (!base || bytes < 64)
		return -EINVAL;

	nr = (bytes * 8) / ((F2FS_DIR_ENTRY_SIZE + F2FS_SLOT_LEN) * 8 + 1);
	if (!nr || nr > F2FS_NR_DENTRY_IN_BLOCK)
		return -EINVAL;

	bitmap_bytes = DIV_ROUND_UP(nr, 8);
	reserved = bytes - bitmap_bytes - nr * (F2FS_DIR_ENTRY_SIZE + F2FS_SLOT_LEN);
	*bitmapp = base;
	*dentryp = (const struct f2fs_dir_entry *)(base + bitmap_bytes + reserved);
	*namesp = (const __u8 *)(*dentryp + nr);
	*nrp = nr;
	return 0;
}

static int f2fs_lookup_inline_dir(const struct f2fs_node *dir, const char *name,
				  unsigned int name_len, struct f2fs_lookup_res *res)
{
	const __u8 *bitmap, *names;
	const struct f2fs_dir_entry *dentries;
	unsigned int nr, i;
	int ret;

	ret = f2fs_inline_dentry_params(&dir->i, &bitmap, &dentries, &names, &nr);
	if (ret)
		return ret;

	for (i = 0; i < nr; ) {
		const struct f2fs_dir_entry *de = &dentries[i];
		u16 len;

		if (!f2fs_get_bit(bitmap, i)) {
			i++;
			continue;
		}

		len = le16_to_cpu(de->name_len);
		if (len && len <= F2FS_MAX_NAME_LEN &&
		    i + f2fs_slots(len) <= nr &&
		    f2fs_dentry_name_match(names + i * F2FS_SLOT_LEN, len, name, name_len)) {
			res->nid = le32_to_cpu(de->ino);
			res->type = de->file_type;
			return 0;
		}

		i += f2fs_slots(len ? len : 1);
	}

	return -ENOENT;
}

static int f2fs_lookup_in_dir(const struct f2fs_node *dir, const char *name,
			       unsigned int name_len, struct f2fs_lookup_res *res)
{
	struct f2fs_node child;
	int ret;

	if (!(le16_to_cpu(dir->i.i_mode) & S_IFDIR))
		return -ENOTDIR;

	if (name_len == 1 && name[0] == '.') {
		res->nid = le32_to_cpu(dir->footer.nid);
		res->type = FS_DT_DIR;
		res->mode = le16_to_cpu(dir->i.i_mode);
		res->size = le64_to_cpu(dir->i.i_size);
		return 0;
	}

	ret = (dir->i.i_inline & F2FS_INLINE_DENTRY) ?
		f2fs_lookup_inline_dir(dir, name, name_len, res) :
		f2fs_lookup_regular_dir(dir, name, name_len, res);
	if (ret)
		return ret;

	ret = f2fs_read_node(res->nid, &child);
	if (ret)
		return ret;

	res->mode = le16_to_cpu(child.i.i_mode);
	res->size = le64_to_cpu(child.i.i_size);
	if (res->type == FS_DT_UNKNOWN)
		res->type = f2fs_mode_to_fs_dt(res->mode);
	return 0;
}

static int f2fs_find_path(const char *path, struct f2fs_node *node, u32 *nidp)
{
	char comp[F2FS_MAX_NAME_LEN + 1];
	const char *p = path;
	u32 nid = le32_to_cpu(gctx.sb.root_ino);
	int ret;

	if (!path || !*path)
		return -EINVAL;

	ret = f2fs_read_node(nid, node);
	if (ret)
		return ret;

	while (*p == '/')
		p++;

	if (!*p) {
		if (nidp)
			*nidp = nid;
		return 0;
	}

	while (*p) {
		const char *slash = strchr(p, '/');
		unsigned int len = slash ? (unsigned int)(slash - p) : strlen(p);
		struct f2fs_lookup_res res;

		if (!len || len > F2FS_MAX_NAME_LEN)
			return -EINVAL;
		memcpy(comp, p, len);
		comp[len] = '\0';

		if (len == 2 && comp[0] == '.' && comp[1] == '.')
			return -ENOTSUPP;

		ret = f2fs_lookup_in_dir(node, comp, len, &res);
		if (ret)
			return ret;

		nid = res.nid;
		ret = f2fs_read_node(nid, node);
		if (ret)
			return ret;

		p = slash ? slash + 1 : p + len;
		while (*p == '/')
			p++;
	}

	if (nidp)
		*nidp = nid;
	return 0;
}

static void f2fs_fill_dirent(struct fs_dirent *dent, const char *name,
			     unsigned int name_len, const struct f2fs_node *node)
{
	unsigned int n = name_len;

	if (n >= sizeof(dent->name))
		n = sizeof(dent->name) - 1;
	memcpy(dent->name, name, n);
	dent->name[n] = '\0';
	dent->type = f2fs_mode_to_fs_dt(le16_to_cpu(node->i.i_mode));
	dent->size = le64_to_cpu(node->i.i_size);
}

static int f2fs_next_regular_dentry(struct f2fs_dir_stream_priv *s,
				    struct fs_dirent **dentp)
{
	struct f2fs_dentry_block *dblk;
	u64 block_index;
	int ret = -ENOENT;

	dblk = malloc(sizeof(*dblk));
	if (!dblk)
		return -ENOMEM;

	while (s->index < s->max_index) {
		u32 slot = s->index % F2FS_NR_DENTRY_IN_BLOCK;
		u32 blkaddr;

		block_index = s->index / F2FS_NR_DENTRY_IN_BLOCK;
		ret = f2fs_file_block(&s->dir, block_index, &blkaddr);
		if (ret)
			goto out;

		if (blkaddr == NULL_ADDR || blkaddr == NEW_ADDR) {
			s->index += F2FS_NR_DENTRY_IN_BLOCK - slot;
			continue;
		}
		if (blkaddr == COMPRESS_ADDR) {
			ret = -ENOTSUPP;
			goto out;
		}

		ret = f2fs_read_block(blkaddr, dblk);
		if (ret)
			goto out;

		while (slot < F2FS_NR_DENTRY_IN_BLOCK && s->index < s->max_index) {
			struct f2fs_dir_entry *de = &dblk->dentry[slot];
			struct f2fs_node child;
			u16 len;

			if (!f2fs_get_bit(dblk->dentry_bitmap, slot)) {
				slot++;
				s->index++;
				continue;
			}

			len = le16_to_cpu(de->name_len);
			s->index += f2fs_slots(len ? len : 1);
			if (!len || len > F2FS_MAX_NAME_LEN ||
			    slot + f2fs_slots(len) > F2FS_NR_DENTRY_IN_BLOCK) {
				slot = s->index % F2FS_NR_DENTRY_IN_BLOCK;
				continue;
			}

			ret = f2fs_read_node(le32_to_cpu(de->ino), &child);
			if (ret)
				goto out;

			f2fs_fill_dirent(&s->dent, (char *)&dblk->filename[slot][0], len, &child);
			*dentp = &s->dent;
			ret = 0;
			goto out;
		}
	}

	ret = -ENOENT;
out:
	free(dblk);
	return ret;
}

static int f2fs_next_inline_dentry(struct f2fs_dir_stream_priv *s,
				   struct fs_dirent **dentp)
{
	const __u8 *bitmap, *names;
	const struct f2fs_dir_entry *dentries;
	unsigned int nr;
	int ret;

	ret = f2fs_inline_dentry_params(&s->dir.i, &bitmap, &dentries, &names, &nr);
	if (ret)
		return ret;

	while (s->index < nr) {
		unsigned int slot = s->index;
		const struct f2fs_dir_entry *de = &dentries[slot];
		struct f2fs_node child;
		u16 len;

		if (!f2fs_get_bit(bitmap, slot)) {
			s->index++;
			continue;
		}

		len = le16_to_cpu(de->name_len);
		s->index += f2fs_slots(len ? len : 1);
		if (!len || len > F2FS_MAX_NAME_LEN || slot + f2fs_slots(len) > nr)
			continue;

		ret = f2fs_read_node(le32_to_cpu(de->ino), &child);
		if (ret)
			return ret;

		f2fs_fill_dirent(&s->dent, (const char *)(names + slot * F2FS_SLOT_LEN), len, &child);
		*dentp = &s->dent;
		return 0;
	}

	return -ENOENT;
}

int f2fs_probe(struct blk_desc *fs_dev_desc, struct disk_partition *fs_partition)
{
	int ret;

	f2fs_close();
	if (!fs_dev_desc || !fs_partition)
		return -EINVAL;

	memset(&gctx, 0, sizeof(gctx));
	gctx.desc = fs_dev_desc;
	memcpy(&gctx.part, fs_partition, sizeof(gctx.part));
	gctx.sector_size = fs_dev_desc->blksz ? fs_dev_desc->blksz : 512;

	ret = f2fs_read_super();
	if (ret)
		goto fail;

	ret = f2fs_read_checkpoint();
	if (ret)
		goto fail;

	return 0;

fail:
	f2fs_close();
	return ret;
}

void f2fs_close(void)
{
	free(gctx.cp);
	memset(&gctx, 0, sizeof(gctx));
}

int f2fs_opendir(const char *filename, struct fs_dir_stream **dirsp)
{
	struct f2fs_dir_stream_priv *s;
	int ret;

	if (!dirsp)
		return -EINVAL;

	s = calloc(1, sizeof(*s));
	if (!s)
		return -ENOMEM;

	ret = f2fs_find_path(filename && *filename ? filename : "/", &s->dir, &s->nid);
	if (ret)
		goto fail;

	if (!(le16_to_cpu(s->dir.i.i_mode) & S_IFDIR)) {
		ret = -ENOTDIR;
		goto fail;
	}

	if (s->dir.i.i_inline & F2FS_INLINE_DENTRY) {
		const __u8 *bitmap, *names;
		const struct f2fs_dir_entry *dentries;
		ret = f2fs_inline_dentry_params(&s->dir.i, &bitmap, &dentries, &names,
					      &s->inline_count);
		if (ret)
			goto fail;
		s->max_index = s->inline_count;
	} else {
		s->max_index = DIV_ROUND_UP(le64_to_cpu(s->dir.i.i_size), F2FS_BLKSIZE) *
			F2FS_NR_DENTRY_IN_BLOCK;
	}

	*dirsp = &s->fs;
	return 0;

fail:
	free(s);
	return ret;
}

int f2fs_readdir(struct fs_dir_stream *dirs, struct fs_dirent **dentp)
{
	struct f2fs_dir_stream_priv *s = (struct f2fs_dir_stream_priv *)dirs;
	int ret;

	if (!s || !dentp)
		return -EINVAL;

	*dentp = NULL;
	ret = (s->dir.i.i_inline & F2FS_INLINE_DENTRY) ?
		f2fs_next_inline_dentry(s, dentp) :
		f2fs_next_regular_dentry(s, dentp);

	if (ret == -ENOENT)
		return 0;
	return ret;
}

void f2fs_closedir(struct fs_dir_stream *dirs)
{
	free(dirs);
}

int f2fs_exists(const char *filename)
{
	struct f2fs_node node;

	return f2fs_find_path(filename, &node, NULL) == 0;
}

int f2fs_size(const char *filename, loff_t *size)
{
	struct f2fs_node node;
	int ret;

	if (!size)
		return -EINVAL;

	ret = f2fs_find_path(filename, &node, NULL);
	if (ret)
		return ret;

	*size = le64_to_cpu(node.i.i_size);
	return 0;
}

int f2fs_read(const char *filename, void *buf, loff_t offset, loff_t len,
	      loff_t *actread)
{
	struct f2fs_node node;
	int ret;

	ret = f2fs_find_path(filename, &node, NULL);
	if (ret)
		return ret;

	if ((le16_to_cpu(node.i.i_mode) & S_IFMT) == S_IFDIR)
		return -EISDIR;

	return f2fs_read_inode_data(&node, buf, offset, len, actread);
}

int f2fs_uuid(char *uuid_str)
{
	const __u8 *u = gctx.sb.uuid;

	if (!uuid_str || !gctx.desc)
		return -EINVAL;

	sprintf(uuid_str,
		"%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		u[0], u[1], u[2], u[3], u[4], u[5], u[6], u[7],
		u[8], u[9], u[10], u[11], u[12], u[13], u[14], u[15]);
	return 0;
}
