/* SPDX-License-Identifier: GPL-2.0+ */
#ifndef __U_BOOT_F2FS_H__
#define __U_BOOT_F2FS_H__

#include <blk.h>
#include <fs.h>
#include <part.h>

int f2fs_probe(struct blk_desc *fs_dev_desc, struct disk_partition *fs_partition);
void f2fs_close(void);
int f2fs_opendir(const char *filename, struct fs_dir_stream **dirsp);
int f2fs_readdir(struct fs_dir_stream *dirs, struct fs_dirent **dentp);
void f2fs_closedir(struct fs_dir_stream *dirs);
int f2fs_exists(const char *filename);
int f2fs_size(const char *filename, loff_t *size);
int f2fs_read(const char *filename, void *buf, loff_t offset, loff_t len,
	      loff_t *actread);
int f2fs_uuid(char *uuid_str);

#endif /* __U_BOOT_F2FS_H__ */
