/* Copyright (C) 2010,2011 Aigui Liu
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, visit the http://fsf.org website.
 */

/* 
 * deduplication file data layout
 * +---------------------------------------------------------------------+
 * |  header  |  unique block data  |  logic block data |  file metadata |
 * +---------------------------------------------------------------------+
 *
 * file metedata entry layout
 * +--------------------------------------------+
 * |  entry header  |  pathname  |  entry data  |
 * +--------------------------------------------+
 *
 * entry data layout
 * +---------------------------------------+
 * | bid 1 | bid 2 | ... | bid n-1 | bid n |
 * +---------------------------------------+
 */

#ifndef _DEDUP_H
#define _DEDUP_H

#ifdef __cplusplus
extern "C" {
#endif

#define DEDUPUTIL_VERSION	"1.4.1"

/* deduplication block id type */
typedef unsigned int block_id_t;
#define BLOCK_ID_SIZE   (sizeof(block_id_t))
#define BLOCK_ID_ALLOC_INC	20

#define BLOCK_SIZE	4096	/* 4K Bytes */
#define BLOCK_MIN_SIZE	512
#define BLOCK_MAX_SIZE	32768	/* 32K Bytes */
#define BLOCK_WIN_SIZE	48
#define BUCKET_SIZE     102400
#define BUF_MAX_SIZE	131072	/* 128K Bytes */
#define PATH_MAX_LEN	255
#define TRUE		1
#define FALSE		0

/* deduplication package header */
#define DEDUP_MAGIC_NUM	0x1329149
typedef struct _dedup_package_header {
	unsigned int block_size;
	unsigned int block_num;
	unsigned int blockid_size;
	unsigned int magic_num;
	unsigned int block_z;
	unsigned int file_num;
	unsigned long long ldata_offset;
	unsigned long long metadata_offset;
} dedup_package_header;
#define DEDUP_PKGHDR_SIZE	(sizeof(dedup_package_header))

/* deduplication logic block entry */
typedef struct _dedup_logic_block_entry {
	unsigned long long block_offset;
	unsigned int block_len;
} dedup_logic_block_entry;
#define DEDUP_LOGIC_BLOCK_ENTRY_SIZE	(sizeof(dedup_logic_block_entry))

/* deduplication metadata entry header */
typedef struct _dedup_entry_header {
	unsigned int path_len;
	unsigned int block_num;
	unsigned int entry_size;
	unsigned int last_block_size;
	unsigned long long old_size;
	int mode;
	time_t atime;
	time_t mtime;
} dedup_entry_header;
#define DEDUP_ENTRYHDR_SIZE	(sizeof(dedup_entry_header))

/* deduplication operations */
enum DEDUP_OPERATIONS {
	DEDUP_CREAT = 0,
	DEDUP_EXTRACT,
	DEDUP_APPEND,
	DEDUP_REMOVE,
	DEDUP_LIST,
	DEDUP_STAT
};

/* deduplication chunking algorithms */
#define CHUNK_FSP	"FSP"	/* fixed-sized partition */
#define CHUNK_CDC	"CDC"	/* content-defined chunking */
#define CHUNK_SB	"SB"	/* sliding block */
enum DEDUP_CHUNK_ALGORITHMS {
	DEDUP_CHUNK_FSP = 0,
	DEDUP_CHUNK_CDC,
	DEDUP_CHUNK_SB
};
#define CHUNK_CDC_D	4096
#define CHUNK_CDC_R	13

#define DEDUP_ROLLING_HASH	"adler_hash"
typedef struct _cdc_chunk_hashfunc {
	char hashfunc_name[16];
	unsigned int (*hashfunc)(char *str);
} cdc_chunk_hashfunc;

/* magic number for temporary filename */
#define FILENAME_MAGIC_NUM	"d7d1b627a34d5b56dae225cc4f03ddf7"

#ifdef __cplusplus
}
#endif

#endif
