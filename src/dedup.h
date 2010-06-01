#ifndef _DEDUP_H
#define _DEDUP_H

#include "md5.h"
#include "hash.h"
#include "hashtable.h"
#include "libz.h"

#ifdef __cplusplus
extern "C" {
#endif

/* 
 * deduplication file data layout
 * --------------------------------------------------
 * |  header  |  unique block data |  file metadata |
 * --------------------------------------------------
 *
 * file metedata entry layout
 * -----------------------------------------------------------------
 * |  entry header  |  pathname  |  entry data  |  last block data |
 * -----------------------------------------------------------------
 */

typedef unsigned int block_id_t;

#define BLOCK_SIZE	4096	 /* 4K Bytes */
#define BACKET_SIZE     10240
#define MAX_PATH_LEN	255
#define BLOCK_ID_SIZE   (sizeof(block_id_t))

/* deduplication package header */
#define DEDUP_MAGIC_NUM	0x1329149
typedef struct _dedup_package_header {
	unsigned int block_size;
	unsigned int block_num;
	unsigned int blockid_size;
	unsigned int magic_num;
	unsigned int file_num;
	unsigned long long metadata_offset;
} dedup_package_header;
#define DEDUP_PKGHDR_SIZE	(sizeof(dedup_package_header))

/* deduplication metadata entry header */
typedef struct _dedup_entry_header {
	unsigned int path_len;
	unsigned int block_num;
	unsigned int entry_size;
	unsigned int last_block_size;
	int mode;
} dedup_entry_header;
#define DEDUP_ENTRYHDR_SIZE	(sizeof(dedup_entry_header))

enum DEDUP_OPERATIONS {
	DEDUP_CREAT = 0,
	DEDUP_EXTRACT,
	DEDUP_APPEND,
	DEDUP_REMOVE,
	DEDUP_LIST
};

#define TMP_FILE 	".dedup_d7d1b627a34d5b56dae225cc4f03ddf7\0"
#define MDATA_FILE	".mdata_d7d1b627a34d5b56dae225cc4f03ddf7\0"
#define BDATA_FILE	".bdata_d7d1b627a34d5b56dae225cc4f03ddf7\0"

#ifdef __cplusplus
}
#endif

#endif
