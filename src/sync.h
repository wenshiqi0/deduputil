/* Copyright (C) 2010 Aigui Liu
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

#ifndef _SYNC_H
#define _SYNC_H

#include <stdint.h>

#define BLOCK_SZ        1024
#define BLOCK_MIN_SZ    512
#define BLOCK_MAX_SZ    2048
#define BLOCK_WIN_SZ    48

#define NAME_MAX_SZ		256
#define BUF_MAX_SZ		32768
#define HASHTABLE_BUCKET_SZ	1024

#define CHUNK_CDC_D     BLOCK_SZ
#define CHUNK_CDC_R     13
enum chunk_algo {
	CHUNK_FSP = 0,  /* fixed-size partition */
	CHUNK_CDC,      /* content-define chunking */
	CHUNK_SBC       /* slide block chunking */
};

/* define chunk file header and block entry */
typedef struct _chunk_file_header {
	uint32_t block_sz;
	uint32_t block_nr;
} chunk_file_header;
#define CHUNK_FILE_HEADER_SZ	(sizeof(chunk_file_header))

typedef struct _chunk_block_entry {
	uint64_t offset;
	uint32_t len;
	uint8_t  md5[16 + 1];
	uint8_t  csum[10 + 1];
} chunk_block_entry;
#define CHUNK_BLOCK_ENTRY_SZ	(sizeof(chunk_block_entry))

/* define delta file header and block entry */
typedef struct _delta_file_header {
	uint32_t block_nr;
	uint32_t last_block_sz;
	uint64_t last_block_offset;  /* offset in delta file */
} delta_file_header;
#define DELTA_FILE_HEADER_SZ	(sizeof(delta_file_header))

typedef struct _delta_block_entry {
	uint64_t offset;
	uint32_t len;
	uint8_t  embeded; /* 1, block in delta file; 0, block in source file. */
} delta_block_entry;
#define DELTA_BLOCK_ENTRY_SZ	(sizeof(delta_block_entry))

int file_chunk(char *src_filename, char *chunk_filename, int chunk_algo);
int file_delta(char *src_filename, char *chunk_filename, char *delta_filename, int chunk_algo);
int file_sync(char *src_filename, char *delta_filename);

#endif
