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

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include "md5.h"
#include "checksum.h"
#include "hashtable.h"
#include "sync.h"

/* transfer unsigned integer into string */
static int uint_2_str(unsigned int x, char *str)
{
	int i = 0;
	unsigned int xx = x, t;

	while (xx) {
		str[i++] = (xx % 10) + '0';
		xx = xx / 10;
	}
	str[i] = '\0';

	xx = i;
	for (i = 0; i < xx/2; i++) {
		t = str[i];
		str[i] = str[xx - i -1];
		str[xx - i -1] = t;
	}

	return xx;
}

/* fix-sized file chunking */
static int file_chunk_fsp(int fd_src, int fd_chunk, chunk_file_header *chunk_file_hdr)
{
	unsigned int rwsize;
	unsigned char md5_checksum[16 + 1] = {0};
	unsigned char csum[10 + 1] = {0};
	char buf[BLOCK_SZ] = {0};
	chunk_block_entry chunk_bentry;
	uint64_t offset = 0;


	while (rwsize = read(fd_src, buf, BLOCK_SZ)) {
		md5(buf, rwsize, md5_checksum);
		uint_2_str(adler32_checksum(buf, rwsize), csum);
		chunk_bentry.len = rwsize;
		chunk_bentry.offset = offset;
		memcpy(chunk_bentry.md5, md5_checksum, 16 + 1);
		memcpy(chunk_bentry.csum, csum, 10 + 1);
		rwsize = write(fd_chunk, &chunk_bentry, CHUNK_BLOCK_ENTRY_SZ);
		if (rwsize == -1 || rwsize != CHUNK_BLOCK_ENTRY_SZ)
			return -1;

		offset += rwsize;
		chunk_file_hdr->block_nr++;
	}
	if (rwsize == -1)
		return -1;

	return 0;
}

/* content-defined chunking */
static int file_chunk_cdc(int fd_src, int fd_chunk, chunk_file_header *chunk_file_hdr)
{
	char buf[BUF_MAX_SZ] = {0};
	char block_buf[BLOCK_MAX_SZ] = {0};
	char win_buf[BLOCK_WIN_SZ + 1] = {0};
	unsigned char md5_checksum[16 + 1] = {0};
	unsigned char csum[10 + 1] = {0};
	unsigned int bpos = 0;
	unsigned int rwsize = 0;
	unsigned int exp_rwsize = BUF_MAX_SZ;
	unsigned int head, tail;
	unsigned int block_sz = 0, old_block_sz = 0;
	unsigned int hkey = 0;
	chunk_block_entry chunk_bentry;
	uint64_t offset = 0;

	while(rwsize = read(fd_src, buf + bpos, exp_rwsize)) {
		/* last chunk */
		if ((rwsize + bpos + block_sz) < BLOCK_MIN_SZ)
			break;

		head = 0;
		tail = bpos + rwsize;
		/* avoid unnecessary computation and comparsion */
		if (block_sz < (BLOCK_MIN_SZ - BLOCK_WIN_SZ)) {
			old_block_sz = block_sz;
			block_sz = ((block_sz + tail - head) > (BLOCK_MIN_SZ - BLOCK_WIN_SZ)) ?
				BLOCK_MIN_SZ - BLOCK_WIN_SZ : block_sz + tail -head;
			memcpy(block_buf + old_block_sz, buf + head, block_sz - old_block_sz);
			head += (block_sz - old_block_sz);
		}

		while ((head + BLOCK_WIN_SZ) <= tail) {
			memcpy(win_buf, buf + head, BLOCK_WIN_SZ);
			hkey = (block_sz == (BLOCK_MIN_SZ - BLOCK_WIN_SZ)) ? adler32_checksum(win_buf, BLOCK_WIN_SZ) :
				adler32_rolling_checksum(hkey, BLOCK_WIN_SZ, buf[head-1], buf[head+BLOCK_WIN_SZ-1]);

			/* get a normal chunk, write block info to chunk file */
			if ((hkey % BLOCK_SZ) == CHUNK_CDC_R) {
				memcpy(block_buf + block_sz, buf + head, BLOCK_WIN_SZ);
				head += BLOCK_WIN_SZ;
				block_sz += BLOCK_WIN_SZ;
				if (block_sz >= BLOCK_MIN_SZ) {
					md5(block_buf, block_sz, md5_checksum);
					uint_2_str(adler32_checksum(block_buf, block_sz), csum);
					chunk_file_hdr->block_nr++;
					chunk_bentry.len = block_sz;
					chunk_bentry.offset = offset;
					memcpy(chunk_bentry.md5, md5_checksum, 16 + 1);
					memcpy(chunk_bentry.csum, csum, 10 + 1);
					rwsize = write(fd_chunk, &chunk_bentry, CHUNK_BLOCK_ENTRY_SZ);
					if (rwsize == -1 || rwsize != CHUNK_BLOCK_ENTRY_SZ)
						return -1;
					offset += block_sz;
					block_sz = 0;
				}
			} else {
				block_buf[block_sz++] = buf[head++];
				/* get an abnormal chunk, write block info to chunk file */
				if (block_sz >= BLOCK_MAX_SZ) {
					md5(block_buf, block_sz, md5_checksum);
					uint_2_str(adler32_checksum(block_buf, block_sz), csum);
					chunk_file_hdr->block_nr++;
					chunk_bentry.len = block_sz;
					chunk_bentry.offset = offset;
					memcpy(chunk_bentry.md5, md5_checksum, 16+1);
					memcpy(chunk_bentry.csum, csum, 10 + 1);
					rwsize = write(fd_chunk, &chunk_bentry, CHUNK_BLOCK_ENTRY_SZ);
					if (rwsize == -1 || rwsize != CHUNK_BLOCK_ENTRY_SZ)
						return -1;
					offset += block_sz;
					block_sz = 0;
				}
			}

			/* avoid unnecessary computation and comparsion */
			if (block_sz == 0) {
				block_sz = ((tail - head) > (BLOCK_MIN_SZ - BLOCK_WIN_SZ)) ?
					BLOCK_MIN_SZ - BLOCK_WIN_SZ : tail - head;
				memcpy(block_buf, buf + head, block_sz);
				head = ((tail - head) > (BLOCK_MIN_SZ - BLOCK_WIN_SZ)) ?
					head + (BLOCK_MIN_SZ - BLOCK_WIN_SZ) : tail;
			}
		}

		/* read expected data from file to full up buf */
		bpos = tail - head;
		exp_rwsize = BUF_MAX_SZ - bpos;
		memmove(buf, buf + head, bpos);
	}

	if (rwsize == -1)
		return -1;
	
	/* process last block */
	uint32_t last_block_sz = ((rwsize + bpos + block_sz) >= 0) ? rwsize + bpos + block_sz : 0;
	char last_block_buf[BLOCK_MAX_SZ] = {0};
	if (last_block_sz > 0) {
		memcpy(last_block_buf, block_buf, block_sz);
		memcpy(last_block_buf + block_sz, buf, rwsize + bpos);
		md5(last_block_buf, last_block_sz, md5_checksum);
		uint_2_str(adler32_checksum(last_block_buf, last_block_sz), csum);
		chunk_file_hdr->block_nr++;
		chunk_bentry.len = last_block_sz;
		chunk_bentry.offset = offset;
		memcpy(chunk_bentry.md5, md5_checksum, 16+1);
		memcpy(chunk_bentry.csum, csum, 10 + 1);
		rwsize = write(fd_chunk, &chunk_bentry, CHUNK_BLOCK_ENTRY_SZ);
		if (rwsize == -1 || rwsize != CHUNK_BLOCK_ENTRY_SZ)
			return -1;
	}

	return 0;
}

static int file_chunk_sbc(int fd_src, int fd_chunk, chunk_file_header *chunk_file_hdr)
{
	return file_chunk_fsp(fd_src, fd_chunk, chunk_file_hdr);
}

int file_chunk(char *src_filename, char *chunk_filename, int chunk_algo)
{
	int fd_src, fd_chunk;
	chunk_file_header chunk_file_hdr;
	int ret = 0, rwsize;

	fd_src = open(src_filename, O_RDONLY);
	if (fd_src == -1)
		return -1;

	fd_chunk = open(chunk_filename, O_WRONLY|O_CREAT|O_TRUNC, 0644);
	if (fd_chunk == -1) {
		ret = -1;
		goto _FILE_CHUNK_EXIT;
	}
	
	/* pre-write chunk file header */
	chunk_file_hdr.block_nr = 0;
	rwsize = write(fd_chunk, &chunk_file_hdr, CHUNK_FILE_HEADER_SZ);
	if (rwsize == -1 || rwsize != CHUNK_FILE_HEADER_SZ) {
		ret = -1;
		goto _FILE_CHUNK_EXIT;
	}

	/* file chunking according to chunk algorithms */
	switch(chunk_algo) {
	case CHUNK_FSP:
		ret = file_chunk_fsp(fd_src, fd_chunk, &chunk_file_hdr);
		break;
	case CHUNK_CDC:
		ret = file_chunk_cdc(fd_src, fd_chunk, &chunk_file_hdr);
		break;
	case CHUNK_SBC:
		ret = file_chunk_sbc(fd_src, fd_chunk, &chunk_file_hdr);
		break;
	}

	/* write back chunk file header */
	if (ret == 0) {
		if (lseek(fd_chunk, 0, SEEK_SET) == -1) {
			ret = -1;
			goto _FILE_CHUNK_EXIT;
		}

		chunk_file_hdr.block_sz = BLOCK_SZ;
		rwsize = write(fd_chunk, &chunk_file_hdr, CHUNK_FILE_HEADER_SZ);
		if (rwsize == -1 || rwsize != CHUNK_FILE_HEADER_SZ)
			ret = -1;
	}

_FILE_CHUNK_EXIT:
	close(fd_src);
	close(fd_chunk);

	return ret;
}

/* insert item into hashtable */
static inline void hash_checkin(hashtable *htable, char *md5, chunk_block_entry chunk_bentry)
{
	chunk_block_entry *be = (chunk_block_entry *)malloc(CHUNK_BLOCK_ENTRY_SZ);
	memcpy(be, &chunk_bentry, CHUNK_BLOCK_ENTRY_SZ);
	hash_insert((void *)strdup(md5), (void *)be, htable);
}

static int delta_block_process(hashtable *htab_md5, hashtable *htab_csum, int fd_delta, char *block_buf, uint64_t *offset, uint32_t block_sz)
{
	uint32_t rwsize;
	uint32_t hkey;
	unsigned char md5_checksum[16 + 1] = {0};
	unsigned char csum[10 + 1] = {0};
	chunk_block_entry *chunk_bentry = NULL;
	delta_block_entry delta_bentry;

	/* lookup hashtable */
	hkey = adler32_checksum(block_buf, block_sz);
	uint_2_str(hkey, csum);
	chunk_bentry = (chunk_block_entry *)hash_value((void *)csum, htab_csum);
	if (chunk_bentry != NULL) {
		md5(block_buf, block_sz, md5_checksum);
		chunk_bentry = (chunk_block_entry *)hash_value((void *)md5_checksum, htab_md5);
	}

	delta_bentry.embeded = (chunk_bentry == NULL) ? 1 : 0;
	delta_bentry.offset = (chunk_bentry == NULL) ? offset: chunk_bentry->offset;
	delta_bentry.len = block_sz;

	/* write delta block entry*/
	rwsize = write(fd_delta, &delta_bentry, DELTA_BLOCK_ENTRY_SZ);
	if (rwsize == -1 || rwsize != DELTA_BLOCK_ENTRY_SZ)
		return -1;
	*offset += DELTA_BLOCK_ENTRY_SZ;

	/* write block data if necessary */
	if (chunk_bentry == NULL) {
		rwsize = write(fd_delta, block_buf, block_sz);
		if (rwsize == -1 || rwsize != block_sz)
			return -1;

		*offset += block_sz;
	}

	return 0;
}


/* file delta coding with fixed-size partition */
static int file_delta_fsp(hashtable *htab_md5, hashtable *htab_csum, int fd_src, int fd_delta, delta_file_header *delta_file_hdr)
{
	unsigned int rwsize;
	char buf[BLOCK_SZ] = {0};
	chunk_block_entry *chunk_bentry = NULL;
	delta_block_entry delta_bentry;
	uint64_t offset = DELTA_FILE_HEADER_SZ;
	uint32_t block_nr = 0;

	while (rwsize = read(fd_src, buf, BLOCK_SZ)) {
		if (rwsize != BLOCK_SZ)
			break;

		if (0 != delta_block_process(htab_md5, htab_csum, fd_delta, buf, &offset, BLOCK_SZ))
			return -1;

		block_nr++;
	}
	if (rwsize == -1)
		return -1;

	/* write last block */
	if (rwsize != write(fd_delta, buf, rwsize))
		return -1;

	/* fill up delta file header */
	delta_file_hdr->block_nr = block_nr;
	delta_file_hdr->last_block_sz = rwsize;
	delta_file_hdr->last_block_offset = offset;

	return 0;
}

/* file delta coding with content-defined chunking */
static int file_delta_cdc(hashtable *htab_md5, hashtable *htab_csum, int fd_src, int fd_delta, delta_file_header *delta_file_hdr)
{
	char buf[BUF_MAX_SZ] = {0};
	char block_buf[BLOCK_MAX_SZ] = {0};
	char win_buf[BLOCK_WIN_SZ + 1] = {0};
	unsigned int bpos = 0;
	unsigned int rwsize = 0;
	unsigned int exp_rwsize = BUF_MAX_SZ;
	unsigned int head, tail;
	unsigned int block_sz = 0, old_block_sz = 0;
	unsigned int hkey = 0;
	chunk_block_entry *chunk_bentry = NULL;
	delta_block_entry delta_bentry;
	uint64_t offset = DELTA_FILE_HEADER_SZ;
	uint32_t block_nr = 0;

	while(rwsize = read(fd_src, buf + bpos, exp_rwsize)) {
		/* last chunk */
		if ((rwsize + bpos + block_sz) < BLOCK_MIN_SZ)
			break;

		head = 0;
		tail = bpos + rwsize;
		/* avoid unnecessary computation and comparsion */
		if (block_sz < (BLOCK_MIN_SZ - BLOCK_WIN_SZ)) {
			old_block_sz = block_sz;
			block_sz = ((block_sz + tail - head) > (BLOCK_MIN_SZ - BLOCK_WIN_SZ)) ?
				BLOCK_MIN_SZ - BLOCK_WIN_SZ : block_sz + tail -head;
			memcpy(block_buf + old_block_sz, buf + head, block_sz - old_block_sz);
			head += (block_sz - old_block_sz);
		}

		while ((head + BLOCK_WIN_SZ) <= tail) {
			memcpy(win_buf, buf + head, BLOCK_WIN_SZ);
			hkey = (block_sz == (BLOCK_MIN_SZ - BLOCK_WIN_SZ)) ? adler32_checksum(win_buf, BLOCK_WIN_SZ) :
				adler32_rolling_checksum(hkey, BLOCK_WIN_SZ, buf[head-1], buf[head+BLOCK_WIN_SZ-1]);

			/* get a normal chunk, write block info to delta file */
			if ((hkey % BLOCK_SZ) == CHUNK_CDC_R) {
				memcpy(block_buf + block_sz, buf + head, BLOCK_WIN_SZ);
				head += BLOCK_WIN_SZ;
				block_sz += BLOCK_WIN_SZ;
				if (block_sz >= BLOCK_MIN_SZ) {
					if (0 != delta_block_process(htab_md5, htab_csum, fd_delta, block_buf, &offset, block_sz))
						return -1;
					block_nr++;
					block_sz = 0;
				}
			} else {
				block_buf[block_sz++] = buf[head++];
				/* get an abnormal chunk, write block info to delta file */
				if (block_sz >= BLOCK_MAX_SZ) {
					if (0 != delta_block_process(htab_md5, htab_csum, fd_delta, block_buf, &offset, block_sz))
						return -1;
					block_nr++;
					block_sz = 0;
				}
			}

			/* avoid unnecessary computation and comparsion */
			if (block_sz == 0) {
				block_sz = ((tail - head) > (BLOCK_MIN_SZ - BLOCK_WIN_SZ)) ?
					BLOCK_MIN_SZ - BLOCK_WIN_SZ : tail - head;
				memcpy(block_buf, buf + head, block_sz);
				head = ((tail - head) > (BLOCK_MIN_SZ - BLOCK_WIN_SZ)) ?
					head + (BLOCK_MIN_SZ - BLOCK_WIN_SZ) : tail;
			}
		}

		/* read expected data from file to full up buf */
		bpos = tail - head;
		exp_rwsize = BUF_MAX_SZ - bpos;
		memmove(buf, buf + head, bpos);
	}

	if (rwsize == -1)
		return -1;

	/* write last block */
	if (block_sz != write(fd_delta, block_buf, block_sz))
		return -1;
	if ((rwsize + bpos) != write(fd_delta, buf, rwsize + bpos))
		return -1;

	/* fill up delta file header */
	delta_file_hdr->block_nr = block_nr;
	delta_file_hdr->last_block_sz = block_sz + rwsize + bpos;
	delta_file_hdr->last_block_offset = offset;

	return 0;
}

static int delta_block_cb(int fd_delta, uint64_t offset, uint32_t len, uint8_t embeded, char *buf)
{
	uint32_t rwsize;
	delta_block_entry delta_bentry;

	delta_bentry.offset = offset;
	delta_bentry.len = len;
	delta_bentry.embeded = embeded;
	rwsize = write(fd_delta, &delta_bentry, DELTA_BLOCK_ENTRY_SZ);
	if (rwsize == -1 || rwsize != DELTA_BLOCK_ENTRY_SZ)
		return -1;

	if (embeded) {
		rwsize = write(fd_delta, buf, len);
		if (rwsize == -1 || rwsize != len)
			return -1;
	}

	return 0;
}

typedef enum _block_cmp_status {
	BLOCK_DIFF = 0,	/* different */
	BLOCK_SAME,	/* md5 and csum are same */
	BLOCK_PART	/* csum is same and md5 is unknown */
} block_cmp_status;

/* file delta coding with sliding block chunking */
static int file_delta_sbc(hashtable *htab_md5, hashtable *htab_csum, int fd_src, int fd_delta, delta_file_header *delta_file_hdr)
{
        char buf[BUF_MAX_SZ] = {0};
        char win_buf[BLOCK_MAX_SZ + 1] = {0};
        char block_buf[BLOCK_MAX_SZ] = {0};
	char adler_pre_char;
        unsigned char md5_checksum[16 + 1] = {0};
	unsigned char csum[10 + 1] = {0};
        unsigned int bpos = 0;
        unsigned int slide_sz = 0;
        unsigned int rwsize = 0;
        unsigned int exp_rwsize = BUF_MAX_SZ;
        unsigned int head, tail;
        unsigned int hkey = 0;
        unsigned int bflag = 0;
	chunk_block_entry *chunk_bentry = NULL;
	uint64_t offset = DELTA_FILE_HEADER_SZ;
	uint32_t block_nr = 0;


        while(rwsize = read(fd_src, buf + bpos, exp_rwsize)) {
                /* last chunk */
                if ((rwsize + bpos + slide_sz) < BLOCK_SZ)
                        break;

                head = 0;
                tail = bpos + rwsize;
                while ((head + BLOCK_SZ) <= tail) {
                        memcpy(win_buf, buf + head, BLOCK_SZ);
			hkey = (slide_sz == 0) ? adler32_checksum(win_buf, BLOCK_SZ) :
				adler32_rolling_checksum(hkey, BLOCK_SZ, adler_pre_char, buf[head + BLOCK_SZ -1]);
			uint_2_str(hkey, csum);
			bflag = BLOCK_DIFF;

			chunk_bentry = (chunk_block_entry *)hash_value((void *)csum, htab_csum);
			if (chunk_bentry != NULL) {
				bflag = BLOCK_PART;
				md5(win_buf, BLOCK_SZ, md5_checksum);
				chunk_bentry = (chunk_block_entry *)hash_value((void *)md5_checksum, htab_md5);
				if (chunk_bentry != NULL) {
					/* process fragment */
					if (slide_sz > 0) {
						if (0 != delta_block_cb(fd_delta, offset, slide_sz, 1, block_buf))
							return -1;
						offset += (DELTA_BLOCK_ENTRY_SZ + slide_sz);
						block_nr++;
					}

					/* process fixed-size block */
					if (0 != delta_block_cb(fd_delta, chunk_bentry->offset, BLOCK_SZ, 0, win_buf))
						return -1;
					offset += DELTA_BLOCK_ENTRY_SZ;
					block_nr++;
					head += BLOCK_SZ;
					slide_sz = 0;
					bflag = BLOCK_SAME;
				}
			}

			if (bflag != BLOCK_SAME) {
				block_buf[slide_sz++] = buf[head++];
				/* process fixed-size block */
				if (slide_sz == BLOCK_SZ) {
					if (0 != delta_block_cb(fd_delta, offset, BLOCK_SZ, 1, block_buf))
						return -1;
					offset += (DELTA_BLOCK_ENTRY_SZ + BLOCK_SZ);
					slide_sz = 0;
					block_nr++;
				}
			}
			adler_pre_char = buf[head - 1];
                }

                /* read expected data from file to full up buf */
                bpos = tail - head;
                exp_rwsize = BUF_MAX_SZ - bpos;
		adler_pre_char = buf[head - 1];
                memmove(buf, buf + head, bpos);
        }

	if (rwsize == -1)
		return -1;

	/* write last block */
	if (slide_sz != write(fd_delta, block_buf, slide_sz))
		return -1;
	if ((rwsize + bpos) != write(fd_delta, buf, rwsize + bpos))
		return -1;

	/* fill up delta file header */
	delta_file_hdr->block_nr = block_nr;
	delta_file_hdr->last_block_sz = slide_sz + rwsize + bpos;
	delta_file_hdr->last_block_offset = offset;
	
	return 0;
}


/* file delta coding according to chunk algorithms */
int file_delta(char *src_filename, char *chunk_filename, char *delta_filename, int chunk_algo)
{
	int fd_src, fd_chunk, fd_delta;
	int rwsize;
	hashtable *htab_md5 = NULL;
	hashtable *htab_csum = NULL;
	chunk_file_header chunk_file_hdr;
	chunk_block_entry chunk_bentry;
	delta_file_header delta_file_hdr;
	int i, ret = 0;

	/* open files */
	fd_src = open(src_filename, O_RDONLY);
	if (fd_src == -1)
		return -1;

	fd_chunk = open(chunk_filename, O_RDONLY);
	if (fd_chunk == -1) {
		ret = -1;
		goto _FILE_DELTA_EXIT;
	}

	fd_delta = open(delta_filename, O_WRONLY|O_CREAT|O_TRUNC, 0644);
	if (fd_delta == -1) {
		ret = -1;
		goto _FILE_DELTA_EXIT;
	}

	/* build hashtable from chunk file */
	htab_md5 = create_hashtable(HASHTABLE_BUCKET_SZ);
	htab_csum = create_hashtable(HASHTABLE_BUCKET_SZ);
	if (htab_md5 == NULL || htab_csum == NULL) {
		ret = -1;
		goto _FILE_DELTA_EXIT;
	}

	rwsize = read(fd_chunk, &chunk_file_hdr, CHUNK_FILE_HEADER_SZ);
	if (rwsize == -1 || rwsize != CHUNK_FILE_HEADER_SZ) {
		ret = -1;
		goto _FILE_DELTA_EXIT;
	}

	for(i = 0; i < chunk_file_hdr.block_nr; i++) {
		rwsize = read(fd_chunk, &chunk_bentry, CHUNK_BLOCK_ENTRY_SZ);
		if (rwsize == -1 || rwsize != CHUNK_BLOCK_ENTRY_SZ) {
			ret = -1;
			goto _FILE_DELTA_EXIT;
		}
		hash_checkin(htab_md5, chunk_bentry.md5, chunk_bentry);
		hash_checkin(htab_csum, chunk_bentry.csum, chunk_bentry);
	}

	/* pre-write delte file header */
	delta_file_hdr.block_nr = 0;
	rwsize = write(fd_delta, &delta_file_hdr, DELTA_FILE_HEADER_SZ);
	if (rwsize == -1 || rwsize != DELTA_FILE_HEADER_SZ) {
		ret = -1;
		goto _FILE_DELTA_EXIT;
	}

	/* generate delta file according to chunk algorithms */
	switch(chunk_algo) {
	case CHUNK_FSP:
		ret = file_delta_fsp(htab_md5, htab_csum, fd_src, fd_delta, &delta_file_hdr);
		break;
	case CHUNK_CDC:
		ret = file_delta_cdc(htab_md5, htab_csum, fd_src, fd_delta, &delta_file_hdr);
		break;
	case CHUNK_SBC:
		ret = file_delta_sbc(htab_md5, htab_csum, fd_src, fd_delta, &delta_file_hdr);
		break;
	}

	/* write delta file header */
	if (ret == 0) {
		if (-1 == lseek(fd_delta, 0, SEEK_SET)) {
			ret = -1;
			goto _FILE_DELTA_EXIT;
		}
		rwsize = write(fd_delta, &delta_file_hdr, DELTA_FILE_HEADER_SZ);
		if (rwsize == -1 || rwsize != DELTA_FILE_HEADER_SZ)
			ret = -1;
	}

_FILE_DELTA_EXIT:
	close(fd_src);
	close(fd_chunk);
	close(fd_delta);
	unlink(chunk_filename);
	if (htab_md5 != NULL) hash_free(htab_md5);
	if (htab_csum != NULL) hash_free(htab_csum);

	return ret;
}

/* synchronize file with delta coding */
int file_sync(char *src_filename, char *delta_filename)
{
	int fd_src, fd_delta, fd_tmp;
	uint32_t rwsize;
	int i, ret = 0;
	delta_file_header delta_file_hdr;
	delta_block_entry delta_bentry;
	char buf[BLOCK_MAX_SZ] = {0};
	char tmpname[NAME_MAX_SZ] = {0};
	char template[] = "wsio_XXXXXX";

	fd_src = open(src_filename, O_RDONLY);
	if (fd_src == -1)
		return -1;
	
	fd_delta = open(delta_filename, O_RDONLY);
	if (fd_delta == -1) {
		ret = -1;
		goto _FILE_SYNC_EXIT;
	}

	sprintf(tmpname, ".%s_%d", mktemp(template), getpid());
	fd_tmp = open(tmpname, O_WRONLY|O_CREAT|O_TRUNC, 0644);
	if (fd_tmp == -1) {
		ret = -1;
		goto _FILE_SYNC_EXIT;
	}

	rwsize = read(fd_delta, &delta_file_hdr, DELTA_FILE_HEADER_SZ);
	if (rwsize == -1 || rwsize != DELTA_FILE_HEADER_SZ) {
		ret = -1;
		goto _FILE_SYNC_EXIT;
	}

	/* read and process delta block entry */
	for (i = 0; i < delta_file_hdr.block_nr; i++) {
		rwsize = read(fd_delta, &delta_bentry, DELTA_BLOCK_ENTRY_SZ);
		if (rwsize == -1 || rwsize != DELTA_BLOCK_ENTRY_SZ) {
			ret = -1;
			goto _FILE_SYNC_EXIT;
		}

		if (delta_bentry.embeded) {
			/* read from delta file */
			rwsize = read(fd_delta, buf, delta_bentry.len);
			if (rwsize == -1 || rwsize != delta_bentry.len) {
				ret = -1;
				goto _FILE_SYNC_EXIT;
			}
			rwsize = write(fd_tmp, buf, delta_bentry.len);
			if (rwsize == -1 || rwsize != delta_bentry.len) {
				ret = -1;
				goto _FILE_SYNC_EXIT;
			}
		} else {
			/* read from source file */
			if ( -1 == lseek(fd_src, delta_bentry.offset, SEEK_SET)) {
				ret = -1;
				goto _FILE_SYNC_EXIT;
			}
			rwsize = read(fd_src, buf, delta_bentry.len);
			if (rwsize == -1 || rwsize != delta_bentry.len) {
				ret = -1;
				goto _FILE_SYNC_EXIT;
			}
			rwsize = write(fd_tmp, buf, delta_bentry.len);
			if (rwsize == -1 || rwsize != delta_bentry.len) {
				ret = -1;
				goto _FILE_SYNC_EXIT;
			}
		}
	}

	/* write last block */
	if (-1 == lseek(fd_delta, delta_file_hdr.last_block_offset, SEEK_SET)) {
		ret = -1;
		goto _FILE_SYNC_EXIT;
	}
		
	rwsize = read(fd_delta, buf, delta_file_hdr.last_block_sz);
	if (rwsize == -1 || rwsize != delta_file_hdr.last_block_sz) { 
		ret = -1;
		goto _FILE_SYNC_EXIT;
	}

	rwsize = write(fd_tmp, buf, delta_file_hdr.last_block_sz);
	if (rwsize == -1 || rwsize != delta_file_hdr.last_block_sz) 
		ret = -1;
	

_FILE_SYNC_EXIT:
	close(fd_src);
	close(fd_delta);
	close(fd_tmp);
	unlink(delta_filename);
	if (ret == 0)
		ret = rename(tmpname, src_filename);

	return ret;
}
