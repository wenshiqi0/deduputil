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

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <signal.h>
#include <unistd.h>
#include <getopt.h>
#include <fcntl.h>
#include <utime.h>
#include <dirent.h>
#include <errno.h>
#include <zlib.h>
#include "md5.h"
#include "hash.h"
#include "bighashtable.h"
#include "libz.h"
#include "rabinhash32.h"
#include "dedup.h"
#include "listdb.h"
#include "hashdb.h"

/* unique block number in package */
static unsigned int g_unique_block_nr = 0;

/* regular file number in package */
static unsigned int g_regular_file_nr = 0;

/* offset in logic block data */
static unsigned long long g_ldata_offset = 0;

/* block length */
static unsigned int g_block_size = BLOCK_SIZE;

/* hashtable bucket number */
static unsigned int g_htab_bucket_nr = BUCKET_SIZE;

/* hashtable for pathnames */
static hashtable *g_htable = NULL;

/* hashtable for SB file chunking */
static hashtable *g_sb_htable_crc = NULL;

/* compression flag */
static unsigned int g_bz = 0;

/* deduplication temporary files */
static char tmp_file[PATH_MAX_LEN] = {0};
static char ldata_file[PATH_MAX_LEN] = {0};
static char bdata_file[PATH_MAX_LEN] = {0};
static char mdata_file[PATH_MAX_LEN] = {0};

/* chunking algorithms */
static enum DEDUP_CHUNK_ALGORITHMS g_chunk_algo = DEDUP_CHUNK_CDC;

/* CDC chunking hash function */
static unsigned int (*g_cdc_chunk_hashfunc)(char *str) = ELF_hash;
static unsigned int g_rolling_hash = 1; /* default as adler_hash */
static cdc_chunk_hashfunc CDC_CHUNK_HASHFUNC[] =
{
	{"simple_hash", simple_hash},
	{"RS_hash", RS_hash},
	{"JS_hash", JS_hash},
	{"PJW_hash", PJW_hash},
	{"ELF_hash", ELF_hash},
	{"BKDR_hash", BKDR_hash},
	{"SDBM_hash", SDBM_hash},
	{"DJB_hash", DJB_hash},
	{"AP_hash", AP_hash},
	{"CRC_hash", CRC_hash},
	{"rabin_hash", rabin_hash}
};

/*
 * set hash function for cdc chunking, alder_hash as default
 */
static int set_cdc_chunk_hashfunc(char *hash_func_name)
{
	int i;
	int nr = sizeof(CDC_CHUNK_HASHFUNC) / sizeof(CDC_CHUNK_HASHFUNC[0]);

	if (0 == strcmp(hash_func_name, DEDUP_ROLLING_HASH))
	{
		g_rolling_hash = 1;
		return 0;
	}

	for (i = 0; i < nr; ++i)
	{
		if (0 == strcmp(hash_func_name, CDC_CHUNK_HASHFUNC[i].hashfunc_name))
		{
			g_cdc_chunk_hashfunc = CDC_CHUNK_HASHFUNC[i].hashfunc;
			g_rolling_hash = 0;
			return 0;
		}
	}

	return -1;
}

/*
 * check whether item exists in hashtable
 */
static inline int hash_exist(hashtable *htable, char *str)
{
	return (NULL == hash_value((void *)str, htable)) ? 0 : 1;
}

/*
 * insert item into hashtable
 */
static inline void hash_checkin(hashtable *htable, char *str)
{
	hash_insert(str, (void *)"1", 1, htable);
}

/*
 * print hex md5 checksum
 */
static void show_md5(unsigned char md5_checksum[16])
{
	int i;
	for (i = 0; i < 16; i++)
	{
        	fprintf(stderr, "%02x", md5_checksum[i]);
	}
}

/*
 * transfer md5 into char *, strlen(md5_checksum) >= 32
 */
static void md5_2_str(unsigned char *md5_checksum)
{
	static char *hex = "0123456789abcdef";
	char md5_str[33] = {0};
	int i, j = 0;

	for (i = 0; i < 16; i++) 
	{
		md5_str[j++] = hex[(0xf0 & md5_checksum[i]) >> 4];
		md5_str[j++] = hex[0x0f & md5_checksum[i]];
	}
	md5_str[j] = '\0';
	memcpy(md5_checksum, md5_str, 33);
}

/*
 * print dedup package header
 */
static void show_pkg_header(dedup_package_header dedup_pkg_hdr)
{
        fprintf(stderr, "block_size = %d\n", dedup_pkg_hdr.block_size);
        fprintf(stderr, "block_num = %d\n", dedup_pkg_hdr.block_num);
	fprintf(stderr, "blockid_size = %d\n", dedup_pkg_hdr.blockid_size);
	fprintf(stderr, "magic_num = 0x%x\n", dedup_pkg_hdr.magic_num);
	fprintf(stderr, "block_z = %d\n", dedup_pkg_hdr.block_z);
	fprintf(stderr, "file_num = %d\n", dedup_pkg_hdr.file_num);
	fprintf(stderr, "ldata_offset = %lld\n", dedup_pkg_hdr.ldata_offset);
	fprintf(stderr, "metadata_offset = %lld\n", dedup_pkg_hdr.metadata_offset);
}

/*
 * clean temporary files after deduped
 */
static void dedup_clean()
{
	pid_t pid = getpid();
	sprintf(tmp_file, ".dedup_%s_%d\0", FILENAME_MAGIC_NUM, pid);
	unlink(tmp_file);
	unlink(ldata_file);
	unlink(bdata_file);
	unlink(mdata_file);
}

/*
 * signals process 
 */
static void dedup_sigroutine(int signo)
{
	switch(signo)
	{
	case SIGQUIT:
	case SIGILL:
	case SIGFPE:
	case SIGABRT:
	case SIGSEGV:
	case SIGTERM:
	case SIGINT:
		dedup_clean();
		exit(-1);
	}
}

/*
 * dedup initialize
 */
static void dedup_init()
{
	pid_t pid = getpid();
	sprintf(tmp_file, ".dedup_%s_%d\0", FILENAME_MAGIC_NUM, pid);
	sprintf(ldata_file, ".ldata_%s_%d\0", FILENAME_MAGIC_NUM, pid);
	sprintf(bdata_file, ".bdata_%s_%d\0", FILENAME_MAGIC_NUM, pid);
	sprintf(mdata_file, ".mdata_%s_%d\0", FILENAME_MAGIC_NUM, pid);
	signal(SIGQUIT, dedup_sigroutine);
	signal(SIGILL, dedup_sigroutine);
	signal(SIGFPE, dedup_sigroutine);
	signal(SIGABRT, dedup_sigroutine);
	signal(SIGSEGV, dedup_sigroutine);
	signal(SIGTERM, dedup_sigroutine);
	signal(SIGINT, dedup_sigroutine);
}

/*
 * blocks compare bit by bit
 */
static int block_cmp(char *buf, int fd_ldata, int fd_bdata, unsigned int bindex, unsigned int len)
{
	int i, ret = 0;
	char *block_buf = NULL;
	dedup_logic_block_entry dedup_lblock_entry;

	/* read logic block information */
	if (-1 == lseek(fd_ldata, bindex * DEDUP_LOGIC_BLOCK_ENTRY_SIZE, SEEK_SET))
	{
		perror("lseek in block_cmp");
		exit(errno);
	}
	if (DEDUP_LOGIC_BLOCK_ENTRY_SIZE != read(fd_ldata, &dedup_lblock_entry, DEDUP_LOGIC_BLOCK_ENTRY_SIZE))
	{
		perror("read dedup_lblock_entry in block_cmp");
		exit(errno);
	}
	if (dedup_lblock_entry.block_len != len)
	{
		ret = 1;
		goto _BLOCK_CMP_EXIT;
	}

	/* read phsyical block */
	if (-1 == lseek(fd_bdata, dedup_lblock_entry.block_offset + DEDUP_PKGHDR_SIZE, SEEK_SET))
	{
		perror("lseek in block_cmp");
		exit(errno);
	}
	block_buf = (char *)malloc(len);
	if (NULL == block_buf)
	{
		perror("malloc in block_cmp");
		exit(errno);
	}
	if (len != read(fd_bdata, block_buf, len))
	{
		perror("read block_buf in block_cmp");
		exit(errno);
	}

	/* block compare */
	for (i = 0; i < len; i++)
	{
		if (buf[i] != block_buf[i])
		{
			ret = 1;
			break;
		}
	}
	
_BLOCK_CMP_EXIT:
	if (block_buf) free(block_buf);
	if ( -1 == lseek(fd_bdata, 0, SEEK_END) || -1 == lseek(fd_ldata, 0, SEEK_END))
	{
		perror("lseek in block_cmp");
		exit(errno);
	}

	return ret;
}

/*
 * transfer unsigned integer into string
 */
static int uint_2_str(unsigned int x, char *str)
{
	int i = 0;
	unsigned int xx = x, t;

	while (xx)
	{
		str[i++] = (xx % 10) + '0';
		xx = xx / 10;
	}
	str[i] = '\0';

	xx = i;
	for (i = 0; i < xx/2; i++)
	{
		t = str[i];
		str[i] = str[xx - i -1];
		str[xx - i -1] = t;
	}

	return xx;
}

/*
 * chunking block dedup process: if not duplicated, store the block and label it's index. 
 * 	otherwise, check out the block index.
 * NOTE: no md5 collsion problem with block comparing, but lose some performace
 * hashtable entry format: (md5_key, block_id list)
 * +--------------------------------+
 * | id num | id1 | id2 | ... | idn |
 * +--------------------------------+
 */
static int dedup_regfile_block_process(char *block_buf, unsigned int block_len, char *md5_checksum, int fd_ldata, 
	int fd_bdata, unsigned int *pos, unsigned int *block_num, block_id_t **metadata, hashtable *htable)
{
	dedup_logic_block_entry dedup_lblock_entry;
	unsigned int cbindex;
	int bflag = 0;
	unsigned int *bindex = (block_id_t *)hash_value((void *)md5_checksum, htable);

	/* the block exists */
	if (bindex != NULL)
	{
		int i;
		for (i = 0; i < *bindex; i++)
		{
			if (0 == block_cmp(block_buf, fd_ldata, fd_bdata, *(bindex + i + 1), block_len))
			{
				cbindex = *(bindex + i + 1);
				bflag = 1;
				break;
			}
		}
	}

	/* insert hash entry, write logic block into ldata, and write unique block into bdata*/
	if (bindex == NULL || (bindex != NULL && bflag == 0))
	{
		if (bindex == NULL)
			bflag = 1;

		bindex = (bflag) ? (block_id_t *)malloc(BLOCK_ID_SIZE * 2) :
			(block_id_t *)realloc(bindex, BLOCK_ID_SIZE * ((*bindex) + 2));
		if (NULL == bindex)
		{
			perror("malloc/realloc in dedup_regfile_block_process");
			return errno;
		}

		*bindex = (bflag) ? 1 : (*bindex) + 1;
		*(bindex + *bindex) = g_unique_block_nr;
		cbindex = g_unique_block_nr;
		dedup_lblock_entry.block_offset = g_ldata_offset;
		dedup_lblock_entry.block_len = block_len;
		hash_insert(md5_checksum, (void *)bindex, (((*bindex) + 1) * BLOCK_ID_SIZE), htable);
		if (bindex) free(bindex);
		write(fd_ldata, &dedup_lblock_entry, DEDUP_LOGIC_BLOCK_ENTRY_SIZE);
		write(fd_bdata, block_buf, block_len);
		g_unique_block_nr++;
		g_ldata_offset += block_len;
	}

	/* if metadata is not enough, realloc it */
	if ((*pos + 1) >= (*block_num))
	{
		(*metadata) = realloc(*metadata, BLOCK_ID_SIZE * (*block_num + BLOCK_ID_ALLOC_INC));
		if (NULL == (*metadata))
		{
			perror("realloc in dedup_regfile");
			return errno;
		}
		(*block_num) += BLOCK_ID_ALLOC_INC;
	}

	(*metadata)[*pos] = cbindex;
	(*pos)++;

	return 0;
}

/*
 * content-defined chunking:
 * 1. BLOCK_MIN_SIZE <= block_size <= BLOCK_MAX_SIZE
 * 2. hash(block) % d == r
 */
static int file_chunk_cdc(int fd, int fd_ldata, int fd_bdata, unsigned int *pos, unsigned int *block_num,
	block_id_t **metadata, hashtable *htable, char *last_block_buf, unsigned int *last_block_len)
{
	char buf[BUF_MAX_SIZE] = {0};
	char buf_bz[BUF_MAX_SIZE] = {0};
	char block_buf[BLOCK_MAX_SIZE * 2] = {0};
	char win_buf[BLOCK_WIN_SIZE + 1] = {0};
	char md5_str[33] = {0};
	char adler_pre_char;
	unsigned char md5_checksum[32 + 1] = {0};
	unsigned int bpos = 0;
	unsigned int rwsize = 0, bzsize = 0;
	unsigned int exp_rwsize = BUF_MAX_SIZE;
	unsigned int head, tail;
	unsigned int block_sz = 0, old_block_sz = 0;
	unsigned int hkey = 0;
	int ret = 0;

	while(rwsize = read(fd, buf + bpos, exp_rwsize))
	{
		/* last chunk */
		if ((rwsize + bpos + block_sz) < BLOCK_MIN_SIZE)
			break;

		head = 0;
		tail = bpos + rwsize;
		/* avoid unnecessary computation and comparsion */
		if (block_sz < (BLOCK_MIN_SIZE - BLOCK_WIN_SIZE))
		{
			old_block_sz = block_sz;
			block_sz = ((block_sz + tail - head) > (BLOCK_MIN_SIZE - BLOCK_WIN_SIZE)) ? 
					BLOCK_MIN_SIZE - BLOCK_WIN_SIZE : block_sz + tail -head;  
			memcpy(block_buf + old_block_sz, buf + head, block_sz - old_block_sz);
			head += (block_sz - old_block_sz);
		}

		while ((head + BLOCK_WIN_SIZE) <= tail)
		{
			memcpy(win_buf, buf + head, BLOCK_WIN_SIZE);
			/*
			 * Firstly, i think rabinhash is the best. However, it's performance is very bad.
			 * After some testing, i found ELF_hash is better both on performance and dedup rate.
			 * So, EFL_hash is default. Now, adler_hash as default.
			 */
			if (g_rolling_hash)
			{
				hkey = (block_sz == (BLOCK_MIN_SIZE - BLOCK_WIN_SIZE)) ? adler32_checksum(win_buf, BLOCK_WIN_SIZE) :
					adler32_rolling_checksum(hkey, BLOCK_WIN_SIZE, adler_pre_char, buf[head+BLOCK_WIN_SIZE-1]);
			} 
			else 
				hkey = g_cdc_chunk_hashfunc(win_buf);

			/* get a normal chunk */
			if ((hkey % g_block_size) == CHUNK_CDC_R)
			{
				memcpy(block_buf + block_sz, buf + head, BLOCK_WIN_SIZE);
				head += BLOCK_WIN_SIZE;
				block_sz += BLOCK_WIN_SIZE;
				if (block_sz >= BLOCK_MIN_SIZE)
				{
					/* compress block is -z flag is given */
					if (g_bz) 
					{
						bzsize = BUF_MAX_SIZE;
						if (Z_OK != zlib_compress_block(block_buf, block_sz, buf_bz, &bzsize))
						{
							ret = -1;
							goto _FILE_CHUNK_CDC_EXIT;
						}
						memcpy(block_buf, buf_bz, bzsize);
						block_sz = bzsize;
					}

					md5(block_buf, block_sz, md5_checksum);
					md5_2_str(md5_checksum);
					if (0 != (ret = dedup_regfile_block_process(block_buf, block_sz, 
						md5_checksum, fd_ldata, fd_bdata, pos, block_num, metadata, htable)))
					{
						perror("dedup_reggile_block_process in file_chunk_cdc");
						goto _FILE_CHUNK_CDC_EXIT;
					}
					block_sz = 0;
				}
			}
			else 
			{
				block_buf[block_sz++] = buf[head++];
				/* get an abnormal chunk */
				if (block_sz >= BLOCK_MAX_SIZE)
				{
					/* compress block if -z flag is given */
					if (g_bz)
					{
						bzsize = BUF_MAX_SIZE;
						if (Z_OK != zlib_compress_block(block_buf, block_sz, buf_bz, &bzsize))
						{
							ret = -1;
							goto _FILE_CHUNK_CDC_EXIT;
						}
						memcpy(block_buf, buf_bz, bzsize);
						block_sz = bzsize;
					}

					md5(block_buf, block_sz, md5_checksum);
					md5_2_str(md5_checksum);
					if (0 != (ret = dedup_regfile_block_process(block_buf, block_sz, 
						md5_checksum, fd_ldata, fd_bdata, pos, block_num, metadata, htable)))
					{
						perror("dedup_reggile_block_process in file_chunk_cdc");
						goto _FILE_CHUNK_CDC_EXIT;
					}
					block_sz = 0;
				}
			}

			/* avoid unnecessary computation and comparsion */
			if (block_sz == 0)
			{
				block_sz = ((tail - head) > (BLOCK_MIN_SIZE - BLOCK_WIN_SIZE)) ? 
					BLOCK_MIN_SIZE - BLOCK_WIN_SIZE : tail - head;
				memcpy(block_buf, buf + head, block_sz);
				head = ((tail - head) > (BLOCK_MIN_SIZE - BLOCK_WIN_SIZE)) ? 
					head + (BLOCK_MIN_SIZE - BLOCK_WIN_SIZE) : tail;
			}

			adler_pre_char = buf[head -1];
		}

		/* read expected data from file to full up buf */
		bpos = tail - head;
		exp_rwsize = BUF_MAX_SIZE - bpos;
		adler_pre_char = buf[head -1];
		memmove(buf, buf + head, bpos);
	}
	/* last chunk */
	*last_block_len = ((rwsize + bpos + block_sz) >= 0) ? rwsize + bpos + block_sz : 0;
	if (*last_block_len > 0)
	{
		memcpy(last_block_buf, block_buf, block_sz);
		memcpy(last_block_buf + block_sz, buf, rwsize + bpos);
	}

_FILE_CHUNK_CDC_EXIT:
	return ret;
}

/*
 * slideing block chunking, performance is a big issue due to too many hash lookup.
 */
static int file_chunk_sb(int fd, int fd_ldata, int fd_bdata, unsigned int *pos, unsigned int *block_num,
         block_id_t **metadata, hashtable *htable, char *last_block_buf, unsigned int *last_block_len)
{
	char buf[BUF_MAX_SIZE] = {0};
	char buf_bz[BUF_MAX_SIZE] = {0};
	char win_buf[BLOCK_MAX_SIZE * 2] = {0};
	char block_buf[BLOCK_MAX_SIZE * 2] = {0};
	char adler_pre_char;
	unsigned char md5_checksum[32 + 1] = {0};
	unsigned char md5_checksum1[32 + 1] = {0};
	unsigned char crc_checksum[16] = {0};
	unsigned int bpos = 0;
	unsigned int slide_sz = 0;
	unsigned int rwsize = 0, bzsize = 0, bzsize_f = 0;
	unsigned int exp_rwsize = BUF_MAX_SIZE;
	unsigned int head, tail;
	unsigned int hkey = 0;
	unsigned int bflag = 0;
	int ret = 0;

	while(rwsize = read(fd, buf + bpos, exp_rwsize))
	{
		/* last chunk */
		if ((rwsize + bpos + slide_sz) < g_block_size)
			break;

		head = 0;
		tail = bpos + rwsize;
		while ((head + g_block_size) <= tail)
		{
			memcpy(win_buf, buf + head, g_block_size);
			hkey = (slide_sz == 0) ? adler32_checksum(win_buf, g_block_size) : 
				adler32_rolling_checksum(hkey, g_block_size, adler_pre_char, buf[head+g_block_size-1]);
			uint_2_str(hkey, crc_checksum);

			/* bflag: 0, both CRC and MD5 are not idenitical
			          1, both CRC and MD5 are identical
				  2, CRC is identical and MD5 is not
			 */
			bflag = 0;

			/* this block maybe is duplicate */
			bzsize = g_block_size;
			if (hash_exist(g_sb_htable_crc, crc_checksum))
			{	
				bflag = 2;
				/* compress block if -z flag is given */
				if (g_bz) 
				{
					bzsize = BUF_MAX_SIZE;
					if (Z_OK != zlib_compress_block(win_buf, g_block_size, buf_bz, &bzsize))
					{
						ret = -1;
						goto _FILE_CHUNK_SB_EXIT;
					}
					memcpy(win_buf, buf_bz, bzsize);
				}

				md5(win_buf, bzsize, md5_checksum);
				md5_2_str(md5_checksum);
				if (hash_exist(htable, md5_checksum))
				{
					/* insert fragment */
					if (slide_sz != 0)
					{
						/* compress block if -z flag is given */
						if (g_bz)
						{
							bzsize_f = BUF_MAX_SIZE;
							if (Z_OK != zlib_compress_block(block_buf, slide_sz, buf_bz, &bzsize_f))
							{
								ret = -1;
								goto _FILE_CHUNK_SB_EXIT;
							}
							memcpy(block_buf, buf_bz, bzsize_f);
							slide_sz = bzsize_f;
						}

						md5(block_buf, slide_sz, md5_checksum1);
						md5_2_str(md5_checksum1);
						if (0 != (ret = dedup_regfile_block_process(block_buf, slide_sz, md5_checksum1, 
							fd_ldata, fd_bdata, pos, block_num, metadata, htable)))
						{
							perror("dedup_regfile_block_process in file_chunk_sb");
							goto _FILE_CHUNK_SB_EXIT;
						}
					}

					/* insert fixed-size block */
					if (0 != (ret = dedup_regfile_block_process(win_buf, bzsize, md5_checksum, 
						fd_ldata, fd_bdata, pos, block_num, metadata, htable)))
					{
						perror("dedup_regfile_block_process in file_chunk_sb");
						goto _FILE_CHUNK_SB_EXIT;
					}

					head += g_block_size;
					slide_sz = 0;
					bflag = 1;
				}
			}

			/* this block is not duplicate */
			if (bflag != 1)
			{
				block_buf[slide_sz++] = buf[head++];
				if (slide_sz == g_block_size)
				{
					bzsize = g_block_size;

					/* calculate checksum and check in */
					hkey = adler32_checksum(block_buf, bzsize);
					uint_2_str(hkey, crc_checksum);
					hash_checkin(g_sb_htable_crc, crc_checksum);

					/* compress block if -z flag is given */
					if (g_bz)
					{
						bzsize = BUF_MAX_SIZE;
						if (Z_OK != zlib_compress_block(block_buf, g_block_size, buf_bz, &bzsize))
						{
							ret = -1;
							goto _FILE_CHUNK_SB_EXIT;
						}
						memcpy(block_buf, buf_bz, bzsize);
					}
					md5(block_buf, bzsize, md5_checksum);
					md5_2_str(md5_checksum);
					
					if (0 != (ret = dedup_regfile_block_process(block_buf, bzsize, md5_checksum, 
						fd_ldata, fd_bdata, pos, block_num, metadata, htable)))
					{
						perror("dedup_regfile_block_process in file_chunk_sb");
						goto _FILE_CHUNK_SB_EXIT;
					}

					slide_sz = 0;
				}
			}

			adler_pre_char = buf[head - 1];
		}

		/* read expected data from file to full up buf */
		bpos = tail - head;
		exp_rwsize = BUF_MAX_SIZE - bpos;
		adler_pre_char = buf[head - 1];
		memmove(buf, buf + head, bpos);
	}
	/* last chunk */
	*last_block_len = ((rwsize + bpos + slide_sz) > 0) ? rwsize + bpos + slide_sz : 0;
	if (*last_block_len > 0)
	{
		memcpy(last_block_buf, block_buf, slide_sz);
		memcpy(last_block_buf + slide_sz, buf, rwsize + bpos);
	}

_FILE_CHUNK_SB_EXIT:
	lseek(fd, 0, SEEK_SET);
	return ret;
}

/*
 * fixed-sized file chunking 
 */
static int file_chunk_fsp(int fd, int fd_ldata, int fd_bdata, unsigned int *pos, unsigned int *block_num, 
	block_id_t **metadata, hashtable *htable, char *last_block_buf, unsigned int *last_block_len)
{
	int ret = 0;
	unsigned int rwsize, bzsize;
	unsigned char md5_checksum[32 + 1] = {0};
	char *buf = NULL, *buf_bz = NULL;

	buf = (char *)malloc(g_block_size * 2);
	buf_bz = (char *)malloc(g_block_size * 2);
	if (buf == NULL || buf_bz == NULL)
	{
		perror("malloc in file_chunk_fsp");
		return errno;
	}

	while (rwsize = read(fd, buf, g_block_size))
        {
                /* if the last block */
                if (rwsize != g_block_size)
                        break;

		/* compress block if -z flag is given */
		if (g_bz) {
			bzsize = g_block_size * 2;
			if (Z_OK != zlib_compress_block(buf, rwsize, buf_bz, &bzsize)) {
				ret = -1;
				goto _FILE_CHUNK_FSP_EXIT;
			}
			memcpy(buf, buf_bz, bzsize);
			rwsize = bzsize;
		}
                /* calculate md5 */
                md5(buf, rwsize, md5_checksum);
		md5_2_str(md5_checksum);
		if (0 != (ret = dedup_regfile_block_process(buf, rwsize, md5_checksum, fd_ldata, 
			fd_bdata, pos, block_num, metadata, htable)))
		{
			perror("dedup_regfile_block_process in file_chunk_fsp");
			goto _FILE_CHUNK_FSP_EXIT;
		}
	}
	*last_block_len = (rwsize > 0) ? rwsize : 0;
	if ((*last_block_len)) memcpy(last_block_buf, buf, *last_block_len);

_FILE_CHUNK_FSP_EXIT:
	if (buf) free(buf);
	return ret;
}

/*
 * dedup regular file according to chunking algorithms
 */ 
static int dedup_regfile(char *fullpath, int prepos, int fd_ldata, int fd_bdata, int fd_mdata, 
	hashtable *htable, int verbose)
{
	int fd, ret = 0;
	char *last_block_buf = NULL;
	unsigned int last_block_len, pos;
	block_id_t *metadata = NULL;
	unsigned int block_num = 0;
	struct stat statbuf;
	dedup_entry_header dedup_entry_hdr;


	/* check if the filename already exists */
	if (hash_exist(g_htable, fullpath))
	{
		if (verbose) fprintf(stderr, "Warning: %s already exists in package\n", fullpath);
		return 0;
	} 

	if (-1 == (fd = open(fullpath, O_RDONLY)))
	{
		perror("open regular file in dedup_regfile");
		return errno;
	}

	if (-1 == fstat(fd, &statbuf))
	{
		perror("fstat in dedup_regfile");
		ret = errno;
		goto _DEDUP_REGFILE_EXIT;
	}
	block_num = statbuf.st_size / g_block_size;

	metadata = (unsigned int *)malloc(BLOCK_ID_SIZE * block_num);
	if (metadata == NULL)
	{
		perror("malloc metadata in dedup_regfile");
		ret = errno;
		goto _DEDUP_REGFILE_EXIT;
	}

	last_block_buf = (char *)malloc(BUF_MAX_SIZE);
	if (last_block_buf == NULL)
	{
		perror("malloc buf in dedup_regfile");
		ret = errno;
		goto _DEDUP_REGFILE_EXIT;
	}

	/* file chunking and block deduplication */
	pos = 0;
	switch (g_chunk_algo)
	{
	case DEDUP_CHUNK_FSP:
		ret = file_chunk_fsp(fd, fd_ldata, fd_bdata, &pos, &block_num, &metadata, htable, last_block_buf, &last_block_len);
		break;
	case DEDUP_CHUNK_CDC:
		ret = file_chunk_cdc(fd, fd_ldata, fd_bdata, &pos, &block_num, &metadata, htable, last_block_buf, &last_block_len);
		break;
	case DEDUP_CHUNK_SB:
		ret = file_chunk_sb(fd, fd_ldata, fd_bdata, &pos, &block_num, &metadata, htable, last_block_buf, &last_block_len);
		break;
	}
	if (ret != 0)
	{
		perror("file_chunk in dedup_regfile");
		goto _DEDUP_REGFILE_EXIT;
	}

	/* write metadata into mdata */
	dedup_entry_hdr.path_len = strlen(fullpath) - prepos;
	dedup_entry_hdr.block_num = pos;
	dedup_entry_hdr.entry_size = BLOCK_ID_SIZE;
	dedup_entry_hdr.last_block_size = last_block_len;
	dedup_entry_hdr.mode = statbuf.st_mode;
	dedup_entry_hdr.atime = statbuf.st_atime;
	dedup_entry_hdr.mtime = statbuf.st_mtime;
	dedup_entry_hdr.old_size = statbuf.st_blocks * 512;

	write(fd_mdata, &dedup_entry_hdr, sizeof(dedup_entry_header));
	write(fd_mdata, fullpath + prepos, dedup_entry_hdr.path_len);
	write(fd_mdata, metadata, BLOCK_ID_SIZE * pos);
	write(fd_mdata, last_block_buf, last_block_len);

	g_regular_file_nr++;
	hash_checkin(g_htable, fullpath);

_DEDUP_REGFILE_EXIT:
	close(fd);
	if (metadata != NULL) free(metadata);
	if (last_block_buf != NULL) free(last_block_buf);

	return ret;
}

/*
 * dedup whole directory recursively, but only works on regular files
 */
static int dedup_dir(char *fullpath, int prepos, int fd_ldata, int fd_bdata, int fd_mdata, hashtable *htable, int verbose)
{
	DIR *dp;
	struct dirent *dirp;
	struct stat statbuf;
	char subpath[PATH_MAX_LEN] = {0};
	int ret;

	if (NULL == (dp = opendir(fullpath)))
	{
		return errno;
	}

	while ((dirp = readdir(dp)) != NULL)
	{
		if (strcmp(dirp->d_name, ".") == 0 || strcmp(dirp->d_name, "..") == 0)
			continue;

		sprintf(subpath, "%s/%s", fullpath, dirp->d_name);
		if (0 == lstat(subpath, &statbuf))
		{
			if (verbose)
				fprintf(stderr, "%s\n", subpath);

			if (S_ISDIR(statbuf.st_mode)) {
				dedup_dir(subpath, prepos, fd_ldata, fd_bdata, fd_mdata, htable, verbose);
			} else { /* if (S_ISREG(statbuf.st_mode) || S_ISLINK(statbuf.st_mode)) */
				ret = dedup_regfile(subpath, prepos, fd_ldata, fd_bdata, fd_mdata, htable,verbose);
				if (ret != 0)
					exit(ret);
			}
		}
	}
	closedir(dp);

	return 0;
}

/*
 * preparation for dedup append: rebuild hashtable, metadata and other necessary informations
 */
static int dedup_append_prepare(int fd_pkg, int fd_ldata, int fd_bdata, int fd_mdata, 
	dedup_package_header *dedup_pkg_hdr, hashtable *htable)
{
	int ret = 0, i;
	unsigned int rwsize = 0, bzsize = 0;
	char *buf = NULL;
	char buf_bz[BUF_MAX_SIZE] = {0};
	unsigned char md5_checksum[32 + 1] = {0};
	unsigned char crc_checksum[16] = {0};
	unsigned int *bindex = NULL;
	unsigned int hkey = 0;
	dedup_entry_header dedup_entry_hdr;
	dedup_logic_block_entry dedup_lblock_entry;
	unsigned long long offset;
	char pathname[PATH_MAX_LEN] = {0};

	if (read(fd_pkg, dedup_pkg_hdr, DEDUP_PKGHDR_SIZE) != DEDUP_PKGHDR_SIZE)
	{
		perror("read dedup_package_header");
		return errno;
	}

	if (dedup_pkg_hdr->magic_num != DEDUP_MAGIC_NUM)
	{
		fprintf(stderr, "magic number is error, maybe this file is not a dedup package.\n");
		ret = -1;
		goto _DEDUP_APPEND_PREPARE_EXIT;
	}

	/* get package header info */
	g_bz = (g_bz) ? g_bz : dedup_pkg_hdr->block_z;
	g_unique_block_nr = dedup_pkg_hdr->block_num;
	g_regular_file_nr = dedup_pkg_hdr->file_num;
	g_block_size = 	dedup_pkg_hdr->block_size;
	g_ldata_offset = dedup_pkg_hdr->ldata_offset - DEDUP_PKGHDR_SIZE;

	/* get bdata and rebuild hashtable */
	buf = (char *)malloc(BUF_MAX_SIZE);
	if (buf == NULL)
	{
		ret = errno;
		goto _DEDUP_APPEND_PREPARE_EXIT;
	}

	for(i = 0; i < dedup_pkg_hdr->block_num; i++)
	{
		/* get logic block */
		if (-1 == lseek(fd_pkg, dedup_pkg_hdr->ldata_offset + DEDUP_LOGIC_BLOCK_ENTRY_SIZE * i, SEEK_SET))
		{
			perror("lseek in dedup_append_prepare");
			ret = errno;
			goto _DEDUP_APPEND_PREPARE_EXIT;
		}
		rwsize = read(fd_pkg, &dedup_lblock_entry, DEDUP_LOGIC_BLOCK_ENTRY_SIZE);
		if (rwsize != DEDUP_LOGIC_BLOCK_ENTRY_SIZE)
		{
			perror("read in dedup_append_prepare");
			ret = errno;
			goto _DEDUP_APPEND_PREPARE_EXIT;
		}
		write(fd_ldata, &dedup_lblock_entry, DEDUP_LOGIC_BLOCK_ENTRY_SIZE);

		/* get physical unique block */
		if (-1 == lseek(fd_pkg, DEDUP_PKGHDR_SIZE + dedup_lblock_entry.block_offset, SEEK_SET))
		{
			perror("lseek in dedup_append_prepare");
			ret = errno;
			goto _DEDUP_APPEND_PREPARE_EXIT;
		}
		rwsize = read(fd_pkg, buf, dedup_lblock_entry.block_len);
		if (rwsize != dedup_lblock_entry.block_len)
		{
			perror("read in dedup_append_preapare");
			ret = errno;
			goto _DEDUP_APPEND_PREPARE_EXIT;
		}
		write(fd_bdata, buf, rwsize);

		/* 
		  calculate md5 of every unique block and insert into hashtable 
		  hashtable entry format: (md5_key, block_id list)
		  +--------------------------------+
		  | id num | id1 | id2 | ... | idn |
		  +--------------------------------+
		 */
		md5(buf, rwsize, md5_checksum);
		md5_2_str(md5_checksum);
                int bflag = 0;
                unsigned int *bindex = (block_id_t *)hash_value((void *)md5_checksum, htable);
		bflag = (bindex == NULL) ? 1 : 0;
		bindex = (bflag) ? (block_id_t *)malloc(BLOCK_ID_SIZE * 2) :
                                (block_id_t *)realloc(bindex, BLOCK_ID_SIZE * ((*bindex) + 2));
                if (NULL == bindex)
                {
			perror("malloc/realloc in dedup_append_prepare");
			ret = errno;
			goto _DEDUP_APPEND_PREPARE_EXIT;
                }

                *bindex = (bflag) ? 1 : (*bindex) + 1;
                *(bindex + *bindex) = i;
                hash_insert(md5_checksum, (void *)bindex, (((*bindex) + 1) * BLOCK_ID_SIZE), htable);
		if (bindex) free(bindex);

		/* calculate alder_checksum if g_chunk_algo == DEDUP_CHUNK_SB */
		if (g_chunk_algo == DEDUP_CHUNK_SB)
		{
			/* decompress block if compressed */
			if (g_bz)
			{
				bzsize = BUF_MAX_SIZE;
				if (Z_OK != zlib_decompress_block(buf, rwsize, buf_bz, &bzsize))
				{
					ret = -1;
					goto _DEDUP_APPEND_PREPARE_EXIT;
				}
				memcpy(buf, buf_bz, bzsize);
				rwsize = bzsize;
			}

			hkey = adler32_checksum(buf, rwsize);
			uint_2_str(hkey, crc_checksum);
			hash_checkin(g_sb_htable_crc, crc_checksum);
		}
	}
	
	/* get file metadata */
	offset = dedup_pkg_hdr->metadata_offset;
        for (i = 0; i < dedup_pkg_hdr->file_num; ++i)
        {
                if (lseek(fd_pkg, offset, SEEK_SET) == -1)
                {
			perror("lseek in dedup_append_prepare");
                        ret = errno;
                        goto _DEDUP_APPEND_PREPARE_EXIT;
                }

                if (read(fd_pkg, &dedup_entry_hdr, DEDUP_ENTRYHDR_SIZE) != DEDUP_ENTRYHDR_SIZE)
                {
			perror("read in dedup_append_prepare");
                        ret = errno;
                        goto _DEDUP_APPEND_PREPARE_EXIT;
                }

                /* read pathname from deduped package opened */
                memset(pathname, 0, PATH_MAX_LEN);
                read(fd_pkg, pathname, dedup_entry_hdr.path_len);
		if (0 == hash_exist(g_htable, pathname)) hash_checkin(g_htable, pathname);

                offset += DEDUP_ENTRYHDR_SIZE;
                offset += dedup_entry_hdr.path_len;
                offset += dedup_entry_hdr.block_num * dedup_entry_hdr.entry_size;
                offset += dedup_entry_hdr.last_block_size;
        }

	if (-1 == lseek(fd_pkg, dedup_pkg_hdr->metadata_offset, SEEK_SET))
	{
		perror("lseek in dedup_append_prepare");
		ret = errno;
		goto _DEDUP_APPEND_PREPARE_EXIT;
	}
	while(rwsize = read(fd_pkg, buf, g_block_size))
	{
		write(fd_mdata, buf, rwsize);
	}

_DEDUP_APPEND_PREPARE_EXIT:
	if (buf) free(buf);
	return ret;
}

/*
 * create a dedup package from source files list
 */
static int dedup_package_creat(int path_nr, char **src_paths, char *dest_file, int append, int verbose)
{
	int fd, fd_ldata, fd_bdata, fd_mdata, ret = 0;
	struct stat statbuf;
	hashtable *htable = NULL;
	dedup_package_header dedup_pkg_hdr;
	char **paths = src_paths;
	int i, rwsize, prepos;
	char buf[1024 * 1024] = {0};
	mode_t mode;

	mode = append ? (O_RDWR | O_CREAT) : (O_WRONLY | O_CREAT | O_TRUNC);
	if (-1 == (fd = open(dest_file, mode, 0755)))
	{
		perror("open dest file in dedup_package_creat");
		ret = errno;
		goto _DEDUP_PKG_CREAT_EXIT;
	}

	htable = create_hashtable(g_htab_bucket_nr);
	if (NULL == htable)
	{
		perror("create_hashtable in dedup_package_creat");
		ret = errno;
		goto _DEDUP_PKG_CREAT_EXIT;
	}

	fd_ldata = open(ldata_file, O_RDWR | O_CREAT, 0777);
	fd_bdata = open(bdata_file, O_RDWR | O_CREAT, 0777);
	fd_mdata = open(mdata_file, O_RDWR | O_CREAT, 0777);
	if (-1 == fd_ldata || -1 == fd_bdata || -1 == fd_mdata)
	{
		perror("open ldata, bdata or mdata in dedup_package_creat");
		ret = errno;
		goto _DEDUP_PKG_CREAT_EXIT;
	}

	g_unique_block_nr = 0;
	g_regular_file_nr = 0;
	write(fd_bdata, &dedup_pkg_hdr, DEDUP_PKGHDR_SIZE);
	if (append)
	{
		ret = dedup_append_prepare(fd, fd_ldata, fd_bdata, fd_mdata, &dedup_pkg_hdr, htable);
		if (ret != 0) goto _DEDUP_PKG_CREAT_EXIT;
	}

	for (i = 0; i < path_nr; i++)
	{
		if (lstat(paths[i], &statbuf) < 0)
		{
			perror("lstat source path");
			ret = errno;
			goto _DEDUP_PKG_CREAT_EXIT;
		}

		if (S_ISREG(statbuf.st_mode) || S_ISDIR(statbuf.st_mode) || S_ISLNK(statbuf.st_mode))
		{
			if (verbose)
				fprintf(stderr, "%s\n", paths[i]);
			/* get filename position in pathname */	
			prepos = strlen(paths[i]) - 1;
			if (strcmp(paths[i], "/") != 0 && *(paths[i] + prepos) == '/')
			{
				*(paths[i] + prepos--) = '\0';
			}
			while(*(paths[i] + prepos) != '/' && prepos >= 0) prepos--;
			prepos++;

			if (S_ISDIR(statbuf.st_mode))
				dedup_dir(paths[i], prepos, fd_ldata, fd_bdata, fd_mdata, htable, verbose);
			else
				dedup_regfile(paths[i], prepos, fd_ldata, fd_bdata, fd_mdata, htable, verbose);
		}	
		else 
		{
			if (verbose)
				fprintf(stderr, "%s is not regular file or directory.\n", paths[i]);
		}
	}

	/* fill up dedup package header */
	dedup_pkg_hdr.block_size = g_block_size;
	dedup_pkg_hdr.block_num = g_unique_block_nr;
	dedup_pkg_hdr.blockid_size = BLOCK_ID_SIZE;
	dedup_pkg_hdr.magic_num = DEDUP_MAGIC_NUM;
	dedup_pkg_hdr.block_z = (g_bz) ? TRUE : FALSE;
	dedup_pkg_hdr.file_num = g_regular_file_nr; 
	dedup_pkg_hdr.ldata_offset = DEDUP_PKGHDR_SIZE + g_ldata_offset;
	dedup_pkg_hdr.metadata_offset = dedup_pkg_hdr.ldata_offset + DEDUP_LOGIC_BLOCK_ENTRY_SIZE * g_unique_block_nr;
	lseek(fd_bdata, 0, SEEK_SET);
	write(fd_bdata, &dedup_pkg_hdr, DEDUP_PKGHDR_SIZE);
	lseek(fd_bdata, 0, SEEK_END);

	/* fill up dedup package logic blocks */
	lseek(fd_ldata, 0, SEEK_SET);
	while(rwsize = read(fd_ldata, buf, 1024 * 1024))
	{
		write(fd_bdata, buf, rwsize);
		memset(buf, 0, 1024 * 1024);
	}

	/* fill up dedup package metadata */
	lseek(fd_mdata, 0, SEEK_SET);
	while(rwsize = read(fd_mdata, buf, 1024 * 1024))
	{
		write(fd_bdata, buf, rwsize);
		memset(buf, 0, 1024 * 1024);
	}

	if (verbose)
		show_pkg_header(dedup_pkg_hdr);

_DEDUP_PKG_CREAT_EXIT:
	close(fd);
	close(fd_ldata);
	close(fd_bdata);
	close(fd_mdata);
	if (htable) hash_free(htable);
	
	return ret;
}

/*
 * list files in a dedup package
 */
static int dedup_package_list(char *src_file, int verbose)
{
	int fd, i, ret = 0;
	dedup_package_header dedup_pkg_hdr;
	dedup_entry_header dedup_entry_hdr;
	unsigned long long offset;
	char pathname[PATH_MAX_LEN] = {0};

        if (-1 == (fd = open(src_file, O_RDONLY)))
        {
                perror("open source file");
                return errno;
        }

	if (read(fd, &dedup_pkg_hdr, DEDUP_PKGHDR_SIZE) != DEDUP_PKGHDR_SIZE)
	{
		perror("read dedup_package_header");
		ret = errno;
		goto _DEDUP_PKG_LIST_EXIT;
	}

	if (dedup_pkg_hdr.magic_num != DEDUP_MAGIC_NUM)
	{
		fprintf(stderr, "magic number is error, maybe this file is not a dedup package.\n");
		ret = -1;
		goto _DEDUP_PKG_LIST_EXIT;
	}

	offset = dedup_pkg_hdr.metadata_offset;
	for (i = 0; i < dedup_pkg_hdr.file_num; ++i)
	{
		if (lseek(fd, offset, SEEK_SET) == -1)
		{
			ret = errno;
			break;
		}
			
		if (read(fd, &dedup_entry_hdr, DEDUP_ENTRYHDR_SIZE) != DEDUP_ENTRYHDR_SIZE)
		{
			ret = errno;
			break;
		}
		
		/* read pathname from  deduped package opened */
		memset(pathname, 0, PATH_MAX_LEN);
		read(fd, pathname, dedup_entry_hdr.path_len);
		fprintf(stderr, "%s\n", pathname);

		offset += DEDUP_ENTRYHDR_SIZE;
		offset += dedup_entry_hdr.path_len;
		offset += dedup_entry_hdr.block_num * dedup_entry_hdr.entry_size;
		offset += dedup_entry_hdr.last_block_size;
	}

	if (verbose)
		show_pkg_header(dedup_pkg_hdr);

_DEDUP_PKG_LIST_EXIT:
	close(fd);

	return ret;
}

/*
 * give statistical information about a dedup package
 */
static int dedup_package_stat(char *src_file, int verbose)
{
	int fd, i, j, ret = 0;
	struct stat stat_buf;
	dedup_package_header dedup_pkg_hdr;
	dedup_entry_header dedup_entry_hdr;
	dedup_logic_block_entry dedup_lblock_entry;
	unsigned long long offset;
	unsigned long long last_blocks_sz = 0;
	unsigned long long dup_blocks_sz = 0;
	unsigned long long total_files_sz = 0;
	block_id_t *metadata = NULL;
	block_id_t *lblock_array = NULL;
	unsigned int dup_blocks_nr = 0;

        if (-1 == (fd = open(src_file, O_RDONLY)))
        {
                perror("open source file in dedup_package_stat");
                return errno;
        }

	if (-1 == (fstat(fd, &stat_buf)))
	{
		perror("fstat in dedup_package_stat");
		ret = errno;
		goto _DEDUP_PKG_STAT_EXIT;
	}

	if (read(fd, &dedup_pkg_hdr, DEDUP_PKGHDR_SIZE) != DEDUP_PKGHDR_SIZE)
	{
		perror("read dedup_package_header in dedup_package_stat");
		ret = errno;
		goto _DEDUP_PKG_STAT_EXIT;
	}

	if (dedup_pkg_hdr.magic_num != DEDUP_MAGIC_NUM)
	{
		fprintf(stderr, "magic number is error, maybe this file is not a dedup package.\n");
		ret = -1;
		goto _DEDUP_PKG_STAT_EXIT;
	}

	/* traverse mdata to build lblock_array */
	lblock_array = (block_id_t *)malloc(BLOCK_ID_SIZE * dedup_pkg_hdr.block_num);
	if (lblock_array == NULL)
	{
		perror("malloc lblock_array in dedup_package_stat");
		ret = errno;
		goto _DEDUP_PKG_STAT_EXIT;
	}
	for (i = 0; i < dedup_pkg_hdr.block_num; i++)
		lblock_array[i] = 0;

	offset = dedup_pkg_hdr.metadata_offset;
	for (i = 0; i < dedup_pkg_hdr.file_num; i++)
	{
		if (lseek(fd, offset, SEEK_SET) == -1)
		{
			ret = errno;
			break;
		}
			
		if (read(fd, &dedup_entry_hdr, DEDUP_ENTRYHDR_SIZE) != DEDUP_ENTRYHDR_SIZE)
		{
			ret = errno;
			break;
		}
		
		last_blocks_sz += dedup_entry_hdr.last_block_size;
		total_files_sz += dedup_entry_hdr.old_size;
		metadata = (block_id_t *)malloc(BLOCK_ID_SIZE * dedup_entry_hdr.block_num);
		if (NULL == metadata)
		{
			perror("malloc in dedup_package_stat");
			ret = errno;
			goto _DEDUP_PKG_STAT_EXIT;
		}
		lseek(fd, dedup_entry_hdr.path_len, SEEK_CUR);
		read(fd, metadata, BLOCK_ID_SIZE * dedup_entry_hdr.block_num);
		for (j = 0; j < dedup_entry_hdr.block_num; j++)
			lblock_array[metadata[j]]++;
		if (metadata) free(metadata);

		offset += DEDUP_ENTRYHDR_SIZE;
		offset += dedup_entry_hdr.path_len;
		offset += dedup_entry_hdr.block_num * dedup_entry_hdr.entry_size;
		offset += dedup_entry_hdr.last_block_size;
	}

	/* traverse logic blocks to get dup_blocks_sz */
	lseek(fd, dedup_pkg_hdr.ldata_offset, SEEK_SET);
	for (i = 0; i < dedup_pkg_hdr.block_num; ++i)
	{
		if (lblock_array[i] > 1)
			dup_blocks_nr++;

		read(fd, &dedup_lblock_entry, DEDUP_LOGIC_BLOCK_ENTRY_SIZE);
		dup_blocks_sz += (lblock_array[i] * dedup_lblock_entry.block_len);
	}

	/* show stat information */
	show_pkg_header(dedup_pkg_hdr);
	fprintf(stderr, "duplicated block number: %d\n", dup_blocks_nr);
	fprintf(stderr, "total size in orginal filesystem: %ld\n", total_files_sz);
	fprintf(stderr, "total real size of all orginal files: %ld\n", dup_blocks_sz + last_blocks_sz);
	fprintf(stderr, "total size of dedup package: %ld\n", stat_buf.st_size);
	fprintf(stderr, "dedup rate = %.4f : 1\n", total_files_sz/1.00/stat_buf.st_size);

_DEDUP_PKG_STAT_EXIT:
	close(fd);

	return ret;
}

/*
 * check wether the file is in file lists
 */
static int file_in_lists(char *filepath, int files_nr, char **files_list)
{
	int i;

	for (i = 0; i < files_nr; i++)
	{
		if (0 == strcmp(filepath, files_list[i]))
			return 0;
	}

	return -1;
}

/*
 * remove files from a dedup package, the process is a bit tricky.
 */
static int dedup_package_remove(char *file_pkg, int files_nr, char **files_remove, int verbose)
{
	int fd_pkg, fd_ldata, fd_bdata, fd_mdata, ret = 0;
	dedup_package_header dedup_pkg_hdr;
	dedup_entry_header dedup_entry_hdr;
	dedup_logic_block_entry dedup_lblock_entry;
	int i, j, rwsize;
	int remove_block_nr = 0, remove_file_nr = 0, remove_bytes_nr = 0;
	char buf[1024 * 1024] = {0};
	char *block_buf = NULL;
	LISTDB *lookup_table = NULL;
	block_id_t *metadata = NULL;
	block_id_t TOBE_REMOVED;
	block_id_t value;
	unsigned long long offset;
	char pathname[PATH_MAX_LEN] = {0};
	char listdb_name[PATH_MAX_LEN] = {0};

	/* open files */
	if (-1 == (fd_pkg = open(file_pkg, O_RDWR | O_CREAT, 0755)))
	{
		perror("open package file in dedup_package_remove");
		ret = errno;
		goto _DEDUP_PKG_REMOVE_EXIT;
	}

	fd_ldata = open(ldata_file, O_RDWR | O_CREAT, 0777);
	fd_bdata = open(bdata_file, O_RDWR | O_CREAT, 0777);
	fd_mdata = open(mdata_file, O_RDWR | O_CREAT, 0777);
	if (fd_ldata == -1 || fd_bdata == -1 || fd_mdata == -1)
	{
		perror("open ldata, bdata or mdata file in dedup_package_remove");
		ret = errno;
		goto _DEDUP_PKG_REMOVE_EXIT;
	}

	/* get global information from package */
	if (read(fd_pkg, &dedup_pkg_hdr, DEDUP_PKGHDR_SIZE) != DEDUP_PKGHDR_SIZE)
        {
                perror("read dedup_package_header in dedup_package_remove");
                ret = errno;
		goto _DEDUP_PKG_REMOVE_EXIT;
	}

	if (dedup_pkg_hdr.magic_num != DEDUP_MAGIC_NUM)
	{
		fprintf(stderr, "magic number is error, maybe this file is not a dedup packakge.\n");
		ret = -1;
		goto _DEDUP_PKG_REMOVE_EXIT;
	}

	g_unique_block_nr = dedup_pkg_hdr.block_num;
	g_regular_file_nr = dedup_pkg_hdr.file_num;
	g_block_size = dedup_pkg_hdr.block_size;
	g_ldata_offset = dedup_pkg_hdr.ldata_offset - DEDUP_PKGHDR_SIZE;
	TOBE_REMOVED = g_unique_block_nr;
	if (verbose) show_pkg_header(dedup_pkg_hdr);

	/* traverse mdata to build lookup_table */
	lookup_table = listdb_new(BLOCK_ID_SIZE, DEFAULT_CACHE_SZ, DEFAULT_SWAP_SZ);
	if (lookup_table == NULL)
	{
		perror("malloc lookup_table in dedup_package_remove");
		ret = errno;
		goto _DEDUP_PKG_REMOVE_EXIT;
	}
	sprintf(listdb_name, "/tmp/listdb.%d", getpid());
	if ( -1 == listdb_open(lookup_table, listdb_name))
	{
		perror("listdb_open in dedup_package_remove");
		ret = errno;
		goto _DEDUP_PKG_REMOVE_EXIT;
	}

	value = 0;
	for (i = 0; i < g_unique_block_nr; i++)
	{
		if ( -1 == listdb_set(lookup_table, i, &value))
		{
			perror("listdb_set in dedup_package_remove");
			ret = errno;
			goto _DEDUP_PKG_REMOVE_EXIT;
		}
	}

	offset = dedup_pkg_hdr.metadata_offset;
	for (i = 0; i < g_regular_file_nr; i++)
	{
		if (lseek(fd_pkg, offset, SEEK_SET) == -1)
		{
			perror("lseek in dedup_package_remove");
			ret = errno;
			goto _DEDUP_PKG_REMOVE_EXIT;
		}

		if (read(fd_pkg, &dedup_entry_hdr, DEDUP_ENTRYHDR_SIZE) != DEDUP_ENTRYHDR_SIZE)
		{
			perror("read in dedup_package_remove");
			ret = errno;
			goto _DEDUP_PKG_REMOVE_EXIT;
		}
		
		memset(pathname, 0, PATH_MAX_LEN);
		read(fd_pkg, pathname, dedup_entry_hdr.path_len);
		/* discard file to be removed */
		if (file_in_lists(pathname, files_nr, files_remove) != 0)
		{
			metadata = (block_id_t *)malloc(BLOCK_ID_SIZE * dedup_entry_hdr.block_num);
			if (NULL == metadata)
			{
				perror("malloc in dedup_package_remove");
				ret = errno;
				goto _DEDUP_PKG_REMOVE_EXIT;
			}
			read(fd_pkg, metadata, BLOCK_ID_SIZE * dedup_entry_hdr.block_num);
			for (j = 0; j < dedup_entry_hdr.block_num; j++) 
			{
				if (0 != listdb_get(lookup_table, metadata[j], &value))
				{
					perror("listdb_get in dedup_package_remove");
					ret = errno;
					goto _DEDUP_PKG_REMOVE_EXIT;
				}
				value++;
				if (-1 == listdb_set(lookup_table, metadata[j], &value))
				{
					perror("listdb_set in dedup_package_remove");
					ret = errno;
					goto _DEDUP_PKG_REMOVE_EXIT;
				}
			}
			if (metadata) free(metadata);
		}

		offset += DEDUP_ENTRYHDR_SIZE;
		offset += dedup_entry_hdr.path_len;
		offset += dedup_entry_hdr.block_num * dedup_entry_hdr.entry_size;
		offset += dedup_entry_hdr.last_block_size;
	}

	/* rebuild block number, ldata and bdata */
	remove_block_nr = 0;
	block_buf = (char *)malloc(BLOCK_MAX_SIZE);
	if (block_buf == NULL)
	{
		ret = errno;
		goto _DEDUP_PKG_REMOVE_EXIT;
	}
	write(fd_bdata, &dedup_pkg_hdr, DEDUP_PKGHDR_SIZE);
	for (i = 0; i < g_unique_block_nr; i++)
	{
		lseek(fd_pkg, dedup_pkg_hdr.ldata_offset + i * DEDUP_LOGIC_BLOCK_ENTRY_SIZE, SEEK_SET);
		read(fd_pkg, &dedup_lblock_entry, DEDUP_LOGIC_BLOCK_ENTRY_SIZE);
		if (0 != listdb_get(lookup_table, i, &value))
		{
			perror("listdb_get in dedup_package_remove");
			ret = errno;
			goto _DEDUP_PKG_REMOVE_EXIT;
		}
		if (value == 0)
		{
			value = TOBE_REMOVED;
			if (-1 == listdb_set(lookup_table, i, &value))
			{
				perror("listdb_set in dedup_package_remove");
				ret = errno;
				goto _DEDUP_PKG_REMOVE_EXIT;
			}
			remove_block_nr++;
			remove_bytes_nr += dedup_lblock_entry.block_len;
		}
		else
		{
			value = i - remove_block_nr;
			if (-1 == listdb_set(lookup_table, i, &value))
			{
				perror("listdb_set in dedup_package_remove");
				ret = errno;
				goto _DEDUP_PKG_REMOVE_EXIT;
			}
			lseek(fd_pkg, DEDUP_PKGHDR_SIZE + dedup_lblock_entry.block_offset, SEEK_SET);
			read(fd_pkg, block_buf, dedup_lblock_entry.block_len);
			dedup_lblock_entry.block_offset -= remove_bytes_nr;
			write(fd_ldata, &dedup_lblock_entry, DEDUP_LOGIC_BLOCK_ENTRY_SIZE);
			write(fd_bdata, block_buf, dedup_lblock_entry.block_len);
		}
	}

	/* rebuild mdata */
	remove_file_nr = 0;
	offset = dedup_pkg_hdr.metadata_offset;
	for (i = 0; i < g_regular_file_nr; i++)
	{
		if (lseek(fd_pkg, offset, SEEK_SET) == -1)
		{
			ret = errno;
			goto _DEDUP_PKG_REMOVE_EXIT;
		}

		if (read(fd_pkg, &dedup_entry_hdr, DEDUP_ENTRYHDR_SIZE) != DEDUP_ENTRYHDR_SIZE)
		{
			ret = errno;
			goto _DEDUP_PKG_REMOVE_EXIT;
		}
		
		memset(pathname, 0, PATH_MAX_LEN);
		read(fd_pkg, pathname, dedup_entry_hdr.path_len);
		if (file_in_lists(pathname, files_nr, files_remove) != 0)
		{
			metadata = (block_id_t *)malloc(BLOCK_ID_SIZE * dedup_entry_hdr.block_num);
			if (NULL == metadata)
			{
				ret = errno;
				goto _DEDUP_PKG_REMOVE_EXIT;
			}
			read(fd_pkg, metadata, BLOCK_ID_SIZE * dedup_entry_hdr.block_num);
			read(fd_pkg, block_buf, dedup_entry_hdr.last_block_size);
			for (j = 0; j < dedup_entry_hdr.block_num; j++)
			{
				if (0 != listdb_get(lookup_table, metadata[j], &value))
				{
					perror("listdb_get in dedup_package_remove");
					ret = errno;
					goto _DEDUP_PKG_REMOVE_EXIT;
				}
				metadata[j] = value;
			}
			write(fd_mdata, &dedup_entry_hdr, DEDUP_ENTRYHDR_SIZE);
			write(fd_mdata, pathname, dedup_entry_hdr.path_len);
			write(fd_mdata, metadata, BLOCK_ID_SIZE * dedup_entry_hdr.block_num);
			write(fd_mdata, block_buf, dedup_entry_hdr.last_block_size);
			if (metadata) free(metadata);
		}
		else
		{
			remove_file_nr++;
		}

		offset += DEDUP_ENTRYHDR_SIZE;
		offset += dedup_entry_hdr.path_len;
		offset += dedup_entry_hdr.block_num * dedup_entry_hdr.entry_size;
		offset += dedup_entry_hdr.last_block_size;
	}

	/* rebuild package header and write back */
	dedup_pkg_hdr.block_size = g_block_size;
	dedup_pkg_hdr.block_num = g_unique_block_nr - remove_block_nr;
	dedup_pkg_hdr.blockid_size = BLOCK_ID_SIZE;
	dedup_pkg_hdr.magic_num = DEDUP_MAGIC_NUM;
	dedup_pkg_hdr.file_num = g_regular_file_nr - remove_file_nr; 
	dedup_pkg_hdr.ldata_offset = DEDUP_PKGHDR_SIZE + g_ldata_offset -remove_bytes_nr;
	dedup_pkg_hdr.metadata_offset = dedup_pkg_hdr.ldata_offset + DEDUP_LOGIC_BLOCK_ENTRY_SIZE * dedup_pkg_hdr.block_num;

	/* write package header back */
	lseek(fd_bdata, 0, SEEK_SET);
	write(fd_bdata, &dedup_pkg_hdr, DEDUP_PKGHDR_SIZE);
	lseek(fd_bdata, 0 , SEEK_END);

	/* write ldata back */
	lseek(fd_ldata, 0, SEEK_SET);
	while(rwsize = read(fd_ldata, buf, 1024 * 1024))
	{
		write(fd_bdata, buf, rwsize);
		memset(buf, 0, 1024 * 1024);
	}

	/* write mdata back */
	lseek(fd_mdata, 0, SEEK_SET);
	while(rwsize = read(fd_mdata, buf, 1024 * 1024))
	{
		write(fd_bdata, buf, rwsize);
		memset(buf, 0, 1024 * 1024);
	}

	if (verbose)
		show_pkg_header(dedup_pkg_hdr);

_DEDUP_PKG_REMOVE_EXIT:
	if (fd_pkg) close(fd_pkg);
	if (fd_ldata) close(fd_ldata);
	if (fd_bdata) close(fd_bdata);
	if (fd_mdata) close(fd_mdata);
	if (lookup_table)
	{
		listdb_close(lookup_table);
		listdb_unlink(lookup_table);
		free(lookup_table);
	}
	if (block_buf) free(block_buf);
	
	return ret;
}

/*
 * create necessary directories and open the target file
 */
static int prepare_target_file(char *pathname, char *basepath, int mode)
{
	char fullpath[PATH_MAX_LEN] = {0};
	char path[PATH_MAX_LEN] = {0};
	char *p = NULL;
	int pos = 0, fd;

	sprintf(fullpath, "%s/%s", basepath, pathname);
	p = fullpath;
	while (*p != '\0')
	{
		path[pos++] = *p;
		if (*p == '/')
			mkdir(path, 0755);
		p++;
	} 

	fd = open(fullpath, O_WRONLY | O_CREAT, mode);
	return fd;
}

/*
 * extract file from a dedup package
 */
static int undedup_regfile(int fd, dedup_package_header dedup_pkg_hdr, dedup_entry_header dedup_entry_hdr, char *dest_dir, int verbose)
{
	char pathname[PATH_MAX_LEN] = {0};
	char fullpath[PATH_MAX_LEN] = {0};
	block_id_t *metadata = NULL;
	unsigned int block_num = 0;
	unsigned int rwsize = 0, bzsize = 0;
	char *buf = NULL;
	char *buf_bz = NULL;
	char *last_block_buf = NULL;
	long long offset, i;
	int fd_dest, ret = 0;
	dedup_logic_block_entry dedup_lblock_entry;
	struct utimbuf times;

	metadata = (block_id_t *) malloc(BLOCK_ID_SIZE * dedup_entry_hdr.block_num);
	if (NULL == metadata)
	{
		perror("malloc in undedup_regfile");
		return errno;
	}

	buf = (char *)malloc(BUF_MAX_SIZE);
	buf_bz = (char *)malloc(BUF_MAX_SIZE);
	last_block_buf = (char *)malloc(dedup_entry_hdr.last_block_size);
	if (NULL == buf || NULL == buf_bz || NULL == last_block_buf)
	{
		perror("malloc in undedup_regfile");
		ret = errno;
		goto _UNDEDUP_REGFILE_EXIT;
	}

	read(fd, pathname, dedup_entry_hdr.path_len);
	read(fd, metadata, BLOCK_ID_SIZE * dedup_entry_hdr.block_num);
	read(fd, last_block_buf, dedup_entry_hdr.last_block_size);
	fd_dest = prepare_target_file(pathname, dest_dir, dedup_entry_hdr.mode);
	if (fd_dest == -1)
	{
		perror("prepare_target_file in undedup_regfile");
		ret = errno;
		goto _UNDEDUP_REGFILE_EXIT;
	}

	if (verbose)
		fprintf(stderr, "%s/%s\n", dest_dir, pathname);

	/* write regular block */
	block_num = dedup_entry_hdr.block_num;
	for(i = 0; i < block_num; ++i)
	{
		offset = dedup_pkg_hdr.ldata_offset + metadata[i] * DEDUP_LOGIC_BLOCK_ENTRY_SIZE;
		lseek(fd, offset, SEEK_SET);
		read(fd, &dedup_lblock_entry, DEDUP_LOGIC_BLOCK_ENTRY_SIZE);
		offset = DEDUP_PKGHDR_SIZE + dedup_lblock_entry.block_offset;
		lseek(fd, offset, SEEK_SET);
		rwsize = read(fd, buf, dedup_lblock_entry.block_len);
		/* decompress block if compressed */
		if (g_bz || dedup_pkg_hdr.block_z == TRUE) {
			bzsize = BUF_MAX_SIZE;
			if (Z_OK != zlib_decompress_block(buf, rwsize, buf_bz, &bzsize)) {
				ret = -1;
				goto _UNDEDUP_REGFILE_EXIT;
			}
			memcpy(buf, buf_bz, bzsize);
			rwsize = bzsize;
		}
		write(fd_dest, buf, rwsize);
	}
	/* write last block */
	write(fd_dest, last_block_buf, dedup_entry_hdr.last_block_size);
	close(fd_dest);

	/* timestamps preservation */
	sprintf(fullpath, "%s/%s", dest_dir, pathname);
	times.actime = dedup_entry_hdr.atime;
	times.modtime = dedup_entry_hdr.mtime;
	utime(fullpath, &times);


_UNDEDUP_REGFILE_EXIT:
	if (metadata) free(metadata);
	if (buf) free(buf);
	if (buf_bz) free(buf_bz);
	if (last_block_buf) free(last_block_buf);

	return ret;
}

/*
 * extract all files from a dedup package
 */
static int dedup_package_extract(char *src_file, int files_nr, char **files_extract, char *dest_dir, int verbose)
{
	int fd, i, ret = 0;
	dedup_package_header dedup_pkg_hdr;
	dedup_entry_header dedup_entry_hdr;
	unsigned long long offset;
	char pathname[PATH_MAX_LEN] = {0};

        if (-1 == (fd = open(src_file, O_RDONLY)))
        {
                perror("open source file in dedup_package_extract");
                return errno;
        }

	if (read(fd, &dedup_pkg_hdr, DEDUP_PKGHDR_SIZE) != DEDUP_PKGHDR_SIZE)
	{
		perror("read dedup_package_header in dedup_package_extrace");
		ret = errno;
		goto _DEDUP_PKG_EXTRACT_EXIT;
	}

	if (dedup_pkg_hdr.magic_num != DEDUP_MAGIC_NUM)
	{
		fprintf(stderr, "magic number is error, maybe this file is not a dedup pacakge.\n");
		ret = -1;
		goto _DEDUP_PKG_EXTRACT_EXIT;
	}

	g_block_size = dedup_pkg_hdr.block_size;

	offset = dedup_pkg_hdr.metadata_offset;
	for (i = 0; i < dedup_pkg_hdr.file_num; ++i)
	{
		if (lseek(fd, offset, SEEK_SET) == -1)
		{
			perror("lseek in dedup_package_extract");
			ret = errno;
			break;
		}
			
		if (read(fd, &dedup_entry_hdr, DEDUP_ENTRYHDR_SIZE) != DEDUP_ENTRYHDR_SIZE)
		{
			perror("read in dedup_package_extrace");
			ret = errno;
			break;
		}

		/* extract all files */
		if (files_nr == 0)
		{
			ret = undedup_regfile(fd, dedup_pkg_hdr, dedup_entry_hdr, dest_dir, verbose);
			if (ret != 0)
				break;
		}
		else
		/* extract specific file */
		{
			memset(pathname, 0, PATH_MAX_LEN);
			read(fd, pathname, dedup_entry_hdr.path_len);
			lseek(fd, offset + DEDUP_ENTRYHDR_SIZE, SEEK_SET);
			if (file_in_lists(pathname, files_nr, files_extract) == 0)
			{
				ret = undedup_regfile(fd, dedup_pkg_hdr, dedup_entry_hdr, dest_dir, verbose);
			}
		}

		offset += DEDUP_ENTRYHDR_SIZE;
		offset += dedup_entry_hdr.path_len;
		offset += dedup_entry_hdr.block_num * dedup_entry_hdr.entry_size;
		offset += dedup_entry_hdr.last_block_size;
	}

	if (verbose) show_pkg_header(dedup_pkg_hdr);

_DEDUP_PKG_EXTRACT_EXIT:
	close(fd);

	return ret;
}

/*
 * give dedup util usage information
 */
static void usage()
{
        fprintf(stderr, "Usage: dedup [OPTION...] [FILE]...\n");
        fprintf(stderr, "dedup util packages files with deduplicaton technique.\n\n");
        fprintf(stderr, "Examples:\n");
        fprintf(stderr, "  dedup -c -v foobar.ded foo bar    # Create foobar.ded from files foo and bar.\n");
        fprintf(stderr, "  dedup -a -v foobar.ded foo1 bar1  # Append files foo1 and bar1 into foobar.ded.\n");
        fprintf(stderr, "  dedup -r -v foobar.ded foo1 bar1  # Remove files foo1 and bar1 from foobar.ded.\n");
        fprintf(stderr, "  dedup -t -v foobar.ded            # List all files in foobar.ded.\n");
        fprintf(stderr, "  dedup -x -v foobar.ded            # Extract all files from foobar.ded.\n");
        fprintf(stderr, "  dedup -s -v foobar.ded            # Show information about foobar.ded.\n\n");
        fprintf(stderr, "Main options (must only one):\n");
        fprintf(stderr, "  -c, --creat      create a new archive\n");
        fprintf(stderr, "  -x, --extract    extract files from an archive\n");
        fprintf(stderr, "  -a, --append     append files to an archive\n");
        fprintf(stderr, "  -r, --remove     remove files from an archive\n");
        fprintf(stderr, "  -t, --list       list files in an archive\n");
	fprintf(stderr, "  -s, --stat       show information about an archive\n\n");
	fprintf(stderr, "Other options:\n");
        fprintf(stderr, "  -C, --chunk      chunk algorithms: FSP, CDC, SB, CDC as default\n");
	fprintf(stderr, "                   FSP - fixed-size partition\n");
	fprintf(stderr, "                   CDC - content-defined chunking\n");
	fprintf(stderr, "                   SB - sliding block\n");
	fprintf(stderr, "  -f, --hashfunc   set hash function for CDC file chunking, adler_hash as default\n");
	fprintf(stderr, "                   hash functions list as followed: \n");
	fprintf(stderr, "                   rabin_hash, RS_hash, JS_hash, PJW_hash, ELF_hash, AP_hash\n");
	fprintf(stderr, "                   simple_hash, BKDR_hash, JDBM_hash, DJB_hash, CRC_hash, adler_hash\n");
        fprintf(stderr, "  -z, --compress   filter the archive through zlib compression\n");
        fprintf(stderr, "  -b, --block      block size for deduplication, 4096 as default\n");
        fprintf(stderr, "  -H, --hashtable  hashtable bucket number, 10240 as default\n");
        fprintf(stderr, "  -d, --directory  change to directory, PWD as default\n");
        fprintf(stderr, "  -v, --verbose    print verbose messages\n");
        fprintf(stderr, "  -V, --version    display version number\n");
        fprintf(stderr, "  -h, --help       give this help list\n\n");
        fprintf(stderr, "Report bugs to <Aigui.Liu@gmail.com>.\n");
}

/*
 * give version information
 */
static void version()
{
	fprintf(stderr, "dedup utility %s\n", DEDUPUTIL_VERSION);
	fprintf(stderr, "Copyright (C) 2010 Aigui Liu.\n");
	fprintf(stderr, "This is free software; see the source for copying conditions.  There is NO\n");
	fprintf(stderr, "warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.\n\n");
	fprintf(stderr, "Written by Aigui Liu.\n");
}

int main(int argc, char *argv[])
{
	int bz = 0, bhelp = 0, bverbose = 0, bversion = 0;
	int ret = -1, c;
	int dedup_op = -1, dedup_op_nr = 0;
	int args_nr = 0;
	char path[PATH_MAX_LEN] = ".\0";

	struct option longopts[] =
	{
		{"creat", 0, 0, 'c'},
		{"chunk", 1, 0, 'C'},
		{"hashfunc", 1, 0, 'f'},
		{"extract", 0, 0, 'x'},
		{"append", 0, 0, 'a'},
		{"remove", 0, 0, 'r'},
		{"list", 0, 0, 't'},
		{"stat", 0, 0, 's'},
		{"compress", 0, 0, 'z'},
		{"block", 1, 0, 'b'},
		{"hashtable", 1, 0, 'H'},
		{"directory", 1, 0, 'd'},
		{"verbose", 0, 0, 'v'},
		{"version", 0, 0, 'V'},
		{"help", 0, 0, 'h'},
		{0, 0, 0, 0}
	};

	/* parse options */
	while ((c = getopt_long (argc, argv, "cC:f:xartszb:H:d:vVh", longopts, NULL)) != EOF)
	{
		switch(c) 
		{
		case 'c':
			dedup_op = DEDUP_CREAT;
			dedup_op_nr++;
			args_nr = 2;
			break;
		case 'x':
			dedup_op = DEDUP_EXTRACT;
			dedup_op_nr++;
			args_nr = 1;
			break;
		case 'a':
			dedup_op = DEDUP_APPEND;
			dedup_op_nr++;
			args_nr = 2;
			break;
		case 'r':
			dedup_op = DEDUP_REMOVE;
			dedup_op_nr++;
			args_nr = 2;
			break;
		case 't':
			dedup_op = DEDUP_LIST;
			dedup_op_nr++;
			args_nr = 1;
			break;
		case 's':
			dedup_op = DEDUP_STAT;
			dedup_op_nr++;
			args_nr = 1;
			break;
		case 'z':
			g_bz = bz = 1;
			break;
		case 'b':
			g_block_size = atoi(optarg);
			if(g_block_size > BLOCK_MAX_SIZE)
			{
				fprintf(stderr, "block size(%d) > BLOCK_MAX_SIZE(%d)\n", g_block_size, BLOCK_MAX_SIZE);
				bhelp = 1;
			}
			break;
		case 'H':
			g_htab_bucket_nr = atoi(optarg);
			break;
		case 'd':
			sprintf(path, "%s", optarg);
			break;
		case 'v':
			bverbose = 1;
			break;
		case 'C':
			if (0 == strcmp(optarg, CHUNK_FSP))
				g_chunk_algo = DEDUP_CHUNK_FSP;
			else if (0 == strcmp(optarg, CHUNK_CDC))
				g_chunk_algo = DEDUP_CHUNK_CDC;
			else if (0 == strcmp(optarg, CHUNK_SB))
				g_chunk_algo = DEDUP_CHUNK_SB;
			else 
				bhelp = 1;
			break;
		case 'f':
			if (0 != set_cdc_chunk_hashfunc(optarg))
				bhelp = 1;
			break;
		case 'V':
			bversion = 1;
		case 'h':
		case '?':
		default:
			bhelp = 1;
			break;
		}
	}

	if (bversion)
	{
		version();
		return 0;
	}

	if (bhelp == 1 || (dedup_op == -1 || dedup_op_nr != 1) ||(argc - optind) < args_nr)
	{
		usage();
		return 0;
	}

	dedup_init();
	/* create global hashtables */
	g_htable = create_hashtable(g_htab_bucket_nr);
	if (NULL == g_htable)
	{
		perror("create_hashtable in main");
		return -1;
	}

	if (g_chunk_algo == DEDUP_CHUNK_SB)
	{
		g_sb_htable_crc = create_hashtable(g_htab_bucket_nr);
		if (NULL == g_sb_htable_crc)
		{
			perror("create_hashtable in main");
			return -1;
		}
	}

	sprintf(tmp_file, "%s", argv[optind]);
	/*  execute specific deduplication operation */
	switch(dedup_op)
	{
	case DEDUP_CREAT:
		ret = dedup_package_creat(argc - optind -1 , argv + optind + 1, tmp_file, FALSE, bverbose);
		rename(bdata_file, tmp_file);
		break;
	case DEDUP_EXTRACT:
		ret = dedup_package_extract(tmp_file, argc - optind -1, argv + optind + 1, path, bverbose);
		break;
	case DEDUP_APPEND:
		ret = dedup_package_creat(argc - optind -1 , argv + optind + 1, tmp_file, TRUE, bverbose);
		rename(bdata_file, tmp_file);
		break;
	case DEDUP_REMOVE:
		ret = dedup_package_remove(tmp_file, argc - optind -1, argv + optind + 1, bverbose);
		rename(bdata_file, tmp_file);
		break;
	case DEDUP_LIST:
		ret = dedup_package_list(tmp_file, bverbose);
		break;
	case DEDUP_STAT:
		ret = dedup_package_stat(tmp_file, bverbose);
		break;
	}

	if (g_htable) hash_free(g_htable);
	if (g_sb_htable_crc) hash_free(g_sb_htable_crc);
	dedup_clean();
	return ret;
}

/* The End. */
