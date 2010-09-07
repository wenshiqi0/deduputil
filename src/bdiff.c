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

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <unistd.h>
#include <getopt.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include "md5.h"
#include "hashtable.h"
#include "dedup.h"

/* block length */
static unsigned int g_block_size = BLOCK_SIZE;

/* hashtable backet number */
static unsigned int g_htab_backet_nr = BUCKET_SIZE;

/*
 * output block difference info to file or std.
 */
void output_bdiff(int fd, int block_no, int diff, off_t offset, unsigned int size, int debug)
{
	char buf[128] = {0};
	
	sprintf(buf, "#%d %d %ld %d\n", block_no, diff, offset, size);
	if (debug)
	{
		printf("%s", buf);
		return;
	}

	if (fd)
	{
		write(fd, buf, strlen(buf));
	}
	return;
}

/*
 * search block in dest file with block md5_checksum.
 * if matched, then offset += block_size, else offset++.
 */
off_t block_search(int fd, char *md5_checksum, off_t *offset, int debug)
{
	off_t boffset = -1;
	char *buf = NULL;
	unsigned char md5_checksum_dest[16 + 1] = {0};
	unsigned int rwsize = 0;

	if (-1 == *offset)
		return -1;

	buf = (char *)malloc(g_block_size);
	if (buf == NULL)
	{
		perror("malloc buf in block_search");
		return -1;
	}

	while (-1 != lseek(fd, *offset, SEEK_SET))
	{
		rwsize = read(fd, buf, g_block_size);
		/* get the tail or error */
		if (rwsize != g_block_size)
		{
			if (buf) free(buf);
			*offset = -1;
			return -1;
		}

		/* calculate md5 */
		md5(buf, rwsize, md5_checksum_dest);
		if (0 == strncmp(md5_checksum, md5_checksum_dest, 16))
		{
			boffset = *offset;
			*offset += g_block_size;
			break;
		}
		memset(buf, 0, g_block_size);
		memset(md5_checksum_dest, 0, 16 + 1);
		*offset++;
	}

	if (buf) free(buf);
	return boffset;
}

int bdiff(int fd_src, int fd_dest, int fd_tgt, hashtable *htab_inc, hashtable *htab_off, int debug)
{
	char *buf = NULL;
	unsigned int rwsize;
	off_t pos_src = -1, pos_dest = -1;
	off_t doffset = 0; /* offset in fd_dest */
	unsigned char md5_checksum[16 + 1] = {0};
	unsigned int block_no = 0;
	int ret = 0;

	buf = (char *)malloc(g_block_size);
	if (buf == NULL)
	{
		perror("malloc buf for block in bdiff");
		ret = errno;
		goto _BDIFF_EXIT;
	}

	pos_src = 0;
	while (rwsize = read(fd_src, buf, g_block_size)) 
	{
		/* if the last block */
		if (rwsize != g_block_size)
			break;

		/* calculate md5 */
		md5(buf, rwsize, md5_checksum);

		/* check hashtable with hashkey */
		off_t *b_offset = (block_id_t *)hash_value((void *)md5_checksum, htab_off);
		if (b_offset == NULL)
		{
			b_offset = (unsigned int *)malloc(BLOCK_ID_SIZE);
			if (NULL == b_offset)
			{
				perror("malloc b_offset in bdiff");
				ret = errno;
				break;
			}
			pos_dest = block_search(fd_dest, md5_checksum, &doffset, debug);

			/* insert hash entry and write unique block into bdata*/
			*b_offset = (pos_dest >= 0) ? pos_dest : pos_src;
			hash_insert((void *)strdup(md5_checksum), (void *)b_offset, htab_off);
			if (pos_dest >= 0)
			{
				unsigned int *bflag = (unsigned int *)malloc(sizeof(unsigned int));
				if (NULL == bflag)
				{
					perror("malloc bflag in bdiff");
					ret = errno;
					break;
				}
				hash_insert((void *)strdup(md5_checksum), (void *)bflag, htab_inc);
			}
			output_bdiff(fd_tgt, block_no, (pos_dest >= 0)?1:0, (off_t)*b_offset, g_block_size, debug);
		}
		else
		{
			unsigned int *b_inc = (block_id_t *)hash_value((void *)md5_checksum, htab_inc);
			output_bdiff(fd_tgt, block_no, (b_inc == NULL)? 0:1, (off_t)*b_offset, g_block_size, debug);
		}

		memset(buf, 0, g_block_size);
		memset(md5_checksum, 0, 16 + 1);
		pos_src += g_block_size;
		block_no++;
	}
	/* the last block */
	if (rwsize > 0 && rwsize != g_block_size)
	{
		output_bdiff(fd_tgt, block_no, 0, pos_src, rwsize, debug);
	}

_BDIFF_EXIT:
	if (buf) free(buf);

	return ret;
}

int bdiff_prepare(char *src_file, char *dest_file, char *tgt_file, int debug)
{
	int fd_src, fd_dest, fd_tgt = -1, ret = 0;
	/* record if block of source file is in dest file*/
	hashtable *htab_inc = NULL; 
	/* record block offset in source or dest file */
	hashtable *htab_off = NULL;

	if (-1 == (fd_src = open(src_file, O_RDONLY, 0755)))
	{
		perror("open source file");
		ret = errno;
		goto _BDIFF_PREPARE_EXIT;
	}

	if (-1 == (fd_dest = open(dest_file, O_RDONLY, 0755)))
	{
		perror("open dest file");
		ret = errno;
		goto _BDIFF_PREPARE_EXIT;
	}
	
	if(debug)
		goto _NO_OUTPUT_FILE;
	if (-1 == (fd_tgt = open(tgt_file, O_RDWR | O_CREAT, 0777)))
	{
		perror("open target file");
		ret = errno;
		goto _BDIFF_PREPARE_EXIT;
	}

_NO_OUTPUT_FILE:
	htab_inc = create_hashtable(g_htab_backet_nr);
	htab_off = create_hashtable(g_htab_backet_nr);
	if (NULL == htab_inc || NULL == htab_off)
	{
		perror("create_hashtable");
		ret = errno;
		goto _BDIFF_PREPARE_EXIT;
	}

	bdiff(fd_src, fd_dest, fd_tgt, htab_inc, htab_off, debug);

_BDIFF_PREPARE_EXIT:
	if (fd_src) close(fd_src);
	if (fd_dest) close(fd_dest);
	if (fd_tgt) close(fd_tgt);
	hash_free(htab_inc);
	hash_free(htab_off);
	
	return ret;
}

void usage()
{
	printf("Usage:  bdiff [OPTION...] <source file> <dest file> <output file>\n");
	printf("\ncompare files block by block.\n");
	printf("  -b, --block      block size for compare, default is 4096\n");
	printf("  -t, --hashtable  hashtable backet number, default is 10240\n");
	printf("  -d, --debug      print debug messages\n");
	printf("  -h, --help       give this help list\n");
	printf("\nReport bugs to <Aigui.Liu@gmail.com>.\n");
}

int main(int argc, char *argv[])
{
	int bhelp = 0, bdebug = 0;
	int ret = -1, c;
	struct option longopts[] =
	{
		{"block", 1, 0, 'b'},
		{"hashtable", 1, 0, 't'},
		{"debug", 0, &bdebug, 'd'},
		{"help", 0, &bhelp, 'h'},
		{0, 0, 0, 0}
	};

	/* parse options */
	while ((c = getopt_long (argc, argv, "b:t:dh", longopts, NULL)) != EOF)
	{
		switch(c) 
		{
		case 'b':
			g_block_size = atoi(optarg);
			break;
		case 't':
			g_htab_backet_nr = atoi(optarg);
			break;
		case 'd':
			bdebug = 1;
			break;
		case 'h':
		case '?':
		default:
			bhelp = 1;
			break;
		}
	}

	if (bhelp == 1 || (argc - optind) < 2)
	{
		usage();
		return 0;
	}

	if (bdebug)
		ret = bdiff_prepare(argv[optind], argv[optind + 1], NULL, bdebug);
	else
		ret = bdiff_prepare(argv[optind], argv[optind + 1], argv[optind + 2], bdebug);

	return ret;
}
