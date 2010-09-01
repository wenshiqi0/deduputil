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
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include "hashtable.h"
#include "sync.h"

#define NEITHER       0
#define UP            1
#define LEFT          2
#define UP_AND_LEFT   3

#define MAX(x, y) (((x) > (y)) ? (x) : (y))
#define MIN(x, y) (((x) < (y)) ? (x) : (y))
#define MD5_LEN	17

enum {
	FILE1 = 0,
	FILE2
};

enum {
	LCS_NOT = 0,
	LCS_YES
};

typedef struct {
	uint32_t nr1;
	uint32_t nr2;
	uint32_t len;
} hash_entry;

typedef struct {
	char **str;
	uint32_t len;
} lcs_entry;

static uint32_t sim_union = 0;
static uint32_t sim_intersect = 0;

static void usage()
{
	fprintf(stderr, "Usage: bsim FILE1 FILE2 CHUNK_ALGO LCS\n\n");
	fprintf(stderr, "Similarity detect between FILE1 and FILE2 based on block level.\n");
	fprintf(stderr, "CHUNK_ALGO:\n");
	fprintf(stderr, "  FSP - fixed-size partition\n");
	fprintf(stderr, "  CDC - content-defined chunking\n");
	fprintf(stderr, "  SBC - slide block chunking\n\n");
	fprintf(stderr, "LCS:\n");
	fprintf(stderr, "  LCS_NOT - do not use LCS(longest lommon subsequence) algorithms\n");
	fprintf(stderr, "  LCS_YES - use LCS algorithms\n\n");
	fprintf(stderr, "Report bugs to <Aigui.Liu@gmail.com>.\n");
}

static int parse_arg(char *argname)
{
	if (0 == strcmp(argname, "FSP"))
		return CHUNK_FSP;
	else if (0 == strcmp(argname, "CDC"))
		return CHUNK_CDC;
	else if (0 == strcmp(argname, "SBC"))
		return CHUNK_SBC;
	else if (0 == strcmp(argname, "LCS_NOT"))
		return LCS_NOT;
	else if (0 == strcmp(argname, "LCS_YES"))
		return LCS_YES;
	else
		return -1;
}

static char **alloc_2d_array(int row, int col)
{
        int i;
        char *p, **pp;

        p = (char *)malloc(row * col * sizeof(char));
        pp = (char **)malloc(row * sizeof(char *));
        if (p == NULL || pp == NULL)
                return NULL;

        for (i = 0; i < row; i++) {
                pp[i] = p + col * i;
        }

        return pp;
}

static void free_2d_array(char **str)
{
	free(str[0]);
	free(str);
}

static void show_md5_hex(unsigned char md5_checksum[16])
{
        int i;
        for (i = 0; i < 16; i++) {
                printf("%02x", md5_checksum[i]);
        }
        printf("\n");
}

static int chunk_file_process(char *chunk_file, hashtable *htab, int which, int sim_algo, lcs_entry *le)
{
	int fd, i, ret = 0;
	ssize_t rwsize;
	chunk_file_header chunk_file_hdr;
	chunk_block_entry chunk_bentry;
	hash_entry *he = NULL;

	/* parse chunk file */
	fd = open(chunk_file, O_RDONLY);
	if (-1 == fd) {
		return -1;
	}

	rwsize = read(fd, &chunk_file_hdr, CHUNK_FILE_HEADER_SZ);
	if (rwsize != CHUNK_FILE_HEADER_SZ) {
		ret = -1;
		goto _CHUNK_FILE_PROCESS_EXIT;
	}

	if (sim_algo == LCS_YES) {
		le->str = alloc_2d_array(chunk_file_hdr.block_nr, MD5_LEN);
		if (le->str == NULL) {
			ret = -1;
			goto _CHUNK_FILE_PROCESS_EXIT;
		}
		le->len = chunk_file_hdr.block_nr;
	}

	for(i = 0; i < chunk_file_hdr.block_nr; i++) {
		rwsize = read(fd, &chunk_bentry, CHUNK_BLOCK_ENTRY_SZ);
		if (rwsize != CHUNK_BLOCK_ENTRY_SZ) {
			ret = -1;
			goto _CHUNK_FILE_PROCESS_EXIT;
		}

		he = (hash_entry *)hash_value((void *)chunk_bentry.md5, htab);
		if (he == NULL) {
			he = (hash_entry *)malloc(sizeof(hash_entry));
			he->nr1 = he->nr2 = 0;
			he->len = chunk_bentry.len;
		}
		(which == FILE1) ? he->nr1++ : he->nr2++;
		/* insert or update hash entry */
		hash_insert((void *)strdup(chunk_bentry.md5), (void *)he, htab);
		if (sim_algo == LCS_YES) {
			memcpy(le->str[i], chunk_bentry.md5, MD5_LEN);
		}
	}

_CHUNK_FILE_PROCESS_EXIT:
	close(fd);
	return ret;
}

uint32_t LCS(char** a, int n, char** b, int m, hashtable *htab) 
{
        int** S;
        int** R;

        int ii;
        int jj;

        int pos;
        uint32_t len = 0;
	hash_entry *he = NULL;

	/* Memory allocation */
        S = (int **)malloc( (n+1) * sizeof(int *) );
        R = (int **)malloc( (n+1) * sizeof(int *) );
	if (S == NULL || R == NULL) {
		perror("malloc for S and R in LCS");
		exit(0);
	}

        for(ii = 0; ii <= n; ++ii) {
                S[ii] = (int*) malloc( (m+1) * sizeof(int) );
                R[ii] = (int*) malloc( (m+1) * sizeof(int) );
		if (S[ii] == NULL || R[ii] == NULL) {
			perror("malloc for S[ii] and R[ii] in LCS");
			exit(0);
		}
        }

        /* It is important to use <=, not <.  The next two for-loops are initialization */
        for(ii = 0; ii <= n; ++ii) {
                S[ii][0] = 0;
                R[ii][0] = UP;
        }
        for(jj = 0; jj <= m; ++jj) {
                S[0][jj] = 0;
                R[0][jj] = LEFT;
        }

        /* This is the main dynamic programming loop that computes the score and */
        /* backtracking arrays. */
        for(ii = 1; ii <= n; ++ii) {
                for(jj = 1; jj <= m; ++jj) {

                        if (strcmp(a[ii-1], b[jj-1]) == 0) {
                                S[ii][jj] = S[ii-1][jj-1] + 1;
                                R[ii][jj] = UP_AND_LEFT;
                        }

                        else {
                                S[ii][jj] = S[ii-1][jj-1] + 0;
                                R[ii][jj] = NEITHER;
                        }

                        if( S[ii-1][jj] >= S[ii][jj] ) {
                                S[ii][jj] = S[ii-1][jj];
                                R[ii][jj] = UP;
                        }

                        if( S[ii][jj-1] >= S[ii][jj] ) {
                                S[ii][jj] = S[ii][jj-1];
                                R[ii][jj] = LEFT;
                        }
                }
        }

        /* The length of the longest substring is S[n][m] */
        ii = n;
        jj = m;
        pos = S[ii][jj];

        /* Trace the backtracking matrix. */
        while( ii > 0 || jj > 0 ) {
                if( R[ii][jj] == UP_AND_LEFT ) {
                        ii--;
                        jj--;
                        //lcs[pos--] = a[ii];
			he = (hash_entry *)hash_value((void *)a[ii], htab);
			len += ((he == NULL) ? 0: he->len);
                }

                else if( R[ii][jj] == UP ) {
                        ii--;
                }

                else if( R[ii][jj] == LEFT ) {
                        jj--;
                }
        }

        for(ii = 0; ii <= n; ++ii ) {
                free(S[ii]);
                free(R[ii]);
        }
        free(S);
        free(R);

	return len;
}

int hash_callback(void *key, void *data)
{
	hash_entry *he = (hash_entry *)data;
	sim_union += (he->len * (he->nr1 + he->nr2));
	sim_intersect += (he->len * MIN(he->nr1, he->nr2));
}

static float similarity_detect(hashtable *htab, char **str1, int n, char **str2, int m, int sim_algo)
{
	uint32_t lcs_len = 0;
	hash_for_each_do(htab, hash_callback);
	if (sim_algo == LCS_YES) {
		lcs_len = LCS(str1, n, str2, m, htab);
		return lcs_len * 2.0 / sim_union;
	} else { /* LCS_NOT */
		return sim_intersect * 2.0 / sim_union;
	}
}

int main(int argc, char *argv[])
{
	int chunk_algo = CHUNK_CDC;
	int sim_algo = LCS_NOT;
	char *file1 = NULL;
	char *file2 = NULL;
	lcs_entry le1, le2;
	char tmpname[NAME_MAX_SZ] = {0};
	char template[] = "deduputil_bsim_XXXXXX";
	hashtable *htab = NULL;
	int ret = 0;

	if (argc < 5) {
		usage();
		return -1;
	}

	/* parse chunk algorithms */
	file1 = argv[1];
	file2 = argv[2];
	chunk_algo = parse_arg(argv[3]);
	sim_algo = parse_arg(argv[4]);
	if (chunk_algo == -1 || sim_algo == -1) {
		usage();
		return -1;
	}

	htab = create_hashtable(HASHTABLE_BUCKET_SZ);
	if (htab == NULL) {
		fprintf(stderr, "create hashtabke failed\n");
		return -1;
	}

	/* chunk file1 and file2 into blocks */
	sprintf(tmpname, "/tmp/%s_%d", mktemp(template), getpid());
	ret = file_chunk(file1, tmpname, chunk_algo);
	if (0 != ret) {
		fprintf(stderr, "chunk %s failed\n", file1);
		goto _BENCODE_EXIT;
	}
	le1.str = NULL;
	ret = chunk_file_process(tmpname, htab, FILE1, sim_algo, &le1);
	if (ret != 0) {
		fprintf(stderr, "pasre %s failed\n", file1);
		goto _BENCODE_EXIT;
	}

	ret = file_chunk(file2, tmpname, chunk_algo);
	if (0 != ret){
		fprintf(stderr, "chunk %s failed\n", file2);
		goto _BENCODE_EXIT;
	}
	le2.str = NULL;
	ret = chunk_file_process(tmpname, htab, FILE2, sim_algo, &le2);
	if (ret != 0) {
		fprintf(stderr, "pasre %s failed\n", file2);
		goto _BENCODE_EXIT;
	}

	fprintf(stderr, "similarity = %.4f\n", similarity_detect(htab, le1.str, le1.len, le2.str, le2.len, sim_algo));

_BENCODE_EXIT:
	unlink(tmpname);
	hash_free(htab);
	if (le1.str) free_2d_array(le1.str);
	if (le2.str) free_2d_array(le2.str);
	return ret;
}
