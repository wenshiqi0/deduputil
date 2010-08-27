#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include "hashtable.h"
#include "sync.h"

#define MAX(x, y) (((x) > (y)) ? (x) : (y))
#define MIN(x, y) (((x) < (y)) ? (x) : (y))

enum {
	FILE1 = 0,
	FILE2
};

typedef struct {
	uint32_t nr1;
	uint32_t nr2;
	uint32_t len;
} hash_entry;

static uint32_t sim_union = 0;
static uint32_t sim_intersect = 0;

static void usage()
{
	fprintf(stderr, "Usage: bsim FILE1 FILE2 [CHUNK_ALGO]\n\n");
	fprintf(stderr, "Similarity detect between FILE1 and FILE2 based on block level.\n");
	fprintf(stderr, "CHUNK_ALGO:\n");
	fprintf(stderr, "  FSP - fixed-size partition\n");
	fprintf(stderr, "  CDC - content-defined chunking, as default\n");
	fprintf(stderr, "  SBC - slide block chunking\n\n");
	fprintf(stderr, "Report bugs to <Aigui.Liu@gmail.com>.\n");
}

static int parse_chunk_algo(char *chunk_algo)
{
	if (0 == strcmp(chunk_algo, "FSP"))
		return CHUNK_FSP;
	else if (0 == strcmp(chunk_algo, "CDC"))
		return CHUNK_CDC;
	else if (0 == strcmp(chunk_algo, "SBC"))
		return CHUNK_SBC;
	else 
		return -1;
}

static int chunk_file_process(char *chunk_file, hashtable *htab, int which)
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
	}

_CHUNK_FILE_PROCESS_EXIT:
	close(fd);
	return ret;
}

int hash_callback(void *key, void *data)
{
	hash_entry *he = (hash_entry *)data;
	//sim_union += (he->len * MAX(he->nr1, he->nr2));
	sim_union += he->len;
	//sim_intersect += (he->len * MIN(he->nr1, he->nr2));
	if (he->nr1 && he->nr2)
		sim_intersect += he->len;
}

static float similarity_detect(hashtable *htab)
{
	hash_for_each_do(htab, hash_callback);
	return sim_intersect * 1.0 / sim_union;
}

int main(int argc, char *argv[])
{
	int chunk_algo = CHUNK_CDC;
	char *file1 = NULL;
	char *file2 = NULL;
	char tmpname[NAME_MAX_SZ] = {0};
	char template[] = "dedup_XXXXXX";
	hashtable *htab = NULL;
	int ret = 0;

	if (argc < 3) {
		usage();
		return -1;
	}

	/* parse chunk algorithms */
	file1 = argv[1];
	file2 = argv[2];
	if (argc >= 4) {
		chunk_algo = parse_chunk_algo(argv[3]);
		if (chunk_algo == -1) {
			usage();
			return -1;
		}
	}

	htab = create_hashtable(HASHTABLE_BUCKET_SZ);
	if (htab == NULL) {
		fprintf(stderr, "create hashtabke failed\n");
		return -1;
	}

	/* chunk file1 and file2 into blocks */
	sprintf(tmpname, "/tmp/%s_%d", mktemp(template), getpid());
	ret = file_chunk(file1, tmpname, chunk_algo);
	if (0 != ret){
		fprintf(stderr, "chunk %s failed\n", file1);
		goto _BENCODE_EXIT;
	}
	chunk_file_process(tmpname, htab, FILE1);

	ret = file_chunk(file2, tmpname, chunk_algo);
	if (0 != ret){
		fprintf(stderr, "chunk %s failed\n", file2);
		goto _BENCODE_EXIT;
	}
	chunk_file_process(tmpname, htab, FILE2);
	fprintf(stderr, "similarity = %.4f\n", similarity_detect(htab));
	printf("%d : %d\n", sim_intersect, sim_union);

_BENCODE_EXIT:
	unlink(tmpname);
	hash_free(htab);
	return ret;
}
