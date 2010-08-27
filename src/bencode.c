#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include "sync.h"

static void usage()
{
	fprintf(stderr, "Usage: bencode FILE [CHUNK_ALGO]\n\n");
	fprintf(stderr, "Encode file into fingerprint lists based on chunks.\n");
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

static void show_md5_hex(unsigned char md5_checksum[16])
{	
	int i;
	for (i = 0; i < 16; i++) {
		printf("%02x", md5_checksum[i]);
	}
	printf("\n");
}

int main(int argc, char *argv[])
{
	int chunk_algo = CHUNK_CDC;
	char *src = NULL;
	char tmpname[NAME_MAX_SZ] = {0};
	char template[] = "dedup_XXXXXX";
	int ret = 0, fd, i;
	ssize_t rwsize;
	chunk_file_header chunk_file_hdr;
	chunk_block_entry chunk_bentry;

	if (argc < 2) {
		usage();
		return -1;
	}

	/* parse chunk algorithms */
	src = argv[1];
	if (argc >= 3) {
		chunk_algo = parse_chunk_algo(argv[2]);
		if (chunk_algo == -1) {
			usage();
			return -1;
		}
	}

	/* chunk file into blocks */
	sprintf(tmpname, "/tmp/%s_%d", mktemp(template), getpid());
	ret = file_chunk(src, tmpname, chunk_algo);
	if (0 != ret){
		fprintf(stderr, "chunk file failed\n");
		goto _BENCODE_EXIT;
	}

	/* parse chunk file */
	fd = open(tmpname, O_RDONLY);
	if (-1 == fd) {
		ret = -1;
		goto _BENCODE_EXIT;
	}

	rwsize = read(fd, &chunk_file_hdr, CHUNK_FILE_HEADER_SZ);
	if (rwsize != CHUNK_FILE_HEADER_SZ) {
		ret = -1;
		goto _BENCODE_EXIT;
	}
	for(i = 0; i < chunk_file_hdr.block_nr; i++) {
		rwsize = read(fd, &chunk_bentry, CHUNK_BLOCK_ENTRY_SZ);
		if (rwsize != CHUNK_BLOCK_ENTRY_SZ) {
			ret = -1;
			goto _BENCODE_EXIT;
		}
		show_md5_hex(chunk_bentry.md5);
	}

_BENCODE_EXIT:
	close(fd);
	unlink(tmpname);
	return ret;
}
