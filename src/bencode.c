#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include "sync.h"

void usage()
{
	fprintf(stderr, "Usage: bencode FILE [CHUNK_ALGO]\n");
	fprintf(stderr, "Encode file into fingerprint lists based on chunks\n\n");
	fprintf(stderr, "CHUNK_ALGO:\n");
	fprintf(stderr, "  FSP - fixed-size partition\n");
	fprintf(stderr, "  CDC - content-defined chunking, as default\n");
	fprintf(stderr, "  SBC - slide block chunking\n\n");
	fprintf(stderr, "Report bugs to <Aigui.Liu@gmail.com>.\n");
}

int parse_chunk_algo(char *chunk_algo)
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

int main(int argc, char *argv[])
{
	int chunk_algo = CHUNK_CDC;
	char *src = NULL;
	char tmpname[NAME_MAX_SZ] = {0};
	char template[] = "dedup_XXXXXX";
	int ret = 0;

	if (argc < 2) {
		usage();
		return -1;
	}

	src = argv[1];
	if (argc >= 3) {
		chunk_algo = parse_chunk_algo(argv[2]);
		if (chunk_algo == -1) {
			usage();
			return -1;
		}
	}

	sprintf(tmpname, "/tmp/%s_%d", mktemp(template), getpid());
	fprintf(stderr, "%s\n", tmpname);
	ret = file_chunk(src, tmpname, chunk_algo);
	if (0 != ret){
		fprintf(stderr, "chunk file failed\n");
		goto _BENCODE_EXIT;
	}

_BENCODE_EXIT:
	unlink(tmpname);
	return ret;
}
