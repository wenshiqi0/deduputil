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
#include "dedup.h"

void usage()
{
	printf("Usage: dedup [OPTION...] [FILE]...\n");
	printf("dedup util packages files with deduplicaton technique.\n\n");
	printf("Examples:\n");
	printf("  dedup -c foobar.ded foo bar    # Create foobar.ded from files foo and bar.\n");
	printf("  dedup -a foobar.ded foo1 bar1  # Append files foo1 and bar1 into foobar.ded.\n");
	printf("  dedup -r foobar.ded foo1 bar1  # Remove files foo1 and bar1 from foobar.ded.\n");
	printf("  dedup -t foobar.ded            # List all files in foobar.ded.\n");
	printf("  dedup -x foobar.ded            # Extract all files from foobar.ded.\n\n");
	printf("Options:\n");
	printf("  -c, --creat      create a new archive\n");
	printf("  -x, --extract    extrace files from an archive\n");
	printf("  -a, --append     append files to an archive\n");
	printf("  -r, --remove     remove files from an archive\n");
	printf("  -t, --list       list files in an archive\n");
	printf("  -C, --chunk      chunk algorithms: FSP, CDC, SB, default is FSP\n");
	printf("  -z, --compress   filter the archive through zlib compression\n");
	printf("  -b, --block      block size for deduplication, default is 4096\n");
	printf("  -H, --hashtable  hashtable backet number, default is 10240\n");
	printf("  -d, --directory  change to directory, default is PWD\n");
	printf("  -v, --verbose    print verbose messages\n");
	printf("  -h, --help       give this help list\n\n");
	printf("Report bugs to <Aigui.Liu@gmail.com>.\n");
}

int main(int argc, char *argv[])
{
	int bhelp = 0, i;
	int chunk = DEDUP_CHUNK_FSP;

	for (i = 0; i < argc; i++)
	{
		if (strcmp(argv[i], "-C") == 0 || strcmp(argv[i], "--chunk") == 0)
		{
			if (strcmp(argv[i+1], CHUNK_FSP) == 0)
				chunk = DEDUP_CHUNK_FSP;
			else if (strcmp(argv[i+1], CHUNK_CDC) == 0)
				chunk = DEDUP_CHUNK_CDC;
			else if (strcmp(argv[i+1], CHUNK_SB) == 0)
				chunk = DEDUP_CHUNK_SB;
			else
				chunk = -1;
			break;
		}
	}

	switch (chunk)
	{
	case DEDUP_CHUNK_FSP:
		dedup_fsp(argc, argv);
		break;
	case DEDUP_CHUNK_CDC:
	case DEDUP_CHUNK_SB:
	default:
		usage();
	}

	return 0;
}
