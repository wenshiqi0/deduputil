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

/* unique block number in package */
static unsigned int g_unique_block_nr = 0;

/* regular file number in package */
static unsigned int g_regular_file_nr = 0;

/* block length */
static unsigned int g_block_size = BLOCK_SIZE;

/* hashtable backet number */
static unsigned int g_htab_backet_nr = BACKET_SIZE;

/* hashtable for pathnames */
static hashtable *g_htable = NULL;

static int filename_exist(char *filename)
{
	return (NULL == hash_value((void *)filename, g_htable)) ? 0 : 1;
}

static int filename_checkin(char *filename)
{
	unsigned int *flag = NULL;

	flag = (unsigned int *) malloc (sizeof(unsigned int));
	if (NULL == flag)
	{
		perror("malloc in filename_checkin");
		return errno;
	}

	*flag = 1;
	hash_insert((void *)strdup(filename), (void *)flag, g_htable);

	return 0;
}

void show_md5(unsigned char md5_checksum[16])
{
	int i;
	for (i = 0; i < 16; i++)
	{
        	printf("%02x", md5_checksum[i]);
	}
}

void show_pkg_header(dedup_package_header dedup_pkg_hdr)
{
        printf("block_size = %d\n", dedup_pkg_hdr.block_size);
        printf("block_num = %d\n", dedup_pkg_hdr.block_num);
	printf("blockid_size = %d\n", dedup_pkg_hdr.blockid_size);
	printf("magic_num = 0x%x\n", dedup_pkg_hdr.magic_num);
	printf("file_num = %d\n", dedup_pkg_hdr.file_num);
	printf("metadata_offset = %lld\n\n", dedup_pkg_hdr.metadata_offset);
}

int block_cmp(char *buf, int fd_bdata, unsigned int bindex, unsigned int len)
{
	int i, ret = 0;
	char *block_buf = NULL;

	if (-1 == lseek(fd_bdata, bindex * len, SEEK_SET))
	{
		perror("lseek in block_cmp");
		ret = -1;
		goto _BLOCK_CMP_EXIT;
	}

	block_buf = (char *)malloc(len);
	if (NULL == block_buf)
	{
		perror("malloc in block_cmp");
		ret = -1;
		goto _BLOCK_CMP_EXIT;
	}

	if (len != read(fd_bdata, block_buf, len))
	{
		perror("read in block_cmp");
		ret = -1;
		goto _BLOCK_CMP_EXIT;
	}

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
	lseek(fd_bdata, 0, SEEK_END);
	return ret;
}

int dedup_regfile(char *fullpath, int prepos, int fd_bdata, int fd_mdata, hashtable *htable, int verbose)
{
	int fd;
	char *buf = NULL;
	unsigned int rwsize, pos;
	unsigned char md5_checksum[16 + 1] = {0};
	unsigned int *metadata = NULL;
	unsigned int block_num = 0;
	struct stat statbuf;
	dedup_entry_header dedup_entry_hdr;


	/* check if the filename already exists */
	if (filename_exist(fullpath))
	{
		if (verbose) printf("Warning: %s already exists in package\n", fullpath);
		return 0;
	} 

	if (-1 == (fd = open(fullpath, O_RDONLY)))
	{
		perror("open regulae file");
		return errno;
	}

	if (-1 == fstat(fd, &statbuf))
	{
		perror("fstat regular file");
		goto _DEDUP_REGFILE_EXIT;
	}
	block_num = statbuf.st_size / g_block_size;

	metadata = (unsigned int *)malloc(BLOCK_ID_SIZE * block_num);
	if (metadata == NULL)
	{
		perror("malloc metadata for regfile");
		goto _DEDUP_REGFILE_EXIT;
	}

	buf = (char *)malloc(g_block_size);
	if (buf == NULL)
	{
		perror("malloc buf for regfile");
		goto _DEDUP_REGFILE_EXIT;
	}

	pos = 0;
	while (rwsize = read(fd, buf, g_block_size)) 
	{
		/* if the last block */
		if (rwsize != g_block_size)
			break;

		/* calculate md5 */
		md5(buf, rwsize, md5_checksum);

		/* check hashtable with hashkey 
		   NOTE: no md5 collsion problem, but lose some performace 
		   hashtable entry format: (md5_key, block_id list)
		   +--------------------------------+
		   | id num | id1 | id2 | ... | idn |
		   +--------------------------------+
		*/
		unsigned int cbindex;
		int bflag = 0;
		unsigned int *bindex = (block_id_t *)hash_value((void *)md5_checksum, htable);

		/* the block exists */
		if (bindex != NULL)
		{
			int i;
			for (i = 0; i < *bindex; i++)
			{
				if (0 == block_cmp(buf, fd_bdata, *(bindex + i + 1), g_block_size))
				{
					cbindex = *(bindex + i + 1);
					bflag = 1;
					break;
				}
			}
		}

		/* insert hash entry and write unique block into bdata*/
		if (bindex == NULL || (bindex != NULL && bflag == 0))
		{
			if (bindex == NULL)
				bflag = 1;

			bindex = (bflag) ? (block_id_t *)malloc(BLOCK_ID_SIZE * 2) :
				(block_id_t *)realloc(bindex, BLOCK_ID_SIZE * ((*bindex) + 1));
			if (NULL == bindex)
			{
				perror("malloc/realloc in dedup_regfile");
				break;
			}

			*bindex = (bflag) ? 1 : (*bindex) + 1;
			*(bindex + *bindex) = g_unique_block_nr;
			cbindex = g_unique_block_nr;
			hash_insert((void *)strdup(md5_checksum), (void *)bindex, htable);
			write(fd_bdata, buf, rwsize);
			g_unique_block_nr++;
		}

		metadata[pos] = cbindex;
		memset(buf, 0, g_block_size);
		memset(md5_checksum, 0, 16 + 1);
		pos++;
	}

	/* write metadata into mdata */
	dedup_entry_hdr.path_len = strlen(fullpath) - prepos;
	dedup_entry_hdr.block_num = block_num;
	dedup_entry_hdr.entry_size = BLOCK_ID_SIZE;
	dedup_entry_hdr.last_block_size = rwsize;
	dedup_entry_hdr.mode = statbuf.st_mode;

	write(fd_mdata, &dedup_entry_hdr, sizeof(dedup_entry_header));
	write(fd_mdata, fullpath + prepos, dedup_entry_hdr.path_len);
	write(fd_mdata, metadata, BLOCK_ID_SIZE * block_num);
	write(fd_mdata, buf, rwsize);

	g_regular_file_nr++;
	filename_checkin(fullpath);

_DEDUP_REGFILE_EXIT:
	close(fd);
	if (metadata) free(metadata);
	if (buf) free(buf);

	return 0;
}

int dedup_dir(char *fullpath, int prepos, int fd_bdata, int fd_mdata, hashtable *htable, int verbose)
{
	DIR *dp;
	struct dirent *dirp;
	struct stat statbuf;
	char subpath[MAX_PATH_LEN] = {0};

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
				printf("%s\n", subpath);

			if (S_ISREG(statbuf.st_mode)) 
				dedup_regfile(subpath, prepos, fd_bdata, fd_mdata, htable,verbose);
			else if (S_ISDIR(statbuf.st_mode))
				dedup_dir(subpath, prepos, fd_bdata, fd_mdata, htable, verbose);
		}
	}
	closedir(dp);

	return 0;
}

int dedup_package_creat(int path_nr, char **src_paths, char *dest_file, int verbose)
{
	int fd, fd_bdata, fd_mdata, ret = 0;
	struct stat statbuf;
	hashtable *htable = NULL;
	dedup_package_header dedup_pkg_hdr;
	char **paths = src_paths;
	int i, rwsize, prepos;
	char buf[1024 * 1024] = {0};

	if (-1 == (fd = open(dest_file, O_WRONLY | O_CREAT, 0755)))
	{
		perror("open dest file");
		ret = errno;
		goto _DEDUP_PKG_CREAT_EXIT;
	}

	htable = create_hashtable(g_htab_backet_nr);
	if (NULL == htable)
	{
		perror("create_hashtable");
		ret = errno;
		goto _DEDUP_PKG_CREAT_EXIT;
	}

	fd_bdata = open(BDATA_FILE, O_RDWR | O_CREAT, 0777);
	fd_mdata = open(MDATA_FILE, O_RDWR | O_CREAT, 0777);
	if (-1 == fd_bdata || -1 == fd_mdata)
	{
		perror("open bdata or mdata");
		ret = errno;
		goto _DEDUP_PKG_CREAT_EXIT;
	}

	g_unique_block_nr = 0;
	g_regular_file_nr = 0;
	for (i = 0; i < path_nr; i++)
	{
		if (lstat(paths[i], &statbuf) < 0)
		{
			perror("lstat source path");
			ret = errno;
			goto _DEDUP_PKG_CREAT_EXIT;
		}

		if (S_ISREG(statbuf.st_mode) || S_ISDIR(statbuf.st_mode))
		{
			if (verbose)
				printf("%s\n", paths[i]);
			/* get filename position in pathname */	
			prepos = strlen(paths[i]) - 1;
			if (strcmp(paths[i], "/") != 0 && *(paths[i] + prepos) == '/')
			{
				*(paths[i] + prepos--) = '\0';
			}
			while(*(paths[i] + prepos) != '/' && prepos >= 0) prepos--;
			prepos++;

			if (S_ISREG(statbuf.st_mode))
				dedup_regfile(paths[i], prepos, fd_bdata, fd_mdata, htable, verbose);
			else
				dedup_dir(paths[i], prepos, fd_bdata, fd_mdata, htable, verbose);
		}	
		else 
		{
			if (verbose)
				printf("%s is not regular file or directory.\n", paths[i]);
		}
	}

	/* fill up dedup package header */
	dedup_pkg_hdr.block_size = g_block_size;
	dedup_pkg_hdr.block_num = g_unique_block_nr;
	dedup_pkg_hdr.blockid_size = BLOCK_ID_SIZE;
	dedup_pkg_hdr.magic_num = DEDUP_MAGIC_NUM;
	dedup_pkg_hdr.file_num = g_regular_file_nr; 
	dedup_pkg_hdr.metadata_offset = DEDUP_PKGHDR_SIZE + g_block_size * g_unique_block_nr;
	write(fd, &dedup_pkg_hdr, DEDUP_PKGHDR_SIZE);

	/* fill up dedup package unique blocks*/
	lseek(fd_bdata, 0, SEEK_SET);
	while(rwsize = read(fd_bdata, buf, 1024 * 1024))
	{
		write(fd, buf, rwsize);
		memset(buf, 0, 1024 * 1024);
	}

	/* fill up dedup package metadata */
	lseek(fd_mdata, 0, SEEK_SET);
	while(rwsize = read(fd_mdata, buf, 1024 * 1024))
	{
		write(fd, buf, rwsize);
		memset(buf, 0, 1024 * 1024);
	}

	if (verbose)
		show_pkg_header(dedup_pkg_hdr);

_DEDUP_PKG_CREAT_EXIT:
	close(fd);
	close(fd_bdata);
	close(fd_mdata);
	unlink(BDATA_FILE);
	unlink(MDATA_FILE);
	hash_free(htable);
	
	return ret;
}

int dedup_package_list(char *src_file, int verbose)
{
	int fd, i, ret = 0;
	dedup_package_header dedup_pkg_hdr;
	dedup_entry_header dedup_entry_hdr;
	unsigned long long offset;
	char pathname[MAX_PATH_LEN] = {0};

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

	if (verbose)
		show_pkg_header(dedup_pkg_hdr);

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
		memset(pathname, 0, MAX_PATH_LEN);
		read(fd, pathname, dedup_entry_hdr.path_len);
		printf("%s\n", pathname);

		offset += DEDUP_ENTRYHDR_SIZE;
		offset += dedup_entry_hdr.path_len;
		offset += dedup_entry_hdr.block_num * dedup_entry_hdr.entry_size;
		offset += dedup_entry_hdr.last_block_size;
	}

_DEDUP_PKG_LIST_EXIT:
	close(fd);

	return ret;
}

int dedup_append_prepare(int fd_pkg, int fd_bdata, int fd_mdata,\ 
dedup_package_header *dedup_pkg_hdr, hashtable *htable)
{
	int ret = 0, i;
	unsigned int rwsize = 0;
	char *buf = NULL;
	unsigned char md5_checksum[16 + 1] = {0};
	unsigned int *bindex = NULL;
	dedup_entry_header dedup_entry_hdr;
	unsigned long long offset;
	char pathname[MAX_PATH_LEN] = {0};

	if (read(fd_pkg, dedup_pkg_hdr, DEDUP_PKGHDR_SIZE) != DEDUP_PKGHDR_SIZE)
	{
		perror("read dedup_package_header");
		return errno;
	}

	/* get package header info */
	g_unique_block_nr = dedup_pkg_hdr->block_num;
	g_regular_file_nr = dedup_pkg_hdr->file_num;
	g_block_size = 	dedup_pkg_hdr->block_size;

	/* get bdata and rebuild hashtable */
	buf = (char *)malloc(g_block_size);
	if (buf == NULL)
	{
		ret = -1;
		goto _DEDUP_APPEND_PREPARE_EXIT;
	}

	for(i = 0; i < dedup_pkg_hdr->block_num; i++)
	{
		rwsize = read(fd_pkg, buf, g_block_size);
		if (rwsize != g_block_size)
		{
			ret = -1;
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
                int bflag = 0;
                unsigned int *bindex = (block_id_t *)hash_value((void *)md5_checksum, htable);
		bflag = (bindex == NULL) ? 1 : 0;
		bindex = (bflag) ? (block_id_t *)malloc(BLOCK_ID_SIZE * 2) :
                                (block_id_t *)realloc(bindex, BLOCK_ID_SIZE * ((*bindex) + 1));
                if (NULL == bindex)
                {
			perror("malloc/realloc in dedup_append_prepare");
			ret = -1;
			goto _DEDUP_APPEND_PREPARE_EXIT;
                }

                *bindex = (bflag) ? 1 : (*bindex) + 1;
                *(bindex + *bindex) = i;
                hash_insert((void *)strdup(md5_checksum), (void *)bindex, htable);
	}
	
	/* get mdata */
	offset = dedup_pkg_hdr->metadata_offset;
        for (i = 0; i < dedup_pkg_hdr->file_num; ++i)
        {
                if (lseek(fd_pkg, offset, SEEK_SET) == -1)
                {
                        ret = errno;
                        break;
                }

                if (read(fd_pkg, &dedup_entry_hdr, DEDUP_ENTRYHDR_SIZE) != DEDUP_ENTRYHDR_SIZE)
                {
                        ret = errno;
                        break;
                }

                /* read pathname from  deduped package opened */
                memset(pathname, 0, MAX_PATH_LEN);
                read(fd_pkg, pathname, dedup_entry_hdr.path_len);
		if (0 == filename_exist(pathname))
			filename_checkin(pathname);

                offset += DEDUP_ENTRYHDR_SIZE;
                offset += dedup_entry_hdr.path_len;
                offset += dedup_entry_hdr.block_num * dedup_entry_hdr.entry_size;
                offset += dedup_entry_hdr.last_block_size;
        }

	if (-1 == lseek(fd_pkg, dedup_pkg_hdr->metadata_offset, SEEK_SET))
		goto _DEDUP_APPEND_PREPARE_EXIT;
	while(rwsize = read(fd_pkg, buf, g_block_size))
	{
		write(fd_mdata, buf, rwsize);
	}

_DEDUP_APPEND_PREPARE_EXIT:
	if (buf) free(buf);
	return ret;
}

int dedup_package_append(int path_nr, char **src_paths, char *dest_file, int verbose)
{
	int fd, fd_bdata, fd_mdata, ret = 0;
	struct stat statbuf;
	hashtable *htable = NULL;
	dedup_package_header dedup_pkg_hdr;
	char **paths = src_paths;
	int i, rwsize, prepos;
	char buf[1024 * 1024] = {0};

	if (-1 == (fd = open(dest_file, O_RDWR | O_CREAT, 0755)))
	{
		perror("open dest file");
		ret = errno;
		goto _DEDUP_PKG_APPEND_EXIT;
	}

	htable = create_hashtable(g_htab_backet_nr);
	if (NULL == htable)
	{
		perror("create_hashtable");
		ret = errno;
		goto _DEDUP_PKG_APPEND_EXIT;
	}

	if (-1 == (fd_bdata = open(BDATA_FILE, O_RDWR | O_CREAT, 0777)))
	{
		perror("open bdata");
		ret = errno;
		goto _DEDUP_PKG_APPEND_EXIT;
	}

	if (-1 == (fd_mdata = open(MDATA_FILE, O_RDWR | O_CREAT, 0777)))
	{
		perror("open mdata");
		ret = errno;
		goto _DEDUP_PKG_APPEND_EXIT;
	}

	/* get global information from package */
	ret = dedup_append_prepare(fd, fd_bdata, fd_mdata, &dedup_pkg_hdr, htable);
	if (ret != 0)
		goto _DEDUP_PKG_APPEND_EXIT;
	if (verbose)
		show_pkg_header(dedup_pkg_hdr);

	/* add files into package */
	for (i = 0; i < path_nr; i++)
	{
		if (lstat(paths[i], &statbuf) < 0)
		{
			perror("lstat source path");
			ret = errno;
			goto _DEDUP_PKG_APPEND_EXIT;
		}

		if (S_ISREG(statbuf.st_mode) || S_ISDIR(statbuf.st_mode))
		{
			if (verbose)
				printf("%s\n", paths[i]);
			/* get filename position in pathname */	
			prepos = strlen(paths[i]) - 1;
			if (strcmp(paths[i], "/") != 0 && *(paths[i] + prepos) == '/')
			{
				*(paths[i] + prepos--) = '\0';
			}
			while(*(paths[i] + prepos) != '/' && prepos >= 0) prepos--;
			prepos++;

			if (S_ISREG(statbuf.st_mode))
				dedup_regfile(paths[i], prepos, fd_bdata, fd_mdata, htable, verbose);
			else
				dedup_dir(paths[i], prepos, fd_bdata, fd_mdata, htable, verbose);
		}	
		else 
		{
			if (verbose)
				printf("%s is not regular file or directory.\n", paths[i]);
		}
	}

	/* fill up dedup package header */
	dedup_pkg_hdr.block_size = g_block_size;
	dedup_pkg_hdr.block_num = g_unique_block_nr;
	dedup_pkg_hdr.blockid_size = BLOCK_ID_SIZE;
	dedup_pkg_hdr.magic_num = DEDUP_MAGIC_NUM;
	dedup_pkg_hdr.file_num = g_regular_file_nr; 
	dedup_pkg_hdr.metadata_offset = DEDUP_PKGHDR_SIZE + g_block_size * g_unique_block_nr;
	lseek(fd, 0, SEEK_SET);
	write(fd, &dedup_pkg_hdr, DEDUP_PKGHDR_SIZE);

	/* fill up dedup package unique blocks*/
	lseek(fd_bdata, 0, SEEK_SET);
	while(rwsize = read(fd_bdata, buf, 1024 * 1024))
	{
		write(fd, buf, rwsize);
		memset(buf, 0, 1024 * 1024);
	}

	/* fill up dedup package metadata */
	lseek(fd_mdata, 0, SEEK_SET);
	while(rwsize = read(fd_mdata, buf, 1024 * 1024))
	{
		write(fd, buf, rwsize);
		memset(buf, 0, 1024 * 1024);
	}

	if (verbose)
		show_pkg_header(dedup_pkg_hdr);

_DEDUP_PKG_APPEND_EXIT:
	close(fd);
	close(fd_bdata);
	close(fd_mdata);
	unlink(BDATA_FILE);
	unlink(MDATA_FILE);
	hash_free(htable);
	
	return ret;
}

int file_in_lists(char *filepath, int files_nr, char **files_list)
{
	int i;

	for (i = 0; i < files_nr; i++)
	{
		if (0 == strcmp(filepath, files_list[i]))
			return 0;
	}

	return -1;
}

int dedup_package_remove(char *file_pkg, int files_nr, char **files_remove, int verbose)
{
	int fd_pkg, fd_bdata, fd_mdata, ret = 0;
	dedup_package_header dedup_pkg_hdr;
	dedup_entry_header dedup_entry_hdr;
	int i, j, rwsize;
	int remove_block_nr = 0, remove_file_nr = 0;
	char buf[1024 * 1024] = {0};
	char *block_buf = NULL;
	block_id_t *lookup_table = NULL;
	block_id_t *metadata = NULL;
	block_id_t TOBE_REMOVED;
	unsigned long long offset;
	char pathname[MAX_PATH_LEN] = {0};

	/* open files */
	if (-1 == (fd_pkg = open(file_pkg, O_RDWR | O_CREAT, 0755)))
	{
		perror("open package file");
		ret = errno;
		goto _DEDUP_PKG_REMOVE_EXIT;
	}

	if (-1 == (fd_bdata = open(BDATA_FILE, O_RDWR | O_CREAT, 0777)))
	{
		perror("open bdata file");
		ret = errno;
		goto _DEDUP_PKG_REMOVE_EXIT;
	}

	if (-1 == (fd_mdata = open(MDATA_FILE, O_RDWR | O_CREAT, 0777)))
	{
		perror("open mdata file");
		ret = errno;
		goto _DEDUP_PKG_REMOVE_EXIT;
	}

	/* get global information from package */
	if (read(fd_pkg, &dedup_pkg_hdr, DEDUP_PKGHDR_SIZE) != DEDUP_PKGHDR_SIZE)
        {
                perror("read dedup_package_header");
                ret = errno;
		goto _DEDUP_PKG_REMOVE_EXIT;
	}
	g_unique_block_nr = dedup_pkg_hdr.block_num;
	g_regular_file_nr = dedup_pkg_hdr.file_num;
	g_block_size = dedup_pkg_hdr.block_size;
	TOBE_REMOVED = g_unique_block_nr;
	if (verbose)
		show_pkg_header(dedup_pkg_hdr);

	/* traverse mdata to build lookup_table */
	lookup_table = (block_id_t *)malloc(BLOCK_ID_SIZE * g_unique_block_nr);
	if (lookup_table == NULL)
	{
		perror("malloc lookup_table");
		ret = errno;
		goto _DEDUP_PKG_REMOVE_EXIT;
	}
	for (i = 0; i < g_unique_block_nr; i++)
		lookup_table[i] = 0;

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
		
		memset(pathname, 0, MAX_PATH_LEN);
		read(fd_pkg, pathname, dedup_entry_hdr.path_len);
		/* discard file to be removed */
		if (file_in_lists(pathname, files_nr, files_remove) != 0)
		{
			metadata = (block_id_t *)malloc(BLOCK_ID_SIZE * dedup_entry_hdr.block_num);
			if (NULL == metadata)
			{
				ret = errno;
				goto _DEDUP_PKG_REMOVE_EXIT;
			}
			read(fd_pkg, metadata, BLOCK_ID_SIZE * dedup_entry_hdr.block_num);
			for (j = 0; j < dedup_entry_hdr.block_num; j++)
				lookup_table[metadata[j]]++;
			if (metadata) free(metadata);
		}

		offset += DEDUP_ENTRYHDR_SIZE;
		offset += dedup_entry_hdr.path_len;
		offset += dedup_entry_hdr.block_num * dedup_entry_hdr.entry_size;
		offset += dedup_entry_hdr.last_block_size;
	}

	/* rebuild block number and bdata */
	remove_block_nr = 0;
	block_buf = (char *)malloc(g_block_size);
	if (block_buf == NULL)
	{
		ret = errno;
		goto _DEDUP_PKG_REMOVE_EXIT;
	}
	for (i = 0; i < g_unique_block_nr; i++)
	{
		if (lookup_table[i] == 0)
		{
			lookup_table[i] = TOBE_REMOVED;
			remove_block_nr++;
		}
		else
		{
			lookup_table[i] = i - remove_block_nr;
			lseek(fd_pkg, DEDUP_PKGHDR_SIZE + i * g_block_size, SEEK_SET);
			read(fd_pkg, block_buf, g_block_size);
			write(fd_bdata, block_buf, g_block_size);
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
		
		memset(pathname, 0, MAX_PATH_LEN);
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
				metadata[j] = lookup_table[metadata[j]];
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
	dedup_pkg_hdr.metadata_offset = DEDUP_PKGHDR_SIZE + g_block_size * dedup_pkg_hdr.block_num;
	
	ftruncate(fd_pkg, 0);
	lseek(fd_pkg, 0, SEEK_SET);
	write(fd_pkg, &dedup_pkg_hdr, DEDUP_PKGHDR_SIZE);

	/* write bdata back*/
	lseek(fd_bdata, 0, SEEK_SET);
	while(rwsize = read(fd_bdata, buf, 1024 * 1024))
	{
		write(fd_pkg, buf, rwsize);
		memset(buf, 0, 1024 * 1024);
	}

	/* write mdata back */
	lseek(fd_mdata, 0, SEEK_SET);
	while(rwsize = read(fd_mdata, buf, 1024 * 1024))
	{
		write(fd_pkg, buf, rwsize);
		memset(buf, 0, 1024 * 1024);
	}

	if (verbose)
		show_pkg_header(dedup_pkg_hdr);

_DEDUP_PKG_REMOVE_EXIT:
	if (fd_pkg) close(fd_pkg);
	if (fd_bdata) close(fd_bdata);
	if (fd_mdata) close(fd_mdata);
	unlink(BDATA_FILE);
	unlink(MDATA_FILE);
	if (lookup_table) free(lookup_table);
	if (block_buf) free(block_buf);
	
	return ret;
}

int prepare_target_file(char *pathname, char *basepath, int mode)
{
	char fullpath[MAX_PATH_LEN] = {0};
	char path[MAX_PATH_LEN] = {0};
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

int undedup_regfile(int fd, dedup_entry_header dedup_entry_hdr, char *dest_dir, int verbose)
{
	char pathname[MAX_PATH_LEN] = {0};
	block_id_t *metadata = NULL;
	unsigned int block_num = 0;
	char *buf = NULL;
	char *last_block_buf = NULL;
	long long offset, i;
	int fd_dest, ret = 0;

	metadata = (block_id_t *) malloc(BLOCK_ID_SIZE * dedup_entry_hdr.block_num);
	if (NULL == metadata)
		return errno;

	buf = (char *)malloc(g_block_size);
	last_block_buf = (char *)malloc(g_block_size);
	if (NULL == buf || NULL == last_block_buf)
	{
		ret = errno;
		goto _UNDEDUP_REGFILE_EXIT;
	}

	read(fd, pathname, dedup_entry_hdr.path_len);
	read(fd, metadata, BLOCK_ID_SIZE * dedup_entry_hdr.block_num);
	read(fd, last_block_buf, dedup_entry_hdr.last_block_size);
	fd_dest = prepare_target_file(pathname, dest_dir, dedup_entry_hdr.mode);
	if (fd_dest == -1)
	{
		ret = errno;
		goto _UNDEDUP_REGFILE_EXIT;
	}

	if (verbose)
		printf("%s/%s\n", dest_dir, pathname);

	/* write regular block */
	block_num = dedup_entry_hdr.block_num;
	for(i = 0; i < block_num; ++i)
	{
		offset = DEDUP_PKGHDR_SIZE + metadata[i] * g_block_size;
		lseek(fd, offset, SEEK_SET);
		read(fd, buf, g_block_size);
		write(fd_dest, buf, g_block_size);
	}
	/* write last block */
	write(fd_dest, last_block_buf, dedup_entry_hdr.last_block_size);
	close(fd_dest);

_UNDEDUP_REGFILE_EXIT:
	if (metadata) free(metadata);
	if (buf) free(buf);
	if (last_block_buf) free(last_block_buf);

	return ret;
}

int dedup_package_extract(char *src_file, char *subpath, char *dest_dir, int verbose)
{
	int fd, i, ret = 0;
	dedup_package_header dedup_pkg_hdr;
	dedup_entry_header dedup_entry_hdr;
	unsigned long long offset;
	char pathname[MAX_PATH_LEN] = {0};

        if (-1 == (fd = open(src_file, O_RDONLY)))
        {
                perror("open source file");
                return errno;
        }

	if (read(fd, &dedup_pkg_hdr, DEDUP_PKGHDR_SIZE) != DEDUP_PKGHDR_SIZE)
	{
		perror("read dedup_package_header");
		ret = errno;
		goto _DEDUP_PKG_EXTRACT_EXIT;
	}

	if (verbose)
		show_pkg_header(dedup_pkg_hdr);
	g_block_size = dedup_pkg_hdr.block_size;

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

		/* extract all files */
		if (subpath == NULL)
		{
			ret = undedup_regfile(fd, dedup_entry_hdr, dest_dir, verbose);
			if (ret != 0)
				break;
		}
		else
		/* extract specific file */
		{
			memset(pathname, 0, MAX_PATH_LEN);
			read(fd, pathname, dedup_entry_hdr.path_len);
			lseek(fd, offset + DEDUP_ENTRYHDR_SIZE, SEEK_SET);
			if (strcmp(pathname, subpath) == 0)
			{
				ret = undedup_regfile(fd, dedup_entry_hdr, dest_dir, verbose);
				break;
			}
		}

		offset += DEDUP_ENTRYHDR_SIZE;
		offset += dedup_entry_hdr.path_len;
		offset += dedup_entry_hdr.block_num * dedup_entry_hdr.entry_size;
		offset += dedup_entry_hdr.last_block_size;
	}

_DEDUP_PKG_EXTRACT_EXIT:
	close(fd);

	return ret;
}

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
	int bz = 0, bhelp = 0, bverbose = 0;
	int ret = -1, c;
	int dedup_op = -1, dedup_op_nr = 0;
	int args_nr = 0;
	char tmp_file[MAX_PATH_LEN] = TMP_FILE;
	char path[MAX_PATH_LEN] = ".\0";
	char *subpath = NULL;

	struct option longopts[] =
	{
		{"creat", 1, 0, 'c'},
		{"extract", 1, 0, 'x'},
		{"append", 1, 0, 'a'},
		{"remove", 1, 0, 'r'},
		{"list", 1, 0, 't'},
		{"compress", 0, &bz, 'z'},
		{"block", 1, 0, 'b'},
		{"hashtable", 1, 0, 'H'},
		{"directory", 1, 0, 'd'},
		{"verbose", 0, &bverbose, 'v'},
		{"help", 0, &bhelp, 'h'},
		{0, 0, 0, 0}
	};

	/* parse options */
	while ((c = getopt_long (argc, argv, "cxartzb:H:d:vh", longopts, NULL)) != EOF)
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
		case 'z':
			bz = 1;
			break;
		case 'b':
			g_block_size = atoi(optarg);
			break;
		case 'H':
			g_htab_backet_nr = atoi(optarg);
			break;
		case 'd':
			sprintf(path, "%s", optarg);
			break;
		case 'v':
			bverbose = 1;
			break;
		case 'h':
		case '?':
		default:
			bhelp = 1;
			break;
		}
	}

	if (bhelp == 1 || (dedup_op == -1 || dedup_op_nr != 1) ||(argc - optind) < args_nr)
	{
		usage();
		return 0;
	}

	g_htable = create_hashtable(g_htab_backet_nr);
	if (NULL == g_htable)
	{
		perror("create_hashtable in main");
		return -1;
	}

	/* uncompress package if needed */
	if (bz && dedup_op != DEDUP_CREAT)
	{
		ret = zlib_decompress_file(argv[optind], tmp_file);
		if (ret != 0)
			return ret;
	}
	else if (!bz)
	{
		sprintf(tmp_file, "%s", argv[optind]);
	}

	/*  execute specific deduplication operation */
	switch(dedup_op)
	{
	case DEDUP_CREAT:
		ret = dedup_package_creat(argc - optind -1 , argv + optind + 1, tmp_file, bverbose);
		break;
	case DEDUP_EXTRACT:
		subpath = ((argc - optind) >= 2) ? argv[optind + 1] : NULL;
		ret = dedup_package_extract(tmp_file, subpath, path, bverbose);
		break;
	case DEDUP_APPEND:
		ret = dedup_package_append(argc - optind -1 , argv + optind + 1, tmp_file, bverbose);
		break;
	case DEDUP_REMOVE:
		ret = dedup_package_remove(tmp_file, argc - optind -1, argv + optind + 1, bverbose);
		break;
	case DEDUP_LIST:
		ret = dedup_package_list(tmp_file, bverbose);
		break;
	}

	/* compress package */
	if (bz)
	{
		ret = zlib_compress_file(tmp_file, argv[optind]);
		unlink(tmp_file);
	}

	if (g_htable) hash_free(g_htable);
	return ret;
}
