/* Copyright (C) 2011 Aigui Liu
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
#include <limits.h>
#include "hashdb.h"

HASHDB *hashdb_new(uint64_t tnum, uint32_t bnum, uint32_t cnum, \
	hashfunc_t hash_func1, hashfunc_t hash_func2)
{
	HASHDB *db = NULL;

	if (!(db = malloc(HASHDB_SZ))) {
		return NULL;
	}

	db->header.tnum = tnum;
	db->header.bnum = bnum;
	db->header.cnum = cnum;
	db->hash_func1 = hash_func1;
	db->hash_func2 = hash_func2;

	return db;
}

int hashdb_open(HASHDB *db, const char *path)
{
	int f_ok;
	uint32_t i;
	ssize_t wsize;

	if (!db || !path) {
		return -1;
	}

	f_ok = access(path, F_OK);
	db->dbname = strdup(path);
	db->fd = open(path, O_RDWR|O_CREAT, 0666);
	if (-1 == db->fd) {
		free(db->dbname);
		return -1;
	}

	if (0 == f_ok) {/* existed hashdb */
		/* FIXME: build hashdb from file */
		return -1;
	} else {/* new hashdb */
		db->header.magic = HASHDB_MAGIC;
		db->header.boff = HASHDB_HDR_SZ;
		db->header.hoff = db->header.boff + (db->header.tnum + CHAR_BIT -1)/CHAR_BIT;
		db->header.voff = db->header.hoff + (db->header.bnum * HASH_BUCKET_SZ);
		db->bloom = bloom_create(db->header.tnum);
		if (!db->bloom) {
			goto OUT;
		}

		db->bucket = (HASH_BUCKET *)malloc(db->header.bnum * HASH_BUCKET_SZ);
		if (!db->bucket) {
			goto OUT;
		}
		db->cache = (HASH_ENTRY *)malloc(db->header.cnum * HASH_ENTRY_SZ);
		if (!db->cache) {
			goto OUT;
		}
		for (i = 0; i < db->header.bnum; i++) {
			db->bucket[i].off = 0;
		}
		for (i = 0; i < db->header.cnum; i++) {
			db->cache[i].cached = 0;
			db->cache[i].off = 0;
			db->cache[i].left = 0;
			db->cache[i].right = 0;
		}

		/* prealloc space in the file */
		if (-1 == lseek(db->fd, 0, SEEK_SET)) {
			goto OUT;
		}
		wsize = db->header.boff;
		if (write(db->fd, &db->header, wsize) != wsize) {
			goto OUT;
		}
		wsize = db->header.hoff - db->header.boff;
		if (write(db->fd, db->bloom->a, wsize) != wsize) {
			goto OUT;
		}
		wsize = db->header.voff - db->header.hoff;
		if (write(db->fd, db->bucket, wsize) != wsize) {
			goto OUT;
		}
	}
	return 0;

OUT:
	if (db->dbname) {
		close(db->fd);
		unlink(db->dbname);
		free(db->dbname);
	}

	if (db->bloom) {
		bloom_destroy(db->bloom);
	}

	if (db->bucket) {
		free(db->bucket);
	}

	if (db->cache) {
		free(db->cache);
	}

	return -1;
}

int hashdb_close(HASHDB *db)
{
	uint32_t i;

	if (!db) {
		return -1;
	}

	/* FIXME: flush cached data to file */
	close(db->fd);
	if (db->bloom) {
		bloom_destroy(db->bloom);
	}
	if (db->bucket) {
		free(db->bucket);
	}
	if (db->cache) {
		for (i = 0; i < db->header.cnum; i++) {
			if (db->cache[i].key) {
				free(db->cache[i].key);
			}
			if (db->cache[i].value) {
				free(db->cache[i].value);
			}
		}
		free(db->cache);
	}

	return 0;
}

int hashdb_swapout(HASHDB *db, uint32_t hash1, uint32_t hash2, HASH_ENTRY *he)
{
	char key[HASHDB_KEY_MAX_SZ] = {0};
	char value[HASHDB_VALUE_MAX_SZ] = {0};
	uint64_t root;
	uint32_t pos;
	int cmp, hebuf_sz, lr = 0;
	void *hebuf = NULL;
	char *hkey = NULL;
	char *hvalue = NULL;
	HASH_ENTRY *hentry = NULL;
	HASH_ENTRY parent;
	ssize_t rwsize;


	if (!db) {
		return -1;
	}

	if (!he || !he->cached) {
		return 0;
	}

	/* find offset and parent of the hash entry */
	if (he->off == 0) {
		hebuf_sz = HASH_ENTRY_SZ + HASHDB_KEY_MAX_SZ + HASHDB_VALUE_MAX_SZ; 
		if (NULL == (hebuf = (void *)malloc(hebuf_sz))) {
			return -1;
		}
		pos = hash1 % db->header.bnum;
		root = db->bucket[pos].off;
		parent.off = 0;
		/* search entry with given key and hash in btree */
		while(root) {
			if (-1 == lseek(db->fd, root, SEEK_SET)) {
				free(hebuf);
				return -1;
			}
			memset(hebuf, 0, hebuf_sz);
			rwsize = read(db->fd, hebuf, hebuf_sz);
			if (rwsize != hebuf_sz) {
				free(hebuf);
				return -1;
			}

			hentry = (HASH_ENTRY *)hebuf;
			hkey = (char *)(hebuf + HASH_ENTRY_SZ);
			hvalue = (char *)(hebuf + HASH_ENTRY_SZ + HASHDB_KEY_MAX_SZ);
			memcpy(&parent, hebuf, HASH_ENTRY_SZ);
			if (hentry->hash > hash2) {
				root = hentry->left;
				lr = 0;
			} else if (hentry->hash < hash2) {
				root = hentry->right;
				lr = 1;
			} else {
				cmp = strcmp(hkey, he->key);
				if (cmp > 0) {
					root = hentry->left;
					lr = 0;
				} else if (cmp < 0) {
					root = hentry->right;
					lr = 1;
				} else {
					/* never happen */
				}
			}
		}

		if (hebuf) {
			free(hebuf);
		}

		/* append mode */
		if (-1 == (he->off = lseek(db->fd, 0, SEEK_END))) {
			return -1;
		}
		if (!db->bucket[pos].off) {
			db->bucket[pos].off = he->off;
		}

		/* make relationship with parent  */
		if (parent.off) {
			(lr == 0)? (parent.left = he->off): (parent.right = he->off);
			if (-1 == lseek(db->fd, parent.off, SEEK_SET)) {
				return -1;
			}
			rwsize = HASH_ENTRY_SZ;
			if (write(db->fd, &parent, rwsize) != rwsize) {
				return -1;
			}
		}
	}
	printf("he->off = %lld\n", he->off);
	
	/* flush cached hash entry to file */
	if (-1 == lseek(db->fd, he->off, SEEK_SET)) {
		return -1;
	}
	rwsize = HASH_ENTRY_SZ;
	if (rwsize != write(db->fd, he, rwsize)) {
		return -1;
	}
	sprintf(key, "%s", he->key);
	if (HASHDB_KEY_MAX_SZ != write(db->fd, key, HASHDB_KEY_MAX_SZ)) {
		return -1;
	}
	sprintf(value, "%s", (char *)he->value);
	if (HASHDB_VALUE_MAX_SZ != write(db->fd, value, HASHDB_VALUE_MAX_SZ)) {
		return -1;
	}

	
	if (he->key) {
		free(he->key);
		he->key = NULL;
	}
	if (he->value) {
		free(he->value);
		he->value = NULL;
	}
	he->off = 0;
	he->left = 0;
	he->right = 0;
	he->cached = 0;

	return 0;
}

int hashdb_swapin(HASHDB *db, char *key, uint32_t hash1, uint32_t hash2, HASH_ENTRY *he)
{
	uint32_t pos;
	uint64_t root;
	int cmp, hebuf_sz;
	void *hebuf = NULL;
	char *hkey = NULL;
	char *hvalue = NULL;
	HASH_ENTRY *hentry = NULL;
	ssize_t rsize;
 
	if (!db || !key || he->cached) {
		return -1;
	}

	/* check if the value is set */
	/*if (!bloom_check(db->bloom, hash1, hash2)) {
		printf("swapin bloom_check = false, %d, %d\n", hash1, hash2);
		return -2;
	}*/
	
	hebuf_sz = HASH_ENTRY_SZ + HASHDB_KEY_MAX_SZ + HASHDB_VALUE_MAX_SZ; 
	if (NULL == (hebuf = (void *)malloc(hebuf_sz))) {
		return -1;
	}

	pos = hash1 % db->header.bnum;
	root = db->bucket[pos].off;
	printf("swapin root = %lld\n", root);
	/* search entry with given key and hash in btree */
	while (root) {
		if (-1 == lseek(db->fd, root, SEEK_SET)) {
			free(hebuf);
			return -1;
		}
		memset(hebuf, 0, hebuf_sz);
		rsize = read(db->fd, hebuf, hebuf_sz);
		if (rsize != hebuf_sz) {
			free(hebuf);
			return -1;
		}

		hentry = (HASH_ENTRY *)hebuf;
		hkey = (char *)(hebuf + HASH_ENTRY_SZ);
		hvalue = (char *)(hebuf + HASH_ENTRY_SZ + HASHDB_KEY_MAX_SZ);
		printf("swapin: key=%s, value=%s\n", hkey, hvalue);
		if (hentry->hash > hash2) {
			root = hentry->left;
		} else if (hentry->hash < hash2) {
			root = hentry->right;
		} else {
			cmp = strcmp(hkey, key);
			printf("key cmp: %s, %s\n", hkey, key);
			if (cmp == 0) { /* find the entry */
				memcpy(he, hebuf, HASH_ENTRY_SZ);
				he->key = strdup(hkey);
				he->value = strdup(hvalue);
				he->cached = 1;
				free(hebuf);
				return 0;
			} else if (cmp > 0) {
				root = hentry->left;
			} else {
				root = hentry->right;
			}
		}
	}

	if (hebuf) {
		free(hebuf);
	}
	printf("swapin at the end\n");
	return -2;
}

int hashdb_set(HASHDB *db, char *key, void *value)
{
	int pos;
	uint32_t hash1, hash2;
	uint32_t he_hash1, he_hash2;

	if (!db || !key || !value) {
		return -1;
	}

	hash1 = db->hash_func1(key);
	hash2 = db->hash_func2(key);
	/* cache swap in/out with set-associative */
	pos = hash1 % db->header.cnum;
	if ((db->cache[pos].cached) && ((hash2 != db->cache[pos].hash) || (strcmp(key, db->cache[pos].key) != 0))) {
		he_hash1 = db->hash_func1(db->cache[pos].key);
		he_hash2 = db->cache[pos].hash;
		if (-1 == hashdb_swapout(db, he_hash1, he_hash2, &db->cache[pos])) {
			return -1;
		}

		if (bloom_check(db->bloom, hash1, hash2)) {
			if ( -1 == hashdb_swapin(db, key, hash1, hash2, &db->cache[pos])) {
				return -1;
			}
		}
	}

	if ((strlen(key) > HASHDB_KEY_MAX_SZ) || (strlen((char *)value) > HASHDB_VALUE_MAX_SZ)) {
		return -1;
	}

	/* fill up cache hash entry */
	if (db->cache[pos].key) {
		free(db->cache[pos].key);
	}
	if (db->cache[pos].value) {
		free(db->cache[pos].value);
	}
	db->cache[pos].key = strdup(key);
	db->cache[pos].value = strdup(value);
	db->cache[pos].ksize = strlen(key); 
	db->cache[pos].vsize = strlen((char *)value);
	db->cache[pos].tsize = HASH_ENTRY_SZ + HASHDB_KEY_MAX_SZ + HASHDB_VALUE_MAX_SZ;
	db->cache[pos].hash = hash2;
	if (!db->cache[pos].cached) {
		/* it's a new entry */
		db->cache[pos].off = 0;
		db->cache[pos].left = 0;
		db->cache[pos].right = 0;
	}
	bloom_setbit(db->bloom, hash1, hash2);	
	db->cache[pos].cached = 1;

	return 0;
}

int hashdb_get(HASHDB *db, char *key, void *value)
{
	int pos, ret;
	uint32_t hash1, hash2;
	uint32_t he_hash1, he_hash2;

	if (!db || !key) {
		return -1;
	}

	hash1 = db->hash_func1(key);
	hash2 = db->hash_func2(key);
	/* check if the value is set */
	if (!bloom_check(db->bloom, hash1, hash2)) {
		return -2; 
	}
	printf("hashdb_get bloom_check = true, %d, %d\n", hash1, hash2);

	pos = hash1 % db->header.cnum;
	if ((db->cache[pos].cached) && ((hash2 != db->cache[pos].hash) || (strcmp(key, db->cache[pos].key) != 0))) {
		printf("cached, but not, to swapout: key = %s,%s, hash=%d, %d\n", key, db->cache[pos].key, hash2, db->cache[pos].hash);
		he_hash1 = db->hash_func1(db->cache[pos].key);
		he_hash2 = db->cache[pos].hash;
		if (-1 == hashdb_swapout(db, he_hash1, he_hash2, &db->cache[pos])) {
			printf("swapout failed\n");
			return -1;
		}
	}

	if (!db->cache[pos].cached) {
		printf("not cached, to swapin: %d, %d\n", hash1, hash2);
		if (0 != (ret = hashdb_swapin(db, key, hash1, hash2, &db->cache[pos]))) {
			printf("swapin failed ret = %d\n", ret);
			return ret;
		}
	}
	memcpy(value, db->cache[pos].value, db->cache[pos].vsize);

	return 0;
}

int hashdb_unlink(HASHDB *db)
{
	if (!db) {
		return -1;
	}

	if (db->dbname) {
		unlink(db->dbname);
		free(db->dbname);
	}

	return 0;
}

#ifdef HASHDB_TEST
uint32_t sax_hash(const char *key)
{
	uint32_t h = 0;
	while(*key) h ^= (h<<5)+(h>>2) + (unsigned char)*key++;
	return h;
}

uint32_t sdbm_hash(const char *key)
{
	uint32_t h = 0;
	while(*key) h = (unsigned char)*key++ + (h<<6) + (h<<16) - h;
	return h;
}

int main(int argc, char *argv[])
{
	uint32_t i, ret;
	char key[HASHDB_KEY_MAX_SZ] = {0};
	char value[HASHDB_VALUE_MAX_SZ] = {0};
	uint32_t max = atol(argv[2]);
	char *dbname = argv[1];
	HASHDB *db  = hashdb_new(HASHDB_DEFAULT_TNUM, HASHDB_DEFAULT_BNUM, HASHDB_DEFAULT_CNUM, sax_hash, sdbm_hash);

	if (!db) {
		fprintf(stderr, "hashdb_new failed!\n");
		exit(-1);
	}

	if (-1 == hashdb_open(db, dbname)) {
		fprintf(stderr, "hashdb_open failed!\n");
		exit(-2);
	}

	/* set values */
	for (i = 0; i < max; i++) {
		sprintf(key, "%d", i);
		sprintf(value, "%d", i);
		if (-1 == hashdb_set(db, key, value)) {
			fprintf(stderr, "hashdb_set failed\n");
			goto EXIT;
		}
		fprintf(stderr, "set %s value = %s\n", key, value);
	}

	/* get values */
	for (i = 0; i <= max; i++) {
		sprintf(key, "%d", i);
		memset(value, 0, HASHDB_VALUE_MAX_SZ);
		ret = hashdb_get(db, key, value);
		switch (ret) {
		case -2:
			fprintf(stderr, "the value of #%s is not set\n", key);
			goto EXIT;
			break;
		case -1:
			fprintf(stderr, "hashdb_get failed\n");
			goto EXIT;
		case  0:
			fprintf(stderr, "get %s value = %s\n", key, value);
		}
	}

EXIT:
	hashdb_close(db);
	hashdb_unlink(db);
	free(db);

}
#endif
