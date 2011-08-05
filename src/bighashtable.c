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
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include "bighashtable.h"

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

hashtable *create_hashtable(int size)
{
	HASHDB *db = NULL;
	char hashdb_name[PATH_MAX_LEN] = {0};
	char template[] = "deduputil_hashdb_XXXXXX";

	db = hashdb_new(HASHDB_DEFAULT_TNUM, HASHDB_DEFAULT_BNUM, HASHDB_DEFAULT_CNUM, sax_hash, sdbm_hash);
	if (!db) {
		return NULL;
	}

	sprintf(hashdb_name, "/tmp/%s_%d", mktemp(template), getpid());
	if (-1 == hashdb_open(db, hashdb_name)) {
		free(db);
		return NULL;
	}

	return db;
}

void hash_free(hashtable *tab)
{
	if (tab) {
		hashdb_close(tab, 0);
		hashdb_unlink(tab);
		free(tab);
	}

	return;
}

void hash_insert(void *key, void *data, int datasz, hashtable *tab)
{
	if (-1 == hashdb_set(tab, (char *)key, data, datasz)) {
		fprintf(stderr, "hash_insert failed\n");
		_exit(-1);
	}
}

void *hash_value(void *key, hashtable *tab)
{
	char value[HASHDB_VALUE_MAX_SZ] = {0};
	void *vp = NULL;
	int datasz, ret;

	if (0 != (ret = hashdb_get(tab, (char *)key, (void *)value, &datasz))) {
		if (ret == -1) {
			fprintf(stderr, "hashdb_get faild\n");
			_exit(-1);
		}
		return NULL;
	}

	if (NULL == (vp = malloc(datasz))) {
		return NULL;
	}
	memcpy(vp, value, datasz);

	return vp;
}

