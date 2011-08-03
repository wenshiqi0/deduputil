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
#include "listdb.h"

LISTDB *listdb_new(uint8_t unit_size, uint32_t cache_size, uint16_t swap_size)
{
	LISTDB *db = NULL;
	
	if (!(db = malloc(LISTDB_SZ)))
		return NULL;

	db->dbname = NULL;
	db->fd = -1;
	db->unit_size = unit_size;
	db->cache_size = cache_size;
	db->swap_size = swap_size;
	db->cache_group_nr = cache_size / swap_size;
	db->cache = (void *)malloc(cache_size);
	db->le_array = (LIST_ENTRY *)malloc(LISTENTRY_SZ * db->cache_group_nr);
	if (!db->cache || !db->le_array) {
		if (db->cache)
			free(db->cache);
		if (db->le_array)
			free(db->le_array);
		free(db);
		return NULL;
	}
	memset(db->cache, 0, cache_size);
	memset(db->le_array, 0, LISTENTRY_SZ * db->cache_group_nr);

	return db;
}

int listdb_open(LISTDB *db, const char *path)
{
	int i;
	uint8_t cache_count;
	ssize_t rsize;

	if (!db) {
		return -1;
	}
		
	db->dbname = strdup(path);
	db->fd = open(path, O_RDWR|O_CREAT, 0666);
	if (-1 == db->fd) {
		free(db->dbname);
		return -1;
	}
	/* cache read ahead */
	rsize = read(db->fd, db->cache, db->cache_size);
	cache_count = rsize / db->swap_size;
	for (i = 0; i < cache_count; i++) {
		db->le_array[i].cached = 1;
		db->le_array[i].file_offset = i * db->swap_size;
		db->le_array[i].cache_offset = i * db->swap_size;
	}

	return 0;
}

int listdb_close(LISTDB *db)
{
	int i;

	if (!db) {
		return -1;
	}

	/* flush cached data to file */
	if (db->le_array && db->cache) {
		for (i = 0; i < db->cache_group_nr; i++) {
			if (db->le_array[i].cached) {
				if (-1 == lseek(db->fd, db->le_array[i].file_offset, SEEK_SET))
					return -1;
				if (write(db->fd, db->cache+db->le_array[i].cache_offset, db->swap_size) != db->swap_size)
					return -1;
			}
		}
	}
	close(db->fd);
	if (db->le_array) {
		free(db->le_array);
	}
	if (db->cache) {
		free(db->cache);
	}

	return 0;
}

int listdb_swapin(LISTDB *db, uint16_t pos, uint64_t file_offset)
{
	if (!db || !db->fd || !db->cache || !db->le_array || db->le_array[pos].cached) 
		return -1;

	db->le_array[pos].file_offset = file_offset;
	db->le_array[pos].cache_offset = pos * db->swap_size;
	memset(db->cache+db->le_array[pos].cache_offset, '\n', db->swap_size);
	if (-1 == lseek(db->fd, file_offset, SEEK_SET))
		return -1;
	if (-1 == read(db->fd, db->cache+db->le_array[pos].cache_offset, db->swap_size))
		return -1;
	db->le_array[pos].cached = 1;

	return 0;
}

int listdb_swapout(LISTDB *db, uint16_t pos)
{
	if (!db || !db->fd || !db->cache || !db->le_array || !db->le_array[pos].cached)
		return -1;

	if (-1 == lseek(db->fd, db->le_array[pos].file_offset, SEEK_SET))
		return -1;
	if (db->swap_size != write(db->fd, db->cache+db->le_array[pos].cache_offset, db->swap_size))
		return -1;
	db->le_array[pos].cached = 0;

	return 0;
}

int listdb_value(LISTDB *db, uint64_t index, void *value, uint8_t op)
{
	uint8_t pos;
	uint32_t cache_offset;
	uint64_t file_offset;
	int i, notset;

	if (!db || !db->fd || !db->cache || !db->le_array)
		return -1;

	/* cache swap in/out with set-associative */
	file_offset = index * db->unit_size;
	file_offset = (file_offset / db->swap_size) * db->swap_size;
	pos = (file_offset / db->swap_size) % db->cache_group_nr;
	if (db->le_array[pos].cached) {
		if (db->le_array[pos].file_offset != file_offset) {
			if (-1 == listdb_swapout(db, pos))
				return -1;
		}
	}
	if (!db->le_array[pos].cached) {
		if (-1 == listdb_swapin(db, pos, file_offset))
			return -1;
	}

	cache_offset = (index * db->unit_size) % db->swap_size;
	switch (op) {
	case VALUE_SET:
		memcpy(db->cache+db->le_array[pos].cache_offset + cache_offset, value, db->unit_size);
		break;
	case VALUE_GET:
		/* check if the value is set */
		notset = 1;
		for (i = 0; i < db->unit_size; i++) {
			if (*((char *)(db->cache+db->le_array[pos].cache_offset + cache_offset + i)) != '\n')
				notset = 0;
		}
		if (notset) {
			return -2;
		}
		memcpy(value, db->cache+db->le_array[pos].cache_offset + cache_offset, db->unit_size);
		break;
	}
	
	return 0;
}

int listdb_set(LISTDB *db, uint64_t index, void *value)
{
	return listdb_value(db, index, value, VALUE_SET);
}

int listdb_get(LISTDB *db, uint64_t index, void *value)
{
	return listdb_value(db, index, value, VALUE_GET);
}

int listdb_unlink(LISTDB *db)
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

#ifdef TEST_LISTDB
int main(int argc, char *argv[])
{
	uint32_t i, value, ret;
	uint32_t max = atol(argv[2]);
	char *dbname = argv[1];
	LISTDB *db  = listdb_new(sizeof(uint32_t), DEFAULT_CACHE_SZ, DEFAULT_SWAP_SZ);

	if (!db) {
		fprintf(stderr, "listdb_new failed!\n");
		exit(-1);
	}

	if (-1 == listdb_open(db, dbname)) {
		fprintf(stderr, "listdb_open failed!\n");
		exit(-2);
	}

	/* set values */
	for (i = 0; i < max; i++) {
		value = i;
		if (-1 == listdb_set(db, i, &value)) {
			fprintf(stderr, "listdb_set failed\n");
			exit(-3);
		}
		fprintf(stderr, "set %d value = %d\n", i, value);
	}

	/* get values */
	for (i = 0; i <= max; i++) {
		ret = listdb_get(db, i, &value);
		switch (ret) {
		case -2:
			fprintf(stderr, "the value of #%d is not set\n", i);
			return 0;
		case -1:
			fprintf(stderr, "listdb_get failed\n");
			exit(-4);
		case  0:
			fprintf(stderr, "get %d value = %d\n", i, value);
		}
	}

	listdb_close(db);
	listdb_unlink(db);
	free(db);
}
#endif
