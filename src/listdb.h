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

#ifndef _LISTDB_H
#define _LISTDB_H

#include <stdint.h>

#define DEFAULT_CACHE_SZ 4194304	/* 4MB */
#define DEFAULT_SWAP_SZ  4096		/* 4KB */

typedef struct list_entry {
	uint8_t  cached;	/* cached or not */
	uint64_t file_offset;	/* offset in file */
	uint32_t cache_offset;	/* offset in cache */
} LIST_ENTRY;
#define LISTENTRY_SZ  sizeof(LIST_ENTRY) 

typedef struct listdb
{
	char *dbname;
	int fd;
	uint8_t unit_size;
	uint16_t cache_group_nr;
	uint16_t swap_size;
	uint32_t cache_size;
	LIST_ENTRY *le_array;
	void *cache;
} LISTDB;
#define LISTDB_SZ  sizeof(LISTDB)

enum VALUE_OP {
	VALUE_SET = 0, 
	VALUE_GET
};

LISTDB *listdb_new(uint8_t unit_size, uint32_t cache_size, uint16_t swap_size);
int listdb_open(LISTDB *db, const char *path);
int listdb_close(LISTDB *db);
int listdb_set(LISTDB *db, uint64_t index, void *value);
int listdb_get(LISTDB *db, uint64_t index, void *value);
int listdb_unlink(LISTDB *db);

#endif
