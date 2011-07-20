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

#ifndef _LIST_H
#define _LIST_H

#define CacheSize 4194304	/* 4MB */
#define SwapSize  4096		/* 4KB */

struct list_entry {
	uint64_t file_offset; /* offset in file */
	uint32_t cache_offset; /* offset in cache */
}LIST_ENTRY; 

struct listdb
{
	char *dbname;
	int fp;
	uint8_t unit_size;
	uint16_t cache_group_nr;
	uint32_t cache_size;
	uint16_t swap_size;
	LIST_ENTRY *le_array;
	void *cache;
	int (*compare)(void *, void *);
}LISTDB;

LISTDB *listdb_new(uint8_t unit_size, uint32_t cache_size, uint16_t swap_size,\
	int (*compare)(void *, void *));
int listdb_open(LISTDB *db, const char *path);
int listdb_close(LISTDB *db);
int listdb_set(LISTDB *db, uint64_t offset, void *value);
int listdb_get(LISTDB *db, uint64_t offset, void *value);
int listdb_swap(LISTDB *db, uint64_t file_offset, uint32_t cache_offset);
int listdb_unlink(LISTDB *db);

#endif
