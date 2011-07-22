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
#include "hashdb.h"

HASHDB *hashdb_new(uint64_t tnum, uint32_t bnum, uint16_t cnum)
{
}

int hashdb_open(HASHDB *db, const char *path)
{
}

int hashdb_close(HASHDB *db)
{
}

int hashdb_swapout(HASHDB *db, HASH_ENTRY *he)
{
}

int hashdb_swapin(HASHDB *db, char *key, HASH_ENTRY *he)
{
}

int hashdb_set(HASHDB *db, char *key, void *value)
{
}

int hashdb_get(HASHDB *db, char *key, void *value)
{
}

int hashdb_unlink(HASHDB *db)
{
}
