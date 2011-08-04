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

#ifndef _BIGHASHTABLE_H
#define _BIGHASHTABLE_H

#include "hashdb.h"

#define PATH_MAX_LEN 255
typedef HASHDB hashtable;

hashtable *create_hashtable(int size);
void hash_free(hashtable *tab);
void hash_insert(void *key, void *data, int datasz, hashtable *tab);
void *hash_value(void *key, hashtable *tab);

#endif

