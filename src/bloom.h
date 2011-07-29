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

#ifndef _BLOOM_H
#define _BLOOM_H

#include <stdlib.h>
#include <stdint.h>

typedef struct {
	size_t asize;
	unsigned char *a;
} BLOOM;

BLOOM *bloom_create(size_t size);
int bloom_destroy(BLOOM *bloom);
int bloom_setbit(BLOOM *bloom, int n, ...);
int bloom_check(BLOOM *bloom, int n, ...);

#endif

