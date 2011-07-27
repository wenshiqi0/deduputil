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

#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include "bloom.h"

#define SETBIT(a, n) (a[n/CHAR_BIT] |= (1<<(n%CHAR_BIT)))
#define GETBIT(a, n) (a[n/CHAR_BIT] & (1<<(n%CHAR_BIT)))

BLOOM *bloom_create(size_t size)
{
	BLOOM *bloom;
	
	if(!(bloom = malloc(sizeof(BLOOM)))) {
		return NULL;
	}

	if(!(bloom->a = calloc((size + CHAR_BIT-1)/CHAR_BIT, sizeof(char)))) {
		free(bloom);
		return NULL;
	}
	bloom->asize = size;

	return bloom;
}

int bloom_destroy(BLOOM *bloom)
{
	free(bloom->a);
	free(bloom);

	return 0;
}

int bloom_setbit(BLOOM *bloom, ...)
{
	va_list l;
	uint32_t pos;

	va_start(l, bloom);
	while(pos = va_arg(l, uint32_t)) {
		SETBIT(bloom->a, pos % bloom->asize);
	}
	va_end(l);

	return 0;
}

int bloom_check(BLOOM *bloom, ...)
{
	va_list l;
	uint32_t pos;

	va_start(l, bloom);
	while(pos = va_arg(l, uint32_t)) {
		if(!(GETBIT(bloom->a, pos % bloom->asize))) {
			return 0;
		}
	}
	va_end(l);

	return 1;
}

#ifdef BLOOM_TEST
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
	uint32_t i;
	uint32_t max = atol(argv[1]);
	uint32_t hash1, hash2;
	char buf[32] = {0};

	BLOOM *bloom = bloom_create(max);
	for (i = 0; i < max/2; i++) {
		sprintf(buf, "%d", i);
		hash1 = sax_hash(buf);
		hash2 = sdbm_hash(buf);
		bloom_setbit(bloom, hash1, hash2);
	}

	for (i = 0; i < max; i++) {
		sprintf(buf, "%d", i);
		hash1 = sax_hash(buf);
		hash2 = sdbm_hash(buf);
		if (!bloom_check(bloom, hash1, hash2)) {
			printf("%i not found\n", i);
		}
	}
	bloom_destroy(bloom);
}
#endif

