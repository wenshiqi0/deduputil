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
	uint64_t offset;
}; 

int compare(void *e1, void *e2);
int list_open();
int list_close();
int list_set();
int list_get();
int list_swap();

#endif
