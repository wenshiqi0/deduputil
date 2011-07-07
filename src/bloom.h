/* Copyright (c) 2011 the authors listed at the following URL, and/or
the authors of referenced articles or incorporated external code:
http://en.literateprograms.org/Bloom_filter_(C)?action=history&offset=20100923154723

Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the
"Software"), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

Retrieved from: http://en.literateprograms.org/Bloom_filter_(C)?oldid=16893
*/

#ifndef __BLOOM_H__
#define __BLOOM_H__

#include <stdlib.h>

typedef unsigned int (*hashfunc_t)(const char *);
typedef struct {
	size_t asize;
	unsigned char *a;
	size_t nfuncs;
	hashfunc_t *funcs;
} BLOOM;

BLOOM *bloom_create(size_t size, size_t nfuncs, ...);
int bloom_destroy(BLOOM *bloom);
int bloom_add(BLOOM *bloom, const char *s);
int bloom_check(BLOOM *bloom, const char *s);

#endif

