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

#include <limits.h>
#include <stdarg.h>

#include "bloom.h"

#define SETBIT(a, n) (a[n/CHAR_BIT] |= (1<<(n%CHAR_BIT)))
#define GETBIT(a, n) (a[n/CHAR_BIT] & (1<<(n%CHAR_BIT)))

BLOOM *bloom_create(size_t size, size_t nfuncs, ...)
{
	BLOOM *bloom;
	va_list l;
	int n;
	
	if(!(bloom=malloc(sizeof(BLOOM)))) return NULL;
	if(!(bloom->a=calloc((size+CHAR_BIT-1)/CHAR_BIT, sizeof(char)))) {
		free(bloom);
		return NULL;
	}
	if(!(bloom->funcs=(hashfunc_t*)malloc(nfuncs*sizeof(hashfunc_t)))) {
		free(bloom->a);
		free(bloom);
		return NULL;
	}

	va_start(l, nfuncs);
	for(n=0; n<nfuncs; ++n) {
		bloom->funcs[n]=va_arg(l, hashfunc_t);
	}
	va_end(l);

	bloom->nfuncs=nfuncs;
	bloom->asize=size;

	return bloom;
}

int bloom_destroy(BLOOM *bloom)
{
	free(bloom->a);
	free(bloom->funcs);
	free(bloom);

	return 0;
}

int bloom_add(BLOOM *bloom, const char *s)
{
	size_t n;

	for(n=0; n<bloom->nfuncs; ++n) {
		SETBIT(bloom->a, bloom->funcs[n](s)%bloom->asize);
	}

	return 0;
}

int bloom_check(BLOOM *bloom, const char *s)
{
	size_t n;

	for(n=0; n<bloom->nfuncs; ++n) {
		if(!(GETBIT(bloom->a, bloom->funcs[n](s)%bloom->asize))) return 0;
	}

	return 1;
}

