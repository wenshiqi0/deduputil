#include <string.h>
#include "rabinhash32.h"

static int P = 1;
static int table32[256] = {0};
static int table40[256] = {0};
static int table48[256] = {0};
static int table56[256] = {0};

void initialize_tables() 
{
	int i, j;
	int mods[P_DEGREE];
	// We want to have mods[i] == x^(P_DEGREE+i)
	mods[0] = P;
	for (i = 1; i < P_DEGREE; i++) {
		const int lastmod = mods[i - 1];
		// x^i == x(x^(i-1)) (mod P)
		int thismod = lastmod << 1;
		// if x^(i-1) had a x_(P_DEGREE-1) term then x^i has a
		// x^P_DEGREE term that 'fell off' the top end.
		// Since x^P_DEGREE == P (mod P), we should add P
		// to account for this:
		if ((lastmod & X_P_DEGREE) != 0) {
			thismod ^= P;
		}
		mods[i] = thismod;

	}
	// Let i be a number between 0 and 255 (i.e. a byte).
	// Let its bits be b0, b1, ..., b7.
	// Let Q32 be the polynomial b0*x^39 + b1*x^38 + ... + b7*x^32 (mod P).
	// Then table32[i] is Q32, represented as an int (see below).
	// Likewise Q40 be the polynomial b0*x^47 + b1*x^46 + ... + b7*x^40 (mod P).
	// table40[i] is Q40, represented as an int. Likewise table48 and table56.

	for (i = 0; i < 256; i++) {
		int c = i;
		for (j = 0; j < 8 && c > 0; j++) {
			if ((c & 1) != 0) {
				table32[i] ^= mods[j];
				table40[i] ^= mods[j + 8];
				table48[i] ^= mods[j + 16];
				table56[i] ^= mods[j + 24];
			}
			c >>= 1;
		}
	}
}

int compute_w_shifted(const int w){

	return table32[w & 0xFF] ^table40[(w >> 8) & 0xFF] ^table48[(w >> 16) & 0xFF] ^ table56[(w >> 24) & 0xFF];

}

int rabinhash32_func(const char A[], const int offset, const int length, int w) {

    int s = offset;

    // First, process a few bytes so that the number of bytes remaining is a multiple of 4.
    // This makes the later loop easier.
    const int starter_bytes = length % 4;
    if (starter_bytes != 0) {
        const int max = offset + starter_bytes;
        while (s < max) {
            w = (w << 8) ^ (A[s] & 0xFF);
            s++;
        }
    }

    const int max = offset + length;
    while (s < max) {
        w = compute_w_shifted(w) ^
            (A[s] << 24) ^
            ((A[s + 1] & 0xFF) << 16) ^
            ((A[s + 2] & 0xFF) << 8) ^
            (A[s + 3] & 0xFF);
        s += 4;
    }

    return w;
}

int rabinhash32(const char A[], int poly, const int size) {
	P = poly;
	initialize_tables();
	return rabinhash32_func(A, 0, size, 0);
}

unsigned int rabin_hash(char *str)
{
	return rabinhash32(str, 1, strlen(str));
}
