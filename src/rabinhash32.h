/*
 * rabinhash32.h
 *
 * Aigui.liu@gmail.com, 2010.06.21
 *
 * <p>This class provides an implementation of a hash function based on Rabin fingerprints, one
 * which can efficiently produce a 32-bit hash value for a sequence of bytes. It does so by considering
 * strings of bytes as large polynomials over GF(2) -- that is, with coefficients of 0 and 1 --
 * and then reducing them modulo some irreducible polynomial of degree 32. The result is a hash function
 * with very satisfactory properties. In addition the polynomial operations are fast in hardware;
 * even in this Java implementation the speed is reasonable.</p>
 *
 * <p>Methods in this class can compute a hash value for an array of bytes, chars or ints, as well as
 * any {@link java.io.Serializable} object, String, file, or resource denoted by URL.</p>
 *
 * <p>Methods of this class are all thread-safe, and hash function objects are immutable.</p>
 *
 * <p>Polynomials of degree 32 are used frequently in this code, and are represented efficiently as
 * <code>int</code>s. An <code>int</code> has 32 bits, whereas a polynomial of degree 32 has 33 coefficients.
 * Therefore, the high-order bit of the <code>int</code> is the degree 31 term's
 * coefficient, and the low-order bit is the constant coefficient.</p>
 *
 * <p>For example the integer 0x00000803, in binary, is:</p>
 *
 * <p><code>00000000 00000000 00001000 00000011</code></p>
 *
 * <p>Therefore it correponds to the polynomial:</p>
 *
 * <p><code>x<sup>32</sup> + x<sup>11</sup> + x + 1</code></p>
 *
 * <p>The implementation is derived from the paper "Some applications of Rabin's fingerprinting method"
 * by Andrei Broder. See <a href="http://server3.pa-x.dec.com/SRC/publications/src-papers.html">
 * http://server3.pa-x.dec.com/SRC/publications/src-papers.html</a> for a full citation and the paper
 * in PDF format.</p>
 *
 *
 */

#ifndef _RABINHASH_H
#define _RABINHASH_H

#ifdef __cplusplus
extern "C" {
#endif

#define DEFAULT_IRREDUCIBLE_POLY	0x0000008D
#define P_DEGREE			32
#define X_P_DEGREE			(1 << (P_DEGREE - 1))
#define READ_BUFFER_SIZE		1024

int rabinhash32(const char A[], int poly, const int size);
unsigned int rabin_hash(char *str);

#ifdef __cplusplus
}
#endif

#endif /* _RABINHASH_H_ */
