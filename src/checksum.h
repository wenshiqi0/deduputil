#ifndef _CHECKSUM_H
#define _CHECKSUM_H

#ifdef __cplusplus
extern "C" {
#endif

#define CHAR_OFFSET 0

unsigned int adler32_checksum(char *buf, int len);
unsigned int adler32_rolling_checksum(unsigned int csum, int len, char c1, char c2);

#ifdef __cplusplus
}
#endif

#endif
