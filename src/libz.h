#ifndef _ZLIB_H
#define _ZLIB_H

#ifdef __cplusplus
extern "C" {
#endif

/* compress file with zlib */
int zlib_compress_file(char *src_file, char *dest_file);

/* decompress file with zlib */
int zlib_decompress_file(char *src_file, char *dest_file);

#ifdef __cplusplus
}
#endif

#endif
