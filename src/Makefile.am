CMDS = dedup

AM_CFLAGS = -g3 -Wall
AM_LDFLAGS = -L.

bin_PROGRAMS = $(CMDS)

dedup_SOURCES = dedup.c md5.c hash.c rabinhash32.c checksum.c libz.c listdb.c bloom.c hashdb.c bighashtable.c
dedup_LDADD = -lz

