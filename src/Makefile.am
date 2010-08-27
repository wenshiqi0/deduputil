CMDS = dedup bdiff bencode bsim

AM_CFLAGS = -g3 -Wall 
AM_LDFLAGS = -L.

bin_PROGRAMS = $(CMDS)

dedup_SOURCES = dedup.c md5.c hashtable.c hash.c rabinhash32.c checksum.c libz.c queue.c
dedup_LDADD = -lz

bdiff_SOURCES = bdiff.c md5.c hashtable.c

bencode_SOURCES = bencode.c sync.c md5.c hashtable.c checksum.c

bsim_SOURCES = bsim.c sync.c md5.c hashtable.c checksum.c

