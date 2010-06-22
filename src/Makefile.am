#CMDS = dedup md5 hashtest zfile bdiff
CMDS = dedup

AM_CFLAGS = -g3 -Wall 
AM_LDFLAGS = -L.

bin_PROGRAMS = $(CMDS)

#md5_SOURCES = md5.c
#md5_CFLAGS = -DTEST

#hashtest_SOURCES = hashtest.c hash.c md5.c

#zfile_SOURCES = libz.c
#zfile_CFLAGS = -DTESTZLIB
#zfile_LDADD = -lz

dedup_SOURCES = dedup.c md5.c hashtable.c hash.c rabinhash32.c libz.c queue.c
dedup_LDADD = -lz

#bdiff_SOURCES = bdiff.c md5.c hashtable.c

clean:
	rm -f $(CMDS) *.o *~

