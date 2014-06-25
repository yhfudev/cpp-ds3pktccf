CC=g++

bin_PROGRAMS=unittest

unittest_SOURCES= \
    ds3pktcnt.cc \
    ds3pktccf.cc \
    testccf.cc \
    unittest.cc \
    $(NULL)

unittest_DEPENDENCIES= \
    $(NULL)

unittest_LDADD = \
    $(NULL)

unittest_CPPFLAGS= \
    -I/usr/include/libxml2/ \
    -I$(top_srcdir)/../cache-git/include \
    $(NULL)

DEFS+= \
    -DTESTCCF=1 -DCCFDEBUG=1\
    `getconf LFS_CFLAGS` \
    `getconf LFS64_CFLAGS` \
    -D_GNU_SOURCE \
    -DHAVE_MMAP64=1

AM_LDFLAGS= \
    `getconf LFS_LDFLAGS` \
    `getconf LFS64_LDFLAGS` \
    $(NULL)

LDADD=

if DEBUG
# use "valgrind --tool=memcheck --leak-check=yes" to check memory leak, MemWatch will drag the program.
#DEFS+=-DMEMWATCH
DEFS+= -DDEBUG=1
AM_CFLAGS=-g -Wall
#CFLAGS=-g -Wall
AM_CXXFLAGS=-g -Wall

else
#AM_CFLAGS=-O3 -Wall
AM_CFLAGS=-O3 -Wall
AM_CXXFLAGS=-O3 -Wall
endif

AM_CFLAGS+=-fpermissive
AM_CXXFLAGS+=-fpermissive
