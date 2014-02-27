AM_CFLAGS = -D_OFFSET_BITS=64 -D_LARGEFILE_SOURCE
bin_PROGRAMS = nfex
nfex_SOURCES = 		main.c \
			packet.c \
			init.c \
			hash.c \
			util.c \
			confy.y \
			confl.l \
			conf.c \
			conf.h \
			confy.h \
			search.c \
			extract.c \
			asynch.c

sysconf_DATA = ../conf/nfex.conf

AM_YFLAGS = -d
