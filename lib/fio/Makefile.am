include $(top_srcdir)/config/Rules.am

DEFAULT_INCLUDES += \
	-I$(libcstordir)	\
	-I$(top_srcdir)/include \
	-I$(FIO_SRCDIR)

lib_LTLIBRARIES = replica.la

replica_la_SOURCES = replica.c
replica_la_LDFLAGS = -module
# required for fio external plugins on linux
replica_la_CFLAGS = -D_GNU_SOURCE -DCONFIG_STRSEP -DCONFIG_PWRITEV2
