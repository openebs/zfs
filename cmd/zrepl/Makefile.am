include $(top_srcdir)/config/Rules.am

# -Wnoformat-truncation to get rid of compiler warning for unchecked
#  truncating snprintfs on gcc 7.1.1.
AM_CFLAGS += $(FRAME_LARGER_THAN) $(NO_FORMAT_TRUNCATION)

DEFAULT_INCLUDES += \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/lib/libspl/include

sbin_PROGRAMS = zrepl

zrepl_SOURCES = \
	zrepl.c \
	mgmt_conn.c \
	data_conn.c

zrepl_LDADD = \
	$(top_builddir)/lib/libnvpair/libnvpair.la \
	$(top_builddir)/lib/libuutil/libuutil.la \
	$(top_builddir)/lib/libzpool/libzpool.la \
	$(top_builddir)/lib/libzfs/libzfs.la \
	$(top_builddir)/lib/libzfs_core/libzfs_core.la

EXTRA_DIST = data_conn.h mgmt_conn.h
