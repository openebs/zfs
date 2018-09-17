include $(top_srcdir)/config/Rules.am

AM_CFLAGS += $(DEBUG_STACKFLAGS) $(FRAME_LARGER_THAN)

DEFAULT_INCLUDES += \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/lib/libspl/include

lib_LTLIBRARIES = libzrepl.la

USER_C = \
	mgmt_conn.c \
	data_conn.c

nodist_libzrepl_la_SOURCES = \
	$(USER_C)

libzrepl_la_LIBADD = \
	$(top_builddir)/lib/libunicode/libunicode.la \
	$(top_builddir)/lib/libuutil/libuutil.la \
	$(top_builddir)/lib/libnvpair/libnvpair.la \
	$(top_builddir)/lib/libzpool/libzpool.la \
	$(top_builddir)/lib/libicp/libicp.la

libzrepl_la_LIBADD += $(ZLIB) -ldl -lm -laio $(JEMALLOCLIB) -ljson-c
libzrepl_la_LDFLAGS = -version-info 2:0:0

EXTRA_DIST = $(USER_C)
