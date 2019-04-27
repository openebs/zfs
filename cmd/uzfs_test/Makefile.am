include $(top_srcdir)/config/Rules.am

# -Wnoformat-truncation to get rid of compiler warning for unchecked
#  truncating snprintfs on gcc 7.1.1.
AM_CFLAGS += $(DEBUG_STACKFLAGS) $(FRAME_LARGER_THAN) $(NO_FORMAT_TRUNCATION)
AM_CPPFLAGS += -DDEBUG

DEFAULT_INCLUDES += \
	${UZFS_HEADER}	\
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/lib/libspl/include

sbin_PROGRAMS = uzfs_test

uzfs_test_SOURCES = \
	uzfs_test.c	\
	uzfs_test_sync.c \
	uzfs_zvol_zap.c \
	zrepl_utest.c \
	uzfs_test_rebuilding.c

uzfs_test_LDFLAGS = \
	-Wl,--start-group	\
	$(top_builddir)/lib/libnvpair/libnvpair.la \
	$(top_builddir)/lib/libuutil/libuutil.la \
	$(top_builddir)/lib/libzpool/libzpool.la \
	${UZFS_LIB}	\
	$(top_builddir)/lib/libzfs/libzfs.la \
	$(top_builddir)/lib/libzfs_core/libzfs_core.la -Wl,--end-group

uzfs_test_LDFLAGS += -lm -ljson-c

