include $(top_srcdir)/config/Rules.am

AM_CFLAGS += $(DEBUG_STACKFLAGS) $(FRAME_LARGER_THAN)
AM_CPPFLAGS += -DDEBUG

DEFAULT_INCLUDES += \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/lib/libspl/include

bin_PROGRAMS = raidz_test

raidz_test_SOURCES = \
	raidz_test.h \
	raidz_test.c \
	raidz_bench.c

raidz_test_LDFLAGS = \
	-Wl,--start-group	\
	$(top_builddir)/lib/libnvpair/libnvpair.la \
	$(top_builddir)/lib/libuutil/libuutil.la \
	$(top_builddir)/lib/libzpool/libzpool.la	\
	${UZFS_LIB}	\
	$(top_builddir)/lib/libzfs/libzfs.la \
	$(top_builddir)/lib/libzfs_core/libzfs_core.la -Wl,--end-group

raidz_test_LDFLAGS += -lm -ldl
