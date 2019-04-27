include $(top_srcdir)/config/Rules.am

AM_CPPFLAGS += $(DEBUG_CFLAGS) $(DEBUG_STACKFLAGS)

DEFAULT_INCLUDES += \
	${UZFS_HEADER}	\
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/lib/libspl/include

sbin_PROGRAMS = test_uzfs test_uzfsserver test_zfs test_zrepl_prot

test_uzfsserver_SOURCES = test_uzfsserver.cc
test_uzfs_SOURCES = test_uzfs.cc gtest_utils.cc
test_zrepl_prot_SOURCES = test_zrepl_prot.cc gtest_utils.cc
test_zfs_SOURCES = test_zfs.cc gtest_utils.cc

test_uzfs_LDADD = \
	$(top_builddir)/lib/libnvpair/libnvpair.la \
	$(top_builddir)/lib/libuutil/libuutil.la \
	$(top_builddir)/lib/libzpool/libzpool.la \
	$(top_builddir)/lib/libzfs/libzfs.la \
	$(top_builddir)/lib/libzfs_core/libzfs_core.la

test_uzfsserver_LDADD = \
	$(top_builddir)/lib/libnvpair/libnvpair.la \
	$(top_builddir)/lib/libuutil/libuutil.la \
	$(top_builddir)/lib/libzpool/libzpool.la \
	$(top_builddir)/lib/libzfs/libzfs.la \
	$(top_builddir)/lib/libzfs_core/libzfs_core.la

test_uzfsserver_CXXFLAGS = -std=c++11
test_uzfsserver_LDFLAGS = -pthread -lgtest -lgtest_main ${UZFS_LIB}
test_uzfs_CXXFLAGS = -std=c++11
test_uzfs_LDFLAGS = -pthread -lgtest -lgtest_main ${UZFS_LIB}

#to resolve dependency for zrepl
#LDFLAGS+= -lzfs

test_zrepl_prot_LDFLAGS = -pthread -lgtest -lgtest_main -ljson-c
test_zfs_LDFLAGS = -pthread -lgtest -lgtest_main
