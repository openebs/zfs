include $(top_srcdir)/config/Rules.am

DEFAULT_INCLUDES += \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/lib/libspl/include

sbin_PROGRAMS = test_uzfs test_zrepl_prot test_export

test_uzfs_SOURCES = test_uzfs.cc
test_zrepl_prot_SOURCES = test_zrepl_prot.cc gtest_utils.cc

test_export_SOURCES = \
	test_export.cc gtest_utils.cc

test_uzfs_LDADD = \
	$(top_builddir)/lib/libnvpair/libnvpair.la \
	$(top_builddir)/lib/libuutil/libuutil.la \
	$(top_builddir)/lib/libzpool/libzpool.la \
	$(top_builddir)/lib/libzfs/libzfs.la \
	$(top_builddir)/lib/libzfs_core/libzfs_core.la

test_export_LDADD = \
	$(top_builddir)/lib/libnvpair/libnvpair.la \
	$(top_builddir)/lib/libuutil/libuutil.la \
	$(top_builddir)/lib/libzpool/libzpool.la \
	$(top_builddir)/lib/libzfs/libzfs.la \
	$(top_builddir)/lib/libzfs_core/libzfs_core.la

test_export_CXXFLAGS = -Wno-write-strings -std=c++11
test_export_LDFLAGS = -pthread -lgtest -lgtest_main

test_uzfs_CXXFLAGS = -std=c++11
test_uzfs_LDFLAGS = -pthread -lgtest -lgtest_main
test_zrepl_prot_LDFLAGS = -pthread -lgtest -lgtest_main
