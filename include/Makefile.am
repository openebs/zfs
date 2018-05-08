SUBDIRS = linux sys

COMMON_H = \
	$(top_srcdir)/include/zfeature_common.h \
	$(top_srcdir)/include/zfs_comutil.h \
	$(top_srcdir)/include/zfs_deleg.h \
	$(top_srcdir)/include/zfs_fletcher.h \
	$(top_srcdir)/include/zfs_namecheck.h \
	$(top_srcdir)/include/zfs_prop.h \
	$(top_srcdir)/include/zpios-ctl.h

KERNEL_H = \
	$(top_srcdir)/include/zpios-internal.h

USER_H = \
	$(top_srcdir)/include/libnvpair.h \
	$(top_srcdir)/include/libuutil_common.h \
	$(top_srcdir)/include/libuutil.h \
	$(top_srcdir)/include/libuutil_impl.h \
	$(top_srcdir)/include/libzfs.h \
	$(top_srcdir)/include/libuzfs.h \
	$(top_srcdir)/include/libzfs_core.h \
	$(top_srcdir)/include/libzfs_impl.h \
	$(top_srcdir)/include/uzfs_io.h \
	$(top_srcdir)/include/uzfs_mgmt.h \
	$(top_srcdir)/include/zrepl_prot.h \
	$(top_srcdir)/include/zrepl_mgmt.h \
	$(top_srcdir)/include/uzfs_test.h \
	$(top_srcdir)/include/rte_ring.h \
	$(top_srcdir)/include/rte_atomic_64.h \
	$(top_srcdir)/include/rte_atomic_generic.h \
	$(top_srcdir)/include/rte_atomic.h \
	$(top_srcdir)/include/rte_common.h \
	$(top_srcdir)/include/rte_memory.h \
	$(top_srcdir)/include/rte_pause.h \
	$(top_srcdir)/include/uzfs_zap.h \
	$(top_srcdir)/include/uzfs_rebuilding.h \
	$(top_srcdir)/include/gtest_utils.h

EXTRA_DIST = $(COMMON_H) $(KERNEL_H) $(USER_H)

if CONFIG_USER
libzfsdir = $(includedir)/libzfs
libzfs_HEADERS = $(COMMON_H) $(USER_H)
endif

if CONFIG_KERNEL
kerneldir = @prefix@/src/zfs-$(VERSION)/include
kernel_HEADERS = $(COMMON_H) $(KERNEL_H)
endif
