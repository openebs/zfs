AC_DEFUN([ZFS_ZOL_UZFS], [
	AC_ARG_ENABLE(uzfs,
		AC_HELP_STRING([--enable-uzfs],
		[enable ioctls over tcp to userspace program [[default: no]]]),
        [UZFS_LIB="-lcstor"],
        [enable_uzfs=no])

    AC_ARG_WITH(libcstor,
        AC_HELP_STRING([--with-libcstor=DIR],
            [libcstor headers path]),
        [libcstordir=$withval],
        [libcstordir=check])


	AS_IF([test "x$enable_uzfs" = xyes],
	[
		UZFS_CFLAGS="-D_UZFS -Werror"
	])

    AS_IF([test "x$libcstordir" == xcheck], [
        libcstordir=/usr/local/include/libcstor],[])

	AC_SUBST(UZFS_CFLAGS)
	AC_SUBST(libcstordir)
	AC_SUBST(UZFS_LIB)
	AC_MSG_RESULT([$enable_uzfs])
	AM_CONDITIONAL([ENABLE_UZFS],
	    [test "x$enable_uzfs" = xyes])
])
