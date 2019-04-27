AC_DEFUN([ZFS_ZOL_UZFS], [
	AC_ARG_ENABLE(uzfs,
		AC_HELP_STRING([--enable-uzfs],
		[enable ioctls over tcp to userspace program [[default: no]]]),
        [UZFS_LIB="-lcstor"],
        [enable_uzfs=no])

    AC_ARG_WITH(uzfsheaders,
        AC_HELP_STRING([--with-uzfsheaders],
            [uzfs headers path]),
        [UZFS_HEADER="-I$withval"],
        [UZFS_HEADER])


	AS_IF([test "x$enable_uzfs" = xyes],
	[
		UZFS_CFLAGS="-D_UZFS -Werror"
	])

	AC_SUBST(UZFS_CFLAGS)
	AC_SUBST(UZFS_LIB)
	AC_SUBST(UZFS_HEADER)
	AC_MSG_RESULT([$enable_uzfs])
	AM_CONDITIONAL([ENABLE_UZFS],
	    [test "x$enable_uzfs" = xyes])
])
