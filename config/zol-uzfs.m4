AC_DEFUN([ZFS_ZOL_UZFS], [
	AC_ARG_ENABLE(uzfs,
		AC_HELP_STRING([--enable-uzfs],
		[enable ioctls over tcp to userspace program [[default: no]]]),
		[],enable_uzfs=no)

	AS_IF([test "x$enable_uzfs" = xyes],
	[
		UZFS_CFLAGS="-D_UZFS -Werror"
	])

	AC_MSG_CHECKING(for enabling uzfs)
	AC_MSG_RESULT([$enable_uzfs])

	AC_SUBST(UZFS_CFLAGS)

	AM_CONDITIONAL([ENABLE_UZFS],
	    [test "x$enable_uzfs" = xyes])
])
