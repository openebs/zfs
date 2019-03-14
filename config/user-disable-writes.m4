AC_DEFUN([ZFS_AC_CONFIG_USER_DISABLE_WRITES], [
	AC_ARG_ENABLE(writes,
		AC_HELP_STRING([--disable-writes],
		[disable level 0 writes in userspace [[default: no]]]),
		[writes=$enableval],
		[writes=yes])

	AC_MSG_CHECKING(for enabling writes)
	AC_MSG_RESULT([$writes])

	AS_IF([test "x$writes" == xno], [
		DISABLE_WRITES_CFLAGS="-D_DISABLE_WRITES"
	])

	AC_SUBST(DISABLE_WRITES_CFLAGS)
])
