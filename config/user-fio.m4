AC_DEFUN([ZFS_AC_CONFIG_USER_FIO], [
	AC_ARG_WITH(fio,
		[AC_HELP_STRING([--with-fio=dir],
		    [build with FIO engine for replica protocol])],
		[AC_CHECK_FILE($withval/fio.h,
		    [FIO_SRCDIR=$withval],
		    [AC_MSG_FAILURE([Not a valid fio repository])])])
	])

	AC_SUBST([FIO_SRCDIR])
])
