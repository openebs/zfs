AC_DEFUN([ZFS_AC_CONFIG_USER_ENABLE_TUNING], [
	AC_ARG_ENABLE(tuning,
		AC_HELP_STRING([--enable-tuning],
		[Enable zfs parameters tuning [[default: no]]]),
		[tuning=$enableval])

	AC_MSG_CHECKING(for enabling tuning)
	AC_MSG_RESULT([$tuning])

	AS_IF([test "x$tuning" == xyes], [
		ENABLE_TUNING_FLAGS="-D_ENABLE_TUNING"
	], [ENABLE_TUNING_FLAGS=])

	AC_SUBST(ENABLE_TUNING_FLAGS)
])
