AC_DEFUN([ZFS_AC_CONFIG_USER_SMALL_IND_SZ], [
	AC_ARG_ENABLE(small_ind_sz,
		AC_HELP_STRING([--enable-small-ind-sz],
		[enable small indirect blocksize [[default: no]]]),
		[small_ind_sz=$enableval],
		[small_ind_sz=no])

	AC_MSG_CHECKING(for enabling small indirect size)
	AC_MSG_RESULT([$small_ind_sz])

	AS_IF([test "x$small_ind_sz" == xyes], [
		SMALL_IND_SZ="-D_SMALL_IND_SZ"
	])

	AC_SUBST(SMALL_IND_SZ)
])
