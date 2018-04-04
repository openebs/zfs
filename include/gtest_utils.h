
#ifndef _UZFS_UTILS_H
#define	_UZFS_UTILS_H

#include <gtest/gtest.h>

/* Prints errno string if cond is not true */
#define	ASSERT_ERRNO(fname, cond)	do { \
	if (!(cond)) { \
		perror(fname); \
		ASSERT_EQ(errno, 0); \
	} \
} while (0)

namespace GtestUtils {
	std::string execCmd(std::string const &zfsCmd, std::string const &args);
	std::string getCmdPath(std::string zfsCmd);
	int verify_buf(void *buf, int len, const char *pattern);
	void init_buf(void *buf, int len, const char *pattern);
}

#endif	// _UZFS_UTILS_H
