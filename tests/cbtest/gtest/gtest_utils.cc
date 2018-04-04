
#include <cstdio>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <array>

#include "gtest_utils.h"

void GtestUtils::init_buf(void *buf, int len, const char *pattern) {
	int i;
	char c;
	int pat_len = strlen(pattern);

	for (i = 0; i < len; i++) {
		c = pattern[i % pat_len];
		((char *)buf)[i] = c;
	}
}

int GtestUtils::verify_buf(void *buf, int len, const char *pattern) {
	int i;
	char c;
	int pat_len = strlen(pattern);

	for (i = 0; i < len; i++) {
		c = pattern[i % pat_len];
		if (c != ((char *)buf)[i])
			return 1;
	}

	return 0;
}

std::string GtestUtils::getCmdPath(std::string zfsCmd) {
	std::string cmdPath;
	const char *srcPath = std::getenv("SRC_PATH");

	if (srcPath == nullptr) {
		cmdPath += ".";
	} else {
		cmdPath = srcPath;
	}
	cmdPath += "/cmd/" + zfsCmd + "/" + zfsCmd;

	return cmdPath;
}

/*
 * Executes given zfs command with specified arguments and returns its output
 * or throws exception if anything (including the command itself) fails).
 */
std::string GtestUtils::execCmd(std::string const &zfsCmd,
				std::string const &args) {
	std::string cmdLine;
	std::array<char, 128> buffer;
	std::string result;
	FILE *pipe;
	int rc;

	cmdLine = getCmdPath(zfsCmd) + " " + args;

	pipe = popen(cmdLine.c_str(), "r");
	if (!pipe)
		throw std::runtime_error("popen() failed");
	while (!feof(pipe)) {
		if (fgets(buffer.data(), 128, pipe) != nullptr)
			result += buffer.data();
	}
	rc = pclose(pipe);
	if (rc != 0)
		throw std::runtime_error(std::string("Command failed: ") +
		    cmdLine);

	return result;
}
