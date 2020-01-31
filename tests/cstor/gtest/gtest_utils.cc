
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>

#include <cstdio>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <array>
#include <algorithm>

#include "gtest_utils.h"

#define	POOL_SIZE	(100 * 1024 * 1024)
#define	ZVOL_SIZE	(10 * 1024 * 1024)

/*
 * We have to wait for the other end to close the connection, because the
 * next test case could initiate a new connection before this one is
 * fully closed and cause a handshake error. Or it could result in EBUSY
 * error when destroying zpool if it is not released in time by zrepl.
 */
void GtestUtils::graceful_close(int sockfd)
{
	int rc;
	char val;

	if (sockfd < 0)
		return;
	shutdown(sockfd, SHUT_WR);
	rc = read(sockfd, &val, sizeof (val));
	ASSERT_EQ(rc, 0);
	close(sockfd);
}

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

	// Trim white space at the end of string
	result.erase(std::find_if(result.rbegin(), result.rend(),
	    std::not1(std::ptr_fun<int, int>(std::isspace))).base(),
	    result.end());
	return result;
}

void GtestUtils::Vdev::create() {
	int fd, rc;

	fd = open(m_path.c_str(), O_RDWR | O_CREAT | O_TRUNC, 0666);
	if (fd < 0)
		throw std::system_error(errno, std::system_category(),
		    "Cannot create vdev file");

	rc = ftruncate(fd, POOL_SIZE);
	close(fd);
	if (rc != 0)
		throw std::system_error(errno, std::system_category(),
		    "Cannot truncate vdev file");
}

void GtestUtils::TestPool::create() {
	m_vdev->create();
	execCmd("zpool", std::string("create ") + m_name + " " +
	    m_vdev->m_path);
}

void GtestUtils::TestPool::import() {
	execCmd("zpool", std::string("import ") + m_name + " -d /tmp");
}

void GtestUtils::TestPool::pExport() {
	execCmd("zpool", std::string("export ") + m_name);
}

void GtestUtils::TestPool::createZvol(std::string name, std::string arg /*= ""*/) {
	execCmd("zfs",
	    std::string("create -sV ") + std::to_string(ZVOL_SIZE) +
	    " -o volblocksize=4k " + arg + " " + m_name + "/" + name);
}

void GtestUtils::TestPool::destroyZvol(std::string name) {
	execCmd("zfs", std::string("destroy -R ") + m_name + "/" + name);
}

std::string GtestUtils::TestPool::getZvolName(std::string name) {
	return (m_name + "/" + name);
}

void GtestUtils::Zrepl::start() {
	std::string zrepl_path = getCmdPath("zrepl");
	int i = 0;

	if (m_pid != 0) {
		throw std::runtime_error(
		    std::string("zrepl has been already started"));
	}
	m_pid = fork();
	if (m_pid == 0) {
		execl(zrepl_path.c_str(), zrepl_path.c_str(), NULL);
	}
	/* wait for zrepl to come up - is there a better way? */
	while (i < 10) {
		try {
			execCmd("zpool", "list");
			return;
		} catch (std::runtime_error &) {
			sleep(1);
			i++;
		}
	}
	throw std::runtime_error(
	    std::string("Timed out waiting for zrepl to come up"));
}

void GtestUtils::Zrepl::kill() {
	int rc;

	if (m_pid != 0) {
		rc = ::kill(m_pid, SIGTERM);
		while (rc == 0) {
			(void) waitpid(m_pid, NULL, 0);
			rc = ::kill(m_pid, 0);
		}
		m_pid = 0;
	}
}

/*
 * Copies src to the dstsize buffer at dst. The copy will never
 * overflow the destination buffer and the buffer will always be null
 * terminated.
 *
 * This function should be used instead of strncpy to silence errors
 * from coverity about possibly unterminated string. The definition is
 * taken from SPL lib.
 */
size_t
GtestUtils::strlcpy(char *dst, const char *src, size_t len)
{
        size_t slen = strlen(src);
        size_t copied;

        if (len == 0)
                return (slen);

        if (slen >= len)
                copied = len - 1;
        else
                copied = slen;
        (void) memcpy(dst, src, copied);
        dst[copied] = '\0';
        return (slen);
}

int &
GtestUtils::SocketFd::fd()
{
	return m_fd;
}

bool
GtestUtils::SocketFd::opened()
{
	return m_fd;
}

GtestUtils::SocketFd&
GtestUtils::SocketFd::operator=(int other)
{
	m_fd = other;
	return *this;
}

/*
 * We have to wait for the other end to close the connection, because the
 * next test case could initiate a new connection before this one is
 * fully closed and cause a handshake error. Or it could result in EBUSY
 * error when destroying zpool if it is not released in time by zrepl.
 */
void
GtestUtils::SocketFd::graceful_close()
{
	char val;
	int rc;

	if (m_fd >= 0) {
		shutdown(m_fd, SHUT_WR);
		rc = read(m_fd, &val, sizeof (val));
		close(m_fd);
		m_fd = -1;
	}
}

/*
 * Send header for data write. Leave write of actual data to the caller.
 * len is real length - including metadata headers.
 */
void
GtestUtils::write_data_start(int data_fd, uint64_t &ioseq, size_t offset, int len)
{
	zvol_io_hdr_t hdr_out = {0};
	int rc;

	hdr_out.version = REPLICA_VERSION;
	hdr_out.opcode = ZVOL_OPCODE_WRITE;
	hdr_out.status = ZVOL_OP_STATUS_OK;
	hdr_out.io_seq = ++ioseq;
	hdr_out.offset = offset;
	hdr_out.len = len;

	rc = write(data_fd, &hdr_out, sizeof (hdr_out));
	ASSERT_EQ(rc, sizeof (hdr_out));
}

/*
 * Write data at given offset with io_num through data connection
 */
void
GtestUtils::write_data(int data_fd, uint64_t &ioseq, void *buf, size_t offset,
    int len, uint64_t io_num)
{
	struct zvol_io_rw_hdr write_hdr;
	int rc;

	write_data_start(data_fd, ioseq, offset, sizeof (write_hdr) + len);

	write_hdr.len = len;
	write_hdr.io_num = io_num;

	rc = write(data_fd, &write_hdr, sizeof (write_hdr));
	ASSERT_EQ(rc, sizeof (write_hdr));

	rc = write(data_fd, buf, len);
	ASSERT_EQ(rc, len);
}

/*
 * Write data at given offset and io_num
 * Updates io_seq of volume
 */
void
GtestUtils::write_data_and_verify_resp(int data_fd, uint64_t &ioseq, char *buf,
    size_t offset, uint64_t len, uint64_t io_num)
{
	zvol_io_hdr_t hdr_in;
	struct zvol_io_rw_hdr read_hdr;
	int rc;
	struct zvol_io_rw_hdr write_hdr;

	write_data(data_fd, ioseq, buf, offset, len, io_num);

	rc = read(data_fd, &hdr_in, sizeof (hdr_in));
	ASSERT_ERRNO("read", rc >= 0);
	ASSERT_EQ(rc, sizeof (hdr_in));
	EXPECT_EQ(hdr_in.opcode, ZVOL_OPCODE_WRITE);
	EXPECT_EQ(hdr_in.status, ZVOL_OP_STATUS_OK);
	EXPECT_EQ(hdr_in.io_seq, ioseq);
	EXPECT_EQ(hdr_in.offset, offset);
	ASSERT_EQ(hdr_in.len, sizeof (write_hdr) + len);
}

/*
 * Send command to read data and read reply header.
 * Reading payload is left to the caller.
 */
void
GtestUtils::read_data_start(int data_fd, uint64_t &ioseq, size_t offset, int len,
    zvol_io_hdr_t *hdr_inp, struct zvol_io_rw_hdr *rw_hdr, int flags)
{
	zvol_io_hdr_t hdr_out = {0};
	int rc;

	hdr_out.version = REPLICA_VERSION;
	hdr_out.opcode = ZVOL_OPCODE_READ;
	hdr_out.status = ZVOL_OP_STATUS_OK;
	hdr_out.io_seq = ++ioseq;
	hdr_out.offset = offset;
	hdr_out.len = len;
	hdr_out.flags = flags;

	rc = write(data_fd, &hdr_out, sizeof (hdr_out));
	ASSERT_EQ(rc, sizeof (hdr_out));

	rc = read(data_fd, hdr_inp, sizeof (*hdr_inp));
	ASSERT_EQ(rc, sizeof (*hdr_inp));
	ASSERT_EQ(hdr_inp->opcode, ZVOL_OPCODE_READ);
	ASSERT_EQ(hdr_inp->io_seq, ioseq);
	ASSERT_EQ(hdr_inp->offset, offset);

	if (rw_hdr && (hdr_inp->status == ZVOL_OP_STATUS_OK)) {
		rc = read(data_fd, rw_hdr, sizeof (*rw_hdr));
		ASSERT_ERRNO("read", rc >= 0);
		ASSERT_EQ(rc, sizeof (*rw_hdr));
	}
}
