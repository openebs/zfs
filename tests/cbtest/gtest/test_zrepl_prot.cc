/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */

/*
 * Copyright (c) 2018 CloudByte, Inc. All rights reserved.
 */

#include <gtest/gtest.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <zrepl_prot.h>
#include "gtest_utils.h"

using namespace GtestUtils;

pid_t start_zrepl() {
	std::string zrepl_path = getCmdPath("zrepl");
	pid_t pid;
	int i = 0;

	pid = fork();
	if (pid == 0) {
		execl(zrepl_path.c_str(), zrepl_path.c_str(),
			"start", "-t", "127.0.0.1", NULL);
	}
	/* wait for zrepl to come up - is there a better way? */
	while (i < 10) {
		try {
			execCmd("zpool", "list");
			return pid;
		} catch (std::runtime_error &) {
			sleep(1);
			i++;
		}
	}
	throw std::runtime_error(
	    std::string("Timed out waiting for zrepl to come up"));
}

/*
 * Listen for incoming connection from replica and return new connection fd.
 */
int setup_control_connection() {
	struct sockaddr_in addr;
	int listenfd, fd;
	int opt = 1;
	int rc;

	listenfd = socket(AF_INET, SOCK_STREAM, 0);
	if (listenfd < 0) {
		perror("socket");
		return (-1);
	}
	setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, (void *) &opt,
	    sizeof (opt));
	memset(&addr, 0, sizeof (addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_ANY);
	addr.sin_port = htons(TARGET_PORT);
	rc = bind(listenfd, (struct sockaddr *) &addr, sizeof (addr));
	if (rc != 0) {
		perror("bind");
		close(listenfd);
		return (-1);
	}
	rc = listen(listenfd, 1);
	if (rc != 0) {
		perror("listen");
		close(listenfd);
		return (-1);
	}
	fd = accept(listenfd, NULL, NULL);
	if (rc < 0) {
		perror("accept");
		close(listenfd);
		return (-1);
	}
	close(listenfd);
	return fd;
}

class TestZvol {
public:
	TestZvol(std::string poolname) {
		pool = poolname;
		path = std::string("/tmp/") + pool;
		name = pool + "/vol";
	}

	~TestZvol() {
		try {
			execCmd("zpool", std::string("destroy -f ") + pool);
		} catch (std::runtime_error re) {
			;
		}
		unlink(path.c_str());
	}

	void create() {
		int fd, rc;

		fd = open(path.c_str(), O_RDWR | O_CREAT | O_TRUNC, 0666);
		if (fd < 0)
			throw std::system_error(errno, std::system_category(),
			    "Cannot create vdev file");

		rc = ftruncate(fd, 100 * 1024 * 1024);
		close(fd);
		if (rc != 0)
			throw std::system_error(errno, std::system_category(),
			    "Cannot truncate vdev file");
		execCmd("zpool", std::string("create ") + pool + " " + path);
		execCmd("zfs", std::string("create -sV 10m -o volblocksize=4k ")
		    + name);
	}

	std::string name;
	std::string pool;
	std::string path;
};

class ZreplHandshakeTest : public testing::Test {
protected:
	/* Shared setup hook for all zrepl handshake tests - called just once */
	static void SetUpTestCase() {
		m_pid = start_zrepl();
		m_zvol = new TestZvol("handshake");
		m_zvol->create();
	}

	static void TearDownTestCase() {
		delete m_zvol;
		if (m_pid > 0)
			kill(m_pid, SIGTERM);
	}

	ZreplHandshakeTest() {
		m_control_fd = -1;
	}

	virtual void SetUp() override {
		m_control_fd = setup_control_connection();
		ASSERT_GE(m_control_fd, 0);
	}

	virtual void TearDown() override {
		if (m_control_fd >= 0)
			close(m_control_fd);
	}

	static pid_t	m_pid;
	static TestZvol *m_zvol;

	int	m_control_fd;
};

pid_t ZreplHandshakeTest::m_pid = 0;
TestZvol *ZreplHandshakeTest::m_zvol = nullptr;

class ZreplDataTest : public testing::Test {
protected:
	/* Shared setup hook for all zrepl data tests - called just once */
	static void SetUpTestCase() {
		zvol_io_hdr_t hdr_out, hdr_in;
		mgmt_ack_t mgmt_ack;
		m_zvol = new TestZvol("handshake");
		int rc;

		m_pid = start_zrepl();
		m_control_fd = setup_control_connection();
		ASSERT_GE(m_control_fd, 0);

		m_zvol->create();

		hdr_out.version = REPLICA_VERSION;
		hdr_out.opcode = ZVOL_OPCODE_HANDSHAKE;
		hdr_out.status = ZVOL_OP_STATUS_OK;
		hdr_out.io_seq = 0;
		hdr_out.offset = 0;
		hdr_out.len = m_zvol->name.length() + 1;

		rc = write(m_control_fd, &hdr_out, sizeof (hdr_out));
		ASSERT_EQ(rc, sizeof (hdr_out));
		rc = write(m_control_fd, m_zvol->name.c_str(), hdr_out.len);
		ASSERT_EQ(rc, hdr_out.len);

		rc = read(m_control_fd, &hdr_in, sizeof (hdr_in));
		ASSERT_EQ(rc, sizeof (hdr_in));
		EXPECT_EQ(hdr_in.version, REPLICA_VERSION);
		EXPECT_EQ(hdr_in.opcode, ZVOL_OPCODE_HANDSHAKE);
		EXPECT_EQ(hdr_in.status, ZVOL_OP_STATUS_OK);
		EXPECT_EQ(hdr_in.io_seq, 0);
		ASSERT_EQ(hdr_in.len, sizeof (mgmt_ack));
		rc = read(m_control_fd, &mgmt_ack, sizeof (mgmt_ack));
		ASSERT_EQ(rc, sizeof (mgmt_ack));
		EXPECT_STREQ(mgmt_ack.volname, m_zvol->name.c_str());
		m_host = std::string(mgmt_ack.ip);
		m_port = mgmt_ack.port;
	}

	static void TearDownTestCase() {
		delete m_zvol;
		if (m_control_fd >= 0)
			close(m_control_fd);
		if (m_pid > 0)
			kill(m_pid, SIGTERM);
	}

	ZreplDataTest() {
		m_data_fd = -1;
		m_ioseq = 0;
	}

	/*
	 * Create data connection and send handshake msg for the zvol.
	 */
	virtual void SetUp() override {
		struct sockaddr_in addr;
		zvol_io_hdr_t hdr_out;
		int rc;

		m_data_fd = socket(AF_INET, SOCK_STREAM, 0);
		ASSERT_TRUE(m_data_fd >= 0);
		memset(&addr, 0, sizeof (addr));
		addr.sin_family = AF_INET;
		addr.sin_port = htons(m_port);
		rc = inet_pton(AF_INET, m_host.c_str(), &addr.sin_addr);
		ASSERT_TRUE(rc > 0);
		rc = connect(m_data_fd, (struct sockaddr *)&addr, sizeof (addr));
		if (rc != 0) {
			perror("connect");
			ASSERT_EQ(errno, 0);
		}

		hdr_out.version = REPLICA_VERSION;
		hdr_out.opcode = ZVOL_OPCODE_HANDSHAKE;
		hdr_out.status = ZVOL_OP_STATUS_OK;
		hdr_out.io_seq = 0;
		hdr_out.offset = 0;
		hdr_out.len = m_zvol->name.length() + 1;

		rc = write(m_data_fd, &hdr_out, sizeof (hdr_out));
		ASSERT_EQ(rc, sizeof (hdr_out));
		rc = write(m_data_fd, m_zvol->name.c_str(), hdr_out.len);
		ASSERT_EQ(rc, hdr_out.len);
	}

	virtual void TearDown() override {
		int rc, val;

		if (m_data_fd >= 0) {
			/*
			 * We have to wait for the other end to close the
			 * connection, because the next test case could
			 * initiate a new connection before this one is
			 * fully closed and cause a handshake error.
			 */
			shutdown(m_data_fd, SHUT_WR);
			rc = read(m_data_fd, &val, sizeof (val));
			ASSERT_EQ(rc, 0);
			close(m_data_fd);
		}
	}

	/*
	 * Send header for data write. Leave write of actual data to the caller.
	 * len is real length - including metadata headers.
	 */
	void write_data_start(size_t offset, int len) {
		zvol_io_hdr_t hdr_out;
		int rc;

		hdr_out.version = REPLICA_VERSION;
		hdr_out.opcode = ZVOL_OPCODE_WRITE;
		hdr_out.status = ZVOL_OP_STATUS_OK;
		hdr_out.io_seq = ++m_ioseq;
		hdr_out.offset = offset;
		hdr_out.len = len;

		rc = write(m_data_fd, &hdr_out, sizeof (hdr_out));
		ASSERT_EQ(rc, sizeof (hdr_out));
	}

	void write_data(void *buf, size_t offset, int len, uint64_t io_num) {
		struct zvol_io_rw_hdr write_hdr;
		int rc;

		write_data_start(offset, sizeof (write_hdr) + len);

		write_hdr.len = len;
		write_hdr.io_num = io_num;
		rc = write(m_data_fd, &write_hdr, sizeof (write_hdr));
		ASSERT_EQ(rc, sizeof (write_hdr));
		rc = write(m_data_fd, buf, len);
		ASSERT_EQ(rc, len);
	}

	/*
	 * Send command to read data and read reply header. Reading payload is
	 * left to the caller.
	 */
	void read_data_start(size_t offset, int len, zvol_io_hdr_t *hdr_inp)
	{
		zvol_io_hdr_t hdr_out;
		int rc;

		hdr_out.version = REPLICA_VERSION;
		hdr_out.opcode = ZVOL_OPCODE_READ;
		hdr_out.status = ZVOL_OP_STATUS_OK;
		hdr_out.io_seq = ++m_ioseq;
		hdr_out.offset = offset;
		hdr_out.len = len;

		rc = write(m_data_fd, &hdr_out, sizeof (hdr_out));
		ASSERT_EQ(rc, sizeof (hdr_out));
		rc = read(m_data_fd, hdr_inp, sizeof (*hdr_inp));
		ASSERT_EQ(rc, sizeof (*hdr_inp));
		ASSERT_EQ(hdr_inp->opcode, ZVOL_OPCODE_READ);
		ASSERT_EQ(hdr_inp->status, ZVOL_OP_STATUS_OK);
		ASSERT_EQ(hdr_inp->io_seq, m_ioseq);
		ASSERT_EQ(hdr_inp->offset, offset);
	}

	static pid_t	m_pid;
	static int	m_control_fd;
	static uint16_t m_port;
	static std::string m_host;
	static TestZvol *m_zvol;

	int	m_data_fd;
	int	m_ioseq;
};

pid_t ZreplDataTest::m_pid = 0;
int ZreplDataTest::m_control_fd = -1;
uint16_t ZreplDataTest::m_port = 0;
std::string ZreplDataTest::m_host = "";
TestZvol *ZreplDataTest::m_zvol = nullptr;

TEST_F(ZreplHandshakeTest, HandshakeOk) {
	zvol_io_hdr_t hdr_out, hdr_in;
	std::string output;
	mgmt_ack_t mgmt_ack;
	int rc;

	hdr_out.version = REPLICA_VERSION;
	hdr_out.opcode = ZVOL_OPCODE_HANDSHAKE;
	hdr_out.status = ZVOL_OP_STATUS_OK;
	hdr_out.io_seq = 0;
	hdr_out.offset = 0;
	hdr_out.len = m_zvol->name.length() + 1;

	rc = write(m_control_fd, &hdr_out, sizeof (hdr_out));
	ASSERT_EQ(rc, sizeof (hdr_out));
	rc = write(m_control_fd, m_zvol->name.c_str(), hdr_out.len);
	ASSERT_EQ(rc, hdr_out.len);

	rc = read(m_control_fd, &hdr_in, sizeof (hdr_in));
	ASSERT_EQ(rc, sizeof (hdr_in));
	EXPECT_EQ(hdr_in.version, REPLICA_VERSION);
	EXPECT_EQ(hdr_in.opcode, ZVOL_OPCODE_HANDSHAKE);
	EXPECT_EQ(hdr_in.status, ZVOL_OP_STATUS_OK);
	EXPECT_EQ(hdr_in.io_seq, 0);
	EXPECT_EQ(hdr_in.offset, 0);
	ASSERT_EQ(hdr_in.len, sizeof (mgmt_ack));
	rc = read(m_control_fd, &mgmt_ack, sizeof (mgmt_ack));
	ASSERT_EQ(rc, sizeof (mgmt_ack));
	EXPECT_STREQ(mgmt_ack.volname, m_zvol->name.c_str());
	output = execCmd("zpool", std::string("get guid -Hpo value ") +
	    m_zvol->pool);
	EXPECT_EQ(mgmt_ack.pool_guid, std::stoul(output));
	output = execCmd("zfs", std::string("get guid -Hpo value ") +
	    m_zvol->name);
	EXPECT_EQ(mgmt_ack.zvol_guid, std::stoul(output));
}

TEST_F(ZreplHandshakeTest, HandshakeWrongVersion) {
	zvol_io_hdr_t hdr_out, hdr_in;
	int rc;
	char *msg;

	hdr_out.version = REPLICA_VERSION + 1;
	hdr_out.opcode = ZVOL_OPCODE_HANDSHAKE;
	hdr_out.status = ZVOL_OP_STATUS_OK;
	hdr_out.io_seq = 0;
	hdr_out.offset = 0;
	hdr_out.len = m_zvol->name.length() + 1;

	/*
	 * It must be set in one chunk so that server does not close the
	 * connection after sending header but before sending zvol name.
	 */
	msg = (char *)malloc(sizeof (hdr_out) + hdr_out.len);
	memcpy(msg, &hdr_out, sizeof (hdr_out));
	memcpy(msg + sizeof (hdr_out), m_zvol->name.c_str(), hdr_out.len);
	rc = write(m_control_fd, msg, sizeof (hdr_out) + hdr_out.len);
	ASSERT_EQ(rc, sizeof (hdr_out) + hdr_out.len);
	free(msg);

	rc = read(m_control_fd, &hdr_in, sizeof (hdr_in));
	ASSERT_EQ(rc, sizeof (hdr_in));
	EXPECT_EQ(hdr_in.version, REPLICA_VERSION);
	EXPECT_EQ(hdr_in.opcode, ZVOL_OPCODE_HANDSHAKE);
	EXPECT_EQ(hdr_in.status, ZVOL_OP_STATUS_VERSION_MISMATCH);
	EXPECT_EQ(hdr_in.io_seq, 0);
	EXPECT_EQ(hdr_in.offset, 0);
	ASSERT_EQ(hdr_in.len, 0);
}

TEST_F(ZreplHandshakeTest, HandshakeUnknownZvol) {
	zvol_io_hdr_t hdr_out, hdr_in;
	int rc;
	const char *volname = "handshake/unknown";

	hdr_out.version = REPLICA_VERSION;
	hdr_out.opcode = ZVOL_OPCODE_HANDSHAKE;
	hdr_out.status = ZVOL_OP_STATUS_OK;
	hdr_out.io_seq = 0;
	hdr_out.offset = 0;
	hdr_out.len = strlen(volname) + 1;

	rc = write(m_control_fd, &hdr_out, sizeof (hdr_out));
	ASSERT_ERRNO("write", rc >= 0);
	ASSERT_EQ(rc, sizeof (hdr_out));
	rc = write(m_control_fd, volname, hdr_out.len);
	ASSERT_ERRNO("write", rc >= 0);
	ASSERT_EQ(rc, hdr_out.len);

	rc = read(m_control_fd, &hdr_in, sizeof (hdr_in));
	ASSERT_ERRNO("read", rc >= 0);
	ASSERT_EQ(rc, sizeof (hdr_in));
	EXPECT_EQ(hdr_in.version, REPLICA_VERSION);
	EXPECT_EQ(hdr_in.opcode, ZVOL_OPCODE_HANDSHAKE);
	EXPECT_EQ(hdr_in.status, ZVOL_OP_STATUS_FAILED);
	EXPECT_EQ(hdr_in.io_seq, 0);
	EXPECT_EQ(hdr_in.offset, 0);
	ASSERT_EQ(hdr_in.len, 0);
}

/*
 * Write two blocks with the same io_num and third one with a different io_num
 * and test that read returns two metadata chunks.
 */
TEST_F(ZreplDataTest, ReadBlocks) {
	zvol_io_hdr_t hdr_in;
	struct zvol_io_rw_hdr read_hdr;
	int rc;
	struct zvol_io_rw_hdr write_hdr;
	char buf[4096];

	/* write 1th data block */
	init_buf(buf, sizeof (buf), "cStor-data");
	write_data(buf, 0, sizeof (buf), 123);
	rc = read(m_data_fd, &hdr_in, sizeof (hdr_in));
	ASSERT_ERRNO("read", rc >= 0);
	ASSERT_EQ(rc, sizeof (hdr_in));
	EXPECT_EQ(hdr_in.opcode, ZVOL_OPCODE_WRITE);
	EXPECT_EQ(hdr_in.status, ZVOL_OP_STATUS_OK);
	EXPECT_EQ(hdr_in.io_seq, m_ioseq);
	EXPECT_EQ(hdr_in.offset, 0);
	ASSERT_EQ(hdr_in.len, sizeof (buf) + sizeof (write_hdr));

	/* write two chunks with different IO nums in one request */
	write_data_start(sizeof (buf), 2 * (sizeof (write_hdr) + sizeof (buf)));

	write_hdr.len = sizeof (buf);
	write_hdr.io_num = 123;
	rc = write(m_data_fd, &write_hdr, sizeof (write_hdr));
	ASSERT_ERRNO("write", rc >= 0);
	ASSERT_EQ(rc, sizeof (write_hdr));
	rc = write(m_data_fd, buf, sizeof (buf));
	ASSERT_ERRNO("write", rc >= 0);
	ASSERT_EQ(rc, sizeof (buf));

	write_hdr.len = sizeof (buf);
	write_hdr.io_num = 124;
	rc = write(m_data_fd, &write_hdr, sizeof (write_hdr));
	ASSERT_ERRNO("write", rc >= 0);
	ASSERT_EQ(rc, sizeof (write_hdr));
	rc = write(m_data_fd, buf, sizeof (buf));
	ASSERT_ERRNO("write", rc >= 0);
	ASSERT_EQ(rc, sizeof (buf));

	rc = read(m_data_fd, &hdr_in, sizeof (hdr_in));
	ASSERT_ERRNO("write", rc >= 0);
	ASSERT_EQ(rc, sizeof (hdr_in));
	EXPECT_EQ(hdr_in.opcode, ZVOL_OPCODE_WRITE);
	EXPECT_EQ(hdr_in.status, ZVOL_OP_STATUS_OK);
	EXPECT_EQ(hdr_in.io_seq, m_ioseq);

	/* read all blocks at once and check IO nums */
	read_data_start(0, 3 * sizeof (buf), &hdr_in);
	ASSERT_EQ(hdr_in.len, 2 * sizeof (read_hdr) + 3 * sizeof (buf));

	rc = read(m_data_fd, &read_hdr, sizeof (read_hdr));
	ASSERT_ERRNO("read", rc >= 0);
	ASSERT_EQ(rc, sizeof (read_hdr));
	ASSERT_EQ(read_hdr.io_num, 123);
	ASSERT_EQ(read_hdr.len, 2 * sizeof (buf));
	rc = read(m_data_fd, buf, sizeof (buf));
	ASSERT_ERRNO("read", rc >= 0);
	ASSERT_EQ(rc, sizeof (buf));
	rc = verify_buf(buf, sizeof (buf), "cStor-data");
	ASSERT_EQ(rc, 0);
	rc = read(m_data_fd, buf, sizeof (buf));
	ASSERT_ERRNO("read", rc >= 0);
	ASSERT_EQ(rc, sizeof (buf));
	rc = verify_buf(buf, sizeof (buf), "cStor-data");
	ASSERT_EQ(rc, 0);

	rc = read(m_data_fd, &read_hdr, sizeof (read_hdr));
	ASSERT_ERRNO("read", rc >= 0);
	ASSERT_EQ(rc, sizeof (read_hdr));
	ASSERT_EQ(read_hdr.io_num, 124);
	ASSERT_EQ(read_hdr.len, sizeof (buf));
	rc = read(m_data_fd, buf, read_hdr.len);
	ASSERT_ERRNO("read", rc >= 0);
	ASSERT_EQ(rc, read_hdr.len);
	rc = verify_buf(buf, sizeof (buf), "cStor-data");
	ASSERT_EQ(rc, 0);
}

TEST_F(ZreplDataTest, ReadBlockWithoutMeta) {
	zvol_io_hdr_t hdr_in;
	struct zvol_io_rw_hdr read_hdr;
	int rc;
	char buf[4096];

	read_data_start(1024 * sizeof (buf), sizeof (buf), &hdr_in);
	ASSERT_EQ(hdr_in.len, sizeof (read_hdr) + sizeof (buf));

	rc = read(m_data_fd, &read_hdr, sizeof (read_hdr));
	ASSERT_ERRNO("read", rc >= 0);
	ASSERT_EQ(rc, sizeof (read_hdr));
	ASSERT_EQ(read_hdr.io_num, 0);
	ASSERT_EQ(read_hdr.len, sizeof (buf));
	rc = read(m_data_fd, buf, read_hdr.len);
	ASSERT_ERRNO("read", rc >= 0);
	ASSERT_EQ(rc, read_hdr.len);
}
