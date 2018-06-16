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

/*
 * Common characteristic of the tests in this file is that they test zrepl
 * protocol by issuing commands to independent zrepl process over TCP
 * (this is important distinction from the case when zrepl is instantiated
 * on behalf of the test process itself). Hence all we can test here is the
 * network API. We cannot test any of the uzfs library API directly here.
 */

#include <gtest/gtest.h>
#include <iostream>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <zrepl_prot.h>
#include "gtest_utils.h"

#define	POOL_SIZE	(100 * 1024 * 1024)
#define	ZVOL_SIZE	(10 * 1024 * 1024)

using namespace GtestUtils;

/*
 * Return either when the socket is readable or when timeout expires.
 */
static int ready_for_read(int fd, int timeout) {
	struct timeval tv = {.tv_sec = timeout, .tv_usec = 0};
	fd_set rfds;
	int rc;

	FD_ZERO(&rfds);
	FD_SET(fd, &rfds);

	rc = select(fd + 1, &rfds, NULL, NULL, (timeout >= 0) ? &tv : NULL);
	if (rc == -1) {
		perror("select");
		return (-1);
	}
	return ((rc > 0) ? 1 : 0);
}

/*
 * This fn does handshake for given volname, and fills host/IP
 * res is the expected status of handshake
 */
static void do_handshake(std::string zvol_name, std::string &host,
    uint16_t &port, uint64_t *ionum, int control_fd, int res) {
	zvol_io_hdr_t hdr_out, hdr_in;
	int rc;
	mgmt_ack_t mgmt_ack;
	hdr_out.version = REPLICA_VERSION;
	hdr_out.opcode = ZVOL_OPCODE_HANDSHAKE;
	hdr_out.status = ZVOL_OP_STATUS_OK;
	hdr_out.io_seq = 0;
	hdr_out.offset = 0;
	hdr_out.len = zvol_name.length() + 1;

	rc = write(control_fd, &hdr_out, sizeof (hdr_out));
	ASSERT_EQ(rc, sizeof (hdr_out));
	rc = write(control_fd, zvol_name.c_str(), hdr_out.len);
	ASSERT_EQ(rc, hdr_out.len);

	rc = read(control_fd, &hdr_in, sizeof (hdr_in));
	ASSERT_EQ(rc, sizeof (hdr_in));
	EXPECT_EQ(hdr_in.version, REPLICA_VERSION);
	EXPECT_EQ(hdr_in.opcode, ZVOL_OPCODE_HANDSHAKE);
	EXPECT_EQ(hdr_in.status, res);
	EXPECT_EQ(hdr_in.io_seq, 0);
	if (res == ZVOL_OP_STATUS_FAILED)
		return;
	ASSERT_EQ(hdr_in.len, sizeof (mgmt_ack));
	rc = read(control_fd, &mgmt_ack, sizeof (mgmt_ack));
	ASSERT_EQ(rc, sizeof (mgmt_ack));
	EXPECT_STREQ(mgmt_ack.volname, zvol_name.c_str());
	host = std::string(mgmt_ack.ip);
	port = mgmt_ack.port;
	if (ionum != NULL)
		*ionum = hdr_in.checkpointed_io_seq;
}

/*
 * This fn does data conn for a host:ip and volume, and fills data fd
 *
 * NOTE: Return value must be void otherwise we could not use asserts
 * (pecularity of gtest framework).
 */
static void do_data_connection(int &data_fd, std::string host, uint16_t port,
    std::string zvol_name, int bs=4096, int timeout=120,
    int res=ZVOL_OP_STATUS_OK) {
	struct sockaddr_in addr;
	zvol_io_hdr_t hdr_out, hdr_in;
	zvol_op_open_data_t open_data;
	int rc;

	data_fd = socket(AF_INET, SOCK_STREAM, 0);
	ASSERT_TRUE(data_fd >= 0);
	memset(&addr, 0, sizeof (addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	rc = inet_pton(AF_INET, host.c_str(), &addr.sin_addr);
	ASSERT_TRUE(rc > 0);
	rc = connect(data_fd, (struct sockaddr *)&addr, sizeof (addr));
	if (rc != 0) {
		perror("connect");
		ASSERT_EQ(errno, 0);
	}

	hdr_out.version = REPLICA_VERSION;
	hdr_out.opcode = ZVOL_OPCODE_OPEN;
	hdr_out.status = ZVOL_OP_STATUS_OK;
	hdr_out.io_seq = 0;
	hdr_out.offset = 0;
	hdr_out.len = sizeof (open_data);

	rc = write(data_fd, &hdr_out, sizeof (hdr_out));
	ASSERT_EQ(rc, sizeof (hdr_out));

	open_data.tgt_block_size = bs;
	open_data.timeout = timeout;
	strncpy(open_data.volname, zvol_name.c_str(),
	    sizeof (open_data.volname));
	rc = write(data_fd, &open_data, hdr_out.len);

	rc = read(data_fd, &hdr_in, sizeof (hdr_in));
	ASSERT_EQ(rc, sizeof (hdr_in));
	ASSERT_EQ(hdr_in.version, REPLICA_VERSION);
	ASSERT_EQ(hdr_in.opcode, ZVOL_OPCODE_OPEN);
	ASSERT_EQ(hdr_in.len, 0);
	ASSERT_EQ(hdr_in.status, res);
}

/*
 * Send header for data write. Leave write of actual data to the caller.
 * len is real length - including metadata headers.
 */
static void write_data_start(int data_fd, int &ioseq, size_t offset, int len) {
	zvol_io_hdr_t hdr_out;
	int rc;

	hdr_out.version = REPLICA_VERSION;
	hdr_out.opcode = ZVOL_OPCODE_WRITE;
	hdr_out.status = ZVOL_OP_STATUS_OK;
	hdr_out.io_seq = ++ioseq;
	hdr_out.offset = offset;
	hdr_out.len = len;
	hdr_out.flags = 0;

	rc = write(data_fd, &hdr_out, sizeof (hdr_out));
	ASSERT_EQ(rc, sizeof (hdr_out));
}

static void write_data(int data_fd, int &ioseq, void *buf, size_t offset,
    int len, uint64_t io_num) {
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
 * Send command to read data and read reply header. Reading payload is
 * left to the caller.
 */
static void read_data_start(int data_fd, int &ioseq, size_t offset, int len,
    zvol_io_hdr_t *hdr_inp, int flags = 0) {
	zvol_io_hdr_t hdr_out;
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
}

/*
 * Read 3 blocks of 4096 size at offset 0
 * Compares the io_num with expected value (hardcoded) and data
 */
static void read_data_and_verify_resp(int data_fd, int &ioseq) {
	zvol_io_hdr_t hdr_in;
	struct zvol_io_rw_hdr read_hdr;
	int rc;
	struct zvol_io_rw_hdr write_hdr;
	char buf[4096];
	int len = 4096;

	/* read all blocks at once and check IO nums */
	read_data_start(data_fd, ioseq, 0, 3 * sizeof (buf), &hdr_in);
	ASSERT_EQ(hdr_in.status, ZVOL_OP_STATUS_OK);
	ASSERT_EQ(hdr_in.len, 2 * sizeof (read_hdr) + 3 * sizeof (buf));

	rc = read(data_fd, &read_hdr, sizeof (read_hdr));
	ASSERT_ERRNO("read", rc >= 0);
	ASSERT_EQ(rc, sizeof (read_hdr));
	ASSERT_EQ(read_hdr.io_num, 123);
	ASSERT_EQ(read_hdr.len, 2 * sizeof (buf));
	rc = read(data_fd, buf, sizeof (buf));
	ASSERT_ERRNO("read", rc >= 0);
	ASSERT_EQ(rc, sizeof (buf));
	rc = verify_buf(buf, sizeof (buf), "cStor-data");
	ASSERT_EQ(rc, 0);
	rc = read(data_fd, buf, sizeof (buf));
	ASSERT_ERRNO("read", rc >= 0);
	ASSERT_EQ(rc, sizeof (buf));
	rc = verify_buf(buf, sizeof (buf), "cStor-data");
	ASSERT_EQ(rc, 0);

	rc = read(data_fd, &read_hdr, sizeof (read_hdr));
	ASSERT_ERRNO("read", rc >= 0);
	ASSERT_EQ(rc, sizeof (read_hdr));
	ASSERT_EQ(read_hdr.io_num, 124);
	ASSERT_EQ(read_hdr.len, sizeof (buf));
	rc = read(data_fd, buf, read_hdr.len);
	ASSERT_ERRNO("read", rc >= 0);
	ASSERT_EQ(rc, read_hdr.len);
	rc = verify_buf(buf, sizeof (buf), "cStor-data");
	ASSERT_EQ(rc, 0);
}

/*
 * Writes two blocks of size 4096 with different io_num (hardcoded) at
 * hardcoded offset
 * Verifies the resp of write IO
 */
static void write_two_chunks_and_verify_resp(int data_fd, int &ioseq,
    size_t offset) {
	zvol_io_hdr_t hdr_in;
	struct zvol_io_rw_hdr read_hdr;
	int rc;
	struct zvol_io_rw_hdr write_hdr;
	char buf[4096];
	int len = 4096;
	/* write 1th data block */
	init_buf(buf, sizeof (buf), "cStor-data");

	/* write two chunks with different IO nums in one request */
	write_data_start(data_fd, ioseq, sizeof (buf),
	    2 * (sizeof (write_hdr) + sizeof (buf)));

	write_hdr.len = sizeof (buf);
	write_hdr.io_num = 123;
	rc = write(data_fd, &write_hdr, sizeof (write_hdr));
	ASSERT_ERRNO("write", rc >= 0);
	ASSERT_EQ(rc, sizeof (write_hdr));
	rc = write(data_fd, buf, sizeof (buf));
	ASSERT_ERRNO("write", rc >= 0);
	ASSERT_EQ(rc, sizeof (buf));

	write_hdr.len = sizeof (buf);
	write_hdr.io_num = 124;
	rc = write(data_fd, &write_hdr, sizeof (write_hdr));
	ASSERT_ERRNO("write", rc >= 0);
	ASSERT_EQ(rc, sizeof (write_hdr));
	rc = write(data_fd, buf, sizeof (buf));
	ASSERT_ERRNO("write", rc >= 0);
	ASSERT_EQ(rc, sizeof (buf));

	rc = read(data_fd, &hdr_in, sizeof (hdr_in));
	ASSERT_ERRNO("write", rc >= 0);
	ASSERT_EQ(rc, sizeof (hdr_in));
	EXPECT_EQ(hdr_in.opcode, ZVOL_OPCODE_WRITE);
	EXPECT_EQ(hdr_in.status, ZVOL_OP_STATUS_OK);
	EXPECT_EQ(hdr_in.io_seq, ioseq);
}

/*
 * Writes data block of size 4096 at given offset and io_num
 * Updates io_seq of volume
 */
static void write_data_and_verify_resp(int data_fd, int &ioseq, size_t offset,
    uint64_t io_num, int blocksize=4096) {
	zvol_io_hdr_t hdr_in;
	struct zvol_io_rw_hdr read_hdr;
	int rc;
	struct zvol_io_rw_hdr write_hdr;
	char *buf;

	buf = (char *)malloc(blocksize);
	init_buf(buf, blocksize, "cStor-data");
	write_data(data_fd, ioseq, buf, offset, blocksize, io_num);
	free(buf);

	rc = read(data_fd, &hdr_in, sizeof (hdr_in));
	ASSERT_ERRNO("read", rc >= 0);
	ASSERT_EQ(rc, sizeof (hdr_in));
	EXPECT_EQ(hdr_in.opcode, ZVOL_OPCODE_WRITE);
	EXPECT_EQ(hdr_in.status, ZVOL_OP_STATUS_OK);
	EXPECT_EQ(hdr_in.io_seq, ioseq);
	EXPECT_EQ(hdr_in.offset, offset);
	ASSERT_EQ(hdr_in.len, sizeof (write_hdr) + blocksize);
}

static void get_zvol_status(std::string zvol_name, int &ioseq, int control_fd,
    int state, int rebuild_status)
{
	zvol_io_hdr_t hdr_out, hdr_in;
	struct zrepl_status_ack status;
	int rc;
	hdr_out.version = REPLICA_VERSION;
	hdr_out.opcode = ZVOL_OPCODE_REPLICA_STATUS;
	hdr_out.status = ZVOL_OP_STATUS_OK;
	hdr_out.io_seq = ++ioseq;
	hdr_out.offset = 0;
	hdr_out.len = zvol_name.length() + 1;
	hdr_out.flags = 0;
	rc = write(control_fd, &hdr_out, sizeof (hdr_out));
	ASSERT_ERRNO("write", rc >= 0);
	ASSERT_EQ(rc, sizeof (hdr_out));
	rc = write(control_fd, zvol_name.c_str(), hdr_out.len);
	ASSERT_ERRNO("write", rc >= 0);
	ASSERT_EQ(rc, hdr_out.len);
	rc = read(control_fd, &hdr_in, sizeof (hdr_in));
	ASSERT_ERRNO("read", rc >= 0);
	ASSERT_EQ(rc, sizeof (hdr_in));
	EXPECT_EQ(hdr_in.opcode, ZVOL_OPCODE_REPLICA_STATUS);
	EXPECT_EQ(hdr_in.io_seq, ioseq);
	EXPECT_EQ(hdr_in.status, ZVOL_OP_STATUS_OK);
	EXPECT_EQ(hdr_in.len, sizeof (status));
	rc = read(control_fd, &status, sizeof (status));
	ASSERT_ERRNO("read", rc >= 0);
	ASSERT_EQ(rc, sizeof (status));
	EXPECT_EQ(status.state, state);
	EXPECT_EQ(status.rebuild_status, rebuild_status);
}

static void transition_zvol_to_online(int &ioseq, int control_fd,
    std::string zvol_name)
{
	zvol_io_hdr_t hdr_in, hdr_out;
	struct mgmt_ack mgmt_ack;
	int rc;
	hdr_out.version = REPLICA_VERSION;
	hdr_out.opcode = ZVOL_OPCODE_START_REBUILD;
	hdr_out.status = ZVOL_OP_STATUS_OK;
	hdr_out.io_seq = ++ioseq;
	hdr_out.offset = 0;
	hdr_out.len = sizeof (mgmt_ack);
	hdr_out.flags = 0;
	rc = write(control_fd, &hdr_out, sizeof (hdr_out));
	ASSERT_ERRNO("write", rc >= 0);
	ASSERT_EQ(rc, sizeof (hdr_out));
	// Hack to tell the replica that it is the only replica
	//  -> rebuild will immediately finish
	mgmt_ack.volname[0] = '\0';
	mgmt_ack.ip[0] = '\0';
	mgmt_ack.port = 0;
	strncpy(mgmt_ack.dw_volname, zvol_name.c_str(),
	    sizeof (mgmt_ack.dw_volname));
	rc = write(control_fd, &mgmt_ack, sizeof (mgmt_ack));
	ASSERT_ERRNO("write", rc >= 0);
	ASSERT_EQ(rc, sizeof (mgmt_ack));

	rc = read(control_fd, &hdr_in, sizeof (hdr_in));
	ASSERT_ERRNO("read", rc >= 0);
	ASSERT_EQ(rc, sizeof (hdr_in));
	EXPECT_EQ(hdr_in.opcode, ZVOL_OPCODE_START_REBUILD);
	EXPECT_EQ(hdr_in.io_seq, ioseq);
	EXPECT_EQ(hdr_in.status, ZVOL_OP_STATUS_OK);
	EXPECT_EQ(hdr_in.len, 0);
}

/*
 * We have to wait for the other end to close the connection, because the
 * next test case could initiate a new connection before this one is
 * fully closed and cause a handshake error. Or it could result in EBUSY
 * error when destroying zpool if it is not released in time by zrepl.
 */
static void graceful_close(int sockfd)
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

static std::string getPoolState(std::string pname)
{
	return (execCmd("zpool", std::string("list -Ho health ") + pname));
}

/*
 * Object simulating iSCSI target. It has listen and accept methods.
 * Listening port is automatically closed when object goes out of scope.
 */
class Target {
public:
	Target() {
		m_listenfd = -1;
	}

	~Target() {
		if (m_listenfd >= 0) {
			close(m_listenfd);
			m_listenfd = -1;
		}
	}

	/*
	 * Listen for incoming connection from replica.
	 */
	int listen(uint16_t port = TARGET_PORT) {
		struct sockaddr_in addr;
		int fd;
		int opt = 1;
		int rc;

		m_listenfd = socket(AF_INET, SOCK_STREAM, 0);
		if (m_listenfd < 0) {
			perror("socket");
			return (-1);
		}
		setsockopt(m_listenfd, SOL_SOCKET, SO_REUSEADDR, (void *) &opt,
		    sizeof (opt));
		memset(&addr, 0, sizeof (addr));
		addr.sin_family = AF_INET;
		addr.sin_addr.s_addr = htonl(INADDR_ANY);
		addr.sin_port = htons(port);
		rc = bind(m_listenfd, (struct sockaddr *) &addr, sizeof (addr));
		if (rc != 0) {
			perror("bind");
			close(m_listenfd);
			return (-1);
		}
		rc = ::listen(m_listenfd, 1);
		if (rc != 0) {
			perror("listen");
			close(m_listenfd);
			return (-1);
		}
		return (m_listenfd);
	}

	/*
	 * Accept new connection from replica and return its FD (timeout is in
	 * seconds).
	 */
	int accept(int timeout) {
		fd_set rfds;
		struct timeval tv = {.tv_sec = timeout, .tv_usec = 0};
		int fd;
		int rc;

		FD_ZERO(&rfds);
		FD_SET(m_listenfd, &rfds);

		rc = select(m_listenfd + 1, &rfds, NULL, NULL,
		    (timeout >= 0) ? &tv : NULL);
		if (rc == -1) {
			perror("select");
			return (-1);
		}
		if (rc > 0) {
			fd = ::accept(m_listenfd, NULL, NULL);
			if (rc < 0) {
				perror("accept");
				return (-1);
			}
			return (fd);
		}
		return (-1);
	}

	int m_listenfd;
};

class ZreplHandshakeTest : public testing::Test {
protected:
	/* Shared setup hook for all zrepl handshake tests - called just once */
	static void SetUpTestCase() {
		m_zrepl = new Zrepl();
		m_pool = new TestPool("handshake");
		m_zrepl->start();
		m_pool->create();
		m_pool->createZvol("vol1", "-o io.openebs:targetip=127.0.0.1:6060");
		m_zvol_name = m_pool->getZvolName("vol1");
	}

	static void TearDownTestCase() {
		delete m_pool;
		delete m_zrepl;
	}

	virtual void SetUp() override {
		int rc;

		rc = m_target.listen();
		ASSERT_GE(rc, 0);
		m_control_fd = m_target.accept(-1);
		ASSERT_GE(m_control_fd, 0);
	}

	virtual void TearDown() override {
		if (m_control_fd >= 0)
			close(m_control_fd);
	}

	static Zrepl	*m_zrepl;
	static TestPool *m_pool;
	static std::string m_zvol_name;

	int	m_control_fd;
	Target	m_target;
};

Zrepl *ZreplHandshakeTest::m_zrepl = nullptr;
TestPool *ZreplHandshakeTest::m_pool = nullptr;
std::string ZreplHandshakeTest::m_zvol_name = "";

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
	hdr_out.len = m_zvol_name.length() + 1;

	rc = write(m_control_fd, &hdr_out, sizeof (hdr_out));
	ASSERT_EQ(rc, sizeof (hdr_out));
	rc = write(m_control_fd, m_zvol_name.c_str(), hdr_out.len);
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
	EXPECT_STREQ(mgmt_ack.volname, m_zvol_name.c_str());
	output = execCmd("zpool", std::string("get guid -Hpo value ") +
	    m_pool->m_name);
	EXPECT_EQ(mgmt_ack.pool_guid, std::stoul(output));
	output = execCmd("zfs", std::string("get guid -Hpo value ") +
	    m_zvol_name);
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
	hdr_out.len = m_zvol_name.length() + 1;

	/*
	 * It must be set in one chunk so that server does not close the
	 * connection after sending header but before sending zvol name.
	 */
	msg = (char *)malloc(sizeof (hdr_out) + hdr_out.len);
	memcpy(msg, &hdr_out, sizeof (hdr_out));
	memcpy(msg + sizeof (hdr_out), m_zvol_name.c_str(), hdr_out.len);
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

TEST_F(ZreplHandshakeTest, UnknownOpcode) {
	zvol_io_hdr_t hdr_out, hdr_in;
	int rc;

	hdr_out.version = REPLICA_VERSION;
	hdr_out.opcode = (zvol_op_code_t) 255;
	hdr_out.status = ZVOL_OP_STATUS_OK;
	hdr_out.io_seq = 0;
	hdr_out.offset = 0;
	hdr_out.len = m_zvol_name.length() + 1;

	rc = write(m_control_fd, &hdr_out, sizeof (hdr_out));
	ASSERT_ERRNO("write", rc >= 0);
	ASSERT_EQ(rc, sizeof (hdr_out));
	rc = write(m_control_fd, m_zvol_name.c_str(), hdr_out.len);
	ASSERT_ERRNO("write", rc >= 0);
	ASSERT_EQ(rc, hdr_out.len);

	rc = read(m_control_fd, &hdr_in, sizeof (hdr_in));
	ASSERT_ERRNO("read", rc >= 0);
	ASSERT_EQ(rc, sizeof (hdr_in));
	EXPECT_EQ(hdr_in.version, REPLICA_VERSION);
	EXPECT_EQ(hdr_in.opcode, 255);
	EXPECT_EQ(hdr_in.status, ZVOL_OP_STATUS_FAILED);
	EXPECT_EQ(hdr_in.io_seq, 0);
	EXPECT_EQ(hdr_in.offset, 0);
	ASSERT_EQ(hdr_in.len, 0);
}

class ZreplDataTest : public testing::Test {
protected:
	/*
	 * Shared setup hook for all zrepl data tests - called just once.
	 *
	 * TODO: we do more here than we are supposed to do (we should not test
	 * things in setup hook). We create pool, restart zrepl, import the pool
	 * again and then the tests issue IO to it. This scenario is currently
	 * not covered by any test and should be. When we have a test for it,
	 * the setup hook should be simplified to minimum again.
	 */
	static void SetUpTestCase() {
		zvol_io_hdr_t hdr_out, hdr_in;
		Target target1, target2;
		m_pool1 = new TestPool("ihandshake");
		m_pool2 = new TestPool("handshake");
		m_zrepl = new Zrepl();
		int rc;

		m_zrepl->start();
		m_pool1->create();
		m_pool1->createZvol("vol1", "-o io.openebs:targetip=127.0.0.1:6060");
		m_zvol_name1 = m_pool1->getZvolName("vol1");

		rc = target1.listen();
		ASSERT_GE(rc, 0);
		m_control_fd1 = target1.accept(-1);
		ASSERT_GE(m_control_fd1, 0);

		do_handshake(m_zvol_name1, m_host1, m_port1, NULL, m_control_fd1,
		    ZVOL_OP_STATUS_OK);
		m_zrepl->kill();

		m_zrepl->start();
		m_pool1->import();
		m_control_fd1 = target1.accept(-1);
		ASSERT_GE(m_control_fd1, 0);

		do_handshake(m_zvol_name1, m_host1, m_port1, NULL, m_control_fd1,
		    ZVOL_OP_STATUS_OK);

		m_pool2->create();
		m_pool2->createZvol("vol1", "-o io.openebs:targetip=127.0.0.1:12345");
		m_zvol_name2 = m_pool1->getZvolName("vol1");

		rc = target2.listen(12345);
		ASSERT_GE(rc, 0);
		m_control_fd2 = target2.accept(-1);
		ASSERT_GE(m_control_fd2, 0);

		do_handshake(m_zvol_name2, m_host2, m_port2, NULL, m_control_fd2,
		    ZVOL_OP_STATUS_FAILED);

		m_zvol_name2 = m_pool2->getZvolName("vol1");
		do_handshake(m_zvol_name2, m_host2, m_port2, NULL, m_control_fd2,
		    ZVOL_OP_STATUS_OK);
	}

	static void TearDownTestCase() {
		m_pool1->destroyZvol("vol1");
		m_pool2->destroyZvol("vol1");
		delete m_pool1;
		delete m_pool2;
		if (m_control_fd1 >= 0)
			close(m_control_fd1);
		if (m_control_fd2 >= 0)
			close(m_control_fd2);
		delete m_zrepl;
	}

	ZreplDataTest() {
		m_data_fd1 = -1;
		m_data_fd2 = -1;
		m_ioseq1 = 0;
		m_ioseq2 = 0;
	}

	/*
	 * Create data connection and send handshake msg for the zvol.
	 */
	virtual void SetUp() override {
		do_data_connection(m_data_fd1, m_host1, m_port1, m_zvol_name1);
		do_data_connection(m_data_fd2, m_host2, m_port2, m_zvol_name2);
	}

	virtual void TearDown() override {
		graceful_close(m_data_fd1);
		graceful_close(m_data_fd2);
	}

	static int	m_control_fd1;
	static int	m_control_fd2;
	static uint16_t m_port1;
	static uint16_t m_port2;
	static std::string m_host1;
	static std::string m_host2;
	static Zrepl	*m_zrepl;
	static TestPool *m_pool1;
	static TestPool *m_pool2;
	static std::string m_zvol_name1;
	static std::string m_zvol_name2;

	int	m_data_fd1;
	int	m_data_fd2;
	int	m_ioseq1;
	int	m_ioseq2;
};

int ZreplDataTest::m_control_fd1 = -1;
uint16_t ZreplDataTest::m_port1 = 0;
std::string ZreplDataTest::m_host1 = "";
std::string ZreplDataTest::m_zvol_name1 = "";
TestPool *ZreplDataTest::m_pool1 = nullptr;
int ZreplDataTest::m_control_fd2 = -1;
uint16_t ZreplDataTest::m_port2 = 0;
std::string ZreplDataTest::m_host2 = "";
std::string ZreplDataTest::m_zvol_name2 = "";
TestPool *ZreplDataTest::m_pool2 = nullptr;
Zrepl *ZreplDataTest::m_zrepl = nullptr;

/*
 * Write two blocks with the same io_num and third one with a different io_num
 * and test that read returns two metadata chunks.
 */
TEST_F(ZreplDataTest, WriteAndReadBlocksWithIonum) {
	write_data_and_verify_resp(m_data_fd1, m_ioseq1, 0, 123);
	write_two_chunks_and_verify_resp(m_data_fd1, m_ioseq1, 4096);
	read_data_and_verify_resp(m_data_fd1, m_ioseq1);

	write_data_and_verify_resp(m_data_fd2, m_ioseq2, 0, 123);
	write_two_chunks_and_verify_resp(m_data_fd2, m_ioseq2, 4096);
	read_data_and_verify_resp(m_data_fd2, m_ioseq2);
}

/* Read two blocks without metadata from the end of zvol */
TEST_F(ZreplDataTest, ReadBlockWithoutMeta) {
	zvol_io_hdr_t hdr_in;
	struct zvol_io_rw_hdr read_hdr;
	int rc;
	char buf[4096];
	size_t offset = ZVOL_SIZE - 2 * sizeof (buf);

	for (int i = 0; i < 2; i++) {
		read_data_start(m_data_fd1, m_ioseq1, offset, sizeof (buf), &hdr_in);
		ASSERT_EQ(hdr_in.status, ZVOL_OP_STATUS_OK);
		ASSERT_EQ(hdr_in.len, sizeof (read_hdr) + sizeof (buf));

		rc = read(m_data_fd1, &read_hdr, sizeof (read_hdr));
		ASSERT_ERRNO("read", rc >= 0);
		ASSERT_EQ(rc, sizeof (read_hdr));
		ASSERT_EQ(read_hdr.io_num, 0);
		ASSERT_EQ(read_hdr.len, sizeof (buf));
		rc = read(m_data_fd1, buf, read_hdr.len);
		ASSERT_ERRNO("read", rc >= 0);
		ASSERT_EQ(rc, read_hdr.len);
		offset += sizeof (buf);
	}
}

/*
 * Issue a sync request. We don't have a way to test that the data were really
 * sync'd but at least we test the basic command flow.
 */
TEST_F(ZreplDataTest, WriteAndSync) {
	zvol_io_hdr_t hdr_out, hdr_in;
	char buf[4096];
	int rc;

	init_buf(buf, sizeof (buf), "cStor-data");
	write_data(m_data_fd1, m_ioseq1, buf, 0, sizeof (buf), ++m_ioseq1);
	rc = read(m_data_fd1, &hdr_in, sizeof (hdr_in));
	ASSERT_ERRNO("read", rc >= 0);
	ASSERT_EQ(rc, sizeof (hdr_in));
	EXPECT_EQ(hdr_in.opcode, ZVOL_OPCODE_WRITE);
	EXPECT_EQ(hdr_in.status, ZVOL_OP_STATUS_OK);
	EXPECT_EQ(hdr_in.io_seq, m_ioseq1);

	hdr_out.version = REPLICA_VERSION;
	hdr_out.opcode = ZVOL_OPCODE_SYNC;
	hdr_out.status = ZVOL_OP_STATUS_OK;
	hdr_out.io_seq = ++m_ioseq1;
	hdr_out.offset = 0;
	hdr_out.len = 0;
	hdr_out.flags = 0;

	rc = write(m_data_fd1, &hdr_out, sizeof (hdr_out));
	ASSERT_ERRNO("write", rc >= 0);
	ASSERT_EQ(rc, sizeof (hdr_out));

	rc = read(m_data_fd1, &hdr_in, sizeof (hdr_in));
	ASSERT_ERRNO("read", rc >= 0);
	ASSERT_EQ(rc, sizeof (hdr_in));
	EXPECT_EQ(hdr_in.opcode, ZVOL_OPCODE_SYNC);
	EXPECT_EQ(hdr_in.status, ZVOL_OP_STATUS_OK);
	EXPECT_EQ(hdr_in.io_seq, m_ioseq1);
	EXPECT_EQ(hdr_in.offset, 0);
	EXPECT_EQ(hdr_in.len, 0);
}

TEST_F(ZreplDataTest, UnknownOpcode) {
	zvol_io_hdr_t hdr_out, hdr_in;
	int rc;

	hdr_out.version = REPLICA_VERSION;
	hdr_out.opcode = (zvol_op_code_t) 255;
	hdr_out.status = ZVOL_OP_STATUS_OK;
	hdr_out.io_seq = ++m_ioseq1;
	hdr_out.offset = 0;
	hdr_out.len = 0;
	hdr_out.flags = 0;

	rc = write(m_control_fd1, &hdr_out, sizeof (hdr_out));
	ASSERT_ERRNO("write", rc >= 0);
	ASSERT_EQ(rc, sizeof (hdr_out));

	rc = read(m_control_fd1, &hdr_in, sizeof (hdr_in));
	ASSERT_ERRNO("read", rc >= 0);
	ASSERT_EQ(rc, sizeof (hdr_in));
	EXPECT_EQ(hdr_in.opcode, 255);
	EXPECT_EQ(hdr_in.status, ZVOL_OP_STATUS_FAILED);
	EXPECT_EQ(hdr_in.io_seq, m_ioseq1);
}

TEST_F(ZreplDataTest, ReadInvalidOffset) {
	zvol_io_hdr_t hdr_in;
	int rc;

	// unaligned offset
	read_data_start(m_data_fd1, m_ioseq1, 33, 4096, &hdr_in);
	ASSERT_EQ(hdr_in.status, ZVOL_OP_STATUS_FAILED);
	ASSERT_EQ(hdr_in.len, 0);

	// offset past the end of zvol
	read_data_start(m_data_fd1, m_ioseq1, ZVOL_SIZE + 4096, 4096, &hdr_in);
	ASSERT_EQ(hdr_in.status, ZVOL_OP_STATUS_FAILED);
	ASSERT_EQ(hdr_in.len, 0);
}

TEST_F(ZreplDataTest, ReadInvalidLength) {
	zvol_io_hdr_t hdr_in;
	int rc;

	// unaligned length
	read_data_start(m_data_fd1, m_ioseq1, 0, 4097, &hdr_in);
	ASSERT_EQ(hdr_in.status, ZVOL_OP_STATUS_FAILED);
	ASSERT_EQ(hdr_in.len, 0);

	// length past the end of zvol
	read_data_start(m_data_fd1, m_ioseq1, ZVOL_SIZE - 4096, 2 * 4096, &hdr_in);
	ASSERT_EQ(hdr_in.status, ZVOL_OP_STATUS_FAILED);
	ASSERT_EQ(hdr_in.len, 0);
}

TEST_F(ZreplDataTest, WriteInvalidOffset) {
	zvol_io_hdr_t hdr_in;
	char buf[4096];
	int rc;

	// Writing last block of zvol should succeed
	init_buf(buf, sizeof (buf), "cStor-data");
	write_data(m_data_fd1, m_ioseq1, buf, ZVOL_SIZE - sizeof (buf), sizeof (buf), 333);
	rc = read(m_data_fd1, &hdr_in, sizeof (hdr_in));
	ASSERT_ERRNO("read", rc >= 0);
	ASSERT_EQ(rc, sizeof (hdr_in));
	EXPECT_EQ(hdr_in.opcode, ZVOL_OPCODE_WRITE);
	EXPECT_EQ(hdr_in.io_seq, m_ioseq1);
	EXPECT_EQ(hdr_in.status, ZVOL_OP_STATUS_OK);

	// Writing past the end of zvol should fail
	write_data(m_data_fd1, m_ioseq1, buf, ZVOL_SIZE, sizeof (buf), 334);
	rc = read(m_data_fd1, &hdr_in, sizeof (hdr_in));
	ASSERT_ERRNO("read", rc >= 0);
	ASSERT_EQ(rc, sizeof (hdr_in));
	EXPECT_EQ(hdr_in.opcode, ZVOL_OPCODE_WRITE);
	EXPECT_EQ(hdr_in.io_seq, m_ioseq1);
	EXPECT_EQ(hdr_in.status, ZVOL_OP_STATUS_FAILED);
}

TEST_F(ZreplDataTest, WriteInvalidLength) {
	zvol_io_hdr_t hdr_in;
	char buf[2 * 4096];
	int rc;

	init_buf(buf, sizeof (buf), "cStor-data");

	write_data(m_data_fd1, m_ioseq1, buf, ZVOL_SIZE - 4096, sizeof (buf), 334);
	rc = read(m_data_fd1, &hdr_in, sizeof (hdr_in));
	ASSERT_ERRNO("read", rc >= 0);
	ASSERT_EQ(rc, sizeof (hdr_in));
	EXPECT_EQ(hdr_in.opcode, ZVOL_OPCODE_WRITE);
	EXPECT_EQ(hdr_in.io_seq, m_ioseq1);
	EXPECT_EQ(hdr_in.status, ZVOL_OP_STATUS_FAILED);
}

/*
 * Metadata ionum should be returned when zvol is degraded (rebuild
 * not finished) or when requested by ZVOL_OP_FLAG_REBUILD flag.
 */
TEST_F(ZreplDataTest, RebuildFlag) {
	zvol_io_hdr_t hdr_in, hdr_out;
	struct zvol_io_rw_hdr read_hdr;
	struct zvol_io_rw_hdr write_hdr;
	struct zrepl_status_ack status;
	struct mgmt_ack mgmt_ack;
	char buf[4096];
	int rc;

	/* write a data block with known ionum */
	write_data_and_verify_resp(m_data_fd1, m_ioseq1, 0, 654);

	/* Get zvol status before rebuild */
	get_zvol_status(m_zvol_name1, m_ioseq1, m_control_fd1, ZVOL_STATUS_DEGRADED, ZVOL_REBUILDING_INIT);
	/* transition the zvol to online state */
	transition_zvol_to_online(m_ioseq1, m_control_fd1, m_zvol_name1);

	sleep(5);

	/* Get zvol status after rebuild */
	get_zvol_status(m_zvol_name1, m_ioseq1, m_control_fd1, ZVOL_STATUS_HEALTHY, ZVOL_REBUILDING_DONE);

	/* read the block without rebuild flag */
	read_data_start(m_data_fd1, m_ioseq1, 0, sizeof (buf), &hdr_in, 0);
	ASSERT_EQ(hdr_in.status, ZVOL_OP_STATUS_OK);
	ASSERT_EQ(hdr_in.len, sizeof (read_hdr) + sizeof (buf));
	rc = read(m_data_fd1, &read_hdr, sizeof (read_hdr));
	ASSERT_ERRNO("read", rc >= 0);
	ASSERT_EQ(rc, sizeof (read_hdr));
	ASSERT_EQ(read_hdr.io_num, 0);
	ASSERT_EQ(read_hdr.len, sizeof (buf));
	rc = read(m_data_fd1, buf, sizeof (buf));
	ASSERT_ERRNO("read", rc >= 0);
	ASSERT_EQ(rc, sizeof (buf));

	/* read the block with rebuild flag */
	read_data_start(m_data_fd1, m_ioseq1, 0, sizeof (buf), &hdr_in, ZVOL_OP_FLAG_REBUILD);
	ASSERT_EQ(hdr_in.status, ZVOL_OP_STATUS_OK);
	ASSERT_EQ(hdr_in.len, sizeof (read_hdr) + sizeof (buf));
	rc = read(m_data_fd1, &read_hdr, sizeof (read_hdr));
	ASSERT_ERRNO("read", rc >= 0);
	ASSERT_EQ(rc, sizeof (read_hdr));
	ASSERT_EQ(read_hdr.io_num, 654);
	ASSERT_EQ(read_hdr.len, sizeof (buf));
	rc = read(m_data_fd1, buf, sizeof (buf));
	ASSERT_ERRNO("read", rc >= 0);
	ASSERT_EQ(rc, sizeof (buf));
}

/*
 * Metadata ionum should be returned when requested by
 * ZVOL_OP_FLAG_READ_METADATA flag.
 */
TEST_F(ZreplDataTest, ReadMetaDataFlag) {
	zvol_io_hdr_t hdr_in, hdr_out;
	struct zvol_io_rw_hdr read_hdr;
	struct zvol_io_rw_hdr write_hdr;
	struct zrepl_status_ack status;
	struct mgmt_ack mgmt_ack;
	char buf[4096];
	int rc;

	/* write a data block with known ionum */
	write_data_and_verify_resp(m_data_fd1, m_ioseq1, 0, 654);

	/* read the block without ZVOL_OP_FLAG_READ_METADATA flag */
	read_data_start(m_data_fd1, m_ioseq1, 0, sizeof (buf), &hdr_in, 0);
	ASSERT_EQ(hdr_in.status, ZVOL_OP_STATUS_OK);
	ASSERT_EQ(hdr_in.len, sizeof (read_hdr) + sizeof (buf));
	rc = read(m_data_fd1, &read_hdr, sizeof (read_hdr));
	ASSERT_ERRNO("read", rc >= 0);
	ASSERT_EQ(rc, sizeof (read_hdr));
	ASSERT_EQ(read_hdr.io_num, 0);
	ASSERT_EQ(read_hdr.len, sizeof (buf));
	rc = read(m_data_fd1, buf, sizeof (buf));
	ASSERT_ERRNO("read", rc >= 0);
	ASSERT_EQ(rc, sizeof (buf));

	/* read the block with ZVOL_OP_FLAG_READ_METADATA flag */
	read_data_start(m_data_fd1, m_ioseq1, 0, sizeof (buf), &hdr_in, ZVOL_OP_FLAG_READ_METADATA);
	ASSERT_EQ(hdr_in.status, ZVOL_OP_STATUS_OK);
	ASSERT_EQ(hdr_in.len, sizeof (read_hdr) + sizeof (buf));
	rc = read(m_data_fd1, &read_hdr, sizeof (read_hdr));
	ASSERT_ERRNO("read", rc >= 0);
	ASSERT_EQ(rc, sizeof (read_hdr));
	ASSERT_EQ(read_hdr.io_num, 654);
	ASSERT_EQ(read_hdr.len, sizeof (buf));
	rc = read(m_data_fd1, buf, sizeof (buf));
	ASSERT_ERRNO("read", rc >= 0);
	ASSERT_EQ(rc, sizeof (buf));
}

/*
 * This test has many steps. If it proves to be too complicated, then split it
 * into multiple smaller tests. It creates:
 *
 *   1 zvol with default target IP
 *   1 zvol with explicit target IP
 *    - restart zrepl -
 *   1 zvol with default target IP
 *   1 zvol with explicit target IP
 *   destroy all zvols
 *
 * Verify that zrepl establishes and tears down connections as appropriate.
 */
TEST(TargetIPTest, CreateAndDestroy) {
	Zrepl zrepl;
	TestPool pool("handshake");
	Target targetImpl, targetExpl;
	int fdImpl, fdExpl;
	char buf[1];
	int rc;

	zrepl.start();
	pool.create();
	pool.createZvol("implicit1", "-o io.openebs:targetip=127.0.0.1:6060");
	pool.createZvol("explicit1", "-o io.openebs:targetip=127.0.0.1:12345");
	zrepl.kill();

	rc = targetImpl.listen();
	ASSERT_GE(rc, 0);
	rc = targetExpl.listen(12345);
	ASSERT_GE(rc, 0);

	zrepl.start();
	pool.import();

	// two new connections (one for each target)
	fdImpl = targetImpl.accept(50);
	ASSERT_GE(fdImpl, 0);
	fdExpl = targetExpl.accept(50);
	ASSERT_GE(fdExpl, 0);

	pool.createZvol("implicit2", "-o io.openebs:targetip=127.0.0.1:6060");
	pool.createZvol("explicit2", "-o io.openebs:targetip=127.0.0.1:12345");

	// no new connections
	rc = targetImpl.accept(5);
	ASSERT_EQ(rc, -1);
	rc = targetExpl.accept(5);
	ASSERT_EQ(rc, -1);

	// nothing should happen if we destroy only one of the two zvols
	// using the control connection
	pool.destroyZvol("implicit1");
	rc = ready_for_read(fdImpl, 5);
	ASSERT_EQ(rc, 0);
	pool.destroyZvol("explicit1");
	rc = ready_for_read(fdExpl, 5);
	ASSERT_EQ(rc, 0);

	// should close the connection
	pool.destroyZvol("implicit2");
	rc = ready_for_read(fdImpl, 5);
	ASSERT_EQ(rc, 1);
	rc = read(fdImpl, buf, sizeof (buf));
	ASSERT_EQ(rc, 0);
	close(fdImpl);

	// should close the connection
	pool.destroyZvol("explicit2");
	rc = ready_for_read(fdExpl, 5);
	ASSERT_EQ(rc, 1);
	rc = read(fdExpl, buf, sizeof (buf));
	ASSERT_EQ(rc, 0);
	close(fdExpl);
}

/*
 * Test that zrepl will try to reconnect when target restarts.
 */
TEST(TargetIPTest, Reconnect) {
	zvol_io_hdr_t hdr_out, hdr_in;
	Zrepl zrepl;
	TestPool pool("handshake");
	std::string zvolname = pool.getZvolName("reconnect");
	Target target;
	int fd;
	char buf[1];
	int rc;

	zrepl.start();
	pool.create();
	pool.createZvol("reconnect", "-o io.openebs:targetip=127.0.0.1:6060");

	// First we test that zrepl connects even if it could not connect
	// first couple of times after start
	sleep(5);
	rc = target.listen();
	ASSERT_GE(rc, 0);
	fd = target.accept(5);
	ASSERT_GE(fd, 0);

	// Send a simple request to zrepl without waiting for reply
	hdr_out.version = REPLICA_VERSION;
	hdr_out.opcode = ZVOL_OPCODE_HANDSHAKE;
	hdr_out.status = ZVOL_OP_STATUS_OK;
	hdr_out.io_seq = 0;
	hdr_out.offset = 0;
	hdr_out.len = zvolname.length() + 1;
	rc = write(fd, &hdr_out, sizeof (hdr_out));
	ASSERT_EQ(rc, sizeof (hdr_out));
	rc = write(fd, zvolname.c_str(), hdr_out.len);
	ASSERT_EQ(rc, hdr_out.len);

	// simulate the target restart
	close(target.m_listenfd);
	target.m_listenfd = -1;
	close(fd);
	rc = target.listen();
	ASSERT_GE(rc, 0);
	fd = target.accept(5);
	ASSERT_GE(fd, 0);

	// should close the connection
	pool.destroyZvol("reconnect");
	rc = ready_for_read(fd, 5);
	ASSERT_EQ(rc, 1);
	rc = read(fd, buf, sizeof (buf));
	ASSERT_EQ(rc, 0);
	close(fd);
}

/*
 * Test setting interval for updating checkpointed ionum.
 * Open two zvols, each with different interval setting and after some time
 * check committed ionum on both of them.
 */
TEST(Misc, ZreplCheckpointInterval) {
	Zrepl	 zrepl;
	TestPool pool("checkpoint");
	Target	target;
	std::string zvol_name_slow, zvol_name_fast;
	int	rc, control_fd;
	int	data_fd_slow, data_fd_fast;
	int	ioseq = 0;
	std::string host_slow, host_fast;
	uint16_t port_slow, port_fast;
	uint64_t ionum_slow, ionum_fast;

	zrepl.start();
	pool.create();
	pool.createZvol("slow", "-o io.openebs:targetip=127.0.0.1:6060");
	pool.createZvol("fast", "-o io.openebs:targetip=127.0.0.1:6060");
	zvol_name_slow = pool.getZvolName("slow");
	zvol_name_fast = pool.getZvolName("fast");

	rc = target.listen();
	ASSERT_GE(rc, 0);
	control_fd = target.accept(-1);
	ASSERT_GE(control_fd, 0);

	do_handshake(zvol_name_slow, host_slow, port_slow, &ionum_slow,
	    control_fd, ZVOL_OP_STATUS_OK);
	do_handshake(zvol_name_fast, host_fast, port_fast, &ionum_fast,
	    control_fd, ZVOL_OP_STATUS_OK);
	ASSERT_NE(ionum_slow, 888);
	ASSERT_NE(ionum_fast, 888);
	transition_zvol_to_online(ioseq, control_fd, zvol_name_slow);
	transition_zvol_to_online(ioseq, control_fd, zvol_name_fast);

	do_data_connection(data_fd_slow, host_slow, port_slow, zvol_name_slow,
	    4096, 1000);
	do_data_connection(data_fd_fast, host_fast, port_fast, zvol_name_fast,
	    4096, 1);

	write_data_and_verify_resp(data_fd_slow, ioseq, 0, 888);
	write_data_and_verify_resp(data_fd_fast, ioseq, 0, 888);
	sleep(2);

	do_handshake(zvol_name_slow, host_slow, port_slow, &ionum_slow,
	    control_fd, ZVOL_OP_STATUS_OK);
	do_handshake(zvol_name_fast, host_fast, port_fast, &ionum_fast,
	    control_fd, ZVOL_OP_STATUS_OK);
	ASSERT_NE(ionum_slow, 888);
	ASSERT_EQ(ionum_fast, 888);

	graceful_close(data_fd_slow);
	graceful_close(data_fd_fast);
	graceful_close(control_fd);
}

class ZreplBlockSizeTest : public testing::Test {
protected:
	/*
	 * Shared setup hook for all zrepl block size tests - called just once.
	 */
	static void SetUpTestCase() {
		zvol_io_hdr_t hdr_out, hdr_in;
		m_pool = new TestPool("blocksize");
		m_zrepl = new Zrepl();

		m_zrepl->start();
		m_pool->create();
	}

	static void TearDownTestCase() {
		delete m_pool;
		delete m_zrepl;
	}

	ZreplBlockSizeTest() {
		m_ioseq = 0;
	}

	/*
	 * Create data connection and send handshake msg for the zvol.
	 */
	virtual void SetUp() override {
		Target target;
		int rc;

		m_data_fd = -1;
		m_control_fd = -1;
		rc = target.listen();
		ASSERT_GE(rc, 0);

		m_pool->createZvol("vol", "-o io.openebs:targetip=127.0.0.1");
		m_zvol_name = m_pool->getZvolName("vol");
		m_control_fd = target.accept(-1);
		ASSERT_GE(m_control_fd, 0);

		do_handshake(m_zvol_name, m_host, m_port, NULL, m_control_fd,
		    ZVOL_OP_STATUS_OK);
	}

	virtual void TearDown() override {
		m_pool->destroyZvol("vol");
		if (m_data_fd >= 0)
			close(m_data_fd);
		if (m_control_fd >= 0)
			close(m_control_fd);
	}

	static Zrepl	*m_zrepl;
	static TestPool *m_pool;

	uint16_t m_port;
	std::string m_host;
	std::string m_zvol_name;
	int	m_ioseq, m_data_fd, m_control_fd;
};

TestPool *ZreplBlockSizeTest::m_pool = nullptr;
Zrepl *ZreplBlockSizeTest::m_zrepl = nullptr;

/*
 * Test setting metadata granularity on zvol.
 */
TEST_F(ZreplBlockSizeTest, SetMetaBlockSize) {
	do_data_connection(m_data_fd, m_host, m_port, m_zvol_name, 4096);
	write_data_and_verify_resp(m_data_fd, m_ioseq, 0, 1);
	graceful_close(m_data_fd);
	m_data_fd = -1;
	do_data_connection(m_data_fd, m_host, m_port, m_zvol_name, 4096);
	write_data_and_verify_resp(m_data_fd, m_ioseq, 0, 1);
}

TEST_F(ZreplBlockSizeTest, SetMetaBlockSizeSmallerThanBlockSize) {
	do_data_connection(m_data_fd, m_host, m_port, m_zvol_name, 512);
	write_data_and_verify_resp(m_data_fd, m_ioseq, 0, 1, 512);
}

TEST_F(ZreplBlockSizeTest, SetMetaBlockSizeBiggerThanBlockSize) {
	do_data_connection(m_data_fd, m_host, m_port, m_zvol_name, 8192);
	write_data_and_verify_resp(m_data_fd, m_ioseq, 0, 1, 8192);
}

TEST_F(ZreplBlockSizeTest, SetMetaBlockSizeUnaligned) {
	do_data_connection(m_data_fd, m_host, m_port, m_zvol_name, 513, 120,
	    ZVOL_OP_STATUS_FAILED);
}

TEST_F(ZreplBlockSizeTest, SetDifferentMetaBlockSizes) {
	do_data_connection(m_data_fd, m_host, m_port, m_zvol_name, 4096);
	write_data_and_verify_resp(m_data_fd, m_ioseq, 0, 1);
	graceful_close(m_data_fd);
	m_data_fd = -1;
	do_data_connection(m_data_fd, m_host, m_port, m_zvol_name, 512, 120,
	    ZVOL_OP_STATUS_FAILED);
}

/*
 * Test disk replacement
 */
TEST(DiskReplaceTest, SpareReplacement) {
	Zrepl zrepl;
	Target target;
	int rc, data_fd, control_fd;
	std::string host;
	uint16_t port;
	int ioseq;
	Vdev vdev2("vdev2");
	Vdev spare("spare");
	TestPool pool("rplcpool");

	zrepl.start();
	vdev2.create();
	spare.create();
	pool.create();
	pool.createZvol("vol", "-o io.openebs:targetip=127.0.0.1");

	rc = target.listen();
	ASSERT_GE(rc, 0);
	control_fd = target.accept(-1);
	ASSERT_GE(control_fd, 0);
	do_handshake(pool.getZvolName("vol"), host, port, NULL, control_fd,
	    ZVOL_OP_STATUS_OK);
	do_data_connection(data_fd, host, port, pool.getZvolName("vol"));
	write_data_and_verify_resp(data_fd, ioseq, 0, 10);

	// construct mirrored pool with a spare
	execCmd("zpool", std::string("attach ") + pool.m_name + " " +
	    pool.m_vdev->m_path + " " + vdev2.m_path);
	write_data_and_verify_resp(data_fd, ioseq, 0, 10);
	execCmd("zpool", std::string("add ") + pool.m_name + " spare " +
	    spare.m_path);
	write_data_and_verify_resp(data_fd, ioseq, 0, 10);
	ASSERT_STREQ(getPoolState(pool.m_name).c_str(), "ONLINE");

	// fail one of the disks in the mirror
	execCmd("zpool", std::string("offline ") + pool.m_name + " " +
	    vdev2.m_path);
	write_data_and_verify_resp(data_fd, ioseq, 0, 10);
	ASSERT_STREQ(getPoolState(pool.m_name).c_str(), "DEGRADED");

	// replace failed disk by the spare and remove it from mirror
	execCmd("zpool", std::string("replace ") + pool.m_name + " " +
	    vdev2.m_path + " " + spare.m_path);
	write_data_and_verify_resp(data_fd, ioseq, 0, 10);
	execCmd("zpool", std::string("detach ") + pool.m_name + " " +
	    vdev2.m_path);
	ASSERT_STREQ(getPoolState(pool.m_name).c_str(), "ONLINE");

	//std::cout << execCmd("zpool", std::string("status ") + pool.m_name);

	graceful_close(data_fd);
	graceful_close(control_fd);
}

/*
 * Snapshot create and destroy.
 */
TEST(Snapshot, CreateAndDestroy) {
	zvol_io_hdr_t hdr_out, hdr_in;
	Zrepl zrepl;
	Target target;
	int rc, control_fd;
	TestPool pool("snappool");
	std::string snap_name = pool.getZvolName("vol@snap");
	std::string bad_snap_name = pool.getZvolName("vol");
	std::string unknown_snap_name = pool.getZvolName("unknown@snap");

	zrepl.start();
	pool.create();
	pool.createZvol("vol", "-o io.openebs:targetip=127.0.0.1");

	rc = target.listen();
	ASSERT_GE(rc, 0);
	control_fd = target.accept(-1);
	ASSERT_GE(control_fd, 0);

	// try to create snap of invalid zvol
	hdr_out.version = REPLICA_VERSION;
	hdr_out.opcode = ZVOL_OPCODE_SNAP_CREATE;
	hdr_out.status = ZVOL_OP_STATUS_OK;
	hdr_out.io_seq = 0;
	hdr_out.offset = 0;
	hdr_out.len = bad_snap_name.length() + 1;
	rc = write(control_fd, &hdr_out, sizeof (hdr_out));
	ASSERT_EQ(rc, sizeof (hdr_out));
	rc = write(control_fd, bad_snap_name.c_str(), hdr_out.len);
	ASSERT_EQ(rc, hdr_out.len);
	rc = read(control_fd, &hdr_in, sizeof (hdr_in));
	ASSERT_EQ(rc, sizeof (hdr_in));
	EXPECT_EQ(hdr_in.status, ZVOL_OP_STATUS_FAILED);
	ASSERT_EQ(hdr_in.len, 0);

	// try to create snap of unknown zvol
	hdr_out.version = REPLICA_VERSION;
	hdr_out.opcode = ZVOL_OPCODE_SNAP_CREATE;
	hdr_out.status = ZVOL_OP_STATUS_OK;
	hdr_out.io_seq = 0;
	hdr_out.offset = 0;
	hdr_out.len = unknown_snap_name.length() + 1;
	rc = write(control_fd, &hdr_out, sizeof (hdr_out));
	ASSERT_EQ(rc, sizeof (hdr_out));
	rc = write(control_fd, unknown_snap_name.c_str(), hdr_out.len);
	ASSERT_EQ(rc, hdr_out.len);
	rc = read(control_fd, &hdr_in, sizeof (hdr_in));
	ASSERT_EQ(rc, sizeof (hdr_in));
	EXPECT_EQ(hdr_in.status, ZVOL_OP_STATUS_FAILED);
	ASSERT_EQ(hdr_in.len, 0);

	// create the snapshot
	hdr_out.version = REPLICA_VERSION;
	hdr_out.opcode = ZVOL_OPCODE_SNAP_CREATE;
	hdr_out.status = ZVOL_OP_STATUS_OK;
	hdr_out.io_seq = 0;
	hdr_out.offset = 0;
	hdr_out.len = snap_name.length() + 1;

	rc = write(control_fd, &hdr_out, sizeof (hdr_out));
	ASSERT_EQ(rc, sizeof (hdr_out));
	rc = write(control_fd, snap_name.c_str(), hdr_out.len);
	ASSERT_EQ(rc, hdr_out.len);

	rc = read(control_fd, &hdr_in, sizeof (hdr_in));
	ASSERT_EQ(rc, sizeof (hdr_in));
	EXPECT_EQ(hdr_in.version, REPLICA_VERSION);
	EXPECT_EQ(hdr_in.opcode, ZVOL_OPCODE_SNAP_CREATE);
	EXPECT_EQ(hdr_in.status, ZVOL_OP_STATUS_OK);
	EXPECT_EQ(hdr_in.io_seq, 0);
	ASSERT_EQ(hdr_in.len, 0);

	ASSERT_NO_THROW(execCmd("zfs", std::string("list ") + snap_name));

	// destroy the snapshot
	hdr_out.version = REPLICA_VERSION;
	hdr_out.opcode = ZVOL_OPCODE_SNAP_DESTROY;
	hdr_out.status = ZVOL_OP_STATUS_OK;
	hdr_out.io_seq = 1;
	hdr_out.offset = 0;
	hdr_out.len = snap_name.length() + 1;

	rc = write(control_fd, &hdr_out, sizeof (hdr_out));
	ASSERT_EQ(rc, sizeof (hdr_out));
	rc = write(control_fd, snap_name.c_str(), hdr_out.len);
	ASSERT_EQ(rc, hdr_out.len);

	rc = read(control_fd, &hdr_in, sizeof (hdr_in));
	ASSERT_EQ(rc, sizeof (hdr_in));
	EXPECT_EQ(hdr_in.version, REPLICA_VERSION);
	EXPECT_EQ(hdr_in.opcode, ZVOL_OPCODE_SNAP_DESTROY);
	EXPECT_EQ(hdr_in.status, ZVOL_OP_STATUS_OK);
	EXPECT_EQ(hdr_in.io_seq, 1);
	ASSERT_EQ(hdr_in.len, 0);

	ASSERT_THROW(execCmd("zfs", std::string("list ") + snap_name),
	    std::runtime_error);

	graceful_close(control_fd);
}

/*
 * Test zvol resize
 */
TEST(ZvolResizeTest, ResizeZvol) {
	zvol_io_hdr_t hdr_out, hdr_in;
	Zrepl zrepl;
	Target target;
	int rc, control_fd;
	std::string host;
	std::string str;
	uint64_t val1, val2;
	uint16_t port;
	zvol_op_resize_data_t resize_data;
	TestPool pool("resizepool");
	std::string zvolname = pool.getZvolName("vol");

	zrepl.start();
	pool.create();
	pool.createZvol("vol", "-o io.openebs:targetip=127.0.0.1");

	// get the zvol size before
	str = execCmd("zfs", std::string("get -Hpo value volsize ") + zvolname);
	val1 = atoi(str.c_str());

	rc = target.listen();
	ASSERT_GE(rc, 0);
	control_fd = target.accept(-1);
	ASSERT_GE(control_fd, 0);
	do_handshake(zvolname, host, port, NULL, control_fd,
	    ZVOL_OP_STATUS_OK);

	hdr_out.version = REPLICA_VERSION;
	hdr_out.opcode = ZVOL_OPCODE_RESIZE;
	hdr_out.status = ZVOL_OP_STATUS_OK;
	hdr_out.io_seq = 1;
	hdr_out.offset = 0;
	hdr_out.len = sizeof (resize_data);
	rc = write(control_fd, &hdr_out, sizeof (hdr_out));
	ASSERT_EQ(rc, sizeof (hdr_out));
	// double the zvol size
	val1 <<= 1;
	strcpy(resize_data.volname, zvolname.c_str());
	resize_data.size = val1;
	rc = write(control_fd, &resize_data, sizeof (resize_data));
	ASSERT_EQ(rc, sizeof (resize_data));

	rc = read(control_fd, &hdr_in, sizeof (hdr_in));
	ASSERT_EQ(rc, sizeof (hdr_in));
	EXPECT_EQ(hdr_in.status, ZVOL_OP_STATUS_OK);
	ASSERT_EQ(hdr_in.len, 0);

	// get the zvol size after
	str = execCmd("zfs", std::string("get -Hpo value volsize ") + zvolname);
	val2 = atoi(str.c_str());
	EXPECT_EQ(val1, val2);

	graceful_close(control_fd);
}

/*
 * Test zvol clone
 *
 * There is no clone protocol command but we need to test that after
 * the clone is created, it connects successfully to iscsi target,
 * hence the test is here in zrepl protocol test suite.
 */
TEST(ZvolCloneTest, CloneZvol) {
	Zrepl zrepl;
	Target target;
	int rc, control_fd;
	std::string host;
	uint16_t port;
	zvol_op_resize_data_t resize_data;
	TestPool pool("resizepool");
	std::string zvolname = pool.getZvolName("vol");
	std::string snapname = pool.getZvolName("vol@snap");
	std::string clonename = pool.getZvolName("clone");
	std::string clonesnapname = pool.getZvolName("clone@snap");

	zrepl.start();
	pool.create();
	pool.createZvol("vol", "-o io.openebs:targetip=127.0.0.1");
	execCmd("zfs", std::string("snapshot " + snapname));

	// clone the zvol
	execCmd("zfs", std::string("clone -o "
	    "io.openebs:targetip=127.0.0.1:6060 " +
	    snapname + " " + clonename));

	rc = target.listen(6060);
	ASSERT_GE(rc, 0);
	control_fd = target.accept(-1);
	ASSERT_GE(control_fd, 0);
	do_handshake(zvolname, host, port, NULL, control_fd,
	    ZVOL_OP_STATUS_OK);

	// promote the clone
	execCmd("zfs", std::string("promote " + clonename));
	// check that snap name has changed after promote
	execCmd("zfs", std::string("list -t snapshot " + clonesnapname));

	graceful_close(control_fd);
}

/*
 * Due to ASSERT_* macros this function must be void and return value in
 * parameter.
 */
void
get_used(int control_fd, std::string zvolname, uint64_t *val)
{
	zvol_io_hdr_t hdr_out, hdr_in;
	zvol_op_stat_t stat;
	int rc;

	hdr_out.version = REPLICA_VERSION;
	hdr_out.opcode = ZVOL_OPCODE_STATS;
	hdr_out.status = ZVOL_OP_STATUS_OK;
	hdr_out.io_seq = 1;
	hdr_out.offset = 0;
	hdr_out.len = zvolname.length() + 1;
	rc = write(control_fd, &hdr_out, sizeof (hdr_out));
	ASSERT_EQ(rc, sizeof (hdr_out));
	rc = write(control_fd, zvolname.c_str(), hdr_out.len);
	ASSERT_EQ(rc, hdr_out.len);

	rc = read(control_fd, &hdr_in, sizeof (hdr_in));
	ASSERT_EQ(rc, sizeof (hdr_in));
	EXPECT_EQ(hdr_in.status, ZVOL_OP_STATUS_OK);
	ASSERT_EQ(hdr_in.len, sizeof (stat));
	rc = read(control_fd, &stat, sizeof (stat));
	ASSERT_EQ(rc, sizeof (stat));
	EXPECT_STREQ(stat.label, "used");
	*val = stat.value;
}

/*
 * Test zvol stats command
 */
TEST(ZvolStatsTest, StatsZvol) {
	Zrepl zrepl;
	Target target;
	int rc, control_fd, data_fd;
	int ioseq = 0;
	std::string host;
	uint16_t port;
	uint64_t val1, val2;
	TestPool pool("statspool");
	std::string zvolname = pool.getZvolName("vol");

	zrepl.start();
	pool.create();
	pool.createZvol("vol", "-o io.openebs:targetip=127.0.0.1");

	rc = target.listen();
	ASSERT_GE(rc, 0);
	control_fd = target.accept(-1);
	ASSERT_GE(control_fd, 0);
	do_handshake(zvolname, host, port, NULL, control_fd,
	    ZVOL_OP_STATUS_OK);

	// get "used" before
	get_used(control_fd, zvolname, &val1);

	do_data_connection(data_fd, host, port, zvolname, 4096);
	for (int i = 0; i < 100; i++) {
		write_data_and_verify_resp(data_fd, ioseq, 4096 * i, i + 1);
	}
	graceful_close(data_fd);

	// get "used" after
	get_used(control_fd, zvolname, &val2);
	EXPECT_GT(val2, val1);
	graceful_close(control_fd);
}
