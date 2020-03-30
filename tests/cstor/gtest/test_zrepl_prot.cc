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
#include <json-c/json.h>
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
    uint16_t &port, uint64_t *ionum, uint64_t *degraded_ionum, int control_fd, int res) {
	zvol_io_hdr_t hdr_in, hdr_out = {0};
	int rc;
	mgmt_ack_t mgmt_ack;

	hdr_out.version = REPLICA_VERSION;
	hdr_out.opcode = ZVOL_OPCODE_HANDSHAKE;
	hdr_out.status = ZVOL_OP_STATUS_OK;
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
	host = std::string(mgmt_ack.ip, sizeof (mgmt_ack.ip));
	port = mgmt_ack.port;
	if (ionum != NULL)
		*ionum = mgmt_ack.checkpointed_io_seq;
	if (degraded_ionum != NULL)
		*degraded_ionum = mgmt_ack.checkpointed_degraded_io_seq;
}

/*
 * This fn does data conn for a host:ip and volume, and fills data fd
 *
 * NOTE: Return value must be void otherwise we could not use asserts
 * (peculiarity of gtest framework).
 */
static void do_data_connection(int &data_fd, std::string host, uint16_t port,
    std::string zvol_name, int bs=4096, int timeout=120,
    int res=ZVOL_OP_STATUS_OK, int rep_factor = 3,
    int version = REPLICA_VERSION, uint64_t size = 0) {
	struct sockaddr_in addr;
	zvol_io_hdr_t hdr_in, hdr_out = {0};
	zvol_op_open_data_t open_data;
	int rc;
	char val;
	int fd;

	memset(&addr, 0, sizeof (addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	rc = inet_pton(AF_INET, host.c_str(), &addr.sin_addr);
	ASSERT_TRUE(rc > 0);
retry:
	fd = socket(AF_INET, SOCK_STREAM, 0);
	rc = connect(fd, (struct sockaddr *)&addr, sizeof (addr));
	if (rc != 0) {
		perror("connect");
		ASSERT_EQ(errno, 0);
	}
	hdr_out.version = version;
	hdr_out.opcode = ZVOL_OPCODE_OPEN;
	hdr_out.status = ZVOL_OP_STATUS_OK;
	hdr_out.volsize = size;
	if (version == 3)
		hdr_out.len = sizeof (zvol_op_open_data_ver_3_t);
	else
		hdr_out.len = sizeof (open_data);

	rc = write(fd, &hdr_out, sizeof (hdr_out));
	ASSERT_EQ(rc, sizeof (hdr_out));

	open_data.tgt_block_size = bs;
	open_data.timeout = timeout;
	GtestUtils::strlcpy(open_data.volname, zvol_name.c_str(),
	    sizeof (open_data.volname));
	open_data.replication_factor = rep_factor;
	rc = write(fd, &open_data, hdr_out.len);

	rc = read(fd, &hdr_in, sizeof (hdr_in));
	ASSERT_EQ(rc, sizeof (hdr_in));
	ASSERT_EQ(hdr_in.version, hdr_out.version);
	ASSERT_EQ(hdr_in.opcode, ZVOL_OPCODE_OPEN);
	ASSERT_EQ(hdr_in.len, 0);
	if (hdr_in.status != res) {
		sleep(2);
		shutdown(fd, SHUT_WR);
		rc = read(fd, &val, sizeof (val));
		close(fd);
		goto retry;
	}
	data_fd = fd;
}

/*
 * Read 3 blocks of 4096 size at offset 0
 * Compares the io_num with expected value (hardcoded) and data
 */
static void read_data_and_verify_resp(int data_fd, uint64_t &ioseq) {
	zvol_io_hdr_t hdr_in;
	struct zvol_io_rw_hdr read_hdr;
	int rc;
	struct zvol_io_rw_hdr write_hdr;
	char buf[4096];
	int len = 4096;

	/* read all blocks at once and check IO nums */
	read_data_start(data_fd, ioseq, 0, 3 * sizeof (buf), &hdr_in, &read_hdr);
	ASSERT_EQ(hdr_in.status, ZVOL_OP_STATUS_OK);
	ASSERT_EQ(hdr_in.len, 2 * sizeof (read_hdr) + 3 * sizeof (buf));
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
static void write_two_chunks_and_verify_resp(int data_fd, uint64_t &ioseq,
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

static void wait_for_zvol_status(std::string zvol_name, uint64_t &ioseq, int control_fd,
    int state, int rebuild_status, int version = REPLICA_VERSION, int max_retry_count = 1)
{
	zvol_io_hdr_t hdr_in, hdr_out = {0};
	struct zrepl_status_ack status;
	int rc;

	while (max_retry_count > 0) {
		hdr_out.version = version;
		hdr_out.opcode = ZVOL_OPCODE_REPLICA_STATUS;
		hdr_out.status = ZVOL_OP_STATUS_OK;
		hdr_out.io_seq = ++ioseq;
		hdr_out.len = zvol_name.length() + 1;
		rc = write(control_fd, &hdr_out, sizeof (hdr_out));
		ASSERT_ERRNO("write", rc >= 0);
		ASSERT_EQ(rc, sizeof (hdr_out));
		rc = write(control_fd, zvol_name.c_str(), hdr_out.len);
		ASSERT_ERRNO("write", rc >= 0);
		ASSERT_EQ(rc, hdr_out.len);
		rc = read(control_fd, &hdr_in, sizeof (hdr_in));
		ASSERT_ERRNO("read", rc >= 0);
		ASSERT_EQ(rc, sizeof (hdr_in));
		EXPECT_EQ(hdr_in.version, hdr_out.version);
		EXPECT_EQ(hdr_in.opcode, ZVOL_OPCODE_REPLICA_STATUS);
		EXPECT_EQ(hdr_in.io_seq, ioseq);
		EXPECT_EQ(hdr_in.status, ZVOL_OP_STATUS_OK);
		EXPECT_EQ(hdr_in.len, sizeof (status));
		rc = read(control_fd, &status, sizeof (status));
		ASSERT_ERRNO("read", rc >= 0);
		ASSERT_EQ(rc, sizeof (status));
		if (status.state == state) {
			break;
		}
		if (max_retry_count > 1) {
			sleep(3);
		}
		max_retry_count--;
	}
	EXPECT_EQ(status.state, state);
	EXPECT_EQ(status.rebuild_status, rebuild_status);
}

static void transition_zvol_to_online(uint64_t &ioseq, int control_fd,
    std::string zvol_name, int res = ZVOL_OP_STATUS_OK, int version = REPLICA_VERSION)
{
	zvol_io_hdr_t hdr_in, hdr_out = {0};
	rebuild_req_t req = {0};
	int rc;

	hdr_out.version = version;
	hdr_out.opcode = ZVOL_OPCODE_START_REBUILD;
	hdr_out.status = ZVOL_OP_STATUS_OK;
	hdr_out.io_seq = ++ioseq;
	hdr_out.len = sizeof (req);
	rc = write(control_fd, &hdr_out, sizeof (hdr_out));
	ASSERT_ERRNO("write", rc >= 0);
	ASSERT_EQ(rc, sizeof (hdr_out));
	// Hack to tell the replica that it is the only replica
	//  -> rebuild will immediately finish
	GtestUtils::strlcpy(req.dw_volname, zvol_name.c_str(),
	    sizeof (req.dw_volname));
	rc = write(control_fd, &req, sizeof (req));
	ASSERT_ERRNO("write", rc >= 0);
	ASSERT_EQ(rc, sizeof (req));

	rc = read(control_fd, &hdr_in, sizeof (hdr_in));
	ASSERT_ERRNO("read", rc >= 0);
	ASSERT_EQ(rc, sizeof (hdr_in));
	EXPECT_EQ(hdr_in.opcode, ZVOL_OPCODE_START_REBUILD);
	EXPECT_EQ(hdr_in.io_seq, ioseq);
	EXPECT_EQ(hdr_in.status, res);
	EXPECT_EQ(hdr_in.len, 0);
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
		rc = setsockopt(m_listenfd, SOL_SOCKET, SO_REUSEADDR, (void *) &opt,
		    sizeof (opt));
		if (rc != 0) {
			perror("setsockopt");
			close(m_listenfd);
			return (-1);
		}
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
			if (fd < 0) {
				perror("accept");
				return (-1);
			}
			return (fd);
		}
		return (-1);
	}

	int m_listenfd;
};

/*
 * Stale Snapshot deletion verification
 */
TEST(StaleSnapshot, Destroy) {
	Zrepl zrepl;
	Target target;
	int rc, control_fd;
	SocketFd datasock;
	TestPool pool("stale_snap_pool");
	std::string vol_name = pool.getZvolName("vol");
	std::string snap_name1 = pool.getZvolName("vol@usersnap");
	std::string snap_name2 = pool.getZvolName("vol@.io_snap");
	std::string snap_name3 = pool.getZvolName("vol@.io_snap1.2");
	std::string snap_name4 = pool.getZvolName("vol@rebuild_snap");
	std::string snap_name5 = pool.getZvolName("vol_rebuild_clone@.io_snap");
	std::string snap_name6 = pool.getZvolName("vol_rebuild_clone@.io_snap1.2");
	std::string host;
	uint16_t port;
	std::string output;

	zrepl.start();
	pool.create();
	pool.createZvol("vol", "-o io.openebs:targetip=127.0.0.1 -o io.openebs:zvol_replica_id=12345");
	pool.createZvol("vol_rebuild_clone", "-o io.openebs:targetip=127.0.0.2 -o io.openebs:zvol_replica_id=12345");
	output = execCmd("zfs", std::string("snapshot ") + snap_name1);
	output = execCmd("zfs", std::string("snapshot ") + snap_name2);
	output = execCmd("zfs", std::string("snapshot ") + snap_name3);
	output = execCmd("zfs", std::string("snapshot ") + snap_name4);
	output = execCmd("zfs", std::string("snapshot ") + snap_name5);
	output = execCmd("zfs", std::string("snapshot ") + snap_name6);
	output = execCmd("zfs", std::string("list -t all"));

	printf("%s\n", output.c_str());

	zrepl.kill();

	zrepl.start();
	pool.import();

	rc = target.listen();
	ASSERT_GE(rc, 0);
	control_fd = target.accept(-1);
	ASSERT_GE(control_fd, 0);

	do_handshake(vol_name, host, port, NULL, NULL, control_fd, ZVOL_OP_STATUS_OK);
	do_data_connection(datasock.fd(), host, port, vol_name, 4096, 2);

	output = execCmd("zfs", std::string("list -t all"));
	printf("%s\n", output.c_str());
	ASSERT_EQ(output.find(".io_snap"), std::string::npos);
}

class ZreplHandshakeTest : public testing::Test {
protected:
	/* Shared setup hook for all zrepl handshake tests - called just once */
	static void SetUpTestCase() {
		m_zrepl = new Zrepl();
		m_pool = new TestPool("handshake");
		m_zrepl->start();
		m_pool->create();
		m_pool->createZvol("vol1", "-o io.openebs:targetip=127.0.0.1:6060 -o io.openebs:zvol_replica_id=12345");
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
	zvol_io_hdr_t hdr_in, hdr_out = {0};
	std::string output;
	mgmt_ack_t mgmt_ack;
	int rc;

	hdr_out.version = REPLICA_VERSION;
	hdr_out.opcode = ZVOL_OPCODE_HANDSHAKE;
	hdr_out.status = ZVOL_OP_STATUS_OK;
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
	output = execCmd("zfs", std::string("get io.openebs:zvol_replica_id  -Hpo value ") +
	    m_zvol_name);
	EXPECT_STREQ(mgmt_ack.replica_id, output.c_str());
}

TEST_F(ZreplHandshakeTest, HandshakeMinVersion) {
	zvol_io_hdr_t hdr_in, hdr_out = {0};
	std::string output;
	mgmt_ack_ver_5_t mgmt_ack;
	int rc;

	hdr_out.version = MIN_SUPPORTED_REPLICA_VERSION;
	hdr_out.opcode = ZVOL_OPCODE_HANDSHAKE;
	hdr_out.status = ZVOL_OP_STATUS_OK;
	hdr_out.len = m_zvol_name.length() + 1;

	rc = write(m_control_fd, &hdr_out, sizeof (hdr_out));
	ASSERT_EQ(rc, sizeof (hdr_out));
	rc = write(m_control_fd, m_zvol_name.c_str(), hdr_out.len);
	ASSERT_EQ(rc, hdr_out.len);

	rc = read(m_control_fd, &hdr_in, sizeof (hdr_in));
	ASSERT_EQ(rc, sizeof (hdr_in));
	EXPECT_EQ(hdr_in.version, hdr_out.version);
	EXPECT_EQ(hdr_in.opcode, ZVOL_OPCODE_HANDSHAKE);
	EXPECT_EQ(hdr_in.status, ZVOL_OP_STATUS_OK);
	EXPECT_EQ(hdr_in.io_seq, 0);
	EXPECT_EQ(hdr_in.offset, 0);
	ASSERT_EQ(hdr_in.len, sizeof (mgmt_ack_ver_5_t));
	rc = read(m_control_fd, &mgmt_ack, sizeof (mgmt_ack_ver_5_t));
	ASSERT_EQ(rc, sizeof (mgmt_ack_ver_5_t));
	EXPECT_STREQ(mgmt_ack.volname, m_zvol_name.c_str());
	output = execCmd("zpool", std::string("get guid -Hpo value ") +
	    m_pool->m_name);
	EXPECT_EQ(mgmt_ack.pool_guid, std::stoul(output));
	output = execCmd("zfs", std::string("get guid -Hpo value ") +
	    m_zvol_name);
	EXPECT_EQ(mgmt_ack.zvol_guid, std::stoul(output));
}

TEST_F(ZreplHandshakeTest, HandshakeWrongVersion) {
	zvol_io_hdr_t hdr_in, hdr_out = {0};
	// use unique ptr to implicitly dealloc mem when exiting from func
	std::unique_ptr<char[]> msgp(new char[sizeof (hdr_out) + m_zvol_name.length() + 1]);
	int rc;

	hdr_out.version = REPLICA_VERSION + 1;
	hdr_out.opcode = ZVOL_OPCODE_HANDSHAKE;
	hdr_out.status = ZVOL_OP_STATUS_OK;
	hdr_out.len = m_zvol_name.length() + 1;

	/*
	 * It must be set in one chunk so that server does not close the
	 * connection after sending header but before sending zvol name.
	 */
	memcpy(msgp.get(), &hdr_out, sizeof (hdr_out));
	memcpy(msgp.get() + sizeof (hdr_out), m_zvol_name.c_str(), hdr_out.len);
	rc = write(m_control_fd, msgp.get(), 2);
	ASSERT_EQ(rc, 2);

	rc = read(m_control_fd, &hdr_in, sizeof (hdr_in));
	ASSERT_EQ(rc, sizeof (hdr_in));
	EXPECT_EQ(hdr_in.version, REPLICA_VERSION);
	EXPECT_EQ(hdr_in.opcode, ZVOL_OPCODE_HANDSHAKE);
	EXPECT_EQ(hdr_in.status, ZVOL_OP_STATUS_VERSION_MISMATCH);
	EXPECT_EQ(hdr_in.io_seq, 0);
	EXPECT_EQ(hdr_in.offset, 0);
	ASSERT_EQ(hdr_in.len, 0);
	rc = read(m_control_fd, &hdr_in, sizeof (hdr_in));
	ASSERT_EQ(rc, 0);
}

TEST_F(ZreplHandshakeTest, HandshakeUnknownZvol) {
	zvol_io_hdr_t hdr_in, hdr_out = {0};
	int rc;
	const char *volname = "handshake/unknown";

	hdr_out.version = MIN_SUPPORTED_REPLICA_VERSION;
	hdr_out.opcode = ZVOL_OPCODE_HANDSHAKE;
	hdr_out.status = ZVOL_OP_STATUS_OK;
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
	EXPECT_EQ(hdr_in.version, hdr_out.version);
	EXPECT_EQ(hdr_in.opcode, ZVOL_OPCODE_HANDSHAKE);
	EXPECT_EQ(hdr_in.status, ZVOL_OP_STATUS_FAILED);
	EXPECT_EQ(hdr_in.io_seq, 0);
	EXPECT_EQ(hdr_in.offset, 0);
	ASSERT_EQ(hdr_in.len, 0);
}

TEST_F(ZreplHandshakeTest, UnknownOpcode) {
	zvol_io_hdr_t hdr_in, hdr_out = {0};
	int rc;

	hdr_out.version = REPLICA_VERSION;
	hdr_out.opcode = (zvol_op_code_t) 255;
	hdr_out.status = ZVOL_OP_STATUS_OK;
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
		m_pool1 = new TestPool("ihandshake");
		m_pool2 = new TestPool("handshake");
		m_zrepl = new Zrepl();
		target1 = new Target();
		target2 = new Target();
		int rc;

		m_zrepl->start();
		m_pool1->create();
		m_pool1->createZvol("ivol1", "-o io.openebs:targetip=127.0.0.1:6060 -o io.openebs:zvol_replica_id=12345");
		m_zvol_name1 = m_pool1->getZvolName("ivol1");

		rc = target1->listen();
		ASSERT_GE(rc, 0);
		m_control_fd1 = target1->accept(-1);
		ASSERT_GE(m_control_fd1, 0);

		do_handshake(m_zvol_name1, m_host1, m_port1, NULL, NULL, m_control_fd1,
		    ZVOL_OP_STATUS_OK);
		m_zrepl->kill();

		m_zrepl->start();
		m_pool1->import();
		m_control_fd1 = target1->accept(-1);
		ASSERT_GE(m_control_fd1, 0);

		do_handshake(m_zvol_name1, m_host1, m_port1, NULL, NULL, m_control_fd1,
		    ZVOL_OP_STATUS_OK);

		m_pool2->create();
		m_pool2->createZvol("vol1", "-o io.openebs:targetip=127.0.0.1:12345 -o io.openebs:zvol_replica_id=12345");
		m_zvol_name2 = m_pool1->getZvolName("ivol1");

		rc = target2->listen(12345);
		ASSERT_GE(rc, 0);
		m_control_fd2 = target2->accept(-1);
		ASSERT_GE(m_control_fd2, 0);

		do_handshake(m_zvol_name2, m_host2, m_port2, NULL, NULL, m_control_fd2,
		    ZVOL_OP_STATUS_FAILED);

		m_zvol_name2 = m_pool2->getZvolName("vol1");
		do_handshake(m_zvol_name2, m_host2, m_port2, NULL, NULL, m_control_fd2,
		    ZVOL_OP_STATUS_OK);
	}

	static void TearDownTestCase() {
		m_pool1->destroyZvol("ivol1");
		m_pool2->destroyZvol("vol1");
		delete m_pool1;
		delete m_pool2;
		if (m_control_fd1 >= 0)
			close(m_control_fd1);
		if (m_control_fd2 >= 0)
			close(m_control_fd2);
		delete m_zrepl;
		delete target1;
		delete target2;
	}

	ZreplDataTest() {
		m_ioseq1 = 0;
		m_ioseq2 = 0;
	}

	/*
	 * Create data connection and send handshake msg for the zvol.
	 */
	virtual void SetUp() override {
		do_data_connection(m_datasock1.fd(), m_host1, m_port1, m_zvol_name1);
		do_data_connection(m_datasock2.fd(), m_host2, m_port2, m_zvol_name2);
	}

	virtual void TearDown() override {
		m_datasock1.graceful_close();
		m_datasock2.graceful_close();
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
	static Target *target1;
	static Target *target2;

	SocketFd m_datasock1;
	SocketFd m_datasock2;
	uint64_t m_ioseq1;
	uint64_t m_ioseq2;
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

Target *ZreplDataTest::target1 = nullptr;
Target *ZreplDataTest::target2 = nullptr;

TEST_F(ZreplDataTest, WrongVersion) {
	zvol_io_hdr_t hdr_in, hdr_out = {0};
	// use unique ptr to implicitly dealloc mem when exiting from func
	int rc;

	hdr_out.version = REPLICA_VERSION + 1;
	hdr_out.opcode = ZVOL_OPCODE_HANDSHAKE;
	hdr_out.status = ZVOL_OP_STATUS_OK;
	hdr_out.len = 0;

	rc = write(m_datasock1.fd(), &hdr_out, 2);
	ASSERT_EQ(rc, 2);

	rc = read(m_datasock1.fd(), &hdr_in, sizeof (hdr_in));
	ASSERT_EQ(rc, 0);
}

/*
 * Write two blocks with the same io_num and third one with a different io_num
 * and test that read returns two metadata chunks.
 */
TEST_F(ZreplDataTest, WriteAndReadBlocksWithIonum) {
	char buf[4096];

	init_buf(buf, sizeof (buf), "cStor-data");
	write_data_and_verify_resp(m_datasock1.fd(), m_ioseq1, buf, 0, sizeof (buf), 123);
	write_two_chunks_and_verify_resp(m_datasock1.fd(), m_ioseq1, 4096);
	read_data_and_verify_resp(m_datasock1.fd(), m_ioseq1);

	write_data_and_verify_resp(m_datasock2.fd(), m_ioseq2, buf, 0, sizeof (buf), 123);
	write_two_chunks_and_verify_resp(m_datasock2.fd(), m_ioseq2, 4096);
	read_data_and_verify_resp(m_datasock2.fd(), m_ioseq2);
	m_datasock1.graceful_close();
	m_datasock2.graceful_close();
	sleep(5);
}

/* Read two blocks without metadata from the end of zvol */
TEST_F(ZreplDataTest, ReadBlockWithoutMeta) {
	zvol_io_hdr_t hdr_in;
	struct zvol_io_rw_hdr read_hdr;
	int rc;
	char buf[4096];
	size_t offset = ZVOL_SIZE - 2 * sizeof (buf);

	for (int i = 0; i < 2; i++) {
		read_data_start(m_datasock1.fd(), m_ioseq1, offset, sizeof (buf), &hdr_in, &read_hdr);
		ASSERT_EQ(hdr_in.status, ZVOL_OP_STATUS_OK);
		ASSERT_EQ(hdr_in.len, sizeof (read_hdr) + sizeof (buf));
		ASSERT_EQ(read_hdr.io_num, 0);
		ASSERT_EQ(read_hdr.len, sizeof (buf));

		rc = read(m_datasock1.fd(), buf, read_hdr.len);
		ASSERT_ERRNO("read", rc >= 0);
		ASSERT_EQ(rc, read_hdr.len);
		offset += sizeof (buf);
	}
	m_datasock1.graceful_close();
	m_datasock2.graceful_close();
	sleep(5);
}

/*
 * Issue a sync request. We don't have a way to test that the data were really
 * sync'd but at least we test the basic command flow.
 */
TEST_F(ZreplDataTest, WriteAndSync) {
	zvol_io_hdr_t hdr_in, hdr_out = {0};
	char buf[4096];
	int rc;

	init_buf(buf, sizeof (buf), "cStor-data");
	write_data(m_datasock1.fd(), m_ioseq1, buf, 0, sizeof (buf), ++m_ioseq1);
	rc = read(m_datasock1.fd(), &hdr_in, sizeof (hdr_in));
	ASSERT_ERRNO("read", rc >= 0);
	ASSERT_EQ(rc, sizeof (hdr_in));
	EXPECT_EQ(hdr_in.opcode, ZVOL_OPCODE_WRITE);
	EXPECT_EQ(hdr_in.status, ZVOL_OP_STATUS_OK);
	EXPECT_EQ(hdr_in.io_seq, m_ioseq1);

	hdr_out.version = REPLICA_VERSION;
	hdr_out.opcode = ZVOL_OPCODE_SYNC;
	hdr_out.status = ZVOL_OP_STATUS_OK;
	hdr_out.io_seq = ++m_ioseq1;

	rc = write(m_datasock1.fd(), &hdr_out, sizeof (hdr_out));
	ASSERT_ERRNO("write", rc >= 0);
	ASSERT_EQ(rc, sizeof (hdr_out));

	rc = read(m_datasock1.fd(), &hdr_in, sizeof (hdr_in));
	ASSERT_ERRNO("read", rc >= 0);
	ASSERT_EQ(rc, sizeof (hdr_in));
	EXPECT_EQ(hdr_in.opcode, ZVOL_OPCODE_SYNC);
	EXPECT_EQ(hdr_in.status, ZVOL_OP_STATUS_OK);
	EXPECT_EQ(hdr_in.io_seq, m_ioseq1);
	EXPECT_EQ(hdr_in.offset, 0);
	EXPECT_EQ(hdr_in.len, 0);
	m_datasock1.graceful_close();
	m_datasock2.graceful_close();
	sleep(5);
}

TEST_F(ZreplDataTest, UnknownOpcode) {
	zvol_io_hdr_t hdr_in, hdr_out = {0};
	int rc;

	hdr_out.version = REPLICA_VERSION;
	hdr_out.opcode = (zvol_op_code_t) 255;
	hdr_out.status = ZVOL_OP_STATUS_OK;
	hdr_out.io_seq = ++m_ioseq1;

	rc = write(m_control_fd1, &hdr_out, sizeof (hdr_out));
	ASSERT_ERRNO("write", rc >= 0);
	ASSERT_EQ(rc, sizeof (hdr_out));

	rc = read(m_control_fd1, &hdr_in, sizeof (hdr_in));
	ASSERT_ERRNO("read", rc >= 0);
	ASSERT_EQ(rc, sizeof (hdr_in));
	EXPECT_EQ(hdr_in.opcode, 255);
	EXPECT_EQ(hdr_in.status, ZVOL_OP_STATUS_FAILED);
	EXPECT_EQ(hdr_in.io_seq, m_ioseq1);
	m_datasock1.graceful_close();
	m_datasock2.graceful_close();
	sleep(5);
}

TEST_F(ZreplDataTest, ReadInvalidOffset) {
	zvol_io_hdr_t hdr_in;
	int rc;

	// unaligned offset
	read_data_start(m_datasock1.fd(), m_ioseq1, 33, 4096, &hdr_in, NULL);
	ASSERT_EQ(hdr_in.status, ZVOL_OP_STATUS_FAILED);
	ASSERT_EQ(hdr_in.len, 0);

	// offset past the end of zvol
	read_data_start(m_datasock1.fd(), m_ioseq1, ZVOL_SIZE + 4096, 4096, &hdr_in, NULL);
	ASSERT_EQ(hdr_in.status, ZVOL_OP_STATUS_FAILED);
	ASSERT_EQ(hdr_in.len, 0);
	m_datasock1.graceful_close();
	m_datasock2.graceful_close();
	sleep(5);
}

TEST_F(ZreplDataTest, ReadInvalidLength) {
	zvol_io_hdr_t hdr_in;
	int rc;

	// unaligned length
	read_data_start(m_datasock1.fd(), m_ioseq1, 0, 4097, &hdr_in, NULL);
	ASSERT_EQ(hdr_in.status, ZVOL_OP_STATUS_FAILED);
	ASSERT_EQ(hdr_in.len, 0);

	// length past the end of zvol
	read_data_start(m_datasock1.fd(), m_ioseq1, ZVOL_SIZE - 4096, 2 * 4096, &hdr_in, NULL);
	ASSERT_EQ(hdr_in.status, ZVOL_OP_STATUS_FAILED);
	ASSERT_EQ(hdr_in.len, 0);
	m_datasock1.graceful_close();
	m_datasock2.graceful_close();
	sleep(5);
}

TEST_F(ZreplDataTest, WriteInvalidOffset) {
	zvol_io_hdr_t hdr_in;
	char buf[4096];
	int rc;

	// Writing last block of zvol should succeed
	init_buf(buf, sizeof (buf), "cStor-data");
	write_data(m_datasock1.fd(), m_ioseq1, buf, ZVOL_SIZE - sizeof (buf), sizeof (buf), 333);
	rc = read(m_datasock1.fd(), &hdr_in, sizeof (hdr_in));
	ASSERT_ERRNO("read", rc >= 0);
	ASSERT_EQ(rc, sizeof (hdr_in));
	EXPECT_EQ(hdr_in.opcode, ZVOL_OPCODE_WRITE);
	EXPECT_EQ(hdr_in.io_seq, m_ioseq1);
	EXPECT_EQ(hdr_in.status, ZVOL_OP_STATUS_OK);

	// Writing past the end of zvol should fail
	write_data(m_datasock1.fd(), m_ioseq1, buf, ZVOL_SIZE, sizeof (buf), 334);
	rc = read(m_datasock1.fd(), &hdr_in, sizeof (hdr_in));
	ASSERT_ERRNO("read", rc >= 0);
	ASSERT_EQ(rc, sizeof (hdr_in));
	EXPECT_EQ(hdr_in.opcode, ZVOL_OPCODE_WRITE);
	EXPECT_EQ(hdr_in.io_seq, m_ioseq1);
	EXPECT_EQ(hdr_in.status, ZVOL_OP_STATUS_FAILED);
	m_datasock1.graceful_close();
	m_datasock2.graceful_close();
	sleep(5);
}

TEST_F(ZreplDataTest, WriteInvalidLength) {
	zvol_io_hdr_t hdr_in;
	char buf[2 * 4096];
	int rc;

	init_buf(buf, sizeof (buf), "cStor-data");

	write_data(m_datasock1.fd(), m_ioseq1, buf, ZVOL_SIZE - 4096, sizeof (buf), 334);
	rc = read(m_datasock1.fd(), &hdr_in, sizeof (hdr_in));
	ASSERT_ERRNO("read", rc >= 0);
	ASSERT_EQ(rc, sizeof (hdr_in));
	EXPECT_EQ(hdr_in.opcode, ZVOL_OPCODE_WRITE);
	EXPECT_EQ(hdr_in.io_seq, m_ioseq1);
	EXPECT_EQ(hdr_in.status, ZVOL_OP_STATUS_FAILED);
	m_datasock1.graceful_close();
	m_datasock2.graceful_close();
	sleep(5);
}

/*
 * Metadata ionum should be returned when zvol is degraded (rebuild
 * not finished) or when requested by ZVOL_OP_FLAG_REBUILD flag.
 */
TEST_F(ZreplDataTest, RebuildFlag) {
	zvol_io_hdr_t hdr_in;
	struct zvol_io_rw_hdr read_hdr;
	struct zvol_io_rw_hdr write_hdr;
	struct zrepl_status_ack status;
	struct mgmt_ack mgmt_ack;
	char buf[4096];
	int rc;
	std::string output;
	std::string::size_type n;

	init_buf(buf, sizeof (buf), "cStor-data");

	/* write a data block with known ionum */
	write_data_and_verify_resp(m_datasock1.fd(), m_ioseq1, buf, 0, sizeof (buf), 654);

	/* get zvol status before rebuild */
	wait_for_zvol_status(m_zvol_name1, m_ioseq1, m_control_fd1, ZVOL_STATUS_DEGRADED,
	    ZVOL_REBUILDING_INIT, MIN_SUPPORTED_REPLICA_VERSION);

	output = execCmd("zfs", std::string("stats ") + m_zvol_name1);
	ASSERT_NE(output.find("Degraded"), std::string::npos);

	/* volume is created with quorum off */
	output = execCmd("zfs", std::string("stats ") + m_zvol_name1);
	ASSERT_NE(output.find("\"quorum\":0"), std::string::npos);

	/* transition the zvol to online state */
	transition_zvol_to_online(m_ioseq1, m_control_fd1, m_zvol_name1);

	output = execCmd("zfs", std::string("stats ") + m_zvol_name1);
	n = output.find("Rebuilding");
	if (n == std::string::npos)
		ASSERT_NE(output.find("Healthy"), std::string::npos);
	else
		ASSERT_NE(output.find("Rebuilding"), std::string::npos);

	/* Get zvol status after rebuild */
	wait_for_zvol_status(m_zvol_name1, m_ioseq1, m_control_fd1, ZVOL_STATUS_HEALTHY, ZVOL_REBUILDING_DONE, REPLICA_VERSION, 5);

	output = execCmd("zfs", std::string("stats ") + m_zvol_name1);
	ASSERT_NE(output.find("Healthy"), std::string::npos);

	/* Volume became healthy so quorum is expected to be 1 from stats*/
	output = execCmd("zfs", std::string("stats ") + m_zvol_name1);
	ASSERT_NE(output.find("\"quorum\":1"), std::string::npos);

	/* read the block without rebuild flag */
	read_data_start(m_datasock1.fd(), m_ioseq1, 0, sizeof (buf), &hdr_in, &read_hdr);
	ASSERT_EQ(hdr_in.status, ZVOL_OP_STATUS_OK);
	ASSERT_EQ(hdr_in.len, sizeof (read_hdr) + sizeof (buf));
	ASSERT_EQ(read_hdr.io_num, 0);
	ASSERT_EQ(read_hdr.len, sizeof (buf));

	memset(buf, 0, sizeof (buf));
	rc = read(m_datasock1.fd(), buf, sizeof (buf));
	ASSERT_ERRNO("read", rc >= 0);
	ASSERT_EQ(rc, sizeof (buf));

	/* read the block with rebuild flag */
	read_data_start(m_datasock1.fd(), m_ioseq1, 0, sizeof (buf), &hdr_in, NULL, ZVOL_OP_FLAG_REBUILD);
	ASSERT_EQ(hdr_in.status, ZVOL_OP_STATUS_FAILED);
	m_datasock1.graceful_close();
	m_datasock2.graceful_close();
	sleep(5);
}

/*
 * Metadata ionum should be returned when requested by
 * ZVOL_OP_FLAG_READ_METADATA flag.
 */
TEST_F(ZreplDataTest, ReadMetaDataFlag) {
	zvol_io_hdr_t hdr_in;
	struct zvol_io_rw_hdr read_hdr;
	struct zvol_io_rw_hdr write_hdr;
	struct zrepl_status_ack status;
	struct mgmt_ack mgmt_ack;
	char buf[4096];
	int rc;

	init_buf(buf, sizeof (buf), "cStor-data");

	/* write a data block with known ionum */
	write_data_and_verify_resp(m_datasock1.fd(), m_ioseq1, buf, 0, sizeof (buf), 654);

	/* read the block with ZVOL_OP_FLAG_READ_METADATA flag */
	read_data_start(m_datasock1.fd(), m_ioseq1, 0, sizeof (buf), &hdr_in, &read_hdr, ZVOL_OP_FLAG_READ_METADATA);
	ASSERT_EQ(hdr_in.status, ZVOL_OP_STATUS_OK);
	ASSERT_EQ(hdr_in.len, sizeof (read_hdr) + sizeof (buf));
	ASSERT_EQ(read_hdr.io_num, 654);
	ASSERT_EQ(read_hdr.len, sizeof (buf));

	memset(buf, 0, sizeof (buf));
	rc = read(m_datasock1.fd(), buf, sizeof (buf));
	ASSERT_ERRNO("read", rc >= 0);
	ASSERT_EQ(rc, sizeof (buf));
	m_datasock1.graceful_close();
	m_datasock2.graceful_close();
	sleep(5);
}

static bool is_zvol_readonly(std::string zvol) {
	std::string output;

	output = execCmd("zfs", std::string("get  io.openebs:readonly ") + std::string(" -Hpo value ") + zvol);
	if (output.compare("on") == 0)
		return true;

	output = execCmd("zfs", std::string("stats ") + zvol);
	std::size_t found = output.find("\"readOnly\":on");
	if (found != std::string::npos) {
		return true;
	}

	return false;
}

static bool isIOAckSenderCreated(std::string zvol) {
	std::string output;

	output = execCmd("zfs", std::string("stats ") + zvol);
	if (output.find("\"isIOAckSenderCreated\":1") != std::string::npos)
		return true;

	return false;
}

static bool isIOReceiverCreated(std::string zvol) {
	std::string output;

	output = execCmd("zfs", std::string("stats ") + zvol);
	if (output.find("\"isIOReceiverCreated\":1") != std::string::npos)
		return true;

	return false;
}

/*
 * if zvol is readonly then..
 *  	- write should fail
 *  	- read should happen
 */
TEST_F(ZreplDataTest, ZVolReadOnly) {
	zvol_io_hdr_t hdr_in;
	struct zvol_io_rw_hdr read_hdr;
	struct zvol_io_rw_hdr write_hdr;
	struct zrepl_status_ack status;
	struct mgmt_ack mgmt_ack;
	char buf[4096];
	int rc;
	std::string output;

	execCmd("zfs", std::string("set io.openebs:readonly=on ") + m_zvol_name1);
	EXPECT_EQ(is_zvol_readonly(m_zvol_name1), true);
	EXPECT_EQ(isIOAckSenderCreated(m_zvol_name1), true);
	EXPECT_EQ(isIOReceiverCreated(m_zvol_name1), true);

	// read should happen
	read_data_start(m_datasock1.fd(), m_ioseq1, 0, sizeof (buf), &hdr_in, &read_hdr);
	ASSERT_EQ(hdr_in.status, ZVOL_OP_STATUS_OK);
	ASSERT_EQ(hdr_in.len, sizeof (read_hdr) + sizeof (buf));
	ASSERT_EQ(read_hdr.len, sizeof (buf));

	rc = read(m_datasock1.fd(), buf, read_hdr.len);
	ASSERT_ERRNO("read", rc >= 0);
	ASSERT_EQ(rc, read_hdr.len);

	// write should fail
	init_buf(buf, sizeof (buf), "cStor-data");
	write_data(m_datasock1.fd(), m_ioseq1, buf, 0, sizeof (buf), ++m_ioseq1);
	rc = read(m_datasock1.fd(), &hdr_in, sizeof (hdr_in));
	ASSERT_ERRNO("read", rc >= 0);
	ASSERT_EQ(rc, sizeof (hdr_in));
	EXPECT_EQ(hdr_in.opcode, ZVOL_OPCODE_WRITE);
	EXPECT_EQ(hdr_in.status, ZVOL_OP_STATUS_FAILED);
	EXPECT_EQ(hdr_in.io_seq, m_ioseq1);

	m_pool1->pExport();
	m_pool1->import();

	// mgmt connection should not happen
	m_control_fd1 = target1->accept(10);
	ASSERT_EQ(m_control_fd1, -1);
	EXPECT_EQ(isIOAckSenderCreated(m_zvol_name1), false);
	EXPECT_EQ(isIOReceiverCreated(m_zvol_name1), false);

	execCmd("zfs", std::string("set io.openebs:readonly=off ") + m_zvol_name1);
	EXPECT_EQ(is_zvol_readonly(m_zvol_name1), false);

	// mgmt connection should happen
	m_control_fd1 = target1->accept(10);
	ASSERT_GE(m_control_fd1, 0);

	do_handshake(m_zvol_name1, m_host1, m_port1, NULL, NULL, m_control_fd1,
	    ZVOL_OP_STATUS_OK);

	do_data_connection(m_datasock1.fd(), m_host1, m_port1, m_zvol_name1);
	EXPECT_EQ(isIOAckSenderCreated(m_zvol_name1), true);
	EXPECT_EQ(isIOReceiverCreated(m_zvol_name1), true);

	// write should happen
	write_data(m_datasock1.fd(), m_ioseq1, buf, 0, sizeof (buf), ++m_ioseq1);
	rc = read(m_datasock1.fd(), &hdr_in, sizeof (hdr_in));
	ASSERT_ERRNO("read", rc >= 0);
	ASSERT_EQ(rc, sizeof (hdr_in));
	EXPECT_EQ(hdr_in.opcode, ZVOL_OPCODE_WRITE);
	EXPECT_EQ(hdr_in.status, ZVOL_OP_STATUS_OK);
	EXPECT_EQ(hdr_in.io_seq, m_ioseq1);

	m_datasock1.graceful_close();
	m_datasock2.graceful_close();
	sleep(5);
}

/*
 * if zpool is readonly then..
 *  	- write should fail
 *  	- read should happen
 */
TEST_F(ZreplDataTest, ZpoolReadOnly) {
	zvol_io_hdr_t hdr_in;
	struct zvol_io_rw_hdr read_hdr;
	struct zvol_io_rw_hdr write_hdr;
	struct zrepl_status_ack status;
	struct mgmt_ack mgmt_ack;
	char buf[4096];
	int rc;
	std::string output;

	execCmd("zpool", std::string("set io.openebs:readonly=on ") + m_pool1->m_name);
	EXPECT_EQ(m_pool1->isReadOnly(), true);
	EXPECT_EQ(isIOAckSenderCreated(m_zvol_name1), true);
	EXPECT_EQ(isIOReceiverCreated(m_zvol_name1), true);

	// read should happen
	read_data_start(m_datasock1.fd(), m_ioseq1, 0, sizeof (buf), &hdr_in, &read_hdr);
	ASSERT_EQ(hdr_in.status, ZVOL_OP_STATUS_OK);
	ASSERT_EQ(hdr_in.len, sizeof (read_hdr) + sizeof (buf));
	ASSERT_EQ(read_hdr.len, sizeof (buf));

	rc = read(m_datasock1.fd(), buf, read_hdr.len);
	ASSERT_ERRNO("read", rc >= 0);
	ASSERT_EQ(rc, read_hdr.len);

	// write should fail
	init_buf(buf, sizeof (buf), "cStor-data");
	write_data(m_datasock1.fd(), m_ioseq1, buf, 0, sizeof (buf), ++m_ioseq1);
	rc = read(m_datasock1.fd(), &hdr_in, sizeof (hdr_in));
	ASSERT_ERRNO("read", rc >= 0);
	ASSERT_EQ(rc, sizeof (hdr_in));
	EXPECT_EQ(hdr_in.opcode, ZVOL_OPCODE_WRITE);
	EXPECT_EQ(hdr_in.status, ZVOL_OP_STATUS_FAILED);
	EXPECT_EQ(hdr_in.io_seq, m_ioseq1);

	m_pool1->pExport();
	m_pool1->import();

	// mgmt connection should not happen
	m_control_fd1 = target1->accept(10);
	ASSERT_EQ(m_control_fd1, -1);
	EXPECT_EQ(isIOAckSenderCreated(m_zvol_name1), false);
	EXPECT_EQ(isIOReceiverCreated(m_zvol_name1), false);

	execCmd("zpool", std::string("set io.openebs:readonly=off ") + m_pool1->m_name);
	EXPECT_EQ(m_pool1->isReadOnly(), false);

	// mgmt connection should happen
	m_control_fd1 = target1->accept(10);
	ASSERT_GE(m_control_fd1, 0);

	do_handshake(m_zvol_name1, m_host1, m_port1, NULL, NULL, m_control_fd1,
	    ZVOL_OP_STATUS_OK);

	do_data_connection(m_datasock1.fd(), m_host1, m_port1, m_zvol_name1);
	EXPECT_EQ(isIOAckSenderCreated(m_zvol_name1), true);
	EXPECT_EQ(isIOReceiverCreated(m_zvol_name1), true);

	// write should happen
	write_data(m_datasock1.fd(), m_ioseq1, buf, 0, sizeof (buf), ++m_ioseq1);
	rc = read(m_datasock1.fd(), &hdr_in, sizeof (hdr_in));
	ASSERT_ERRNO("read", rc >= 0);
	ASSERT_EQ(rc, sizeof (hdr_in));
	EXPECT_EQ(hdr_in.opcode, ZVOL_OPCODE_WRITE);
	EXPECT_EQ(hdr_in.status, ZVOL_OP_STATUS_OK);
	EXPECT_EQ(hdr_in.io_seq, m_ioseq1);

	m_datasock1.graceful_close();
	m_datasock2.graceful_close();
	sleep(5);
}

TEST(ReplicaState, SingleReplicaQuorumOff) {
	Zrepl zrepl;
	TestPool pool("replicaState");
	Target targetQuorumOn, targetQuorumOff;
	int rc;
	int control_fd1, control_fd2, datasock1_fd, datasock2_fd;
	std::string host1, host2, zvol_name1, zvol_name2;
	uint16_t port1, port2;
	uint64_t ioseq1, ioseq2;

	zrepl.start();
	pool.create();
	pool.createZvol("quorumon", "-o quorum=on -o io.openebs:targetip=127.0.0.1:6060 -o io.openebs:zvol_replica_id=12345");
	pool.createZvol("quorumoff", "-o io.openebs:targetip=127.0.0.1:6161 -o io.openebs:zvol_replica_id=12345");
	zvol_name1 = pool.getZvolName("quorumon");
	zvol_name2 = pool.getZvolName("quorumoff");

	rc = targetQuorumOn.listen();
	ASSERT_GE(rc, 0);
	rc = targetQuorumOff.listen(6161);
	ASSERT_GE(rc, 0);

	control_fd1 = targetQuorumOn.accept(-1);
	ASSERT_GE(control_fd1, 0);
	do_handshake(zvol_name1, host1, port1, NULL, NULL, control_fd1,
	    ZVOL_OP_STATUS_OK);
	do_data_connection(datasock1_fd, host1, port1, zvol_name1, 4096, 120, ZVOL_OP_STATUS_OK, 1);

	control_fd2 = targetQuorumOff.accept(-1);
	ASSERT_GE(control_fd2, 0);
	do_handshake(zvol_name2, host2, port2, NULL, NULL, control_fd2,
	    ZVOL_OP_STATUS_OK);
	do_data_connection(datasock2_fd, host2, port2, zvol_name2, 4096, 120, ZVOL_OP_STATUS_OK, 1,
	    MIN_SUPPORTED_REPLICA_VERSION);

	wait_for_zvol_status(zvol_name1, ioseq1, control_fd1, ZVOL_STATUS_HEALTHY, ZVOL_REBUILDING_DONE);
	wait_for_zvol_status(zvol_name2, ioseq1, control_fd2, ZVOL_STATUS_DEGRADED, ZVOL_REBUILDING_INIT);

	/* transition the zvol to online state since replica is already Healthy it should return ZVOL_OP_STATUS_OK */
	transition_zvol_to_online(ioseq1, control_fd1, zvol_name1, ZVOL_OP_STATUS_OK, MIN_SUPPORTED_REPLICA_VERSION);

	zrepl.kill();
}

TEST(ReplicaState, MultiReplicaAndDegradedSingleReplicaDuringUpgrade) {
	Zrepl zrepl;
	TestPool pool("replicaState");
	Target targetQuorumOn;
	int rc;
	int control_fd1, datasock1_fd;
	std::string host1, host2, zvol_name1, zvol_name2;
	uint16_t port1;
	uint64_t ioseq1;

	zrepl.start();
	pool.create();
	pool.createZvol("quorumon", "-o quorum=on -o io.openebs:targetip=127.0.0.1:6060 -o io.openebs:zvol_replica_id=12345");
	zvol_name1 = pool.getZvolName("quorumon");

	rc = targetQuorumOn.listen();
	ASSERT_GE(rc, 0);

	control_fd1 = targetQuorumOn.accept(-1);
	ASSERT_GE(control_fd1, 0);
	do_handshake(zvol_name1, host1, port1, NULL, NULL, control_fd1,
	    ZVOL_OP_STATUS_OK);
	do_data_connection(datasock1_fd, host1, port1, zvol_name1, 4096, 120, ZVOL_OP_STATUS_OK, 3);

	wait_for_zvol_status(zvol_name1, ioseq1, control_fd1, ZVOL_STATUS_DEGRADED, ZVOL_REBUILDING_INIT);

	zrepl.kill();

	zrepl.start();
	pool.import();

	control_fd1 = targetQuorumOn.accept(-1);
	ASSERT_GE(control_fd1, 0);
	do_handshake(zvol_name1, host1, port1, NULL, NULL, control_fd1,
	    ZVOL_OP_STATUS_OK);
	do_data_connection(datasock1_fd, host1, port1, zvol_name1, 4096, 120, ZVOL_OP_STATUS_OK, 1);

	wait_for_zvol_status(zvol_name1, ioseq1, control_fd1, ZVOL_STATUS_DEGRADED, ZVOL_REBUILDING_INIT);

	zrepl.kill();
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
	std::string output;

	zrepl.start();
	pool.create();
	pool.createZvol("implicit1", "-o io.openebs:targetip=127.0.0.1:6060 -o io.openebs:zvol_replica_id=12345");
	pool.createZvol("explicit1", "-o io.openebs:targetip=127.0.0.1:12345 -o io.openebs:zvol_replica_id=12345");

	output = execCmd("zfs", std::string("stats ") + pool.getZvolName("implicit1"));
	ASSERT_NE(output.find("Offline"), std::string::npos);

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

	pool.createZvol("implicit2", "-o io.openebs:targetip=127.0.0.1:6060 -o io.openebs:zvol_replica_id=12345");
	pool.createZvol("explicit2", "-o io.openebs:targetip=127.0.0.1:12345 -o io.openebs:zvol_replica_id=12345");

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
	zvol_io_hdr_t hdr_in, hdr_out = {0};
	Zrepl zrepl;
	TestPool pool("handshake");
	std::string zvolname = pool.getZvolName("reconnect");
	Target target;
	int fd;
	char buf[1];
	int rc;

	zrepl.start();
	pool.create();
	pool.createZvol("reconnect", "-o io.openebs:targetip=127.0.0.1:6060 -o io.openebs:zvol_replica_id=12345");

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
	SocketFd datasock_slow, datasock_fast;
	uint64_t ioseq = 0;
	std::string host_slow, host_fast;
	uint16_t port_slow, port_fast;
	uint64_t ionum_slow, ionum_fast;
	uint64_t degraded_ionum_slow, degraded_ionum_fast;

	zvol_io_hdr_t hdr_in;
	struct zvol_io_rw_hdr read_hdr;
	struct zvol_io_rw_hdr write_hdr;
	struct zrepl_status_ack status;
	struct mgmt_ack mgmt_ack;
	char buf[4096];

	zrepl.start();
	pool.create();
	pool.createZvol("slow", "-o io.openebs:targetip=127.0.0.1:6060 -o io.openebs:zvol_replica_id=12345");
	pool.createZvol("fast", "-o io.openebs:targetip=127.0.0.1:6060 -o io.openebs:zvol_replica_id=12345");
	zvol_name_slow = pool.getZvolName("slow");
	zvol_name_fast = pool.getZvolName("fast");

	rc = target.listen();
	ASSERT_GE(rc, 0);
	control_fd = target.accept(-1);
	ASSERT_GE(control_fd, 0);

	do_handshake(zvol_name_slow, host_slow, port_slow, &ionum_slow, &degraded_ionum_slow,
	    control_fd, ZVOL_OP_STATUS_OK);
	do_handshake(zvol_name_fast, host_fast, port_fast, &ionum_fast, &degraded_ionum_fast,
	    control_fd, ZVOL_OP_STATUS_OK);
	ASSERT_NE(ionum_slow, 888);
	ASSERT_NE(ionum_fast, 888);

	do_data_connection(datasock_slow.fd(), host_slow, port_slow, zvol_name_slow,
	    4096, 1000);
	do_data_connection(datasock_fast.fd(), host_fast, port_fast, zvol_name_fast,
	    4096, 2);

	init_buf(buf, sizeof (buf), "cStor-data");
	write_data_and_verify_resp(datasock_slow.fd(), ioseq, buf, 0, sizeof (buf), 555);
	write_data_and_verify_resp(datasock_fast.fd(), ioseq, buf, 0, sizeof (buf), 555);

	/* we are updating io_seq for degraded mode in every 5 seconds */
	sleep(7);	// sleep more than 5 seconds

	transition_zvol_to_online(ioseq, control_fd, zvol_name_slow);
	transition_zvol_to_online(ioseq, control_fd, zvol_name_fast);
	sleep(5);

	write_data_and_verify_resp(datasock_slow.fd(), ioseq, buf, 0, sizeof (buf), 888);
	write_data_and_verify_resp(datasock_fast.fd(), ioseq, buf, 0, sizeof (buf), 888);

	/* read the block without ZVOL_OP_FLAG_READ_METADATA flag in healthy state */
	read_data_start(datasock_slow.fd(), ioseq, 0, sizeof (buf), &hdr_in, &read_hdr, 0);
	ASSERT_EQ(hdr_in.status, ZVOL_OP_STATUS_OK);
	ASSERT_EQ(hdr_in.len, sizeof (read_hdr) + sizeof (buf));
	ASSERT_EQ(read_hdr.io_num, 0);
	ASSERT_EQ(read_hdr.len, sizeof (buf));

	memset(buf, 0, sizeof (buf));
	rc = read(datasock_slow.fd(), buf, sizeof (buf));
	ASSERT_ERRNO("read", rc >= 0);
	ASSERT_EQ(rc, sizeof (buf));

	sleep(10);	/* Due to spa sync interval, sleep for 10 sec is required here */

	zrepl.kill();

	zrepl.start();
	pool.import();

	control_fd = target.accept(-1);
	ASSERT_GE(control_fd, 0);

	do_handshake(zvol_name_slow, host_slow, port_slow, &ionum_slow, &degraded_ionum_slow,
	    control_fd, ZVOL_OP_STATUS_OK);
	do_handshake(zvol_name_fast, host_fast, port_fast, &ionum_fast, &degraded_ionum_fast,
	    control_fd, ZVOL_OP_STATUS_OK);

	ASSERT_NE(ionum_slow, 888);
	ASSERT_EQ(ionum_fast, 888);
	ASSERT_EQ(degraded_ionum_slow, 555);
	ASSERT_EQ(degraded_ionum_fast, 555);

	do_data_connection(datasock_slow.fd(), host_slow, port_slow, zvol_name_slow,
	    4096, 1000);
	datasock_fast.graceful_close();
	datasock_slow.graceful_close();
	graceful_close(control_fd);
	sleep(5);
}

class ZreplBlockSizeTest : public testing::Test {
protected:
	/*
	 * Shared setup hook for all zrepl block size tests - called just once.
	 */
	static void SetUpTestCase() {
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
		m_port = 0;
	}

	/*
	 * Create data connection and send handshake msg for the zvol.
	 */
	virtual void SetUp() override {
		Target target;
		int rc;

		m_control_fd = -1;
		rc = target.listen();
		ASSERT_GE(rc, 0);

		m_pool->createZvol("vol", "-o io.openebs:targetip=127.0.0.1 -o io.openebs:zvol_replica_id=12345");
		m_zvol_name = m_pool->getZvolName("vol");
		m_control_fd = target.accept(-1);
		ASSERT_GE(m_control_fd, 0);

		do_handshake(m_zvol_name, m_host, m_port, NULL, NULL, m_control_fd,
		    ZVOL_OP_STATUS_OK);
	}

	virtual void TearDown() override {
		m_pool->destroyZvol("vol");
		if (m_control_fd >= 0)
			close(m_control_fd);
	}

	static Zrepl	*m_zrepl;
	static TestPool *m_pool;

	uint16_t m_port;
	std::string m_host;
	std::string m_zvol_name;
	uint64_t m_ioseq;
	int	 m_control_fd;
};

TestPool *ZreplBlockSizeTest::m_pool = nullptr;
Zrepl *ZreplBlockSizeTest::m_zrepl = nullptr;

/*
 * Test setting metadata granularity on zvol.
 */
TEST_F(ZreplBlockSizeTest, SetMetaBlockSize) {
	SocketFd datasock1, datasock2;
	char buf[4096];

	init_buf(buf, sizeof (buf), "cStor-data");
	do_data_connection(datasock1.fd(), m_host, m_port, m_zvol_name, 4096);
	write_data_and_verify_resp(datasock1.fd(), m_ioseq, buf, 0, sizeof (buf), 1);
	datasock1.graceful_close();
	sleep(5);
	do_data_connection(datasock2.fd(), m_host, m_port, m_zvol_name, 4096);
	write_data_and_verify_resp(datasock2.fd(), m_ioseq, buf, 0, sizeof (buf), 1);
	datasock2.graceful_close();
	sleep(5);
}

TEST_F(ZreplBlockSizeTest, SetMetaBlockSizeSmallerThanBlockSize) {
	SocketFd datasock;
	char buf[4096];

	init_buf(buf, sizeof (buf), "cStor-data");
	do_data_connection(datasock.fd(), m_host, m_port, m_zvol_name, 512);
	write_data_and_verify_resp(datasock.fd(), m_ioseq, buf, 0, sizeof (buf), 1);
	datasock.graceful_close();
	sleep(5);
}

TEST_F(ZreplBlockSizeTest, SetMetaBlockSizeBiggerThanBlockSize) {
	SocketFd datasock;
	char buf[8192];

	init_buf(buf, sizeof (buf), "cStor-data");
	do_data_connection(datasock.fd(), m_host, m_port, m_zvol_name, 8192);
	write_data_and_verify_resp(datasock.fd(), m_ioseq, buf, 0, sizeof (buf), 1);
	datasock.graceful_close();
	sleep(5);
}

TEST_F(ZreplBlockSizeTest, SetMetaBlockSizeUnaligned) {
	SocketFd datasock;

	do_data_connection(datasock.fd(), m_host, m_port, m_zvol_name, 513, 120,
	    ZVOL_OP_STATUS_FAILED);
	datasock.graceful_close();
	sleep(5);
}

TEST_F(ZreplBlockSizeTest, SetDifferentMetaBlockSizes) {
	SocketFd datasock1, datasock2;
	char buf[4096];

	init_buf(buf, sizeof (buf), "cStor-data");
	do_data_connection(datasock1.fd(), m_host, m_port, m_zvol_name, 4096);
	write_data_and_verify_resp(datasock1.fd(), m_ioseq, buf, 0, sizeof (buf), 1);
	datasock1.graceful_close();
	sleep(5);
	do_data_connection(datasock2.fd(), m_host, m_port, m_zvol_name, 512, 120,
	    ZVOL_OP_STATUS_FAILED);
	datasock2.graceful_close();
	sleep(5);
}

/*
 * Test disk replacement
 */
TEST(DiskReplaceTest, SpareReplacement) {
	Zrepl zrepl;
	Target target;
	int rc, control_fd;
	SocketFd datasock;
	std::string host;
	uint16_t port;
	uint64_t ioseq;
	Vdev vdev2("vdev2");
	Vdev spare("spare");
	TestPool pool("rplcpool");
	char buf[4096];

	zrepl.start();
	vdev2.create();
	spare.create();
	pool.create();
	pool.createZvol("vol", "-o io.openebs:targetip=127.0.0.1 -o io.openebs:zvol_replica_id=12345");
	init_buf(buf, sizeof (buf), "cStor-data");

	rc = target.listen();
	ASSERT_GE(rc, 0);
	control_fd = target.accept(-1);
	ASSERT_GE(control_fd, 0);
	do_handshake(pool.getZvolName("vol"), host, port, NULL, NULL, control_fd,
	    ZVOL_OP_STATUS_OK);
	do_data_connection(datasock.fd(), host, port, pool.getZvolName("vol"));
	write_data_and_verify_resp(datasock.fd(), ioseq, buf, 0, sizeof (buf), 10);

	// construct mirrored pool with a spare
	execCmd("zpool", std::string("attach ") + pool.m_name + " " +
	    pool.m_vdev->m_path + " " + vdev2.m_path);
	write_data_and_verify_resp(datasock.fd(), ioseq, buf, 0, sizeof (buf), 10);
	execCmd("zpool", std::string("add ") + pool.m_name + " spare " +
	    spare.m_path);
	write_data_and_verify_resp(datasock.fd(), ioseq, buf, 0, sizeof (buf), 10);
	ASSERT_STREQ(getPoolState(pool.m_name).c_str(), "ONLINE");

	// fail one of the disks in the mirror
	execCmd("zpool", std::string("offline ") + pool.m_name + " " +
	    vdev2.m_path);
	write_data_and_verify_resp(datasock.fd(), ioseq, buf, 0, sizeof (buf), 10);
	ASSERT_STREQ(getPoolState(pool.m_name).c_str(), "DEGRADED");

	// replace failed disk by the spare and remove it from mirror
	execCmd("zpool", std::string("replace ") + pool.m_name + " " +
	    vdev2.m_path + " " + spare.m_path);
	write_data_and_verify_resp(datasock.fd(), ioseq, buf, 0, sizeof (buf), 10);
	execCmd("zpool", std::string("detach ") + pool.m_name + " " +
	    vdev2.m_path);
	ASSERT_STREQ(getPoolState(pool.m_name).c_str(), "ONLINE");

	//std::cout << execCmd("zpool", std::string("status ") + pool.m_name);

	datasock.graceful_close();
	graceful_close(control_fd);
	sleep(5);
}

static void verify_listsnap_details(std::string zvol_name) {
	struct json_object *jobj = NULL, *jsnaplist_map = NULL;
	struct json_object *jstrvolname, *jsnap = NULL;
	std::string snapshot_output;
	const char *volname, *snapname;
	struct json_object_iterator it;
	struct json_object_iterator itEnd;
	std::string json, volsnap, snap;

	json = execCmd("zfs", std::string("listsnap ") +
	    zvol_name);

	jobj = json_tokener_parse(json.c_str());
	printf("%s\n", json.c_str());
	ASSERT_NE((jobj == NULL), 1);

	json_object_object_get_ex(jobj, "name", &jstrvolname);
	volname = json_object_get_string(jstrvolname);
	ASSERT_EQ(volname, zvol_name);

	json_object_object_get_ex(jobj, "snaplist", &jsnaplist_map);

	it = json_object_iter_begin(jsnaplist_map);
	itEnd = json_object_iter_end(jsnaplist_map);

	while (!json_object_iter_equal(&it, &itEnd)) {
		snapname = json_object_iter_peek_name(&it);
		snapshot_output = execCmd("zfs", std::string("list -t snapshot -Ho name " + zvol_name + std::string("@") + snapname));
		ASSERT_EQ(zvol_name + std::string("@") + snapname, snapshot_output);
		json_object_iter_next(&it);
	}

	snapshot_output = execCmd("zfs", std::string("list -t snapshot -Ho name"));
	std::stringstream ss(snapshot_output);
	while (std::getline(ss, volsnap, '\n')) {
		std::stringstream volss(volsnap);
		int count = 1;
		while (std::getline(volss, snap, '@')) {
			if (count == 2)
				break;
			count = count + 1;
		}
		json_bool ret = json_object_object_get_ex(jsnaplist_map, snap.c_str(), &jsnap);
		printf("%s\n", snap.c_str());
		ASSERT_EQ(ret, 1);
	}
}

static void verify_snapshot_details(std::string zvol_name, std::string json, std::string requested_snap) {
	struct json_object *jobj = NULL, *jarr = NULL;
	struct json_object *jsnap, *jsnapname, *jprop;
	int arrlen, i;
	std::string output;
	char jsval[32];
	uint64_t jival;
	jobj = json_tokener_parse(json.c_str());
	ASSERT_NE((jobj == NULL), 1);

	json_object_object_get_ex(jobj, "snapshot", &jarr);
	ASSERT_NE((jarr == NULL), 1);

	arrlen = json_object_array_length(jarr);
	for (i = 0; i < arrlen; i++) {
		jsnap = json_object_array_get_idx(jarr, i);
		ASSERT_NE((jsnap == NULL), 1);

		json_object_object_get_ex(jsnap, "name", &jsnapname);
		ASSERT_NE((jsnapname == NULL), 1);

		json_object_object_get_ex(jsnap, "properties", &jprop);
		ASSERT_NE((jprop == NULL), 1);

		if (!requested_snap.empty())
			EXPECT_EQ(zvol_name + std::string("@") + (char *)json_object_get_string(jsnapname), requested_snap);

		json_object_object_foreach(jprop, key, val) {
			output = execCmd("zfs", std::string("get ") + key +
			    std::string(" -Hpo value ") + zvol_name +
			    std::string("@") +
			    (char *)json_object_get_string(jsnapname));

			/*
			 * We are verifying only those values which can
			 * be obtained from ZFS command.
			 */
			if (!strcmp(key, "available") ||
			    !strcmp(key, "refquota") ||
			    !strcmp(key, "type") ||
			    !strcmp(key, "volblocksize") ||
			    !strcmp(key, "refreservation")) {
				continue;
			} else if (!strcmp(key, "refcompressratio") ||
			    !strcmp(key, "compressratio")) {
				jival = std::stoul(json_object_get_string(val));
				snprintf(jsval, sizeof (jsval), "%llu.%02llux",
				    (u_longlong_t)(jival/100), (u_longlong_t)(jival%100));
				EXPECT_STREQ(jsval, output.c_str());
			} else if (!strcmp(key, "logicalreferenced") ||
			    !strcmp(key, "creation") ||
			    !strcmp(key, "createtxg") ||
			    !strcmp(key, "guid") ||
			    !strcmp(key, "userrefs") ||
			    !strcmp(key, "written") ||
			    !strcmp(key, "logicalreferenced")) {
				jival = std::stoul(json_object_get_string(val));
				EXPECT_EQ(jival, std::stoul(output));
			} else if (!strcmp(key, "defer_destroy")) {
				jival = std::stoul(json_object_get_string(val));
				snprintf(jsval, sizeof(jsval), "%s", (jival) ? "on" : "off");
				EXPECT_STREQ(jsval, output.c_str());
			} else {
				EXPECT_STREQ(json_object_get_string(val), output.c_str());
			}
		}
	}
	json_object_put(jobj);
}

static
void prep_snap(int control_fd, std::string snapname, uint64_t io_seq, int status)
{
	int rc;
	zvol_io_hdr_t phdr_in, phdr_out = {0};
	phdr_out.version = REPLICA_VERSION;
	phdr_out.opcode = ZVOL_OPCODE_SNAP_PREPARE;
	phdr_out.status = ZVOL_OP_STATUS_OK;
	phdr_out.io_seq = io_seq;
	phdr_out.len = snapname.length() + 1;
	rc = write(control_fd, &phdr_out, sizeof (phdr_out));
	ASSERT_EQ(rc, sizeof (phdr_out));
	rc = write(control_fd, snapname.c_str(), phdr_out.len);
	ASSERT_EQ(rc, phdr_out.len);
	rc = read(control_fd, &phdr_in, sizeof (phdr_in));
	ASSERT_EQ(rc, sizeof (phdr_in));
	EXPECT_EQ(phdr_in.status, status);
	ASSERT_EQ(phdr_in.len, 0);
}

/*
 * Snapshot create , list and destroy.
 */
TEST(Snapshot, CreateAndDestroy) {
	zvol_io_hdr_t hdr_in, hdr_out = {0};
	Zrepl zrepl;
	Target target;
	int rc, control_fd, io_seq;
	SocketFd datasock;
	TestPool pool("snappool");
	char *buf;
	std::string vol_name = pool.getZvolName("vol");
	std::string snap_name = pool.getZvolName("vol@snap");
	std::string snap1_name = pool.getZvolName("vol@snap1");
	std::string bad_snap_name = pool.getZvolName("vol");
	std::string unknown_snap_name = pool.getZvolName("unknown@snap");
	uint64_t ioseq;
	std::string host;
	uint16_t port;
	struct zvol_snapshot_list *snaplist;
	std::string output;

	io_seq = 0;
	zrepl.start();
	pool.create();
	pool.createZvol("vol", "-o io.openebs:targetip=127.0.0.1 -o io.openebs:zvol_replica_id=12345");

	rc = target.listen();
	ASSERT_GE(rc, 0);
	control_fd = target.accept(-1);
	ASSERT_GE(control_fd, 0);

	do_handshake(vol_name, host, port, NULL, NULL, control_fd, ZVOL_OP_STATUS_OK);
	do_data_connection(datasock.fd(), host, port, vol_name, 4096, 2);

	// try to create snap of invalid zvol
	hdr_out.version = REPLICA_VERSION;
	hdr_out.opcode = ZVOL_OPCODE_SNAP_CREATE;
	hdr_out.status = ZVOL_OP_STATUS_OK;
	hdr_out.io_seq = io_seq;
	hdr_out.len = bad_snap_name.length() + 1;
	prep_snap(control_fd, bad_snap_name, hdr_out.io_seq, ZVOL_OP_STATUS_FAILED);
	rc = write(control_fd, &hdr_out, sizeof (hdr_out));
	ASSERT_EQ(rc, sizeof (hdr_out));
	rc = write(control_fd, bad_snap_name.c_str(), hdr_out.len);
	ASSERT_EQ(rc, hdr_out.len);
	rc = read(control_fd, &hdr_in, sizeof (hdr_in));
	ASSERT_EQ(rc, sizeof (hdr_in));
	EXPECT_EQ(hdr_in.status, ZVOL_OP_STATUS_FAILED);
	ASSERT_EQ(hdr_in.len, 0);

	// try to create snap of unknown zvol
	hdr_out.io_seq = ++io_seq;
	hdr_out.len = unknown_snap_name.length() + 1;
	prep_snap(control_fd, unknown_snap_name, hdr_out.io_seq, ZVOL_OP_STATUS_FAILED);
	rc = write(control_fd, &hdr_out, sizeof (hdr_out));
	ASSERT_EQ(rc, sizeof (hdr_out));
	rc = write(control_fd, unknown_snap_name.c_str(), hdr_out.len);
	ASSERT_EQ(rc, hdr_out.len);
	rc = read(control_fd, &hdr_in, sizeof (hdr_in));
	ASSERT_EQ(rc, sizeof (hdr_in));
	EXPECT_EQ(hdr_in.status, ZVOL_OP_STATUS_FAILED);
	ASSERT_EQ(hdr_in.len, 0);

	// try to create snap on degraded zvol
	hdr_out.io_seq = ++io_seq;
	hdr_out.len = snap_name.length() + 1;
	prep_snap(control_fd, snap_name, hdr_out.io_seq, ZVOL_OP_STATUS_OK);
	rc = write(control_fd, &hdr_out, sizeof (hdr_out));
	ASSERT_EQ(rc, sizeof (hdr_out));
	rc = write(control_fd, snap_name.c_str(), hdr_out.len);
	ASSERT_EQ(rc, hdr_out.len);
	rc = read(control_fd, &hdr_in, sizeof (hdr_in));
	ASSERT_EQ(rc, sizeof (hdr_in));
	EXPECT_EQ(hdr_in.status, ZVOL_OP_STATUS_FAILED);
	ASSERT_EQ(hdr_in.len, 0);

	// create the snapshot
	transition_zvol_to_online(ioseq, control_fd, vol_name);
	sleep(5);
	hdr_out.io_seq = ++io_seq;
	hdr_out.len = snap_name.length() + 1;
	prep_snap(control_fd, snap_name, hdr_out.io_seq, ZVOL_OP_STATUS_OK);
	rc = write(control_fd, &hdr_out, sizeof (hdr_out));
	ASSERT_EQ(rc, sizeof (hdr_out));
	rc = write(control_fd, snap_name.c_str(), hdr_out.len);
	ASSERT_EQ(rc, hdr_out.len);
	rc = read(control_fd, &hdr_in, sizeof (hdr_in));
	ASSERT_EQ(rc, sizeof (hdr_in));
	EXPECT_EQ(hdr_in.version, REPLICA_VERSION);
	EXPECT_EQ(hdr_in.opcode, ZVOL_OPCODE_SNAP_CREATE);
	EXPECT_EQ(hdr_in.status, ZVOL_OP_STATUS_OK);
	EXPECT_EQ(hdr_in.io_seq, io_seq);
	ASSERT_EQ(hdr_in.len, 0);

	ASSERT_NO_THROW(execCmd("zfs", std::string("list ") + snap_name));

	// create one more snapshot
	hdr_out.io_seq = ++io_seq;
	hdr_out.len = snap1_name.length() + 1;
	prep_snap(control_fd, snap_name, hdr_out.io_seq, ZVOL_OP_STATUS_OK);
	rc = write(control_fd, &hdr_out, sizeof (hdr_out));
	ASSERT_EQ(rc, sizeof (hdr_out));
	rc = write(control_fd, snap1_name.c_str(), hdr_out.len);
	ASSERT_EQ(rc, hdr_out.len);
	rc = read(control_fd, &hdr_in, sizeof (hdr_in));
	ASSERT_EQ(rc, sizeof (hdr_in));
	EXPECT_EQ(hdr_in.version, REPLICA_VERSION);
	EXPECT_EQ(hdr_in.opcode, ZVOL_OPCODE_SNAP_CREATE);
	EXPECT_EQ(hdr_in.status, ZVOL_OP_STATUS_OK);
	EXPECT_EQ(hdr_in.io_seq, io_seq);
	ASSERT_EQ(hdr_in.len, 0);
	ASSERT_NO_THROW(execCmd("zfs", std::string("list ") + snap1_name));

	// Try to fetch snapshot list
	hdr_out.io_seq = ++io_seq;
	hdr_out.len = vol_name.length() + 1;
	hdr_out.opcode = ZVOL_OPCODE_SNAP_LIST;
	rc = write(control_fd, &hdr_out, sizeof (hdr_out));
	ASSERT_EQ(rc, sizeof (hdr_out));
	rc = write(control_fd, vol_name.c_str(), hdr_out.len);
	ASSERT_EQ(rc, hdr_out.len);
	rc = read(control_fd, &hdr_in, sizeof (hdr_in));
	ASSERT_EQ(rc, sizeof (hdr_in));
	EXPECT_EQ(hdr_in.version, REPLICA_VERSION);
	EXPECT_EQ(hdr_in.opcode, ZVOL_OPCODE_SNAP_LIST);
	EXPECT_EQ(hdr_in.status, ZVOL_OP_STATUS_OK);
	EXPECT_EQ(hdr_in.io_seq, io_seq);
	ASSERT_GE(hdr_in.len, sizeof (struct zvol_snapshot_list));
	buf = (char *)malloc(hdr_in.len);
	rc = read(control_fd, buf, hdr_in.len);
	ASSERT_EQ(rc, hdr_in.len);
	snaplist = (struct zvol_snapshot_list *) buf;
	output = execCmd("zfs", std::string("get guid -Hpo value ") +
	    vol_name);
	EXPECT_EQ(snaplist->zvol_guid, std::stoul(output));
	verify_snapshot_details(vol_name, snaplist->data, "");

	verify_listsnap_details(vol_name);

	// Try to fetch snapshot list using snapshot name
	hdr_out.io_seq = ++io_seq;
	hdr_out.len = snap_name.length() + 1;
	hdr_out.opcode = ZVOL_OPCODE_SNAP_LIST;
	rc = write(control_fd, &hdr_out, sizeof (hdr_out));
	ASSERT_EQ(rc, sizeof (hdr_out));
	rc = write(control_fd, snap_name.c_str(), hdr_out.len);
	ASSERT_EQ(rc, hdr_out.len);
	rc = read(control_fd, &hdr_in, sizeof (hdr_in));
	ASSERT_EQ(rc, sizeof (hdr_in));
	EXPECT_EQ(hdr_in.version, REPLICA_VERSION);
	EXPECT_EQ(hdr_in.opcode, ZVOL_OPCODE_SNAP_LIST);
	EXPECT_EQ(hdr_in.status, ZVOL_OP_STATUS_OK);
	EXPECT_EQ(hdr_in.io_seq, io_seq);
	ASSERT_GE(hdr_in.len, sizeof (struct zvol_snapshot_list));
	buf = (char *)malloc(hdr_in.len);
	rc = read(control_fd, buf, hdr_in.len);
	ASSERT_EQ(rc, hdr_in.len);
	snaplist = (struct zvol_snapshot_list *) buf;
	output = execCmd("zfs", std::string("get guid -Hpo value ") +
	    vol_name);
	EXPECT_EQ(snaplist->zvol_guid, std::stoul(output));
	verify_snapshot_details(vol_name, snaplist->data, snap_name);
	verify_listsnap_details(vol_name);

	// destroy the snapshot
	hdr_out.opcode = ZVOL_OPCODE_SNAP_DESTROY;
	hdr_out.io_seq = ++io_seq;
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
	EXPECT_EQ(hdr_in.io_seq, io_seq);
	ASSERT_EQ(hdr_in.len, 0);
	verify_listsnap_details(vol_name);

	// Try to fetch snapshot list using wrong snapshot name
	hdr_out.io_seq = ++io_seq;
	hdr_out.len = strlen("vol@pqrst") + 1;
	hdr_out.opcode = ZVOL_OPCODE_SNAP_LIST;
	rc = write(control_fd, &hdr_out, sizeof (hdr_out));
	ASSERT_EQ(rc, sizeof (hdr_out));
	rc = write(control_fd, "vol@pqrst", hdr_out.len);
	ASSERT_EQ(rc, hdr_out.len);
	rc = read(control_fd, &hdr_in, sizeof (hdr_in));
	ASSERT_EQ(rc, sizeof (hdr_in));
	EXPECT_EQ(hdr_in.version, REPLICA_VERSION);
	EXPECT_EQ(hdr_in.opcode, ZVOL_OPCODE_SNAP_LIST);
	EXPECT_EQ(hdr_in.status, ZVOL_OP_STATUS_OK);
	EXPECT_EQ(hdr_in.io_seq, io_seq);
	ASSERT_GE(hdr_in.len, sizeof (struct zvol_snapshot_list));
	buf = (char *)malloc(hdr_in.len);
	rc = read(control_fd, buf, hdr_in.len);
	ASSERT_EQ(rc, hdr_in.len);
	snaplist = (struct zvol_snapshot_list *) buf;
	ASSERT_NE((strstr(snaplist->data, "pqrst"), NULL), 1);

	// try to create snap without snap prep
	hdr_out.io_seq = ++io_seq;
	hdr_out.len = snap_name.length() + 1;
	hdr_out.opcode = ZVOL_OPCODE_SNAP_CREATE;
	rc = write(control_fd, &hdr_out, sizeof (hdr_out));
	ASSERT_EQ(rc, sizeof (hdr_out));
	rc = write(control_fd, snap_name.c_str(), hdr_out.len);
	ASSERT_EQ(rc, hdr_out.len);
	rc = read(control_fd, &hdr_in, sizeof (hdr_in));
	ASSERT_EQ(rc, sizeof (hdr_in));
	EXPECT_EQ(hdr_in.status, ZVOL_OP_STATUS_OK);
	ASSERT_EQ(hdr_in.len, 0);
	verify_listsnap_details(vol_name);

	// destroy the snapshot
	hdr_out.opcode = ZVOL_OPCODE_SNAP_DESTROY;
	hdr_out.io_seq = ++io_seq;
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
	EXPECT_EQ(hdr_in.io_seq, io_seq);
	ASSERT_EQ(hdr_in.len, 0);
	verify_listsnap_details(vol_name);

	ASSERT_THROW(execCmd("zfs", std::string("list ") + snap_name),
	    std::runtime_error);

	datasock.graceful_close();
	graceful_close(control_fd);
	sleep(3);
}

TEST(Snapshot, ZVolReadOnly) {
	zvol_io_hdr_t hdr_in, hdr_out = {0};
	Zrepl zrepl;
	Target target;
	int rc, control_fd;
	SocketFd datasock;
	TestPool pool("snappool");
	char *buf;
	std::string vol_name = pool.getZvolName("vol");
	std::string snap_name = pool.getZvolName("vol@snap");
	uint64_t ioseq;
	std::string host;
	uint16_t port;
	struct zvol_snapshot_list *snaplist;
	std::string output;

	zrepl.start();
	pool.create();
	pool.createZvol("vol", "-o io.openebs:targetip=127.0.0.1 -o io.openebs:zvol_replica_id=12345");

	rc = target.listen();
	ASSERT_GE(rc, 0);
	control_fd = target.accept(-1);
	ASSERT_GE(control_fd, 0);

	do_handshake(vol_name, host, port, NULL, NULL, control_fd, ZVOL_OP_STATUS_OK);
	do_data_connection(datasock.fd(), host, port, vol_name, 4096, 2);

	// create the snapshot
	transition_zvol_to_online(ioseq, control_fd, vol_name);
	sleep(5);
	hdr_out.io_seq = 2;
	hdr_out.len = snap_name.length() + 1;

	// make zvol readonly
	execCmd("zfs", std::string("set io.openebs:readonly=on ") + vol_name);
	EXPECT_EQ(is_zvol_readonly(vol_name), true);
	// snap prepare should fail
	prep_snap(control_fd, snap_name, hdr_out.io_seq, ZVOL_OP_STATUS_FAILED);

	// disable zvol readonly
	execCmd("zfs", std::string("set io.openebs:readonly=off ") + vol_name);
	EXPECT_EQ(is_zvol_readonly(vol_name), false);
	// snap prepare should happen
	prep_snap(control_fd, snap_name, hdr_out.io_seq, ZVOL_OP_STATUS_OK);


	// set zvol readonly
	execCmd("zfs", std::string("set io.openebs:readonly=on ") + vol_name);
	EXPECT_EQ(is_zvol_readonly(vol_name), true);

	hdr_out.version = REPLICA_VERSION;
	hdr_out.opcode = ZVOL_OPCODE_SNAP_CREATE;
	hdr_out.status = ZVOL_OP_STATUS_OK;
	hdr_out.io_seq = 0;
	hdr_out.len = snap_name.length() + 1;
	rc = write(control_fd, &hdr_out, sizeof (hdr_out));
	ASSERT_EQ(rc, sizeof (hdr_out));
	rc = write(control_fd, snap_name.c_str(), hdr_out.len);
	ASSERT_EQ(rc, hdr_out.len);

	// snap create should fail
	rc = read(control_fd, &hdr_in, sizeof (hdr_in));
	ASSERT_EQ(rc, sizeof (hdr_in));
	EXPECT_EQ(hdr_in.version, REPLICA_VERSION);
	EXPECT_EQ(hdr_in.opcode, ZVOL_OPCODE_SNAP_CREATE);
	EXPECT_EQ(hdr_in.status, ZVOL_OP_STATUS_FAILED);
	EXPECT_EQ(hdr_in.io_seq, 0);
	ASSERT_EQ(hdr_in.len, 0);

	datasock.graceful_close();
	graceful_close(control_fd);
	sleep(3);
}

TEST(Snapshot, ZpoolReadOnly) {
	zvol_io_hdr_t hdr_in, hdr_out = {0};
	Zrepl zrepl;
	Target target;
	int rc, control_fd;
	SocketFd datasock;
	TestPool pool("snappool");
	char *buf;
	std::string vol_name = pool.getZvolName("vol");
	std::string snap_name = pool.getZvolName("vol@snap");
	uint64_t ioseq;
	std::string host;
	uint16_t port;
	struct zvol_snapshot_list *snaplist;
	std::string output;

	zrepl.start();
	pool.create();
	pool.createZvol("vol", "-o io.openebs:targetip=127.0.0.1 -o io.openebs:zvol_replica_id=12345");

	rc = target.listen();
	ASSERT_GE(rc, 0);
	control_fd = target.accept(-1);
	ASSERT_GE(control_fd, 0);

	do_handshake(vol_name, host, port, NULL, NULL, control_fd, ZVOL_OP_STATUS_OK);
	do_data_connection(datasock.fd(), host, port, vol_name, 4096, 2);

	// create the snapshot
	transition_zvol_to_online(ioseq, control_fd, vol_name);
	sleep(5);
	hdr_out.io_seq = 2;
	hdr_out.len = snap_name.length() + 1;

	// make zvol readonly
	execCmd("zpool", std::string("set io.openebs:readonly=on ") + pool.m_name);
	EXPECT_EQ(pool.isReadOnly(), true);
	// snap prepare should fail
	prep_snap(control_fd, snap_name, hdr_out.io_seq, ZVOL_OP_STATUS_FAILED);

	// disable zvol readonly
	execCmd("zpool", std::string("set io.openebs:readonly=off ") + pool.m_name);
	EXPECT_EQ(pool.isReadOnly(), false);
	// snap prepare should happen
	prep_snap(control_fd, snap_name, hdr_out.io_seq, ZVOL_OP_STATUS_OK);


	// set zvol readonly
	execCmd("zpool", std::string("set io.openebs:readonly=on ") + pool.m_name);
	EXPECT_EQ(pool.isReadOnly(), true);

	hdr_out.version = REPLICA_VERSION;
	hdr_out.opcode = ZVOL_OPCODE_SNAP_CREATE;
	hdr_out.status = ZVOL_OP_STATUS_OK;
	hdr_out.io_seq = 0;
	hdr_out.len = snap_name.length() + 1;
	rc = write(control_fd, &hdr_out, sizeof (hdr_out));
	ASSERT_EQ(rc, sizeof (hdr_out));
	rc = write(control_fd, snap_name.c_str(), hdr_out.len);
	ASSERT_EQ(rc, hdr_out.len);

	// snap create should fail
	rc = read(control_fd, &hdr_in, sizeof (hdr_in));
	ASSERT_EQ(rc, sizeof (hdr_in));
	EXPECT_EQ(hdr_in.version, REPLICA_VERSION);
	EXPECT_EQ(hdr_in.opcode, ZVOL_OPCODE_SNAP_CREATE);
	EXPECT_EQ(hdr_in.status, ZVOL_OP_STATUS_FAILED);
	EXPECT_EQ(hdr_in.io_seq, 0);
	ASSERT_EQ(hdr_in.len, 0);

	datasock.graceful_close();
	graceful_close(control_fd);
	sleep(3);
}



/*
 * resize the cloned volume when while making
 * the data conntection.
 */
TEST(ZvolResizeTest, DataConn) {
	SocketFd datasock;
	zvol_io_hdr_t hdr_in, hdr_out = {0};
	Zrepl zrepl;
	Target target;
	int rc, control_fd;
	std::string host;
	std::string str;
	uint64_t val1, val2, size;
	uint16_t port;
	TestPool pool("resizepool");
	std::string zvolname = pool.getZvolName("vol");

	zrepl.start();
	pool.create();
	pool.createZvol("vol", "-o io.openebs:targetip=127.0.0.1 -o io.openebs:zvol_replica_id=12345");

	// get the zvol size before
	str = execCmd("zfs", std::string("get -Hpo value volsize ") + zvolname);
	val1 = atoi(str.c_str());

	rc = target.listen();
	ASSERT_GE(rc, 0);
	control_fd = target.accept(-1);
	ASSERT_GE(control_fd, 0);
	do_handshake(zvolname, host, port, NULL, NULL, control_fd,
	    ZVOL_OP_STATUS_OK);

	// resize to lower size, it should not succeed
	size = val1 - 4096;
	do_data_connection(datasock.fd(), host, port, zvolname, 4096,
	    120, ZVOL_OP_STATUS_OK, 1, REPLICA_VERSION, size);
	str = execCmd("zfs", std::string("get -Hpo value volsize ") +
	    zvolname + "_rebuild_clone");
	val2 = atoi(str.c_str());
	EXPECT_EQ(val2, val1);
	datasock.graceful_close();

	// resize to zero size, it should not succeed
	size = 0;
	do_data_connection(datasock.fd(), host, port, zvolname, 4096,
	    120, ZVOL_OP_STATUS_OK, 1, REPLICA_VERSION, size);
	str = execCmd("zfs", std::string("get -Hpo value volsize ") +
	    zvolname + "_rebuild_clone");
	val2 = atoi(str.c_str());
	EXPECT_EQ(val2, val1);
	datasock.graceful_close();

	// resize to higher size, it should succeed
	size = val1 + 4096;
	do_data_connection(datasock.fd(), host, port, zvolname, 4096,
	    120, ZVOL_OP_STATUS_OK, 1, REPLICA_VERSION, size);
	str = execCmd("zfs", std::string("get -Hpo value volsize ") +
	    zvolname + "_rebuild_clone");
	val2 = atoi(str.c_str());
	EXPECT_EQ(val2, size);
	datasock.graceful_close();

	graceful_close(control_fd);
}

static
void execute_resize_opcode(uint64_t size, std::string zvolname, int control_fd, int status) {
	zvol_io_hdr_t hdr_in, hdr_out = {0};
	zvol_op_resize_data_t resize_data;
	int rc;

	hdr_out.version = REPLICA_VERSION;
	hdr_out.opcode = ZVOL_OPCODE_RESIZE;
	hdr_out.len = sizeof (resize_data);
	rc = write(control_fd, &hdr_out, sizeof (hdr_out));
	ASSERT_EQ(rc, sizeof (hdr_out));
	GtestUtils::strlcpy(resize_data.volname, zvolname.c_str(),
	    sizeof (resize_data.volname));
	resize_data.size = size;
	rc = write(control_fd, &resize_data, sizeof (resize_data));
	ASSERT_EQ(rc, sizeof (resize_data));

	// Read resize response
	rc = read(control_fd, &hdr_in, sizeof (hdr_in));
	ASSERT_EQ(rc, sizeof (hdr_in));
	EXPECT_EQ(hdr_in.opcode, ZVOL_OPCODE_RESIZE);
	EXPECT_EQ(hdr_in.status, status);
	ASSERT_EQ(hdr_in.len, 0);
}

/*
 * Test zvol resize when it is healthy
 */
TEST(ZvolResizeTest, ResizeHealthyZvol) {
	SocketFd datasock;
	zvol_io_hdr_t hdr_in, hdr_out = {0};
	Zrepl zrepl;
	Target target;
	int rc, control_fd;
	std::string host;
	std::string str;
	uint64_t old_size, new_size, main_zv_size, ioseq;
	uint16_t port;
	TestPool pool("resizepool");
	std::string zvolname = pool.getZvolName("healthyvol");

	zrepl.start();
	pool.create();
	pool.createZvol("healthyvol", "-o quorum=on -o io.openebs:targetip=127.0.0.1 -o io.openebs:zvol_replica_id=12345");

	// get the zvol size before
	str = execCmd("zfs", std::string("get -Hpo value volsize ") + zvolname);
	old_size = atoi(str.c_str());

	rc = target.listen();
	ASSERT_GE(rc, 0);
	control_fd = target.accept(-1);
	ASSERT_GE(control_fd, 0);
	do_handshake(zvolname, host, port, NULL, NULL, control_fd,
	    ZVOL_OP_STATUS_OK);

	// Making data connection with replication factor as 1
	do_data_connection(datasock.fd(), host, port, zvolname, 4096,
	    120, ZVOL_OP_STATUS_OK, 1, REPLICA_VERSION, old_size);

	// send resize opcode with lower size
	new_size = 0;
	execute_resize_opcode(new_size, zvolname, control_fd, ZVOL_OP_STATUS_FAILED);
	// get the main zvol size
	str = execCmd("zfs", std::string("get -Hpo value volsize ") +
			zvolname);
	main_zv_size = atoi(str.c_str());
	EXPECT_EQ(old_size, main_zv_size);

	// send resize opcode with invalid block size
	new_size = old_size + 4095;
	execute_resize_opcode(new_size, zvolname, control_fd, ZVOL_OP_STATUS_FAILED);
	// get the main zvol size
	str = execCmd("zfs", std::string("get -Hpo value volsize ") +
			zvolname);
	main_zv_size = atoi(str.c_str());
	EXPECT_EQ(old_size, main_zv_size);

	// double the zvol size
	new_size = old_size << 1;
	execute_resize_opcode(new_size, zvolname, control_fd, ZVOL_OP_STATUS_OK);
	// get the main zvol size
	str = execCmd("zfs", std::string("get -Hpo value volsize ") +
			zvolname);
	main_zv_size = atoi(str.c_str());
	EXPECT_EQ(new_size, main_zv_size);

	graceful_close(control_fd);
}

/*
 * Test zvol resize when it is degraded
 */
TEST(ZvolResizeTest, ResizeDegradedZvol) {
	SocketFd datasock;
	Zrepl zrepl;
	Target target;
	int rc, control_fd;
	std::string host;
	std::string str;
	uint64_t old_size, new_size, clone_zv_size, main_zv_size, ioseq;
	uint16_t port;
	zvol_op_resize_data_t resize_data;
	TestPool pool("resizepool");
	std::string zvolname = pool.getZvolName("vol");
	//struct zrepl_status_ack status;

	zrepl.start();
	pool.create();

	pool.createZvol("vol", "-o quorum=on -o io.openebs:targetip=127.0.0.1 -o io.openebs:zvol_replica_id=12345");

	// get the zvol size before
	str = execCmd("zfs", std::string("get -Hpo value volsize ") + zvolname);
	old_size = atoi(str.c_str());

	rc = target.listen();
	ASSERT_GE(rc, 0);
	control_fd = target.accept(-1);
	ASSERT_GE(control_fd, 0);
	do_handshake(zvolname, host, port, NULL, NULL, control_fd,
	    ZVOL_OP_STATUS_OK);

	//TODO: Negative scenarios need to cover
	// Making data connection because if replica is in degraded state
	// then we are resizing clone volume
	do_data_connection(datasock.fd(), host, port, zvolname, 4096,
	    120, ZVOL_OP_STATUS_OK, 3, REPLICA_VERSION, old_size);

	// double the zvol size
	new_size = old_size << 1;
	execute_resize_opcode(new_size, zvolname, control_fd, ZVOL_OP_STATUS_OK);
	// get the clone zvol size after triggering resize
	str = execCmd("zfs", std::string("get -Hpo value volsize ") +
			zvolname + "_rebuild_clone");
	clone_zv_size = atoi(str.c_str());
	EXPECT_EQ(new_size, clone_zv_size);

	// get the main zvol size after triggering resize in degrade mode
	str = execCmd("zfs", std::string("get -Hpo value volsize ") +
			zvolname);
	main_zv_size = atoi(str.c_str());
	EXPECT_EQ(old_size, main_zv_size);

	wait_for_zvol_status(zvolname, ioseq, control_fd, ZVOL_STATUS_DEGRADED, ZVOL_REBUILDING_INIT);
	transition_zvol_to_online(ioseq, control_fd, zvolname);
	// waiting for volume to be healthy
	wait_for_zvol_status(zvolname, ioseq, control_fd, ZVOL_STATUS_HEALTHY, ZVOL_REBUILDING_DONE, REPLICA_VERSION, 5);

	// get the main zvol size after it become healthy
	str = execCmd("zfs", std::string("get -Hpo value volsize ") +
			zvolname);
	main_zv_size = atoi(str.c_str());
	EXPECT_EQ(new_size, main_zv_size);

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
	pool.createZvol("vol", "-o io.openebs:targetip=127.0.0.1 -o io.openebs:zvol_replica_id=12345");
	execCmd("zfs", std::string("snapshot " + snapname));

	// clone the zvol
	execCmd("zfs", std::string("clone -o "
	    "io.openebs:targetip=127.0.0.1:6060 " +
	    snapname + " " + clonename));

	rc = target.listen(6060);
	ASSERT_GE(rc, 0);
	control_fd = target.accept(-1);
	ASSERT_GE(control_fd, 0);
	do_handshake(zvolname, host, port, NULL, NULL, control_fd,
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
get_used(int control_fd, std::string zvolname, uint64_t *val, int version = REPLICA_VERSION)
{
	zvol_io_hdr_t hdr_in, hdr_out = {0};
	zvol_op_stat_t stat;
	int rc;

	hdr_out.version = version;
	hdr_out.opcode = ZVOL_OPCODE_STATS;
	hdr_out.status = ZVOL_OP_STATUS_OK;
	hdr_out.io_seq = 1;
	hdr_out.len = zvolname.length() + 1;
	rc = write(control_fd, &hdr_out, sizeof (hdr_out));
	ASSERT_EQ(rc, sizeof (hdr_out));
	rc = write(control_fd, zvolname.c_str(), hdr_out.len);
	ASSERT_EQ(rc, hdr_out.len);

	rc = read(control_fd, &hdr_in, sizeof (hdr_in));
	ASSERT_EQ(rc, sizeof (hdr_in));
	EXPECT_EQ(hdr_in.version, hdr_out.version);
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
	int rc, control_fd;
	SocketFd datasock;
	uint64_t ioseq = 0;
	std::string host;
	uint16_t port;
	uint64_t val1, val2;
	TestPool pool("statspool");
	std::string zvolname = pool.getZvolName("vol");
	char buf[4096];

	zrepl.start();
	pool.create();
	pool.createZvol("vol", "-o io.openebs:targetip=127.0.0.1 -o io.openebs:zvol_replica_id=12345");

	rc = target.listen();
	ASSERT_GE(rc, 0);
	control_fd = target.accept(-1);
	ASSERT_GE(control_fd, 0);
	do_handshake(zvolname, host, port, NULL, NULL, control_fd,
	    ZVOL_OP_STATUS_OK);

	// get "used" before
	get_used(control_fd, zvolname, &val1, MIN_SUPPORTED_REPLICA_VERSION);
	init_buf(buf, sizeof (buf), "cStor-data");
	do_data_connection(datasock.fd(), host, port, zvolname, 4096);
	for (int i = 0; i < 100; i++) {
		write_data_and_verify_resp(datasock.fd(), ioseq, buf, 4096 * i, sizeof (buf), i + 1);
	}
	datasock.graceful_close();
	sleep(5);

	// get "used" after
	get_used(control_fd, zvolname, &val2);
	EXPECT_LE(val1, val2);
	graceful_close(control_fd);
}
