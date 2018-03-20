
#include <gtest/gtest.h>
#include <unistd.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/tcp.h>
#include <netinet/in.h>

#include <zrepl_prot.h>

/* Avoid including conflicting C++ declarations for LE-BE conversions */
#define _SYS_BYTEORDER_H
#include <libuzfs.h>

TEST(uZFSServer, Setup) {
	kernel_init(FREAD);
	EXPECT_GT(kthread_nr, 0);
}

TEST(uZFSServer, ClientConnectNoServer) {
	EXPECT_NE(0, libuzfs_client_init(NULL));
}

TEST(uZFSServer, InitServer) {
	EXPECT_EQ(0, libuzfs_ioctl_init());
}

TEST(uZFSServer, ClientConnectServer) {
	EXPECT_EQ(0, libuzfs_client_init(NULL));
}

std::string getCmdPath(std::string zfsCmd) {
	std::string cmdPath;
	const char *srcPath = std::getenv("SRC_PATH");

	if (srcPath == NULL) {
		cmdPath += ".";
	} else {
		cmdPath = srcPath;
	}
	cmdPath += "/cmd/" + zfsCmd + "/" + zfsCmd;

	return cmdPath;
}

void execCmd(std::string zfsCmd, std::string args) {
	int rc;
	std::string cmdLine;

	cmdLine = getCmdPath(zfsCmd) + " " + args;
	rc = system(cmdLine.c_str());
	if (rc != 0) {
		throw std::runtime_error(
		    std::string("Command failed: ") + cmdLine);
	}
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
		execCmd("zfs", std::string("create -V 10m -s ") + name);
	}

	std::string name;
private:
	std::string pool;
	std::string path;
};

class ZreplTest : public testing::Test {
protected:
	ZreplTest() {
		m_pid = 0;
		m_fd = -1;
		m_listenfd = -1;
	}

	~ZreplTest() {
		if (m_listenfd >= 0)
			close(m_listenfd);
		if (m_fd >= 0)
			close(m_fd);
	}

	virtual void SetUp () override {
		std::string zrepl_path = getCmdPath("zrepl");

		m_pid = fork();
		if (m_pid == 0)
			execl(zrepl_path.c_str(), zrepl_path.c_str(),
			    "127.0.0.1", NULL);
	}

	virtual void TearDown() override {
		if (m_pid != 0)
			kill(m_pid, SIGTERM);
	}

	void connect(void) {
		struct sockaddr_in addr;
		int opt = 1;
		int rc;

		m_listenfd = socket(AF_INET, SOCK_STREAM, 0);
		ASSERT_TRUE(m_listenfd >= 0);
		setsockopt(m_listenfd, SOL_SOCKET, SO_REUSEADDR, (void *) &opt,
		    sizeof (opt));
		memset(&addr, 0, sizeof (addr));
		addr.sin_family = AF_INET;
		addr.sin_addr.s_addr = htonl(INADDR_ANY);
		addr.sin_port = htons(TARGET_PORT);
		rc = bind(m_listenfd, (struct sockaddr *) &addr, sizeof (addr));
		ASSERT_TRUE(rc >= 0);
		rc = listen(m_listenfd, 1);
		ASSERT_TRUE(rc >= 0);
		m_fd = accept(m_listenfd, NULL, NULL);
		ASSERT_TRUE(m_fd >= 0);
	}

	pid_t	m_pid;
	int	m_listenfd;
	int	m_fd;
};

TEST_F(ZreplTest, HandshakeOk) {
	zvol_io_hdr_t hdr_out, hdr_in;
	int rc;
	mgmt_ack_t mgmt_ack;
	TestZvol zvol("handshake");

	connect();
	zvol.create();

	hdr_out.version = REPLICA_VERSION;
	hdr_out.opcode = ZVOL_OPCODE_HANDSHAKE;
	hdr_out.status = ZVOL_OP_STATUS_OK;
	hdr_out.io_seq = 0;
	hdr_out.offset = 0;
	hdr_out.len = zvol.name.length() + 1;

	rc = write(m_fd, &hdr_out, sizeof (hdr_out));
	ASSERT_EQ(rc, sizeof (hdr_out));
	rc = write(m_fd, zvol.name.c_str(), hdr_out.len);
	ASSERT_EQ(rc, hdr_out.len);

	rc = read(m_fd, &hdr_in, sizeof (hdr_in));
	ASSERT_EQ(rc, sizeof (hdr_in));
	EXPECT_EQ(hdr_in.version, REPLICA_VERSION);
	EXPECT_EQ(hdr_in.opcode, ZVOL_OPCODE_HANDSHAKE);
	EXPECT_EQ(hdr_in.status, ZVOL_OP_STATUS_OK);
	EXPECT_EQ(hdr_in.io_seq, 0);
	EXPECT_EQ(hdr_in.offset, 0);
	ASSERT_EQ(hdr_in.len, sizeof (mgmt_ack));
	rc = read(m_fd, &mgmt_ack, sizeof (mgmt_ack));
	ASSERT_EQ(rc, sizeof (mgmt_ack));
	EXPECT_STREQ(mgmt_ack.volname, zvol.name.c_str());
}

TEST_F(ZreplTest, HandshakeWrongVersion) {
	zvol_io_hdr_t hdr_out, hdr_in;
	int rc;
	char *msg;
	mgmt_ack_t mgmt_ack;
	TestZvol zvol("handshake");

	connect();

	hdr_out.version = REPLICA_VERSION + 1;
	hdr_out.opcode = ZVOL_OPCODE_HANDSHAKE;
	hdr_out.status = ZVOL_OP_STATUS_OK;
	hdr_out.io_seq = 0;
	hdr_out.offset = 0;
	hdr_out.len = zvol.name.length() + 1;

	/*
	 * It must be set in one chunk so that server does not close the
	 * connection after sending header but before sending zvol name.
	 */
	msg = (char *)malloc(sizeof (hdr_out) + hdr_out.len);
	memcpy(msg, &hdr_out, sizeof (hdr_out));
	memcpy(msg + sizeof (hdr_out), zvol.name.c_str(), hdr_out.len);
	rc = write(m_fd, msg, sizeof (hdr_out) + hdr_out.len);
	ASSERT_EQ(rc, sizeof (hdr_out) + hdr_out.len);
	free(msg);

	rc = read(m_fd, &hdr_in, sizeof (hdr_in));
	ASSERT_EQ(rc, sizeof (hdr_in));
	EXPECT_EQ(hdr_in.version, REPLICA_VERSION);
	EXPECT_EQ(hdr_in.opcode, ZVOL_OPCODE_HANDSHAKE);
	EXPECT_EQ(hdr_in.status, ZVOL_OP_STATUS_VERSION_MISMATCH);
	EXPECT_EQ(hdr_in.io_seq, 0);
	EXPECT_EQ(hdr_in.offset, 0);
	ASSERT_EQ(hdr_in.len, 0);
}

TEST_F(ZreplTest, HandshakeUnknownZvol) {
	zvol_io_hdr_t hdr_out, hdr_in;
	int rc;
	const char *volname = "handshake/vol";
	mgmt_ack_t mgmt_ack;

	connect();

	hdr_out.version = REPLICA_VERSION;
	hdr_out.opcode = ZVOL_OPCODE_HANDSHAKE;
	hdr_out.status = ZVOL_OP_STATUS_OK;
	hdr_out.io_seq = 0;
	hdr_out.offset = 0;
	hdr_out.len = strlen(volname) + 1;

	rc = write(m_fd, &hdr_out, sizeof (hdr_out));
	ASSERT_EQ(rc, sizeof (hdr_out));
	rc = write(m_fd, volname, hdr_out.len);
	ASSERT_EQ(rc, hdr_out.len);

	rc = read(m_fd, &hdr_in, sizeof (hdr_in));
	ASSERT_EQ(rc, sizeof (hdr_in));
	EXPECT_EQ(hdr_in.version, REPLICA_VERSION);
	EXPECT_EQ(hdr_in.opcode, ZVOL_OPCODE_HANDSHAKE);
	EXPECT_EQ(hdr_in.status, ZVOL_OP_STATUS_FAILED);
	EXPECT_EQ(hdr_in.io_seq, 0);
	EXPECT_EQ(hdr_in.offset, 0);
	ASSERT_EQ(hdr_in.len, 0);
}
