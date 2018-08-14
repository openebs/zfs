
#ifndef _UZFS_UTILS_H
#define	_UZFS_UTILS_H

#include <gtest/gtest.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <arpa/inet.h>

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
size_t strlcpy(char *dst, const char *src, size_t len);

/*
 * Class which creates a vdev file in /tmp which can be used for pool creation.
 * The file is automatically removed when vdev goes out of scope.
 */
class Vdev {
public:
	Vdev(std::string name) {
		m_path = std::string("/tmp/") + name;
	}

	~Vdev() {
		unlink(m_path.c_str());
	}

	void create();

	std::string m_path;
};

/*
 * Class simplifying test zfs pool creation and creation of zvols on it.
 * Automatic pool destruction takes place when object goes out of scope.
 */
class TestPool {
public:
	TestPool(std::string poolname) {
		m_name = poolname;
		m_vdev = new Vdev(std::string("disk-for-") + poolname);
	}

	~TestPool() {
		// C++ destructor must not throw
		try {
			execCmd("zpool", std::string("destroy -f ") + m_name);
		} catch(std::runtime_error re) {
			;
		}
		delete m_vdev;
	}

	void create();
	void import();
	void createZvol(std::string name, std::string arg = "");
	void destroyZvol(std::string name);
	std::string getZvolName(std::string name);

	Vdev *m_vdev;
	std::string m_name;
};

/*
 * zrepl program wrapper.
 *
 * The main benefits are:
 *  1) when zrepl goes out of C++ scope it is automatically terminated,
 *  2) special care is taken when starting and stopping the process to
 *      make sure it is fully operation respectively fully terminated
 *      to avoid various races.
 */
class Zrepl {
public:
	Zrepl() {
		m_pid = 0;
	}

	~Zrepl() {
		kill();
	}

	void start();
	void kill();
	pid_t m_pid;
};

/*
 * File descriptor wrapper which automatically closes the FD when object
 * is destroyed (goes out of scope). This is particularly useful when failed
 * gtest assertion causes premature return from function and without wrapping
 * the FD, it would leak the resource.
 *
 * Note: this is a simplified version which does not support sharing (ref
 * counting) of underlaying FD. Works only for simple cases.
 */
class SocketFd {
public:
	SocketFd() {
		m_fd = socket(AF_INET, SOCK_STREAM, 0);
		if (m_fd < 0) {
			throw std::runtime_error("Failed to create socket");
		}
	}
	~SocketFd() {
		if (m_fd >= 0) {
			close(m_fd);
			m_fd = -1;
		}
	}
	int &fd();
	SocketFd& operator=(int other);
	void graceful_close();
	bool opened();

private:
	int m_fd;
};

}

#endif	// _UZFS_UTILS_H
