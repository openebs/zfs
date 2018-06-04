
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
		// try {
			execCmd("zpool", std::string("destroy -f ") + m_name);
		// } catch (std::runtime_error re) {
			// ;
		// }
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

}

#endif	// _UZFS_UTILS_H
