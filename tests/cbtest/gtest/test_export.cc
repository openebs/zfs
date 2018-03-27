#include <iostream>
#include <libuzfs.h>
#include <libzfs.h>
#include <uzfs_mgmt.h>
#include <zrepl_mgmt.h>
#include <uzfs_io.h>
#include <uzfs.h>
#include <system_error>
#include <sys/spa.h>
#include <gtest/gtest.h>
#include <gtest_utils.h>

#define DISK "/tmp/zrepl_test_disk.img"
#define POOL_NAME "test_export"

using namespace GtestUtils;

int
create_file(void)
{
       int fd;

       if ((fd = open(DISK, O_RDWR | O_CREAT | O_TRUNC, 0666)) < 0)
               throw std::runtime_error("cant create disk image");

       if (ftruncate(fd, 100 * 1024 * 1024) != 0)
               throw std::runtime_error("cant truncate disk image");
       close(fd);
       return (0);
}

class CreatePool : public testing::Test {
public:

	spa_t *spa;
	CreatePool() : zi(NULL), zv(NULL), spa(NULL) {}

	virtual void SetUp() override {
		uzfs_init();
		libuzfs_ioctl_init();
	}


	void createPool() {
		/*  destroy the pool if its auto loaded from cache */
		spa_destroy(pool_name);

		ASSERT_TRUE(uzfs_pool_create(pool_name, DISK, &spa ) == 0);

		/*  implicitly open the pool  */
		spaOpen();
	}

	void importPool() {

		char *spath[1];
		nvlist_t *config = NULL;
		nvlist_t *props = NULL;
		importargs_t args = {0};

		/*
		 * we need to tell the import logic
		 * where to find our truncated file
		 * that it should use for import
		 */

		args.path = spath;
		args.path[0] = "/tmp";
		args.paths = 1;

		args.scan = B_TRUE;
		args.cachefile = NULL;

		gzfs = libzfs_init();

		ASSERT_TRUE(gzfs != NULL);

		error = zpool_tryimport(gzfs, pool_name, &config, &args);
		ASSERT_TRUE(error == 0);

		error = spa_import(pool_name, config, props, ZFS_IMPORT_NORMAL);
		ASSERT_TRUE(error == 0);

		spaOpen();

		libzfs_fini(gzfs);

	}

	void zinfoLookupByName() {

		std::string zv_name(pool_name);
		zv_name.append("/vol2");
		zi = NULL;

		zi = uzfs_zinfo_lookup(zv_name.c_str());
		ASSERT_FALSE(zi == NULL);
		zi->refcnt--;
		ASSERT_EQ(zi->refcnt, 1);

	}

	void createDataset() {
		 execCmd("zfs", std::string("create -V 10m -s ") + POOL_NAME + "/vol1");
	}

	void getZVolInfo() {
		/*  this bumps refcount  */
		std::string zv_name = std::string(POOL_NAME) + "/vol1";
		zi = uzfs_zinfo_lookup(zv_name.c_str());
		ASSERT_FALSE(zi == NULL);
		ASSERT_EQ(strcmp(zi->name, zv_name.c_str()), 0);
		zi->refcnt--;
		ASSERT_EQ(zi->refcnt, 1);

	}

	void writeSome() {

		 char *buf = (char* ) malloc(4096);
		 memset(buf, 'j', 4096);
		 ASSERT_EQ(uzfs_write_data(zi->zv, buf, 0, 4096, NULL, B_FALSE), 0);
		 free(buf);
	}

	void readSome() {
		char *buf = (char* ) malloc(4096);
		memset(buf, 'a', 4096);
		ASSERT_EQ(uzfs_read_data(zi->zv, buf, 0, 4096, NULL), 0);
		for (int i = 0; i < 4096; i++ )
			ASSERT_EQ(buf[i], 'j');
		free(buf);

	}

	void exportPool() {
		spaClose();
		ASSERT_EQ(spa_export(pool_name, NULL, B_TRUE, B_FALSE), 0);
	}


	void finish() {
		uzfs_fini();
	}

	void destroyPool() {
		spaClose();
		ASSERT_EQ(spa_destroy(POOL_NAME), 0);

	}

	void destroyCLI() {
		execCmd("zpool", std::string("destroy ") + POOL_NAME);
	}


	void exportCLI() {
		execCmd("zpool", std::string("export ") + POOL_NAME);
	}

	void spaOpen() {
		spa_open(POOL_NAME, &spa, (void*)"GTEST");
	}

	void spaClose() {
		spa_close(spa,(void*)"GTEST");
	}


private:
	int error;
	zvol_info_t *zi;
	zvol_state_t *zv;
	char *pool_name = POOL_NAME;
	libzfs_handle_t *gzfs;

};

TEST_F(CreatePool, exportTest) {
	create_file();
	createPool();
	createDataset();

	//fixme
	getZVolInfo();
	writeSome();

	readSome();
	exportPool();
	finish();
}

TEST_F(CreatePool, importTest) {
	importPool();
	execCmd("zfs", std::string("create -V 10m -s ") + POOL_NAME + "/vol2");
	zinfoLookupByName();
	exportPool();
	finish();
}

TEST_F(CreatePool, DestroyTest) {
	importPool();
	destroyPool();
	finish();
}

TEST_F(CreatePool, DestroyTestCLI) {
	importPool();
	spaClose();
	execCmd("zpool", std::string("destroy ") + POOL_NAME);
	finish();
}

TEST_F(CreatePool, recreatePoolDestroy) {
	create_file();
	createPool();
	for (int i = 0; i < 5; i++) {
		std::stringstream ss;
		ss << "create -V 10m -s " << POOL_NAME << "/vol" <<  i;
		execCmd("zfs", ss.str());
	}


	for (int i = 0; i < 5; i++) {
		std::stringstream ss;
		ss << "destroy " << POOL_NAME << "/vol" <<  i;
		execCmd("zfs", ss.str());
	}

	spaClose();
	destroyCLI();
	finish();
}

TEST_F(CreatePool, recreatePoolExport) {
	create_file();
	createPool();
	for (int i = 0; i < 5; i++) {
		std::stringstream ss;
		ss << "create -V 10m -s " << POOL_NAME << "/vol" <<  i;
		execCmd("zfs", ss.str());
	}


	for (int i = 0; i < 5; i++) {
		std::stringstream ss;
		ss << "destroy " << POOL_NAME << "/vol" <<  i;
		execCmd("zfs", ss.str());
	}
	spaClose();
	exportCLI();
	finish();
}
TEST_F(CreatePool, ExportAllCLI) {
	create_file();
	/*  make sure there is no pool */
	spa_destroy(POOL_NAME);
	std::stringstream ss;

	ss << "create " << POOL_NAME << " "<< DISK;
	execCmd("zpool", ss.str());
	for (int i = 0; i < 5; i++) {
		std::stringstream ss;
		ss << "create -V 10m -s " << POOL_NAME << "/vol" <<  i;
		execCmd("zfs", ss.str());
	}


	for (int i = 0; i < 5; i++) {
		std::stringstream ss;
		ss << "destroy " << POOL_NAME << "/vol" <<  i;
		execCmd("zfs", ss.str());
	}

	/*
	 *	this tests if we shut down properly and release
	 *	all zinfo_t's in the exort/destroy path
	 */

	for (int i = 0; i < 5; i++) {
		std::stringstream ss;
		ss << "create -V 10m -s " << POOL_NAME << "/vol" <<  i;
		execCmd("zfs", ss.str());
	}

	exportCLI();
	finish();
}

TEST_F(CreatePool, DestroyLeaveAllAllCLI) {
	create_file();
	/*  make sure there is no pool */
	spa_destroy(POOL_NAME);
	std::stringstream ss;

	ss << "create " << POOL_NAME << " "<< DISK;
	execCmd("zpool", ss.str());
	for (int i = 0; i < 5; i++) {
		std::stringstream ss;
		ss << "create -V 10m -s " << POOL_NAME << "/vol" <<  i;
		execCmd("zfs", ss.str());
	}

	destroyCLI();
	finish();
}

TEST_F(CreatePool, DestroyLeaveOneAllCLI) {
	create_file();
	/*  make sure there is no pool */
	spa_destroy(POOL_NAME);
	std::stringstream ss;

	ss << "create " << POOL_NAME << " "<< DISK;
	execCmd("zpool", ss.str());
	for (int i = 0; i < 5; i++) {
		std::stringstream ss;
		ss << "create -V 10m -s " << POOL_NAME << "/vol" <<  i;
		execCmd("zfs", ss.str());
	}

	for (int i = 2; i < 5; i++) {
		std::stringstream ss;
		ss << "destroy " << POOL_NAME << "/vol" <<  i;
		execCmd("zfs", ss.str());
	}

	destroyCLI();
	finish();
}
