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
#include <sys/zfs_context.h>
#include <sys/zfs_rlock.h>
#include <uzfs_mgmt.h>
#include <uzfs_io.h>
#include <uzfs_test.h>
#include <math.h>
#include <zrepl_mgmt.h>
#include <libzfs.h>

int total_time_in_sec = 60;
int log_device = 0;
int sync_data = 0;
int test_iterations = 1;
uint64_t io_block_size = 1024;
uint64_t block_size = 4096;
uint64_t active_size = 0;
uint64_t vol_size = 0;
int run_test = 0;
uint32_t uzfs_test_id = 0;
uint32_t create = 0;
char *pool = "testp";
char *ds = "ds0";
char *pool_dir = "/tmp/";
int max_iops = 0;
zfs_rlock_t zrl;
char *data;
uint64_t *iodata;
uint64_t g_io_num = 10;

void uzfs_test_get_metablk_details(void *arg);
uzfs_test_info_t uzfs_tests[] = {
	{ uzfs_zvol_zap_operation, "uzfs zap operation test" },
	{ replay_fn, "zvol replay test" },
	{ unit_test_fn, "zvol read/write verification test"},
	{ uzfs_rebuild_test, "uzfs rebuild pool test"},
	{ zrepl_utest, "ZFS replication test" },
	{ uzfs_test_get_metablk_details, "Tests offset,len calculations of"\
	    " metadata for given data block" },
	{ unit_test_fn, "zvol random read/write verification with metadata" },
	{ zrepl_rebuild_test, "ZFS rebuild test" },
	{ unmap_test_fn, "ZFS read/write/unmap test" },
};

uint64_t metaverify = 0;
int verify = 0;
int write_op = 0;
int silent = 0;
int verify_err = 0;

void reader_thread(void *zv);

void
verify_data(char *buf, uint64_t offset, int idx, uint64_t block_size)
{
	int i;
	int err = 0;
	if ((buf[0] != ((offset / 256) % 128)) && (buf[0] != 0)) {
		printf("error0 in data..\n");
		err = 1;
	}

	for (i = 0; i < idx; i++) {
		if ((buf[((i + 1) * block_size) - 1] !=
		    (((offset + (i * block_size)) / 4096) % 128)) &&
		    (buf[((i + 1) * block_size) - 1] != 0)) {
			printf("error0 %d in data..\n", i);
			err = 1;
		}
		if ((buf[((i + 1) * block_size)] !=
		    (((offset + ((i + 1) * block_size)) / 256) % 128)) &&
		    (buf[((i + 1) * block_size)] != 0)) {
			printf("error1 %d in data..\n", i);
			err = 1;
		}
	}
	if ((buf[((i + 1) * block_size) - 1] !=
	    (((offset + (i * block_size)) / 4096) % 128)) &&
	    (buf[((i + 1) * block_size) - 1] != 0)) {
		printf("error1 %lu %d in data..\n", offset+i*block_size,
		    buf[((i+1)*block_size)-1]);
		err = 1;
	}
	if (err == 1)
		exit(1);
}

/*
 * Verifies data/metadata read from vol with in-memory copy
 * block_size is size at which IOs are done
 * vol_size is active dataset size
 */
void
verify_vol_data(void *zv, uint64_t block_size, uint64_t vol_size)
{
	uint64_t len, i, j;
	char *buf;
	metadata_desc_t *md, *md_tmp;

	buf = kmem_alloc(block_size, KM_SLEEP);
	len = block_size;
	for (i = 0; i < vol_size; i += len) {
		len = block_size;
		if (len > (vol_size - i))
			len = vol_size - i;
		if (iodata[i/block_size] == 0)
			continue;
		memset(buf, 0, block_size);
		uzfs_read_data(zv, buf, i, len, &md, NULL, NULL);
		for (j = 0; j < len; j++)
			if (data[i+j] != buf[j]) {
				printf("verify error at %lu\n", (i+j));
				exit(1);
			}
		for (md_tmp = md; md_tmp != NULL; md_tmp = md_tmp->next)
			if (iodata[i/block_size] != md_tmp->metadata.io_num) {
				printf("verify merror at %lu %lu %lu\n",
				    i/block_size, md_tmp->metadata.io_num,
				    iodata[i/block_size]);
				exit(1);
			}
		FREE_METADATA_LIST(md);
	}
	printf("Data/metadata verification passed.\n");
}

void
reader_thread(void *arg)
{
	worker_args_t *warg = (worker_args_t *)arg;
	char *buf[15];
	int idx, j, err;
	uint64_t blk_offset, offset, vol_blocks, ios = 0, data_ios = 0;
	hrtime_t end, now;
	void *zv = warg->zv;
	kmutex_t *mtx = warg->mtx;
	kcondvar_t *cv = warg->cv;
	int *threads_done = warg->threads_done;
	uint64_t *total_ios = warg->total_ios;
	uint64_t vol_size = warg->active_size;
	uint64_t block_size = warg->io_block_size;
	int read_error, md_error;
	metadata_desc_t *md;

	for (j = 0; j < 15; j++)
		buf[j] = (char *)umem_alloc(sizeof (char)*(j+1)* block_size,
		    UMEM_NOFAIL);

	now = gethrtime();
	end = now + (hrtime_t)(total_time_in_sec * (hrtime_t)(NANOSEC));

	vol_blocks = (vol_size) / block_size;

	if (silent == 0)
		printf("Starting read..\n");

	while (1) {
		blk_offset = uzfs_random(vol_blocks - 16);
		offset = blk_offset * block_size;

		idx = uzfs_random(15);
		memset(buf[idx], 0, (idx + 1) * block_size);
		err = uzfs_read_data(zv, buf[idx], offset,
		    (idx + 1) * block_size, &md, &read_error, &md_error);

		if (err != 0)
			printf("RIO error at offset: %lu len: %lu\n", offset,
			    (idx + 1) * block_size);
		verify_data(buf[idx], offset, idx, block_size);

		if (buf[idx][0] != 0)
			data_ios += (idx + 1);
		FREE_METADATA_LIST(md);
		ios += (idx + 1);

		now = gethrtime();
		if (now > end)
			break;
	}
	for (j = 0; j < 15; j++)
		umem_free(buf[j], sizeof (char) * (j + 1) * block_size);
	if (silent == 0)
		printf("Stopping read.. ios done: %lu data ios: %lu\n", ios,
		    data_ios);

	mutex_enter(mtx);
	if (total_ios != NULL)
		*total_ios += data_ios;
	*threads_done = *threads_done + 1;
	cv_signal(cv);
	mutex_exit(mtx);
	zk_thread_exit();
}

void
populate_random_data(char *buf, uint64_t offset, int idx, uint64_t block_size)
{
	int i;
	for (i = 0; i < (idx + 1)*block_size; i++)
		buf[i] = uzfs_random(200);
}

void
populate_data(char *buf, uint64_t offset, int idx, uint64_t block_size)
{
	int i;
	buf[0] = (offset / 256) % 128;

	for (i = 0; i < idx; i++) {
		buf[((i + 1) * block_size) - 1] =
		    ((offset + (i * block_size)) / 4096) % 128;
		buf[((i + 1) * block_size)] =
		    ((offset + ((i + 1) * block_size)) / 256) % 128;
	}
	buf[((i + 1) * block_size) - 1] =
	    ((offset + (i * block_size)) / 4096) % 128;
}

void
writer_thread(void *arg)
{
	worker_args_t *warg = (worker_args_t *)arg;
	char *buf[15];
	int idx, i, j, err;
	uint64_t blk_offset, offset, vol_blocks, ios = 0;
	hrtime_t end, now;
	void *zv = warg->zv;
	kmutex_t *mtx = warg->mtx;
	kcondvar_t *cv = warg->cv;
	int *threads_done = warg->threads_done;
	uint64_t *total_ios = warg->total_ios;
	uint64_t vol_size = warg->active_size;
	uint64_t block_size = warg->io_block_size;
	uint64_t io_num;
	rl_t *rl;
	blk_metadata_t md;

	i = 0;
	for (j = 0; j < 15; j++)
		buf[j] = (char *)umem_alloc(sizeof (char)*(j+1)*block_size,
		    UMEM_NOFAIL);

	now = gethrtime();
	end = now + (hrtime_t)(total_time_in_sec * (hrtime_t)(NANOSEC));

	vol_blocks = (vol_size) / block_size;

	if (silent == 0)
		printf("Starting write..\n");

	while (1) {
		mutex_enter(mtx);
		io_num = g_io_num++;
		mutex_exit(mtx);

		blk_offset = uzfs_random(vol_blocks - 16);
		offset = blk_offset * block_size;

		idx = uzfs_random(15);

		if (uzfs_test_id == 2)
			populate_data(buf[idx], offset, idx, block_size);
		else
			populate_random_data(buf[idx], offset, idx, block_size);

		rl = zfs_range_lock(&zrl, offset, (idx + 1)*block_size,
		    RL_WRITER);
		/* randomness in io_num is to test VERSION_0 zil records */
		md.io_num = io_num;
		err = uzfs_write_data(zv, buf[idx], offset,
		    (idx + 1) * block_size,
		    (uzfs_test_id == 2 && uzfs_random(2) == 0) ? NULL : &md,
		    B_FALSE);
		if (err != 0)
			printf("WIO error at offset: %lu len: %lu\n", offset,
			    (idx + 1) * block_size);

		if (uzfs_test_id == 8) {
			memcpy(&data[offset], buf[idx], (idx + 1)*block_size);
			for (i = 0; i < (idx+1); i++) {
				iodata[blk_offset+i] = io_num;
//				printf("%lu: %lu\n", io_num, blk_offset + i);
			}
		}
		zfs_range_unlock(rl);
		ios += (idx + 1);
		now = gethrtime();

		if (now > end)
			break;
	}
	for (j = 0; j < 15; j++)
		umem_free(buf[j], sizeof (char) * (j + 1) * block_size);
	if (silent == 0)
		printf("Stopping write.. ios done: %lu\n", ios);

	mutex_enter(mtx);
	if (total_ios != NULL)
		*total_ios += ios;
	*threads_done = *threads_done + 1;
	cv_signal(cv);
	mutex_exit(mtx);
	zk_thread_exit();
}

void
make_vdev(char *path)
{
	int fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0666);
	if (fd == -1) {
		printf("can't open %s", path);
		exit(1);
	}
	if (ftruncate(fd, vol_size) != 0) {
		printf("can't ftruncate %s", path);
		exit(1);
	}
	(void) close(fd);
}

void
setup_unit_test(void)
{
	make_vdev("/tmp/uztest.1a");
	make_vdev("/tmp/uztest.2a");
	make_vdev("/tmp/uztest.log");
	unlink("/tmp/uztest.xyz");
}

void
unit_test_create_pool_ds(void)
{
	spa_t *spa1, *spa2, *spa3, *spa4, *spa;
	zvol_state_t *zv1 = NULL;
	zvol_state_t *zv3 = NULL;
	zvol_state_t *zv2 = NULL;
	zvol_state_t *zv4 = NULL;
	zvol_state_t *zv5 = NULL;
	zvol_state_t *zv = NULL;
	int err, err1, err2, err3, err4, err5;

	err1 = uzfs_create_pool(pool, "/tmp/uztest.xyz", &spa1);
	if (spa1 != NULL) {
		printf("shouldn't create pool with non existing disk..\n");
		exit(1);
	}

	err = uzfs_create_pool(pool, "/tmp/uztest.1a", &spa);
	if (err != 0 || spa == NULL) {
		printf("creating pool errored %d..\n", err);
		exit(1);
	}

	err1 = uzfs_create_pool(pool, "/tmp/uztest.1a", &spa1);

	err2 = uzfs_create_pool("testpxyz", "/tmp/uztest.xyz", &spa2);
//	err3 = uzfs_open_pool(pool, &spa3);
	err3 = 1;
	spa3 = spa;
	err4 = uzfs_open_pool("testpxyz", &spa4);
	if (spa1 != NULL || spa2 != NULL || spa3 == NULL || spa4 != NULL ||
	    err1 == 0 || err2 == 0 || err3 != 0 || err4 == 0) {
		printf("shouldn't create/open, but succeeded..\n");
	//	exit(1);
	}

	err = uzfs_create_dataset(spa, ds, vol_size, block_size, &zv);
	if (zv == NULL || err != 0) {
		printf("creating ds errored %d..\n", err);
		// exit(1);
	}

	err1 = uzfs_create_dataset(spa, ds, vol_size, block_size, &zv1);
	err2 = uzfs_open_dataset(spa, ds, &zv2);
	err3 = uzfs_open_dataset(spa, "dsxyz", &zv3);
	err4 = uzfs_open_dataset(NULL, "dsxyz", &zv4);
	err5 = uzfs_create_dataset(NULL, ds, vol_size, block_size, &zv5);
	if (zv1 != NULL || zv2 != NULL || zv3 != NULL || zv4 != NULL ||
	    zv5 != NULL || err1 == 0 || err2 == 0 || err3 == 0 || err4 == 0 ||
	    err5 == 0) {
		printf("shouldn't create/open, but succeeded..\n");
		exit(1);
	}

	err1 = uzfs_vdev_add(spa, "/tmp/uztest.xyz", 12, 0);
	err2 = uzfs_vdev_add(spa, "/tmp/uztest.1a", 12, 0);
	err3 = uzfs_vdev_add(spa, "/tmp/uztest.2a", 12, 0);
	if (log_device == 1)
		err4 = uzfs_vdev_add(spa, "/tmp/uztest.log", 12, 1);
	else
		err4 = 0;
	if (err1 == 0 || err2 == 0) {
		printf("shouldn't add vdev, but succeeded..\n");
		exit(1);
	}

	if (err3 != 0 || err4 != 0) {
		printf("vdev add errored %d %d..\n", err3, err4);
		exit(1);
	}

	uzfs_close_dataset(zv);
	uzfs_close_pool(spa);
}

static void usage(int num)
{
	int i = 0;
	int count = sizeof (uzfs_tests) / sizeof (uzfs_tests[0]);

	printf("uzfs_test -t <total_time_in_sec> -a <active data size>"
	    " -b <block_size> -c -d <dsname> -i <io size> -v <vol size>"
	    " -l(for log device) -m <metadata to verify during replay>"
	    " -p <pool name> -s(for sync on) -S(for silent)"
	    " -V <data to verify during replay> -w(for write during replay)"
	    " -T <test id> "
	    "-x(directory to scan for pool import default:/tmp/)\n");

	printf("Test id:\n");

	for (i = 0; i < count; i++) {
		printf("\tid: %d (test : %s)\n", i, uzfs_tests[i].name);
	}

	if (num == 0)
		exit(1);
}

static int
str2shift(const char *buf)
{
	const char *ends = "BKMGTPEZ";
	int i;

	if (buf[0] == '\0')
		return (0);
	for (i = 0; i < strlen(ends); i++) {
		if (toupper(buf[0]) == ends[i])
			break;
	}
	if (i == strlen(ends)) {
		printf("uztest: invalid bytes suffix: %s\n", buf);
		usage(B_FALSE);
	}
	if (buf[1] == '\0' || (toupper(buf[1]) == 'B' && buf[2] == '\0')) {
		return (10*i);
	}
	printf("uztest: invalid bytes suffix: %s\n", buf);
	usage(B_FALSE);
	return (-1);
}


static uint64_t
nicenumtoull(const char *buf)
{
	char *end;
	uint64_t val;

	val = strtoull(buf, &end, 0);
	if (end == buf) {
		printf("uztest: bad numeric value: %s\n", buf);
		usage(B_FALSE);
	} else if (end[0] == '.') {
		double fval = strtod(buf, &end);
		fval *= pow(2, str2shift(end));
		if (fval > UINT64_MAX) {
			printf("uztest: value too large: %s\n", buf);
			usage(B_FALSE);
		}
		val = (uint64_t)fval;
	} else {
		int shift = str2shift(end);
		if (shift >= 64 || (val << shift) >> shift != val) {
			printf("uztest: value too large: %s\n", buf);
			usage(B_FALSE);
		}
		val <<= shift;
	}
	return (val);
}


static void process_options(int argc, char **argv)
{
	int opt;
	uint64_t val = 0;
	uint64_t num_tests = sizeof (uzfs_tests) / sizeof (uzfs_tests[0]);
	uint64_t vol_blocks;

	while ((opt = getopt(argc, argv, "a:b:cd:i:lm:p:sSt:v:V:wT:n:x:"))
	    != EOF) {
		switch (opt) {
			case 'd':
			case 'p':
			case 'x':
				break;
			default:
				if (optarg != NULL)
					val = nicenumtoull(optarg);
				break;
		}

		switch (opt) {
			case 'a':
				active_size = val;
				break;
			case 'b':
				block_size = val;
				break;
			case 'c':
				create = 1;
				break;
			case 'd':
				ds = optarg;
				break;
			case 'i':
				io_block_size = val;
				break;
			case 'l':
				log_device = 1;
				break;
			case 'm':
				metaverify = val;
				break;
			case 'p':
				pool = optarg;
				break;
			case 's':
				sync_data = 1;
				break;
			case 'S':
				silent = 1;
				break;
			case 't':
				total_time_in_sec = val;
				break;
			case 'v':
				vol_size = val;
				break;
			case 'V':
				verify = val;
				break;
			case 'w':
				write_op = 1;
				break;
			case 'T':
				run_test = 1;
				if (val >= num_tests)
					usage(0);
				uzfs_test_id = val;
				break;
			case 'n':
				test_iterations = val;
				break;
			case 'x':
				pool_dir = optarg;
				break;
			default:
				usage(0);
		}
	}
	if (active_size == 0)
		active_size = 1024*1024*1024ULL;

	if (vol_size == 0)
		vol_size = 1024*1024*1024ULL;

	if (active_size > vol_size)
		vol_size = active_size << 1;

	if (uzfs_test_id == 8) {
		data = kmem_zalloc(vol_size, KM_SLEEP);
		vol_blocks = (vol_size) / io_block_size;
		iodata = kmem_zalloc(vol_blocks*sizeof (uint64_t), KM_SLEEP);
	}

	if (silent == 0) {
		printf("vol size: %lu active size: %lu create: %d\n", vol_size,
		    active_size, create);
		printf("pool: %s ds: %s Test: %s\n", pool, ds,
		    uzfs_tests[uzfs_test_id].name);
		printf("block size: %lu io blksize: %lu\n", block_size,
		    io_block_size);
		printf("log: %d sync: %d silent: %d\n", log_device, sync_data,
		    silent);
		printf("write: %d verify: %d metaverify: %lu\n", write_op,
		    verify, metaverify);
		printf("total run time in seconds: %d\n", total_time_in_sec);
	}
}

void
uzfs_test_import_pool(char *pool_name)
{
	int err;
	libzfs_handle_t *hdl = libzfs_init();
	importargs_t importargs = {0};
	nvlist_t *config = NULL;
	nvlist_t *props = NULL;

	importargs.path = &pool_dir;
	importargs.paths = 1;
	importargs.scan = B_FALSE;
	importargs.cachefile = NULL;
	importargs.unique = B_TRUE;
	importargs.poolname = pool_name;

	if ((err = zpool_tryimport(hdl, pool_name, &config, &importargs))
	    != 0) {
		printf("cannot import pool:%s, %s\n", pool_name,
		    libzfs_error_description(hdl));
		libzfs_fini(hdl);
		exit(1);
	}

	if ((err = spa_import(pool_name, config, props, ZFS_IMPORT_VERBATIM))
	    != 0) {
		printf("failed import %s\n", strerror(err));
		libzfs_fini(hdl);
		exit(1);
	}

	libzfs_fini(hdl);
}

void
open_pool(spa_t **spa)
{
	int err = 0;

	uzfs_test_import_pool(pool);

	err = uzfs_open_pool(pool, spa);
	if (err != 0) {
		printf("pool open errored.. %d\n", err);
		exit(1);
	}
}

void
open_ds(spa_t *spa, char *ds, zvol_state_t **zv)
{
	int err;
	err = uzfs_open_dataset(spa, ds, zv);
	if (err != 0) {
		printf("ds open errored.. %d\n", err);
		exit(1);
	}
	uzfs_hold_dataset(*zv);
	uzfs_update_metadata_granularity(*zv, 512);
}

void
unit_test_fn(void *arg)
{
	spa_t *spa;
	zvol_state_t *zv;
	kthread_t *reader1;
	kthread_t *writer[3];
	int i;
	kmutex_t mtx;
	kcondvar_t cv;
	int threads_done = 0;
	int num_threads = 0;
	uint64_t total_ios = 0;
	worker_args_t reader1_args;
	worker_args_t writer_args[3];

	mutex_init(&mtx, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&cv, NULL, CV_DEFAULT, NULL);

	if (create == 1) {
		setup_unit_test();
		unit_test_create_pool_ds();
	}

	open_pool(&spa);
	open_ds(spa, ds, &zv);

	if (uzfs_test_id == 2) {
		reader1_args.zv = zv;
		reader1_args.threads_done = &threads_done;
		reader1_args.total_ios = NULL;
		reader1_args.mtx = &mtx;
		reader1_args.cv = &cv;
		reader1_args.io_block_size = io_block_size;
		reader1_args.active_size = active_size;

		reader1 = zk_thread_create(NULL, 0,
		    (thread_func_t)reader_thread, &reader1_args, 0, NULL,
		    TS_RUN, 0, PTHREAD_CREATE_DETACHED);
		num_threads++;
	}

	for (i = 0; i < 3; i++) {
		writer_args[i].zv = zv;
		writer_args[i].threads_done = &threads_done;
		writer_args[i].total_ios = &total_ios;
		writer_args[i].mtx = &mtx;
		writer_args[i].cv = &cv;
		writer_args[i].io_block_size = io_block_size;
		writer_args[i].active_size = active_size;

		writer[i] = zk_thread_create(NULL, 0,
		    (thread_func_t)writer_thread, &writer_args[i], 0, NULL,
		    TS_RUN, 0, PTHREAD_CREATE_DETACHED);
		num_threads++;
	}

	mutex_enter(&mtx);
	while (threads_done != num_threads)
		cv_wait(&cv, &mtx);
	mutex_exit(&mtx);

	if (uzfs_test_id == 8)
		verify_vol_data(zv, io_block_size, active_size);

	if (silent == 0)
		printf("Total write IOs: %lu\n", total_ios);

	cv_destroy(&cv);
	mutex_destroy(&mtx);
	uzfs_close_dataset(zv);
	uzfs_close_pool(spa);
}

void
check_offset_len(uint64_t offset, uint64_t len, uint64_t blocksize,
    uint64_t exp_offset, uint64_t exp_len)
{
	uint64_t r_offset = P2ALIGN_TYPED(offset, blocksize, uint64_t);
	uint64_t r_len;

	r_len = P2ALIGN_TYPED(((offset - r_offset) + len + blocksize - 1),
	    blocksize, uint64_t);

	if ((r_offset != exp_offset) || (r_len != exp_len)) {
		printf("Error: %lu %lu %lu %lu %lu %lu %lu\n", offset, len,
		    blocksize, exp_offset, exp_len, r_offset, r_len);
		exit(1);
	}
}

void
check_metaobj_block_details(uint64_t offset, uint64_t len,
    uint64_t blocksize, uint64_t metablocksize, uint64_t metadatasize,
    uint64_t exp_r_offset, uint64_t exp_r_len,
    uint64_t exp_m_offset, uint64_t exp_m_len)
{
	metaobj_blk_offset_t m;

	get_metaobj_block_details(&m, blocksize, metablocksize, metadatasize,
	    offset, len);

	if ((m.r_offset != exp_r_offset) || (m.r_len != exp_r_len) ||
	    (m.m_offset != exp_m_offset) || (m.m_len != exp_m_len)) {
		printf("Error: %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu"
		    " %lu\n", offset, len, blocksize, metablocksize,
		    metadatasize, exp_r_offset, exp_r_len, exp_m_offset,
		    exp_m_len, m.r_offset, m.r_len, m.m_offset, m.m_len);
		exit(1);
	}
}

void
uzfs_test_get_metablk_details(void *arg)
{
	check_offset_len(4*1024, 4*1024, 16*1024, 0, 16*1024);
	check_offset_len(15*1024, 1024, 16*1024, 0, 16*1024);
	check_offset_len(14*1024, 1024, 16*1024, 0, 16*1024);
	check_offset_len(15*1024, 2*1024, 16*1024, 0, 32*1024);
	check_offset_len(16*1024, 2*1024, 16*1024, 16*1024, 16*1024);
	check_offset_len(15*1024, 16*1024, 16*1024, 0, 32*1024);
	check_offset_len(15*1024, 17*1024, 16*1024, 0, 32*1024);
	check_offset_len(15*1024, 18*1024, 16*1024, 0, 48*1024);
	check_offset_len(31*1024, 18*1024, 16*1024, 16*1024, 48*1024);

	check_metaobj_block_details(6*1024, 2*1024, 1024, 2*1024, 8, 0, 2*1024,
	    48, 16);
	uint64_t start = 2*(2*1024/8)*1024;
	check_metaobj_block_details(start-1024, 2*1024, 1024, 2*1024, 8, 2*1024,
	    4*1024, 4*1024-8, 16);

	printf("Test passed\n");
}

int
main(int argc, char **argv)
{
	int err;
	process_options(argc, argv);

	zfs_rlock_init(&zrl);

	zfs_arc_max = (512 << 20);
	zfs_arc_min = (256 << 20);

	err = uzfs_init();
	if (err != 0) {
		printf("initialization errored.. %d\n", err);
		exit(1);
	}

	if (silent == 0)
		printf("zarcmax: %lu zarcmin:%lu\n", zfs_arc_max, zfs_arc_min);

	if (!run_test)
		usage(0);

	uzfs_tests[uzfs_test_id].func(&uzfs_tests[uzfs_test_id]);
	zfs_rlock_destroy(&zrl);
	uzfs_fini();
	return (0);
}
