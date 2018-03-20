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
#include <uzfs_mgmt.h>
#include <uzfs_io.h>
#include <uzfs_test.h>
#include <math.h>
#include <zrepl_mgmt.h>

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

uzfs_test_info_t uzfs_tests[] = {
	{ uzfs_zvol_zap_operation, "uzfs zap operation test" },
	{ replay_fn, "zvol replay test" },
	{ unit_test_fn, "zvol read/write verification test"},
	{ uzfs_txg_diff_verifcation_test,
	    "test to verify modified blocks between two txg for zvol" },
	{ uzfs_txg_diff_tree_test, "txg_diff_tree functionality test" },
	{ uzfs_rebuild_test, "uzfs rebuild pool test"},
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
	uint64_t len = 0;
	void *io_num;

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
		len = 0;
		err = uzfs_read_data(zv, buf[idx], offset,
		    (idx + 1) * block_size, &io_num, &len);

		if (err != 0)
			printf("IO error at offset: %lu len: %lu\n", offset,
			    (idx + 1) * block_size);
		verify_data(buf[idx], offset, idx, block_size);

		if (buf[idx][0] != 0)
			data_ios += (idx + 1);
		if (len != 0)
			kmem_free(io_num, len);
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
	int idx, j, err;
	uint64_t blk_offset, offset, vol_blocks, ios = 0;
	hrtime_t end, now;
	void *zv = warg->zv;
	kmutex_t *mtx = warg->mtx;
	kcondvar_t *cv = warg->cv;
	int *threads_done = warg->threads_done;
	uint64_t *total_ios = warg->total_ios;
	uint64_t vol_size = warg->active_size;
	uint64_t block_size = warg->io_block_size;
	static uint64_t io_num = 0;

	for (j = 0; j < 15; j++)
		buf[j] = (char *)umem_alloc(sizeof (char)*(j+1)*block_size,
		    UMEM_NOFAIL);

	now = gethrtime();
	end = now + (hrtime_t)(total_time_in_sec * (hrtime_t)(NANOSEC));

	vol_blocks = (vol_size) / block_size;

	if (silent == 0)
		printf("Starting write..\n");

	while (1) {
		io_num++;
		blk_offset = uzfs_random(vol_blocks - 16);
		offset = blk_offset * block_size;

		idx = uzfs_random(15);

		populate_data(buf[idx], offset, idx, block_size);

		/* randomness in io_num is to test VERSION_0 zil records */
		err = uzfs_write_data(zv, buf[idx], offset,
		    (idx + 1) * block_size, (uzfs_random(2) ? NULL : &io_num),
		    B_FALSE);
		if (err != 0)
			printf("IO error at offset: %lu len: %lu\n", offset,
			    (idx + 1) * block_size);
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
	err3 = uzfs_open_pool(pool, &spa3);
	err4 = uzfs_open_pool("testpxyz", &spa4);
	if (spa1 != NULL || spa2 != NULL || spa3 != NULL || spa4 != NULL ||
	    err1 == 0 || err2 == 0 || err3 == 0 || err4 == 0) {
		printf("shouldn't create/open, but succeeded..\n");
		exit(1);
	}

	err = uzfs_create_dataset(spa, ds, vol_size, block_size, &zv);
	if (zv == NULL || err != 0) {
		printf("creating ds errored %d..\n", err);
		exit(1);
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
	    " -T <test id>\n");

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

	while ((opt = getopt(argc, argv, "a:b:cd:i:lm:p:sSt:v:V:wT:n:"))
	    != EOF) {
		switch (opt) {
			case 'd':
			case 'p':
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
			default:
				usage(0);
		}
	}
	if (active_size == 0)
		active_size = 1024*1024*1024ULL;

	if (vol_size == 0)
		vol_size = 1024*1024*1024ULL;

	if (active_size > vol_size)
		vol_size = active_size;

	if (silent == 0) {
		printf("vol size: %lu active size: %lu create: %d\n", vol_size,
		    active_size, create);
		printf("pool: %s ds: %s\n", pool, ds);
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
open_pool(spa_t **spa)
{
	int err;
	err = uzfs_open_pool(pool, spa);
	if (err != 0) {
		printf("pool open errored.. %d\n", err);
		exit(1);
	}
}

void
open_ds(spa_t *spa, zvol_state_t **zv)
{
	int err;
	err = uzfs_open_dataset(spa, ds, zv);
	if (err != 0) {
		printf("ds open errored.. %d\n", err);
		exit(1);
	}
}

void
unit_test_fn(void *arg)
{
	spa_t *spa;
	zvol_state_t *zv;
	kthread_t *reader1;
	kthread_t *writer[3];
	char name[MAXNAMELEN];
	int i;
	kmutex_t mtx;
	kcondvar_t cv;
	int threads_done = 0;
	int num_threads = 0;
	uint64_t total_ios = 0;
	zvol_info_t *zinfo = NULL;
	worker_args_t reader1_args, writer_args[3];

	mutex_init(&mtx, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&cv, NULL, CV_DEFAULT, NULL);

	if (create == 1) {
		setup_unit_test();
		unit_test_create_pool_ds();
	}

	open_pool(&spa);
	if (create == 1) {
		open_ds(spa, &zv);
	} else {
		zinfo = uzfs_zinfo_lookup(ds);
		zv = zinfo->zv;
	}

	reader1_args.zv = zv;
	reader1_args.threads_done = &threads_done;
	reader1_args.total_ios = NULL;
	reader1_args.mtx = &mtx;
	reader1_args.cv = &cv;
	reader1_args.io_block_size = io_block_size;
	reader1_args.active_size = active_size;

	reader1 = zk_thread_create(NULL, 0, (thread_func_t)reader_thread,
	    &reader1_args, 0, NULL, TS_RUN, 0, PTHREAD_CREATE_DETACHED);
	num_threads++;

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

	if (silent == 0)
		printf("Total write IOs: %lu\n", total_ios);

	cv_destroy(&cv);
	mutex_destroy(&mtx);

	if (create == 1) {
		uzfs_close_dataset(zv);
		uzfs_close_pool(spa);
	} else {
		strlcpy(name, zinfo->name, MAXNAMELEN);
		uzfs_zinfo_drop_refcnt(zinfo, 0);
		uzfs_zinfo_destroy(name);
		uzfs_close_pool(spa);
	}
}

int
main(int argc, char **argv)
{
	int err;
	process_options(argc, argv);

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

	uzfs_fini();
	return (0);
}
