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

extern void verify_data(char *buf, uint64_t offset, int idx,
    uint64_t block_size);
extern void populate_data(char *buf, uint64_t offset, int idx,
    uint64_t block_size);

static uint64_t running_io_num;

static spa_t *spa;
static zvol_state_t *zvol;
zfs_rlock_t zv1_range_lock;
uint64_t unmap_region[50][2];

static boolean_t
check_if_unmaped(uint64_t offset)
{
	int i = 0;
	for (i = 0; i < sizeof (unmap_region); i++) {
		if (offset > unmap_region[i][0] &&
		    offset < (unmap_region[i][0] + unmap_region[i][1]))
			return (B_TRUE);
	}
	return (B_FALSE);
}

void
r_unmap_thread(void *arg)
{
	worker_args_t *warg = (worker_args_t *)arg;
	int idx, err;
	uint64_t blk_offset, offset, vol_blocks, ios = 0, data_ios = 0;
	hrtime_t end, now;
	void *zv = warg->zv;
	kmutex_t *mtx = warg->mtx;
	kcondvar_t *cv = warg->cv;
	int *threads_done = warg->threads_done;
	uint64_t *total_ios = warg->total_ios;
	uint64_t vol_size = warg->active_size;
	uint64_t block_size = warg->io_block_size;
	useconds_t unmap_delay;
	int i = 0;
	rl_t *rl;
	uint64_t io_num;

	now = gethrtime();
	end = now + (hrtime_t)(total_time_in_sec * (hrtime_t)(NANOSEC));
	// We will be executing UNMAP 5 times
	unmap_delay = (total_time_in_sec / 5) * (MICROSEC);

	vol_blocks = (vol_size) / block_size;

	printf("Starting read..\n");

	while (1) {
		blk_offset = uzfs_random(vol_blocks - 16);
		offset = blk_offset * block_size;

		idx = uzfs_random(15);
		io_num = atomic_inc_64_nv(&running_io_num);
		rl = zfs_range_lock(&zv1_range_lock, offset,
		    (idx + 1) * block_size, RL_WRITER);
		err = uzfs_unmap_data(zv, offset, (idx + 1) * block_size,
		    (blk_metadata_t *)&io_num);
		if (err != 0) {
			printf("UNMAP error at offset: %lu len: %lu, err:%d\n",
			    offset, (idx + 1) * block_size, err);
			exit(1);
		}
		zfs_range_unlock(rl);
		ios += (idx + 1);
		unmap_region[i][0] = offset;
		unmap_region[i][0] = (idx + 1) * block_size;
		i++;

		usleep(unmap_delay);
		now = gethrtime();
		if (now > end)
			break;
	}

	mutex_enter(mtx);

	if (total_ios != NULL)
		*total_ios += data_ios;
	*threads_done = *threads_done + 1;
	cv_signal(cv);
	mutex_exit(mtx);
	zk_thread_exit();
}

void
r_read_thread(void *arg)
{
	worker_args_t *warg = (worker_args_t *)arg;
	char *buf[15];
	int idx, j;
	uint64_t blk_offset, offset, vol_blocks, ios = 0, data_ios = 0;
	hrtime_t end, now;
	void *zv = warg->zv;
	kmutex_t *mtx = warg->mtx;
	kcondvar_t *cv = warg->cv;
	int *threads_done = warg->threads_done;
	uint64_t *total_ios = warg->total_ios;
	uint64_t block_size = warg->io_block_size;
	metadata_desc_t *md;
	int tidx = warg->rebuild_test;
	uint64_t read_size = warg->max_iops;
	uint64_t read_start;
	int read_error, md_error;
	rl_t *rl;

	for (j = 0; j < 15; j++)
		buf[j] = (char *)umem_alloc(sizeof (char)*(j+1)* block_size,
		    UMEM_NOFAIL);

	now = gethrtime();
	end = now + (hrtime_t)(total_time_in_sec * (hrtime_t)(NANOSEC));

	vol_blocks = (read_size) / block_size;
	read_start = (tidx * read_size);

	printf("Starting read.. thread:%d\n", tidx);

	while (1) {
		blk_offset = uzfs_random(vol_blocks - 16);
		offset = read_start + (blk_offset * block_size);

		idx = uzfs_random(15);
		read_error = md_error = 0;
		rl = zfs_range_lock(&zv1_range_lock, offset,
		    (idx + 1) * block_size, RL_READER);
		uzfs_read_data(zv, buf[idx], offset,
		    (idx + 1) * block_size, &md, &read_error, &md_error);
		zfs_range_unlock(rl);
		if (!(read_error == EIO && md_error == EIO)) {
			if (read_error == EIO && !md_error) {
				check_if_unmaped(offset);
				continue;
			} else if (read_error || md_error)
				printf("read error at offset: %lu len: %lu for "
				    "thread:%d read_error:%d md_error:%d\n",
				    offset, (idx + 1) * block_size, tidx,
				    read_error, md_error);
		} else {
			continue;
		}

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

	mutex_enter(mtx);

	if (total_ios != NULL)
		*total_ios += data_ios;
	*threads_done = *threads_done + 1;
	cv_signal(cv);
	mutex_exit(mtx);
	printf("finished read with IOs:%lu dataIOs:%lu\n", ios, data_ios);
	zk_thread_exit();
}

void
r_write_thread(void *arg)
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
	uint64_t block_size = warg->io_block_size;
	uint64_t io_num;
	int tidx = warg->rebuild_test;
	uint64_t write_size = warg->max_iops;
	uint64_t write_start;
	blk_metadata_t md;
	rl_t *rl;

	i = 0;
	for (j = 0; j < 15; j++)
		buf[j] = (char *)umem_alloc(sizeof (char)*(j+1)*block_size,
		    UMEM_NOFAIL);

	now = gethrtime();
	end = now + (hrtime_t)(total_time_in_sec * (hrtime_t)(NANOSEC));

	vol_blocks = (write_size) / block_size;
	write_start = (tidx * write_size);

	printf("Starting write.. thread:%d\n", tidx);

	while (1) {
		io_num = atomic_inc_64_nv(&running_io_num);

		blk_offset = uzfs_random(vol_blocks - 16);
		offset = write_start + (blk_offset * block_size);

		idx = uzfs_random(15);

		populate_data(buf[idx], offset, idx, block_size);
		md.io_num = io_num;
		rl = zfs_range_lock(&zv1_range_lock, offset,
		    (idx + 1) * block_size, RL_WRITER);
		err = uzfs_write_data(zv, buf[idx], offset,
		    (idx + 1) * block_size, &md, B_FALSE);
		zfs_range_unlock(rl);
		if (err != 0) {
			printf("write error at offset: %lu len: %lu for "
			    "thread:%d\n", offset,
			    (idx + 1) * block_size, tidx);
			exit(1);
		}

		ios += (idx + 1);
		now = gethrtime();

		if (now > end)
			break;
	}

	for (j = 0; j < 15; j++)
		umem_free(buf[j], sizeof (char) * (j + 1) * block_size);

	mutex_enter(mtx);

	if (total_ios != NULL)
		*total_ios += ios;
	*threads_done = *threads_done + 1;
	cv_signal(cv);
	mutex_exit(mtx);
	printf("finished write with IOs:%lu for thread:%d\n", ios, tidx);
	zk_thread_exit();
}

void
unmap_test_fn(void *arg)
{
	kthread_t *reader[3];
	kthread_t *writer[3];
	kthread_t *unmap_thr[1];
	int i;
	kmutex_t mtx;
	kcondvar_t cv;
	int threads_done = 0;
	int num_threads = 0;
	uint64_t total_ios = 0;
	worker_args_t reader_args[3];
	worker_args_t writer_args[3];
	worker_args_t unmap_args[1];

	mutex_init(&mtx, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&cv, NULL, CV_DEFAULT, NULL);
	zfs_rlock_init(&zv1_range_lock);

	open_pool(&spa);
	open_ds(spa, ds, &zvol);

	// We will be using max_iops for offset and rebuild_test for index
	for (i = 0; i < ARRAY_SIZE(writer_args); i++) {
		writer_args[i].zv = zvol;
		writer_args[i].threads_done = &threads_done;
		writer_args[i].total_ios = &total_ios;
		writer_args[i].mtx = &mtx;
		writer_args[i].cv = &cv;
		writer_args[i].io_block_size = io_block_size;
		writer_args[i].active_size = active_size;
		writer_args[i].max_iops = P2ALIGN((active_size /
		    ARRAY_SIZE(reader_args)), io_block_size);
		writer_args[i].rebuild_test = i;

		writer[i] = zk_thread_create(NULL, 0,
		    (thread_func_t)r_write_thread, &writer_args[i], 0, NULL,
		    TS_RUN, 0, PTHREAD_CREATE_DETACHED);
		num_threads++;
	}

	for (i = 0; i < ARRAY_SIZE(reader_args); i++) {
		reader_args[i].zv = zvol;
		reader_args[i].threads_done = &threads_done;
		reader_args[i].total_ios = &total_ios;
		reader_args[i].mtx = &mtx;
		reader_args[i].cv = &cv;
		reader_args[i].io_block_size = io_block_size;
		reader_args[i].active_size = active_size;
		reader_args[i].max_iops = P2ALIGN((active_size /
		    ARRAY_SIZE(reader_args)), io_block_size);
		reader_args[i].rebuild_test = i;

		reader[i] = zk_thread_create(NULL, 0,
		    (thread_func_t)r_read_thread, &reader_args[i], 0, NULL,
		    TS_RUN, 0, PTHREAD_CREATE_DETACHED);
		num_threads++;
	}

	for (i = 0; i < ARRAY_SIZE(unmap_args); i++) {
		unmap_args[i].zv = zvol;
		unmap_args[i].threads_done = &threads_done;
		unmap_args[i].total_ios = &total_ios;
		unmap_args[i].mtx = &mtx;
		unmap_args[i].cv = &cv;
		unmap_args[i].io_block_size = io_block_size;
		unmap_args[i].active_size = active_size;

		unmap_thr[i] = zk_thread_create(NULL, 0,
		    (thread_func_t)r_unmap_thread, &unmap_args[i], 0, NULL,
		    TS_RUN, 0, PTHREAD_CREATE_DETACHED);
		num_threads++;
	}

	mutex_enter(&mtx);
	while (threads_done != num_threads)
		cv_wait(&cv, &mtx);
	mutex_exit(&mtx);

	cv_destroy(&cv);
	mutex_destroy(&mtx);
	zfs_rlock_destroy(&zv1_range_lock);

	uzfs_close_dataset(zvol);
	uzfs_close_pool(spa);
}
