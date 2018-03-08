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
#include <sys/txg.h>
#include <sys/zil.h>
#include <sys/uzfs_zvol.h>
#include <uzfs_mgmt.h>
#include <uzfs_mtree.h>
#include <uzfs_io.h>
#include <uzfs_test.h>

extern void populate_data(char *buf, uint64_t offset, int idx,
    uint64_t block_size);
extern void writer_thread(void *arg);
extern void reader_thread(void *arg);

void
rebuild_io_thread(void *arg)
{
	worker_args_t *warg = (worker_args_t *)arg;
	char *buf[15];
	int idx, j, err;
	uint64_t blk_offset, offset, vol_blocks, iops = 0;
	hrtime_t end, now;
	void *zv = warg->zv;
	kmutex_t *mtx = warg->mtx;
	kcondvar_t *cv = warg->cv;
	int *threads_done = warg->threads_done;
	uint64_t vol_size = warg->active_size;
	uint64_t block_size = warg->io_block_size;
	static uint64_t io_num = 0;

	for (j = 0; j < 15; j++) {
		buf[j] = (char *)umem_alloc(sizeof (char)*(j+1)*block_size,
		    UMEM_NOFAIL);
	}

	now = gethrtime();
	end = now + (hrtime_t)(total_time_in_sec * (hrtime_t)(NANOSEC));

	vol_blocks = (vol_size) / block_size;

	if (silent == 0)
		printf("Starting rebuild io write..\n");

	while (1) {
		io_num++;
		blk_offset = uzfs_random(vol_blocks - 16);
		offset = blk_offset * block_size;

		idx = uzfs_random(15);

		populate_data(buf[idx], offset, idx, block_size);

		/* randomness in io_num is to test VERSION_0 zil records */
		err = uzfs_write_data(zv, buf[idx], offset,
		    (idx + 1) * block_size, (uzfs_random(2) ? NULL : &io_num),
		    B_TRUE);
		if (err != 0)
			printf("IO error at offset: %lu len: %lu\n", offset,
			    (idx + 1) * block_size);
		iops += (idx + 1);
		now = gethrtime();

		if (now > end)
			break;
	}
	for (j = 0; j < 15; j++)
		umem_free(buf[j], sizeof (char) * (j + 1) * block_size);

	if (silent == 0)
		printf("Stopping rebuilding io.. ios done: %lu\n", iops);

	mutex_enter(mtx);
	*threads_done = *threads_done + 1;
	cv_signal(cv);
	mutex_exit(mtx);
	zk_thread_exit();
}

void
uzfs_rebuild_tree_test(void *arg)
{
	uzfs_test_info_t *test_info = (uzfs_test_info_t *)arg;
	void *spa, *zv;
	kthread_t *reader1;
	kthread_t *writer[3];
	int i;
	kmutex_t mtx;
	kcondvar_t cv;
	int threads_done = 0;
	int num_threads = 0;
	worker_args_t reader1_args, writer_args[3];

	printf("starting %s\n", test_info->name);

	mutex_init(&mtx, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&cv, NULL, CV_DEFAULT, NULL);

	setup_unit_test();

	unit_test_create_pool_ds();

	open_pool(&spa);
	open_ds(spa, &zv);

	uzfs_set_rebuilding_mode(zv);

	for (i = 0; i < 1; i++) {
		writer_args[i].zv = zv;
		writer_args[i].threads_done = &threads_done;
		writer_args[i].mtx = &mtx;
		writer_args[i].cv = &cv;
		writer_args[i].io_block_size = io_block_size;
		writer_args[i].active_size = active_size;

		writer[i] = zk_thread_create(NULL, 0,
		    (thread_func_t)writer_thread, &writer_args[i], 0, NULL,
		    TS_RUN, 0, PTHREAD_CREATE_DETACHED);
		num_threads++;
	}

	uzfs_set_rebuilding_mode(zv);

	writer[i] = zk_thread_create(NULL, 0, (thread_func_t)rebuild_io_thread,
	    &writer_args[i-1], 0, NULL, TS_RUN, 0, PTHREAD_CREATE_DETACHED);
	num_threads++;

	reader1_args.zv = zv;
	reader1_args.threads_done = &threads_done;
	reader1_args.mtx = &mtx;
	reader1_args.cv = &cv;
	reader1_args.io_block_size = io_block_size;
	reader1_args.active_size = active_size;

	mutex_enter(&mtx);
	while (threads_done != num_threads)
		cv_wait(&cv, &mtx);
	mutex_exit(&mtx);


	reader1 = zk_thread_create(NULL, 0, (thread_func_t)reader_thread,
	    &reader1_args, 0, NULL, TS_RUN, 0, PTHREAD_CREATE_DETACHED);
	num_threads++;

	mutex_enter(&mtx);
	while (threads_done != num_threads)
		cv_wait(&cv, &mtx);
	mutex_exit(&mtx);

	cv_destroy(&cv);
	mutex_destroy(&mtx);

	uzfs_unset_rebuilding_mode(zv);
	uzfs_close_dataset(zv);
	uzfs_close_pool(spa);
}
