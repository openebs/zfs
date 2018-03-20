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
#include <rte_ring.h>
#include <uzfs_mgmt.h>
#include <uzfs_mtree.h>
#include <uzfs_io.h>
#include <uzfs_test.h>

extern void make_vdev(char *path);
extern void populate_string(char *buf, uint64_t size);

void *spa1, *spa2, *zvol1, *zvol2;
uint32_t f_index = 0;

#define	POOL_NAME	"testpool"
#define	ZVOL_NAME	"testzvol"
#define	FILE_PATH	"/tmp/uzfstest.xyz"

struct rebuilding_info {
	zvol_state_t *to_zvol;
	zvol_state_t *from_zvol;
	kmutex_t mtx;
	kcondvar_t cv;
	int active;
};

typedef struct uzfs_rebuild_data {
	list_t *io_list;
	zvol_state_t *zvol;
	kmutex_t mtx;
	kcondvar_t cv;
	boolean_t done;
} uzfs_rebuild_data_t;

struct rebuilding_data {
	uzfs_rebuild_data_t *r_data;
	zvol_state_t *zvol;
	uint64_t start_txg;
	uint64_t end_txg;
};

struct replica_read_data {
	uint64_t offset;
	uint64_t len;
};

uint64_t
verify_replica_data(char *buf1, char *buf2, uint64_t len)
{
	uint64_t i = 0;
	uint64_t count = 0;

	for (i = 0; i < len; i++) {
		if (buf1[i] != buf2[i]) {
			if (count == 0)
				printf("error started for len:%lu,"
				    " offset:%lu\n", len, i);
			if (!(count % 100))
				printf("verification failed : %c : %c\n",
				    buf1[i], buf2[i]);
			count++;
		}
	}
	return (count);
}

void
replica_reader_thread(void *arg)
{
	worker_args_t *warg = (worker_args_t *)arg;
	struct replica_read_data *r_data = (struct replica_read_data *)warg->zv;
	char *buf1[15], *buf2[15];
	int idx, j, err;
	uint64_t offset, end, len, iops = 0;
	kmutex_t *mtx = warg->mtx;
	kcondvar_t *cv = warg->cv;
	int *threads_done = warg->threads_done;
	uint64_t block_size = warg->io_block_size;
	uint64_t len1 = 0, len2 = 0;
	uint64_t mismatch_count = 0;

	for (j = 0; j < 15; j++) {
		buf1[j] = (char *)umem_alloc(sizeof (char)*(j+1)* block_size,
		    UMEM_NOFAIL);
		buf2[j] = (char *)umem_alloc(sizeof (char)*(j+1)* block_size,
		    UMEM_NOFAIL);
	}

	if (silent == 0)
		printf("Starting read..\n");

	offset = r_data->offset;
	end = r_data->offset + r_data->len;

	while (1) {
		idx = uzfs_random(15);
		len1 = 0;
		len2 = 0;

		if (offset >= end)
			break;
		len = (idx + 1) * block_size;

		if ((offset + len) > end)
			len = end - offset;

		err = uzfs_read_data(zvol1, buf1[idx], offset,
		    len, NULL, NULL);
		if (err != 0)
			printf("IO error at offset: %lu len: %lu\n", offset,
			    len);

		err = uzfs_read_data(zvol2, buf2[idx], offset,
		    len, NULL, NULL);
		if (err != 0)
			printf("IO error at offset: %lu len: %lu\n", offset,
			    len);

		uint64_t mismatch;
		mismatch = verify_replica_data(buf1[idx], buf2[idx], len);
		mismatch_count += mismatch;
		if (mismatch)
			printf("verification error at %lu, mismatch:%lu\n",
			    offset, mismatch);

		iops += (idx + 1);
		offset += len;
	}

	for (j = 0; j < 15; j++) {
		umem_free(buf1[j], sizeof (char) * (j + 1) * block_size);
		umem_free(buf2[j], sizeof (char) * (j + 1) * block_size);
	}
	if (silent == 0)
		printf("Stopping read.. ios done: %lu total_read: %lu"
		    " error:%lu\n", iops, r_data->len, mismatch_count);

	if (mismatch_count)
		exit(1);

	mutex_enter(mtx);
	*threads_done = *threads_done + 1;
	cv_signal(cv);
	mutex_exit(mtx);

	zk_thread_exit();
}

static int
uzfs_test_txg_diff_traverse_cb(off_t offset, size_t len,
    uint64_t blkid, void *arg)
{
	uzfs_rebuild_data_t *r_data = (uzfs_rebuild_data_t *)arg;
	uzfs_io_chunk_list_t *io;
	int err = 0;

	io = umem_alloc(sizeof (*io), UMEM_NOFAIL);
	io->offset = offset;
	io->len = len;
	io->buf = umem_alloc(len, UMEM_NOFAIL);

	err = uzfs_read_data(r_data->zvol, io->buf, offset, len,
	    NULL, NULL);

	if (err) {
		umem_free(io, sizeof (*io));
		umem_free(io->buf, len);
		goto done;
	}

	mutex_enter(&r_data->mtx);
	list_insert_tail(r_data->io_list, io);
	mutex_exit(&r_data->mtx);

done:
	return (err);
}

void
fetch_modified_data(void *arg)
{
	struct rebuilding_data *repl_data = arg;
	uzfs_rebuild_data_t *r_data = repl_data->r_data;
	int err;

	printf("fetching modified data\n");

	err = uzfs_get_txg_diff(repl_data->zvol, repl_data->start_txg,
	    repl_data->end_txg, uzfs_test_txg_diff_traverse_cb, r_data);

	if (err)
		printf("error(%d)... while fetching modified data\n", err);

	printf("finished fetching modified data\n");

	mutex_enter(&r_data->mtx);
	r_data->done = B_TRUE;
	mutex_exit(&r_data->mtx);

	zk_thread_exit();
}

void
rebuild_replica_thread(void *arg)
{
	struct rebuilding_info *r_info = arg;
	r_info->active = B_TRUE;
	uint64_t start_txg, end_txg;
	zvol_state_t *from_zvol = r_info->from_zvol;
	zvol_state_t *to_zvol = r_info->to_zvol;
	list_t *io_list;
	uzfs_rebuild_data_t r_data;
	struct rebuilding_data repl_data;
	kthread_t *tid = NULL;
	uzfs_io_chunk_list_t *node = NULL;
	int err = 0;
	uint64_t diff_data = 0;

	start_txg = 0;
	txg_wait_synced(spa_get_dsl(to_zvol->zv_spa), 0);

	uzfs_zvol_set_rebuild_status(to_zvol, ZVOL_REBUILDING_INIT);

	txg_wait_synced(spa_get_dsl(from_zvol->zv_spa), 0);
	end_txg = spa_last_synced_txg(from_zvol->zv_spa);

	uzfs_zvol_set_rebuild_status(to_zvol, ZVOL_REBUILDING_IN_PROGRESS);

	mutex_enter(&r_info->mtx);
	cv_signal(&r_info->cv);
	mutex_exit(&r_info->mtx);

	io_list = umem_alloc(sizeof (*io_list), UMEM_NOFAIL);
	list_create(io_list, sizeof (uzfs_io_chunk_list_t),
	    offsetof(uzfs_io_chunk_list_t, link));

	r_data.done = B_FALSE;
	r_data.io_list = io_list;
	r_data.zvol = from_zvol;
	mutex_init(&r_data.mtx, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&r_data.cv, NULL, CV_DEFAULT, NULL);

	repl_data.start_txg = start_txg;
	repl_data.end_txg = end_txg;
	repl_data.r_data = &r_data;
	repl_data.zvol = from_zvol;

	printf("difference : start(%lu) end(%lu)\n", start_txg, end_txg);

	tid = zk_thread_create(NULL, 0,
	    (thread_func_t)fetch_modified_data, &repl_data, 0, NULL,
	    TS_RUN, 0, PTHREAD_CREATE_DETACHED);

	mutex_enter(&r_data.mtx);
	while (!r_data.done || (node = list_remove_head(io_list)) != NULL) {
		if (!node) {
			mutex_exit(&r_data.mtx);
			// sleep for some time here
			usleep(1000);
			mutex_enter(&r_data.mtx);
			continue;
		}
		mutex_exit(&r_data.mtx);

		err = uzfs_write_data(to_zvol, node->buf, node->offset,
		    node->len, NULL, B_TRUE);
		if (err) {
			printf("IO error during rebuilding offset:%lu,"
			    "len:%lu\n", node->offset, node->len);
			exit(2);
		}
		diff_data += node->len;

		umem_free(node->buf, node->len);
		umem_free(node, sizeof (*node));
		mutex_enter(&r_data.mtx);
	}

	mutex_exit(&r_data.mtx);

	printf("rebuilding finished.. written:%lu, actual written:%lu\n",
	    diff_data, to_zvol->rebuild_data.rebuild_bytes);
	umem_free(io_list, sizeof (*io_list));
	mutex_destroy(&r_data.mtx);
	cv_destroy(&r_data.cv);

	uzfs_zvol_set_rebuild_status(to_zvol, ZVOL_REBUILDING_DONE);

	/*
	 * We finished rebuilding data in degraded zvol so set status to
	 * ZVOL_STATUS_HEALTHY
	 */
	uzfs_zvol_set_status(to_zvol, ZVOL_STATUS_HEALTHY);

	mutex_enter(&r_info->mtx);
	r_info->active = B_FALSE;
	cv_signal(&r_info->cv);
	mutex_exit(&r_info->mtx);

	zk_thread_exit();
}

void
replica_writer_thread(void *arg)
{
	worker_args_t *warg = (worker_args_t *)arg;
	char *buf[15];
	int idx, j, err;
	uint64_t blk_offset, offset, vol_blocks, iops = 0;
	hrtime_t end, now, replica_rebuild_start_time;
	hrtime_t replica_down_time, replica_start_time;
	boolean_t replica_active = B_TRUE;
	kmutex_t *mtx = warg->mtx;
	kcondvar_t *cv = warg->cv;
	int *threads_done = warg->threads_done;
	uint64_t vol_size = warg->active_size;
	uint64_t block_size = warg->io_block_size;
	static uint64_t io_num = 0;
	boolean_t rebuilding_started = B_FALSE;
	struct rebuilding_info rebuild_info;
	kthread_t *rebuilding_thread = NULL;
	uint64_t mismatch_count = 0;

	for (j = 0; j < 15; j++)
		buf[j] = (char *)umem_alloc(sizeof (char)*(j+1)*block_size,
		    UMEM_NOFAIL);

	now = gethrtime();
	end = now + (hrtime_t)(total_time_in_sec * (hrtime_t)(NANOSEC));

	/*
	 * If test duration is 100 seconds, then
	 * replica_down_time : 33 seconds
	 * replica_start_time : 66 seconds
	 * rebuild_start_time : 77 seconds
	 */
	replica_start_time = now + (hrtime_t)(total_time_in_sec *
	    (hrtime_t)(NANOSEC)) - (hrtime_t)(total_time_in_sec/3 *
	    (hrtime_t)(NANOSEC));
	replica_down_time = now + (hrtime_t)(total_time_in_sec/3 *
	    (hrtime_t)(NANOSEC));
	replica_rebuild_start_time = replica_start_time +
	    (hrtime_t)(total_time_in_sec/9 * (hrtime_t)(NANOSEC));

	rebuild_info.to_zvol = zvol2;
	rebuild_info.from_zvol = zvol1;
	mutex_init(&rebuild_info.mtx, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&rebuild_info.cv, NULL, CV_DEFAULT, NULL);

	vol_blocks = (vol_size) / block_size;

	if (silent == 0)
		printf("Starting write..\n");

	while (1) {
		io_num++;
		blk_offset = uzfs_random(vol_blocks - 16);
		offset = blk_offset * block_size;

		idx = uzfs_random(15);

		populate_string(buf[idx], (idx + 1) * block_size);

		err = uzfs_write_data(zvol1, buf[idx], offset,
		    (idx + 1) * block_size, NULL, B_FALSE);
		if (err != 0)
			printf("IO error at offset: %lu len: %lu\n", offset,
			    (idx + 1) * block_size);

		if (replica_active) {
			err = uzfs_write_data(zvol2, buf[idx], offset,
			    (idx + 1) * block_size, NULL, B_FALSE);
			if (err != 0)
				printf("IO error at offset: %lu len: %lu\n",
				    offset, (idx + 1) * block_size);
		} else {
			mismatch_count += (idx + 1) * block_size;
		}

		if (err)
			exit(2);

		iops += (idx + 1);
		now = gethrtime();
		if (now > replica_down_time && now < replica_start_time) {
			replica_active = B_FALSE;
		} else if (now > replica_start_time && !replica_active) {
			uzfs_zvol_set_status(zvol2, ZVOL_STATUS_DEGRADED);
			replica_active = B_TRUE;
		} else if (now > replica_rebuild_start_time &&
		    !rebuilding_started) {
			mutex_enter(&rebuild_info.mtx);
			rebuilding_thread = zk_thread_create(NULL, 0,
			    (thread_func_t)rebuild_replica_thread,
			    &rebuild_info, 0, NULL, TS_RUN, 0,
			    PTHREAD_CREATE_DETACHED);

			while (!rebuilding_started) {
				cv_wait(&rebuild_info.cv,
				    &rebuild_info.mtx);
				rebuilding_started = B_TRUE;
				mutex_exit(&rebuild_info.mtx);
			}
			printf("rebuilding started\n");
		}

		if (now > end)
			break;
	}
	for (j = 0; j < 15; j++)
		umem_free(buf[j], sizeof (char) * (j + 1) * block_size);

	if (silent == 0)
		printf("Stopping write.. ios done: %lu\n", iops);

	printf("other replica missed %lu bytes during downtime\n",
	    mismatch_count);

	mutex_enter(&rebuild_info.mtx);
	while (rebuild_info.active)
		cv_wait(&rebuild_info.cv, &rebuild_info.mtx);
	mutex_exit(&rebuild_info.mtx);

	mutex_destroy(&rebuild_info.mtx);
	cv_destroy(&rebuild_info.cv);

	mutex_enter(mtx);
	*threads_done = *threads_done + 1;
	cv_signal(cv);
	mutex_exit(mtx);

	zk_thread_exit();
}

void
create_and_init_pool(void **spa, void **zvol)
{
	int err;
	char *pool_name, *file_name, *zvol_name;
	uint32_t index;
	spa_t *t_spa;
	zvol_state_t *t_zvol;

	index = atomic_inc_32_nv(&f_index);
	pool_name = kmem_asprintf("%s%d", POOL_NAME, index);
	file_name = kmem_asprintf("%s%d", FILE_PATH, index);
	zvol_name = kmem_asprintf("%s%d", ZVOL_NAME, index);

	unlink(file_name);
	make_vdev(file_name);

	err = uzfs_create_pool(pool_name, file_name, &t_spa);
	if (t_spa == NULL || err != 0) {
		printf("shouldn't create pool(%s) with non existing"
		    " disk..err(%d)\n", pool_name, err);
		exit(1);
	}

	err = uzfs_create_dataset(t_spa, zvol_name, vol_size,
	    block_size, &t_zvol);
	if (t_zvol == NULL || err != 0) {
		printf("creating ds(%s) errored %d..\n", zvol_name, err);
		exit(1);
	}

	*spa = t_spa;
	*zvol = t_zvol;

	strfree(pool_name);
	strfree(file_name);
	strfree(zvol_name);
}

void
verify_overlaps(void *zv, uint64_t offset, uint64_t len, int num_args, ...)
{
	list_t *list, check_list;
	va_list arg_list;
	int count, num_chunks;
	uzfs_io_chunk_list_t *node1, *node2;
	uzfs_io_chunk_list_t *chunk_io;
	int i;

	num_chunks = num_args / 2;
	count = uzfs_search_incoming_io_tree(zv, offset, len, (void **)&list);

	if (count != num_chunks) {
		printf("argument mismatch\n");
		exit(1);
	}

	list_create(&check_list, sizeof (uzfs_io_chunk_list_t),
	    offsetof(uzfs_io_chunk_list_t, link));

	va_start(arg_list, num_args);
	for (i = 0; i < num_args; i += 2) {
		chunk_io = umem_alloc(sizeof (*chunk_io), UMEM_NOFAIL);
		chunk_io->offset = va_arg(arg_list, int);
		chunk_io->len = va_arg(arg_list, int);
		list_insert_tail(&check_list, chunk_io);
	}

	va_end(arg_list);

	while ((node1 = list_remove_head(list))) {
		for (node2 = list_head(&check_list); node2 != NULL;
		    node2 = list_next(&check_list, node2)) {
			if (node2->offset == node1->offset &&
			    node2->len == node1->len) {
				list_remove(&check_list, node2);
				umem_free(node2, sizeof (*node2));
				break;
			}
		}
		umem_free(node1, sizeof (*node1));
	}

	VERIFY(list_is_empty(list));
	VERIFY(list_is_empty(&check_list));

	list_destroy(list);
	list_destroy(&check_list);
	umem_free(list, sizeof (*list));
}

void
uzfs_test_check_overlaps(void *zv)
{
	uzfs_add_to_incoming_io_tree(zv, 100, 150);
	uzfs_add_to_incoming_io_tree(zv, 300, 450);
	uzfs_add_to_incoming_io_tree(zv, 800, 100);

	// offset == entry offset
	verify_overlaps(zv, 100, 120, 0);
	verify_overlaps(zv, 100, 150, 0);
	verify_overlaps(zv, 100, 160, 2, 250, 10);
	verify_overlaps(zv, 100, 800, 4, 250, 50, 750, 50);

	// offset > entry offset
	verify_overlaps(zv, 120, 130, 0);
	verify_overlaps(zv, 120, 100, 0);
	verify_overlaps(zv, 120, 150, 2, 250, 20);
	verify_overlaps(zv, 120, 300, 2, 250, 50);

	// offset < entry offset
	verify_overlaps(zv, 50, 60, 2, 50, 50);
	verify_overlaps(zv, 50, 100, 2, 50, 50);
	verify_overlaps(zv, 50, 220, 4, 50, 50, 250, 20);
	verify_overlaps(zv, 50, 1000, 8, 50, 50, 250, 50, 750, 50, 900, 150);
}

void
uzfs_rebuild_test(void *arg)
{
	uzfs_test_info_t *test_info = (uzfs_test_info_t *)arg;
	kmutex_t mtx;
	kcondvar_t cv;
	int threads_done = 0, num_threads = 0;
	kthread_t *writer, *reader;
	worker_args_t writer_args, **reader_args;
	int reader_count;
	int n = 0, check = 0;

	printf("starting %s\n", test_info->name);

	while (n++ < test_iterations) {
		create_and_init_pool(&spa1, &zvol1);
		create_and_init_pool(&spa2, &zvol2);

		mutex_init(&mtx, NULL, MUTEX_DEFAULT, NULL);
		cv_init(&cv, NULL, CV_DEFAULT, NULL);

		writer_args.zv = NULL;
		writer_args.threads_done = &threads_done;
		writer_args.mtx = &mtx;
		writer_args.cv = &cv;
		writer_args.io_block_size = io_block_size;
		writer_args.active_size = active_size;

		/* for test purpose only */
		uzfs_zvol_set_status(zvol1, ZVOL_STATUS_HEALTHY);
		uzfs_zvol_set_status(zvol2, ZVOL_STATUS_HEALTHY);

		writer = zk_thread_create(NULL, 0,
		    (thread_func_t)replica_writer_thread, &writer_args, 0, NULL,
		    TS_RUN, 0, PTHREAD_CREATE_DETACHED);
		num_threads++;

		mutex_enter(&mtx);
		while (threads_done != num_threads)
			cv_wait(&cv, &mtx);
		mutex_exit(&mtx);

		reader_count = 4;
		int i = 0;

		reader_args = umem_alloc(sizeof (*reader_args) * reader_count,
		    UMEM_NOFAIL);

		for (i = 0; i < reader_count; i++) {
			worker_args_t *r_arg;
			struct replica_read_data *r_data;

			r_arg = umem_alloc(sizeof (*r_arg), UMEM_NOFAIL);
			r_data = umem_alloc(sizeof (*r_data), UMEM_NOFAIL);

			r_data->offset = i * ((vol_size) / reader_count);
			r_data->len = (vol_size) / reader_count;
			r_arg->zv = r_data;
			r_arg->threads_done = &threads_done;
			r_arg->mtx = &mtx;
			r_arg->cv = &cv;
			r_arg->io_block_size = io_block_size;
			r_arg->active_size = active_size;
			reader_args[i] = r_arg;

			reader = zk_thread_create(NULL, 0,
			    (thread_func_t)replica_reader_thread,
			    reader_args[i], 0, NULL, TS_RUN, 0,
			    PTHREAD_CREATE_DETACHED);
			num_threads++;
		}

		mutex_enter(&mtx);
		while (threads_done != num_threads)
			cv_wait(&cv, &mtx);
		mutex_exit(&mtx);

		for (i = 0; i < reader_count; i++) {
			worker_args_t *r_arg;

			r_arg  = reader_args[i];
			umem_free(r_arg->zv, sizeof (*r_arg->zv));
			umem_free(r_arg, sizeof (*r_arg));
		}

		umem_free(reader_args, sizeof (*reader_args) * reader_count);

		cv_destroy(&cv);
		mutex_destroy(&mtx);

		/*
		 * This is a small test only to verify most possibilities
		 * of overlapping IO
		 */
		if (!check++)
			uzfs_test_check_overlaps(zvol1);

		uzfs_close_dataset(zvol1);
		uzfs_close_dataset(zvol2);
		uzfs_close_pool(spa1);
		uzfs_close_pool(spa2);
		printf("%s pass:%d\n", test_info->name, n);
	}
}
