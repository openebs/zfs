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
#include <sys/spa.h>
#include <sys/uzfs_zvol.h>
#include <uzfs_mgmt.h>
#include <uzfs_io.h>
#include <zrepl_mgmt.h>
#include <uzfs_zap.h>
#include <uzfs_rebuilding.h>
#include <uzfs_test.h>
#include <string.h>

extern void make_vdev(char *path);
extern void populate_string(char *buf, uint64_t size);
extern void uzfs_test_import_pool(char *pool_name);

spa_t *spa1, *spa2;
zvol_state_t *zvol1, *zvol2;

#define	POOL_NAME	"testpool"
#define	ZVOL_NAME	"testzvol"
#define	FILE_PATH	"/tmp/uzfstest.xyz"

struct rebuilding_info {
	zvol_state_t *to_zvol;
	zvol_state_t *from_zvol;
	uint64_t base_io_num;
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
	uint64_t base_io;
};

struct replica_read_data {
	uint64_t offset;
	uint64_t len;
};

static uint64_t
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

static void
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
	int read_error, md_error;

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
		idx = 0;
		len1 = 0;
		len2 = 0;

		if (offset >= end)
			break;
		len = (idx + 1) * block_size;

		if ((offset + len) > end)
			len = end - offset;
		memset(buf1[idx], 0, len);
		memset(buf2[idx], 0, len);
		err = uzfs_read_data(zvol1, buf1[idx], offset, len,
		    NULL, &read_error, &md_error);
		if (err != 0) {
			printf("IO error at offset: %lu len: %lu in read"
			    " err(%d)\n", offset, len, err);
			exit(1);
		}

		err = uzfs_read_data(zvol2, buf2[idx], offset, len,
		    NULL, &read_error, &md_error);
		if (err != 0) {
			printf("IO error at offset: %lu len: %lu in read"
			    " err(%d)\n", offset, len, err);
			exit(1);
		}

		uint64_t mismatch;
		mismatch = verify_replica_data(buf1[idx], buf2[idx], len);
		mismatch_count += mismatch;

		if (mismatch) {
			printf("verification error at %lu, mismatch:%lu\n",
			    offset, mismatch);
		}

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
uzfs_test_meta_diff_traverse_cb(off_t offset, size_t len,
    blk_metadata_t *md, zvol_state_t *snap_zv, void *arg)
{
	uzfs_rebuild_data_t *r_data = (uzfs_rebuild_data_t *)arg;
	uzfs_io_chunk_list_t *io;
	int err = 0;

	io = umem_alloc(sizeof (*io), UMEM_NOFAIL);
	io->offset = offset;
	io->len = len;
	io->io_number = md->io_num;
	io->buf = umem_alloc(len, UMEM_NOFAIL);

	err = uzfs_read_data(snap_zv, io->buf, offset, len, NULL, NULL, NULL);
	if (err) {
		printf("Failed to read data from snapshot(%s) err(%d)\n",
		    snap_zv->zv_name, err);
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

static void
check_snapshot(zvol_state_t *zv, blk_metadata_t *md, boolean_t err)
{
	objset_t *s_obj;
	char *dataset;
	int ret = 0;

	dataset = kmem_asprintf("%s@%s%lu", zv->zv_name,
	    IO_DIFF_SNAPNAME, md->io_num);

	ret = dmu_objset_own(dataset, DMU_OST_ANY, B_TRUE, zv, &s_obj);
	if ((ret != 0 && err) ||
	    (!err && ret == 0)) {
		printf("ret:%d\n", ret);
		printf("snapshot %s %s\n", dataset,
		    (err) ? "should not be removed" : "should be removed");
		exit(1);
	}

	if (ret == 0)
		dmu_objset_disown(s_obj, zv);
}

static void
fetch_modified_data(void *arg)
{
	struct rebuilding_data *repl_data = arg;
	uzfs_rebuild_data_t *r_data = repl_data->r_data;
	int err;
	blk_metadata_t md;
	off_t offset, end;
	size_t len;
	int max_count = 4;

	printf("fetching modified data\n");
	md.io_num = repl_data->base_io;

	len = r_data->zvol->zv_volsize / max_count;

	for (offset = 0; offset < r_data->zvol->zv_volsize; ) {
		end = offset + len;
		if (end > r_data->zvol->zv_volsize)
			len = r_data->zvol->zv_volsize - offset;

		err = uzfs_get_io_diff(repl_data->zvol, &md,
		    uzfs_test_meta_diff_traverse_cb, offset, len,
		    r_data);
		if (err)
			break;

		offset += len;
		if (offset != r_data->zvol->zv_volsize)
			check_snapshot(repl_data->zvol, &md, B_TRUE);
		else
			break;
	}

	if (err) {
		printf("error(%d)... while fetching modified data\n", err);
		exit(1);
	}

	check_snapshot(repl_data->zvol, &md, B_FALSE);

	printf("finished fetching modified data\n");

	mutex_enter(&r_data->mtx);
	r_data->done = B_TRUE;
	mutex_exit(&r_data->mtx);

	zk_thread_exit();
}

static void
rebuild_replica_thread(void *arg)
{
	struct rebuilding_info *r_info = arg;
	r_info->active = B_TRUE;
	zvol_state_t *from_zvol = r_info->from_zvol;
	zvol_state_t *to_zvol = r_info->to_zvol;
	list_t *io_list;
	uzfs_rebuild_data_t r_data;
	struct rebuilding_data repl_data;
	kthread_t *tid = NULL;
	uzfs_io_chunk_list_t *node = NULL;
	int err = 0;
	uint64_t diff_data = 0;
	uint64_t latest_io;

	uzfs_zvol_set_rebuild_status(to_zvol, ZVOL_REBUILDING_INIT);

	latest_io = uzfs_zvol_get_last_committed_io_no(from_zvol,
	    HEALTHY_IO_SEQNUM);
	printf("io number... healthy replica:%lu degraded replica:%lu\n",
	    latest_io, r_info->base_io_num);
	uzfs_zvol_set_rebuild_status(to_zvol, ZVOL_REBUILDING_SNAP);

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

	repl_data.r_data = &r_data;
	repl_data.base_io = r_info->base_io_num;
	repl_data.zvol = from_zvol;

	tid = zk_thread_create(NULL, 0,
	    (thread_func_t)fetch_modified_data, &repl_data, 0, NULL,
	    TS_RUN, 0, PTHREAD_CREATE_DETACHED);

	mutex_enter(&r_data.mtx);
	while (!r_data.done || (node = list_remove_head(io_list)) != NULL) {
		blk_metadata_t temp_metadata;

		if (!node) {
			mutex_exit(&r_data.mtx);
			// sleep for some time here
			usleep(1000);
			mutex_enter(&r_data.mtx);
			continue;
		}
		mutex_exit(&r_data.mtx);

		temp_metadata.io_num = node->io_number;

		err = uzfs_write_data(to_zvol, node->buf, node->offset,
		    node->len, &temp_metadata, B_TRUE);
		if (err) {
			printf("IO error at offset: %lu len: %lu in rebuild"
			    " err(%d)\n", node->offset, node->len, err);
			exit(2);
		}
		diff_data += node->len;

		umem_free(node->buf, node->len);
		umem_free(node, sizeof (*node));
		mutex_enter(&r_data.mtx);
	}

	mutex_exit(&r_data.mtx);

	printf("rebuilding finished.. written:%lu, actual written:%lu\n",
	    diff_data, to_zvol->rebuild_info.rebuild_bytes);
	umem_free(io_list, sizeof (*io_list));
	mutex_destroy(&r_data.mtx);
	cv_destroy(&r_data.cv);

	uzfs_zvol_set_rebuild_status(to_zvol, ZVOL_REBUILDING_DONE);

	/*
	 * Degraded replica has finished rebuilding.. setting status to
	 * ZVOL_STATUS_HEALTHY
	 */
	uzfs_zvol_set_status(to_zvol, ZVOL_STATUS_HEALTHY);

	mutex_enter(&r_info->mtx);
	r_info->active = B_FALSE;
	cv_signal(&r_info->cv);
	mutex_exit(&r_info->mtx);

	zk_thread_exit();
}

static void
uzfs_zvol_store_last_committed_io_no(zvol_state_t *zv, char *key,
    uint64_t io_seq)
{
	uzfs_zap_kv_t *kv_array[0];
	uzfs_zap_kv_t zap;

	if (io_seq == 0)
		return;

	zap.key = key;
	zap.value = io_seq;
	zap.size = sizeof (io_seq);

	kv_array[0] = &zap;
	VERIFY0(uzfs_update_zap_entries(zv,
	    (const uzfs_zap_kv_t **) kv_array, 1));
}

static void
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
	uint64_t last_io_num = 0;

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
		    (idx + 1) * block_size, (blk_metadata_t *)&io_num, B_FALSE);
		if (err != 0) {
			printf("IO error at offset: %lu len: %lu in write"
			    " err(%d)\n", offset, (idx + 1) * block_size, err);
			exit(1);
		}

		/*
		 * update ZAP entries for io_number frequently.
		 */
		if (!(io_num % 30)) {
			uzfs_zvol_store_last_committed_io_no(zvol1,
			    HEALTHY_IO_SEQNUM, io_num);
			if (replica_active)
				uzfs_zvol_store_last_committed_io_no(zvol2,
				    HEALTHY_IO_SEQNUM, io_num);
		}

		if (replica_active) {
			err = uzfs_write_data(zvol2, buf[idx], offset,
			    (idx + 1) * block_size, (blk_metadata_t *)&io_num,
			    B_FALSE);
			if (err != 0) {
				printf("IO error at offset: %lu len: %lu"
				    " in write err(%d)\n", offset,
				    (idx + 1) * block_size, err);
				exit(1);
			}
		} else {
			mismatch_count += (idx + 1) * block_size;
		}

		iops += (idx + 1);
		now = gethrtime();
		if (now > replica_down_time && now < replica_start_time) {
			replica_active = B_FALSE;
		} else if (now > replica_start_time && !replica_active) {
			uzfs_zvol_set_status(zvol2, ZVOL_STATUS_DEGRADED);

			replica_active = B_TRUE;
			printf("other replica missed %lu bytes during "
			    "downtime\n", mismatch_count);

			/*
			 * For testing purpose, we will copy last committed
			 * io_number from degraded replica to some variable
			 * and continue to update last_committed_io_number in
			 * degraded replica.
			 */
			last_io_num = uzfs_zvol_get_last_committed_io_no(zvol2,
			    HEALTHY_IO_SEQNUM);
			rebuild_info.base_io_num = last_io_num;
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

static void
open_pool_and_dataset(spa_t **spa, char *pool_name, char *ds_name)
{
	int err;

	uzfs_test_import_pool(pool_name);
	err = uzfs_open_pool(pool_name, spa);
	if (err != 0) {
		printf("pool(%s) open errored.. %d\n", pool_name, err);
		exit(1);
	}
}

static void
close_pool_and_dataset(spa_t *spa, zvol_state_t *zvol)
{
	uzfs_close_dataset(zvol);
	uzfs_close_pool(spa);
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
	int n = 0;
	char *pooldup = strdup(pool);
	char *dsdup = strdup(ds);
	char *pool1, *pool2, *ds1, *ds2;
	printf("starting %s\n", test_info->name);

	pool1 = strtok(pooldup, ",");
	pool2 = strtok(NULL, ",");
	ds1 = strtok(dsdup, ",");
	ds2 = strtok(NULL, ",");
	if (!ds2)
		ds2 = ds1;

	open_pool_and_dataset(&spa1, pool1, ds1);
	open_pool_and_dataset(&spa2, pool2, ds2);

	open_ds(spa1, ds1, &zvol1);
	open_ds(spa2, ds2, &zvol2);

	while (n++ < test_iterations) {
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

			r_data->offset = i * ((active_size) / reader_count);
			r_data->len = (active_size) / reader_count;
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

		printf("%s pass:%d\n", test_info->name, n);
	}

	close_pool_and_dataset(spa1, zvol1);
	close_pool_and_dataset(spa2, zvol2);
	free(pooldup);
	free(dsdup);
}
