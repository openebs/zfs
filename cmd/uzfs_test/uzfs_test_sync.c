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

int
verify_fn(void *zv, char *buf, int block_size)
{
	int err;
	uint64_t mdlen;
	void *md = NULL;
	uint64_t io_num = 0;

	if (metaverify != 0) {
		err = uzfs_read_data(zv, buf, 0, block_size, &md, &mdlen);
		if (md == NULL)
			printf("read error.. %d %p\n", err, md);
	} else
	{
		err = uzfs_read_data(zv, buf, 0, block_size, NULL, NULL);
		mdlen = 8; // just to pass condition at the end of this fn
	}

	if (err != 0)
		printf("read error.. %d %p\n", err, md);

	if (md != NULL)
		io_num = *(uint64_t *)md;
	else
		io_num = 0;

	if (silent == 0)
		printf("d:r:%d %d m:r:%lu %lu l:%lu\n", buf[0], verify, io_num,
		    metaverify, mdlen);

	if ((buf[0] == verify) && (err == 0) && (mdlen == 8) &&
	    (io_num == metaverify))
		return (0);
	else
		return (1);
}

void
write_fn(void *zv, char *buf, int block_size)
{
	int err, nometa;
	static uint64_t io_num;
	uint64_t txg1, txg2;

	io_num = uzfs_random(100);
	if (io_num == 0)
		io_num = 1;

	buf[0] = uzfs_random(100);
	if (buf[0] == 0)
		buf[0] = 1;

	/* this is to verify VERSION_0 zil records */
	nometa = uzfs_random(2);
	if (nometa == 1)
		io_num = 0;

	txg1 = uzfs_synced_txg(zv);

	err = uzfs_write_data(zv, buf, 0, block_size,
	    (nometa == 1 ? NULL : &io_num), B_FALSE);
	if (err != 0)
		printf("IO error\n");

	if (sync_data == 0)
		uzfs_flush_data(zv);

	txg2 = uzfs_synced_txg(zv);

	if (txg1 == txg2) {
		printf("%d %lu\n", buf[0], io_num);
		exit(0);
	}
}

void
test_replay(void *zv, uint64_t block_size)
{
	char *buf;
	hrtime_t end, now;

	buf = (char *)umem_alloc(sizeof (char)*block_size, UMEM_NOFAIL);

	now = gethrtime();
	end = now + (hrtime_t)(total_time_in_sec * (hrtime_t)(NANOSEC));

	if (silent == 0)
		printf("Starting %s..\n", write_op ? "write" : "verify");

	while (1) {
		if (write_op == 1)
			write_fn(zv, buf, block_size);
		else {
			verify_err = verify_fn(zv, buf, block_size);
			goto done;
		}

		now = gethrtime();

		if (now > end) {
			printf("unable to write..\n");
			break;
		}
	}
done:
	umem_free(buf, sizeof (char)*block_size);
	if (silent == 0)
		printf("Stoping %s..\n", write_op ? "write" : "verify");
	if (write_op == 1)
		exit(1);
}

void
replay_fn(void *arg)
{
	spa_t *spa;
	zvol_state_t *zv;
	char name[MAXNAMELEN];
	zvol_info_t *zinfo = NULL;

	zfs_txg_timeout = 30;

	if (write_op == 1) {
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
	} else if (verify != 0) {
		open_pool(&spa);
		if (create == 1) {
			open_ds(spa, &zv);
		} else {
			zinfo = uzfs_zinfo_lookup(ds);
			zv = zinfo->zv;
		}
	} else {
		printf("exiting program..\n");
		uzfs_fini();
		exit(1);
	}

	test_replay(zv, io_block_size);

	if (verify != 0)
		if (silent == 0)
			printf("verify error: %d\n", verify_err);
	if (create == 1) {
		uzfs_close_dataset(zv);
		uzfs_close_pool(spa);
	} else {
		strlcpy(name, zinfo->name, MAXNAMELEN);
		uzfs_zinfo_drop_refcnt(zinfo, 0);
		uzfs_zinfo_destroy(name);
		uzfs_close_pool(spa);
	}

	if (verify_err)
		exit(verify_err);
}
