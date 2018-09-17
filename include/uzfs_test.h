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

#ifndef	_UZFS_TEST_H
#define	_UZFS_TEST_H

#include <sys/spa.h>
#include <sys/uzfs_zvol.h>

extern int silent;
extern uint64_t io_block_size;
extern uint64_t metaverify;
extern int sync_data;
extern int zfs_txg_timeout;
extern int total_time_in_sec;
extern int write_op;
extern int verify_err;
extern int verify;
extern int test_iterations;
extern uint64_t active_size;
extern uint64_t vol_size;
extern uint64_t block_size;
extern uint32_t create;
extern char *pool;
extern char *ds;
extern int max_iops;

extern unsigned long zfs_arc_max;
extern unsigned long zfs_arc_min;

extern void replay_fn(void *arg);
extern void setup_unit_test(void);
extern void unit_test_create_pool_ds(void);
extern void open_pool(spa_t **);
extern void open_ds(spa_t *, char *, zvol_state_t **);

typedef struct worker_args {
	void *zv;
	kmutex_t *mtx;
	kcondvar_t *cv;
	uint64_t *total_ios;
	int *threads_done;
	uint64_t io_block_size;
	uint64_t active_size;
	int sfd[2];
	int max_iops;
	int rebuild_test;
} worker_args_t;

typedef struct uzfs_test_info {
	thread_func_t func;
	char *name;
} uzfs_test_info_t;

void uzfs_zvol_zap_operation(void *arg);
void unit_test_fn(void *arg);
void zrepl_utest(void *arg);
void uzfs_rebuild_test(void *arg);
void zrepl_rebuild_test(void *arg);
void unmap_test_fn(void *arg);
#endif
