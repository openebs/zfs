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

/*
 * Copyright (c) 2018 CloudByte, Inc. All rights reserved.
 */

#include <gtest/gtest.h>
#include <unistd.h>

/* Avoid including conflicting C++ declarations for LE-BE conversions */
#define _SYS_BYTEORDER_H
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/spa.h>
#include <libuzfs.h>
#include <zrepl_mgmt.h>
#include <mgmt_conn.h>
#include <data_conn.h>
#include <uzfs_mgmt.h>
#include <sys/epoll.h>

#include <uzfs_rebuilding.h>

#include "gtest_utils.h"

char *ds_name;
char *ds_name2;
char *pool;
spa_t *spa;
zvol_state_t *zv;
zvol_state_t *zv2;
zvol_info_t *zinfo;
zvol_info_t *zinfo2;
int rebuild_test_case = 0;
int data_conn_fd = -1;

extern void (*zinfo_create_hook)(zvol_info_t *, nvlist_t *);
extern void (*zinfo_destroy_hook)(zvol_info_t *);
int receiver_created = 0;
extern uint64_t zvol_rebuild_step_size;

void (*dw_replica_fn)(void *);
#if DEBUG
inject_error_t inject_error;
#endif

void
make_vdev(const char *path)
{
	int fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0666);
	if (fd == -1) {
		printf("can't open %s", path);
		exit(1);
	}
	if (ftruncate(fd, 1024*1024*1024) != 0) {
		printf("can't ftruncate %s", path);
		exit(1);
	}
	(void) close(fd);
}

void
uzfs_mock_io_receiver(void *arg)
{
	int fd = (int)(uintptr_t)arg;
	int rc;
	char buf[100];
	uint64_t nbytes = 20;

	receiver_created = 1;
again:
	rc = uzfs_zvol_socket_read(fd, buf, nbytes);
	if (rc >= 0)
		goto again;

	zk_thread_exit();
}

void
uzfs_mock_rebuild_scanner(void *arg)
{
	int fd = (int)(uintptr_t)arg;
	zvol_io_hdr_t hdr;
	int rc;
	int rcvsize = 30;
	int sndsize = 30;
	char *buf;
	uint64_t cnt;
	struct zvol_io_rw_hdr *io_hdr;
	struct linger lo = { 1, 0 };

	rc = setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvsize, sizeof(int));
	EXPECT_NE(rc, -1);

	rc = setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sndsize, sizeof(int));
	EXPECT_NE(rc, -1);

	rc = setsockopt(fd, SOL_SOCKET, SO_LINGER, &lo, sizeof(lo));
	EXPECT_NE(rc, -1);

	if (rebuild_test_case == 1)
		goto exit1;

	if (rebuild_test_case == 2)
		goto exit;

	/* Read HANDSHAKE */
	rc = uzfs_zvol_socket_read(fd, (char *)&hdr, sizeof (hdr));
	EXPECT_NE(rc, -1);
	EXPECT_EQ(hdr.opcode, ZVOL_OPCODE_HANDSHAKE);

	buf = (char *)malloc(hdr.len);
	rc = uzfs_zvol_socket_read(fd, (char *)buf, hdr.len);
	EXPECT_NE(rc, -1);
	free(buf);

	/* Read REBUILD_STEP */
	rc = uzfs_zvol_socket_read(fd, (char *)&hdr, sizeof (hdr));
	EXPECT_NE(rc, -1);
	EXPECT_EQ(hdr.opcode, ZVOL_OPCODE_REBUILD_STEP);
	EXPECT_EQ(hdr.status, ZVOL_OP_STATUS_OK);
	EXPECT_EQ(hdr.len, zvol_rebuild_step_size);

	hdr.opcode = ZVOL_OPCODE_READ;
	hdr.flags = ZVOL_OP_FLAG_REBUILD;
	hdr.len = 512;
	hdr.offset = 0;
	/* Write hdr with FAILED status */
	if (rebuild_test_case == 3)
		hdr.status = ZVOL_OP_STATUS_FAILED;
	/* Write hdr with invalid write IO */
	else if (rebuild_test_case == 4)
		hdr.len = 512;
	/* Write hdr with valid write IO */
	else
		hdr.len = 512 + sizeof (struct zvol_io_rw_hdr);

	rc = uzfs_zvol_socket_write(fd, (char *)&hdr, sizeof(hdr));
	EXPECT_NE(rc, -1);

	if (rebuild_test_case == 3) {
		rc = uzfs_zvol_socket_read(fd, (char *)&hdr, sizeof (hdr));
		EXPECT_EQ(rc, -1);
		goto exit;
	}

	buf = (char *)malloc(hdr.len);
	cnt = zinfo->write_req_received_cnt;

	if (rebuild_test_case != 4) {
		io_hdr = (struct zvol_io_rw_hdr *)buf;
		io_hdr->io_num = 1000;
		io_hdr->len = 512;
	}

	rc = uzfs_zvol_socket_write(fd, (char *)buf, 100);
	EXPECT_NE(rc, -1);

	rc = uzfs_zvol_socket_write(fd, (char *)buf + 100, 100);
	EXPECT_NE(rc, -1);

	rc = uzfs_zvol_socket_write(fd, (char *)buf + 200, hdr.len - 200);
	EXPECT_NE(rc, -1);
	/* check for write cnt */
	while (1) {
		if (zinfo->write_req_received_cnt != (cnt + 1))
			sleep(1);
		else
			break;
	}
	free(buf);

	if ((rebuild_test_case == 4) || (rebuild_test_case == 5))
		goto exit;

	/* Write REBUILD_STEP_DONE */
	hdr.opcode = ZVOL_OPCODE_REBUILD_STEP_DONE;
	hdr.status = ZVOL_OP_STATUS_OK;
	hdr.len = 0;
	rc = uzfs_zvol_socket_write(fd, (char *)&hdr, sizeof(hdr));
	EXPECT_NE(rc, -1);

	if (rebuild_test_case == 6) {
		close(data_conn_fd);
		sleep(5);
	}

	/* Read REBUILD_STEP */
	rc = uzfs_zvol_socket_read(fd, (char *)&hdr, sizeof (hdr));
	if (rebuild_test_case == 6) {
		if (rc != -1)
			rc = uzfs_zvol_socket_read(fd, (char *)&hdr, sizeof (hdr));
		EXPECT_EQ(rc, -1);
		sleep(3);
		goto exit;
	}

	EXPECT_NE(rc, -1);
	EXPECT_EQ(hdr.opcode, ZVOL_OPCODE_REBUILD_STEP);
	EXPECT_EQ(hdr.status, ZVOL_OP_STATUS_OK);
	EXPECT_EQ(hdr.len, zvol_rebuild_step_size - 2000);

	/* Write REBUILD_STEP_DONE */
	hdr.opcode = ZVOL_OPCODE_REBUILD_STEP_DONE;
	hdr.status = ZVOL_OP_STATUS_OK;
	hdr.len = 0;
	rc = uzfs_zvol_socket_write(fd, (char *)&hdr, sizeof(hdr));
	EXPECT_NE(rc, -1);

	/* Read REBUILD_COMPLETE */
	rc = uzfs_zvol_socket_read(fd, (char *)&hdr, sizeof (hdr));
	EXPECT_NE(rc, -1);
	EXPECT_EQ(hdr.opcode, ZVOL_OPCODE_REBUILD_COMPLETE);
	EXPECT_EQ(hdr.status, ZVOL_OP_STATUS_OK);

exit:
	shutdown(fd, SHUT_RDWR);
exit1:
	rebuild_test_case = 0;
	close(fd);
	zk_thread_exit();
}

void
setup_unit_test(char *path)
{
	make_vdev(path);
}

/* This will be called once for uZFS tests */
TEST(uZFS, Setup) {
	char *path;
	int ret;
	char *pool_ds;
	char *pool_ds2;
	ds_name = (char *)malloc(MAXNAMELEN);
	ds_name2 = (char *)malloc(MAXNAMELEN);
	pool_ds = (char *)malloc(MAXNAMELEN);
	pool_ds2 = (char *)malloc(MAXNAMELEN);
	path = (char *)malloc(MAXNAMELEN);
	pool = (char *)malloc(MAXNAMELEN);

	GtestUtils::strlcpy(path, "/tmp/uztest.1a", MAXNAMELEN);
	GtestUtils::strlcpy(pool, "pool1", MAXNAMELEN);
	GtestUtils::strlcpy(ds_name, "vol1", MAXNAMELEN);
	GtestUtils::strlcpy(ds_name2, "vol3", MAXNAMELEN);
	GtestUtils::strlcpy(pool_ds, "pool1/vol1", MAXNAMELEN);
	GtestUtils::strlcpy(pool_ds2, "pool1/vol3", MAXNAMELEN);
	signal(SIGPIPE, SIG_IGN);

	mutex_init(&conn_list_mtx, NULL, MUTEX_DEFAULT, NULL);
	SLIST_INIT(&uzfs_mgmt_conns);
	mutex_init(&async_tasks_mtx, NULL, MUTEX_DEFAULT, NULL);
	mgmt_eventfd = -1;

	uzfs_init();
	init_zrepl();
	setup_unit_test(path);
	ret = uzfs_create_pool(pool, path, &spa);
	EXPECT_EQ(0, ret);

	uzfs_create_dataset(spa, ds_name, 1024*1024*1024, 512, &zv);
	uzfs_hold_dataset(zv);
	uzfs_update_metadata_granularity(zv, 512);

	zinfo_create_hook = &zinfo_create_cb;
	zinfo_destroy_hook = &zinfo_destroy_cb;

	io_receiver = &uzfs_mock_io_receiver;
	rebuild_scanner = &uzfs_mock_io_receiver;

	zrepl_log_level = LOG_LEVEL_DEBUG;

	/* give time to get the zfs threads created */
	sleep(5);
	/*Create vol3 */
	uzfs_create_dataset(spa, ds_name2, 1024*1024*1024, 512, &zv2);
	uzfs_hold_dataset(zv2);
	uzfs_update_metadata_granularity(zv2, 512);
	strncpy(zv2->zv_target_host,"127.0.0.1:5050", MAXNAMELEN);
	uzfs_zinfo_init(zv2, pool_ds2, NULL);
	zinfo2 = uzfs_zinfo_lookup(ds_name2);
	EXPECT_EQ(0, !zinfo2);

	uzfs_zinfo_init(zv, pool_ds, NULL);
	zinfo = uzfs_zinfo_lookup(ds_name);
	EXPECT_EQ(0, !zinfo);

	EXPECT_GT(kthread_nr, 0);
}

int
uzfs_mgmt_conn_list_count(struct uzfs_mgmt_conn_list *list)
{
	int count = 0;
	uzfs_mgmt_conn_t *mgmt_conn;

	SLIST_FOREACH(mgmt_conn, list, conn_next)
		count++;

	return count;
}

static void 
test_alloc_async_task_and_add_to_list(zvol_info_t *zinfo,
    uzfs_mgmt_conn_t *conn, boolean_t finished, boolean_t conn_closed)
{
	async_task_t *arg;

	uzfs_zinfo_take_refcnt(zinfo);
	arg = (async_task_t *)kmem_zalloc(sizeof (async_task_t), KM_SLEEP);
	arg->conn = conn;
	arg->zinfo = zinfo;
	arg->payload_length = 0;
	arg->payload = NULL;
	arg->finished = finished;
	arg->conn_closed = conn_closed;
	mutex_enter(&async_tasks_mtx);
	SLIST_INSERT_HEAD(&async_tasks, arg, task_next);
	mutex_exit(&async_tasks_mtx);
	return;
}

static int
async_tasks_count()
{
	int count = 0;
	async_task_t *async_task = NULL;

	mutex_enter(&async_tasks_mtx);

	SLIST_FOREACH(async_task, &async_tasks, task_next)
		count++;

	mutex_exit(&async_tasks_mtx);

	return count;
}

TEST(uZFS, asyncTaskProps) {

	async_task_t *arg;
	uzfs_mgmt_conn_t *conn;


	conn = SLIST_FIRST(&uzfs_mgmt_conns);

	/*
	 * Create async_task and mark it un-finished so
	 * that finish_async_tasks() should not process it.
	 */
	test_alloc_async_task_and_add_to_list(zinfo, conn, B_FALSE, B_FALSE);
	finish_async_tasks();

	EXPECT_EQ(1, async_tasks_count());

	/*
	 * Mark async_task finished to true, so that
	 * finish_async_task process it. Since conn_clossed
	 * set to false, it should able to send reply too.
	 * Reply would be failed because of fd is -1.
	 * It should error out after freeing task.
	 */
	arg = SLIST_FIRST(&async_tasks);
	arg->finished = B_TRUE;
	finish_async_tasks();

	EXPECT_EQ(0, async_tasks_count());

	kmem_free(conn->conn_buf, sizeof (zvol_io_hdr_t));
	conn->conn_buf = NULL;

	/*
	 * Create async_task and mark it finished as well as
	 * conn closed so that that finish_async_tasks()
	 * should process it, free it.
	 */
	test_alloc_async_task_and_add_to_list(zinfo, conn, B_TRUE, B_TRUE);

	/*
	 * Create async_task and mark it finished as well as
	 * conn closed so that that finish_async_tasks()
	 *  should process it, free it.
	 */
	test_alloc_async_task_and_add_to_list(zinfo, conn, B_TRUE, B_TRUE);
	EXPECT_EQ(2, async_tasks_count());

	finish_async_tasks();
	EXPECT_EQ(0, async_tasks_count());
}

TEST(uZFS, EmptyCreateProps) {
	uzfs_mgmt_conn_t *conn;

	EXPECT_EQ(2, uzfs_mgmt_conn_list_count(&uzfs_mgmt_conns));
	conn = SLIST_FIRST(&uzfs_mgmt_conns);
	EXPECT_EQ(1, conn->conn_refcount);

	zinfo_create_cb(zinfo, NULL);
	EXPECT_EQ(2, uzfs_mgmt_conn_list_count(&uzfs_mgmt_conns));
	conn = SLIST_FIRST(&uzfs_mgmt_conns);
	EXPECT_EQ(2, conn->conn_refcount);
}

TEST(uZFS, TestZInfoRefcnt) {
	int ret;
	zvol_info_t *zinfo1;
 	char *ds1 = (char *)malloc(MAXNAMELEN);

	EXPECT_EQ(2, zinfo->refcnt);

	uzfs_zinfo_drop_refcnt(zinfo);
	EXPECT_EQ(1, zinfo->refcnt);

	GtestUtils::strlcpy(ds1, "vol1 ", MAXNAMELEN);
	zinfo1 = uzfs_zinfo_lookup(ds1);
	EXPECT_EQ(NULL, zinfo1);

	GtestUtils::strlcpy(ds1, "vol2", MAXNAMELEN);
	zinfo1 = uzfs_zinfo_lookup(ds1);
	EXPECT_EQ(NULL, zinfo1);

	GtestUtils::strlcpy(ds1, "vol", MAXNAMELEN);
	zinfo1 = uzfs_zinfo_lookup(ds1);
	EXPECT_EQ(NULL, zinfo1);

	GtestUtils::strlcpy(ds1, "pool1/vol", MAXNAMELEN);
	zinfo1 = uzfs_zinfo_lookup(ds1);
	EXPECT_EQ(NULL, zinfo1);

	GtestUtils::strlcpy(ds1, "pool1/vol1 ", MAXNAMELEN);
	zinfo1 = uzfs_zinfo_lookup(ds1);
	EXPECT_EQ(NULL, zinfo1);

	GtestUtils::strlcpy(ds1, "pool1/vol1/", MAXNAMELEN);
	zinfo1 = uzfs_zinfo_lookup(ds1);
	EXPECT_EQ(NULL, zinfo1);

	GtestUtils::strlcpy(ds1, "pool1/vol1", MAXNAMELEN);
	zinfo1 = uzfs_zinfo_lookup(ds1);
	EXPECT_EQ(NULL, !zinfo1);
	EXPECT_EQ(2, zinfo->refcnt);

	zinfo1 = uzfs_zinfo_lookup(NULL);
	EXPECT_EQ(NULL, zinfo1);

	GtestUtils::strlcpy(ds1, "vol1", MAXNAMELEN);
	zinfo1 = uzfs_zinfo_lookup(ds1);
	EXPECT_EQ(NULL, !zinfo1);
	EXPECT_EQ(3, zinfo->refcnt);

	uzfs_zinfo_drop_refcnt(zinfo);
	EXPECT_EQ(2, zinfo->refcnt);
}

void
set_start_rebuild_mgmt_ack(mgmt_ack_t *mack, const char *dw_name, const char *volname)
{
	GtestUtils::strlcpy(mack->dw_volname, dw_name, MAXNAMELEN);
	if (volname != NULL)
		GtestUtils::strlcpy(mack->volname, volname, MAXNAMELEN);
}

void
set_mgmt_ack_ip_port(mgmt_ack_t *mack, const char *ip, uint16_t port)
{
	GtestUtils::strlcpy(mack->ip, ip, MAX_IP_LEN);
	mack->port = port;
}

void
set_zvol_io_hdr(zvol_io_hdr_t *hdrp, zvol_op_status_t status,
    zvol_op_code_t opcode, int len)
{
	hdrp->version = REPLICA_VERSION;
	hdrp->status = status;
	hdrp->opcode = opcode;
	hdrp->len = len;
}

TEST(uZFS, TestStartRebuild) {
	int i;
	uzfs_mgmt_conn_t *conn;
	mgmt_ack_t *mack;

	zvol_rebuild_status_t rebuild_status[5];
	rebuild_status[0] = ZVOL_REBUILDING_INIT;
	rebuild_status[1] = ZVOL_REBUILDING_IN_PROGRESS;
	rebuild_status[2] = ZVOL_REBUILDING_DONE;
	rebuild_status[3] = ZVOL_REBUILDING_ERRORED;
	rebuild_status[4] = ZVOL_REBUILDING_FAILED;

	EXPECT_EQ(2, uzfs_mgmt_conn_list_count(&uzfs_mgmt_conns));
	EXPECT_EQ(2, zinfo->refcnt);
	conn = SLIST_FIRST(&uzfs_mgmt_conns);

	zvol_io_hdr_t *hdrp = (zvol_io_hdr_t *)kmem_zalloc(sizeof (*hdrp), KM_SLEEP);
	void *payload = kmem_zalloc(sizeof (mgmt_ack_t) * 5, KM_SLEEP);
	mack = (mgmt_ack_t *)payload;
	set_zvol_io_hdr(hdrp, ZVOL_OP_STATUS_OK, ZVOL_OPCODE_PREPARE_FOR_REBUILD, 0);

	/* payload is 0 */
	conn->conn_buf = NULL;
	handle_start_rebuild_req(conn, hdrp, NULL, 0);
	EXPECT_EQ(ZVOL_OP_STATUS_FAILED, ((zvol_io_hdr_t *)conn->conn_buf)->status);
	EXPECT_EQ(2, zinfo->refcnt);

	/* NULL name in payload */
	conn->conn_buf = NULL;
	handle_start_rebuild_req(conn, hdrp, payload, sizeof (mgmt_ack_t));
	EXPECT_EQ(ZVOL_OP_STATUS_FAILED, ((zvol_io_hdr_t *)conn->conn_buf)->status);
	EXPECT_EQ(2, zinfo->refcnt);

	/* invalid name in payload */
	conn->conn_buf = NULL;
	set_start_rebuild_mgmt_ack(mack, "vol2", NULL);
	handle_start_rebuild_req(conn, hdrp, payload, sizeof (mgmt_ack_t));
	EXPECT_EQ(ZVOL_OP_STATUS_FAILED, ((zvol_io_hdr_t *)conn->conn_buf)->status);
	EXPECT_EQ(2, zinfo->refcnt);

	/* invalid rebuild state */
	for (i = 1; i < 5; i++) {
		conn->conn_buf = NULL;
		uzfs_zvol_set_rebuild_status(zinfo->zv,
		    rebuild_status[i]);
		set_start_rebuild_mgmt_ack(mack, "vol1", NULL);
		handle_start_rebuild_req(conn, hdrp, payload, sizeof (mgmt_ack_t));
		EXPECT_EQ(ZVOL_OP_STATUS_FAILED, ((zvol_io_hdr_t *)conn->conn_buf)->status);
		EXPECT_EQ(2, zinfo->refcnt);
	}

	/* rebuild for single replica case */
	conn->conn_buf = NULL;
	uzfs_zvol_set_rebuild_status(zinfo->zv,
	    ZVOL_REBUILDING_INIT);
	set_start_rebuild_mgmt_ack(mack, "vol1", NULL);
	handle_start_rebuild_req(conn, hdrp, payload, sizeof (mgmt_ack_t));
	EXPECT_EQ(ZVOL_OP_STATUS_OK, ((zvol_io_hdr_t *)conn->conn_buf)->status);
	EXPECT_EQ(ZVOL_REBUILDING_DONE, uzfs_zvol_get_rebuild_status(zinfo->zv));
	EXPECT_EQ(ZVOL_STATUS_HEALTHY, uzfs_zvol_get_status(zinfo->zv));
	EXPECT_EQ(2, zinfo->refcnt);

	/* rebuild in two replicas case with 'connect' failure */
	conn->conn_buf = NULL;
	uzfs_zvol_set_rebuild_status(zinfo->zv,
	    ZVOL_REBUILDING_INIT);
	set_start_rebuild_mgmt_ack(mack, "pool1/vol1", "vol2");
	handle_start_rebuild_req(conn, hdrp, payload, sizeof (mgmt_ack_t));
	EXPECT_EQ(ZVOL_OP_STATUS_OK, ((zvol_io_hdr_t *)conn->conn_buf)->status);
	while (1) {
		/* wait to get FAILD status, and threads to return with refcnt to 2 */
		if (ZVOL_REBUILDING_FAILED != uzfs_zvol_get_rebuild_status(zinfo->zv))
			sleep(1);
		else if (2 != zinfo->refcnt)
			sleep(1);
		else
			break;
	}

	/* rebuild in three replicas case with invalid volname to rebuild */
	conn->conn_buf = NULL;
	uzfs_zvol_set_rebuild_status(zinfo->zv,
	    ZVOL_REBUILDING_INIT);
	set_start_rebuild_mgmt_ack(mack, "pool1/vol1", "vol3");
	set_start_rebuild_mgmt_ack(mack + 1, "vol2", "vol3");
	handle_start_rebuild_req(conn, hdrp, payload, sizeof (mgmt_ack_t)*2);
	EXPECT_EQ(ZVOL_OP_STATUS_FAILED, ((zvol_io_hdr_t *)conn->conn_buf)->status);
	while (1) {
		/* wait to get FAILD status, and threads to return with refcnt to 2 */
		if (ZVOL_REBUILDING_FAILED != uzfs_zvol_get_rebuild_status(zinfo->zv))
			sleep(1);
		else if (2 != zinfo->refcnt)
			sleep(1);
		else
			break;
	}

	/* rebuild in three replicas case with 'connect' failing */
	conn->conn_buf = NULL;
	uzfs_zvol_set_rebuild_status(zinfo->zv,
	    ZVOL_REBUILDING_INIT);
	set_start_rebuild_mgmt_ack(mack, "pool1/vol1", "vol3");
	set_start_rebuild_mgmt_ack(mack + 1, "pool1/vol1", "vol3");
	handle_start_rebuild_req(conn, hdrp, payload, sizeof (mgmt_ack_t)*2);
	EXPECT_EQ(ZVOL_OP_STATUS_OK, ((zvol_io_hdr_t *)conn->conn_buf)->status);
	while (1) {
		/* wait to get FAILD status, and threads to return with refcnt to 2 */
		if (ZVOL_REBUILDING_FAILED != uzfs_zvol_get_rebuild_status(zinfo->zv))
			sleep(1);
		else if (2 != zinfo->refcnt)
			sleep(1);
		else
			break;
	}
}

int
complete_q_list_count(zvol_info_t *zinfo)
{
	int count = 0;
	zvol_io_cmd_t *zio_cmd;

	STAILQ_FOREACH(zio_cmd, &zinfo->complete_queue, cmd_link)
		count++;

	return count;
}

void
create_rebuild_args(rebuild_thread_arg_t **r)
{
	rebuild_thread_arg_t *rebuild_args;
	int rcvsize = 30;
	int sndsize = 30;
	int fd, rc;

	fd = create_and_bind("", B_FALSE, B_FALSE);

	rc = setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvsize, sizeof(int));
	EXPECT_NE(rc, -1);

	rc = setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sndsize, sizeof(int));
	EXPECT_NE(rc, -1);

	rebuild_args = (rebuild_thread_arg_t *)kmem_alloc(sizeof (rebuild_thread_arg_t), KM_SLEEP);
	rebuild_args->fd = fd;
	rebuild_args->zinfo = zinfo;
	rebuild_args->port = REBUILD_IO_SERVER_PORT;
	rc = uzfs_zvol_get_ip(rebuild_args->ip, MAX_IP_LEN);
	EXPECT_NE(rc, -1);
	
	GtestUtils::strlcpy(rebuild_args->zvol_name, "vol2", MAXNAMELEN);
	*r = rebuild_args;
}

TEST(uZFS, RemovePendingCmds) {
	zvol_io_hdr_t hdr;
	zvol_io_cmd_t *zio_cmd;

	memset(&hdr, 0, sizeof (zvol_io_hdr_t));
	hdr.opcode = ZVOL_OPCODE_READ;
	EXPECT_EQ(0, complete_q_list_count(zinfo));

	/* Case of one IO in q */
	zio_cmd = zio_cmd_alloc(&hdr, 1);
	STAILQ_INSERT_TAIL(&zinfo->complete_queue, zio_cmd, cmd_link);
	EXPECT_EQ(1, complete_q_list_count(zinfo));

	remove_pending_cmds_to_ack(2, zinfo);
	EXPECT_EQ(1, complete_q_list_count(zinfo));

	remove_pending_cmds_to_ack(1, zinfo);
	EXPECT_EQ(0, complete_q_list_count(zinfo));

	/* Case of two IOs with different fds in q */
	zio_cmd = zio_cmd_alloc(&hdr, 1);
	STAILQ_INSERT_TAIL(&zinfo->complete_queue, zio_cmd, cmd_link);

	zio_cmd = zio_cmd_alloc(&hdr, 2);
	STAILQ_INSERT_TAIL(&zinfo->complete_queue, zio_cmd, cmd_link);

	EXPECT_EQ(2, complete_q_list_count(zinfo));

	remove_pending_cmds_to_ack(3, zinfo);
	EXPECT_EQ(2, complete_q_list_count(zinfo));

	remove_pending_cmds_to_ack(1, zinfo);
	EXPECT_EQ(1, complete_q_list_count(zinfo));

	remove_pending_cmds_to_ack(2, zinfo);
	EXPECT_EQ(0, complete_q_list_count(zinfo));

	/* Case of two IOs with same fds in q */
	zio_cmd = zio_cmd_alloc(&hdr, 1);
	STAILQ_INSERT_TAIL(&zinfo->complete_queue, zio_cmd, cmd_link);

	zio_cmd = zio_cmd_alloc(&hdr, 1);
	STAILQ_INSERT_TAIL(&zinfo->complete_queue, zio_cmd, cmd_link);

	EXPECT_EQ(2, complete_q_list_count(zinfo));

	remove_pending_cmds_to_ack(1, zinfo);
	EXPECT_EQ(0, complete_q_list_count(zinfo));

	/* Case of three IOs with diff fds in q */
	zio_cmd = zio_cmd_alloc(&hdr, 1);
	STAILQ_INSERT_TAIL(&zinfo->complete_queue, zio_cmd, cmd_link);

	zio_cmd = zio_cmd_alloc(&hdr, 2);
	STAILQ_INSERT_TAIL(&zinfo->complete_queue, zio_cmd, cmd_link);

	zio_cmd = zio_cmd_alloc(&hdr, 3);
	STAILQ_INSERT_TAIL(&zinfo->complete_queue, zio_cmd, cmd_link);

	EXPECT_EQ(3, complete_q_list_count(zinfo));

	remove_pending_cmds_to_ack(2, zinfo);
	EXPECT_EQ(2, complete_q_list_count(zinfo));

	remove_pending_cmds_to_ack(3, zinfo);
	EXPECT_EQ(1, complete_q_list_count(zinfo));

	remove_pending_cmds_to_ack(1, zinfo);
	EXPECT_EQ(0, complete_q_list_count(zinfo));
}

extern uint16_t io_server_port;
extern uint16_t rebuild_io_server_port;

TEST(uZFS, TestIOConnAcceptor) {
	int fd;
	int rc;
	kthread_t *conn_accpt_thread, *conn_accpt_thread1;
	char port[8];
	char ip[MAX_IP_LEN];
	struct sockaddr_in replica_io_addr;
	conn_acceptors_t *ca;

	io_server_port = IO_SERVER_PORT;
	rebuild_io_server_port = REBUILD_IO_SERVER_PORT;
	ca = (conn_acceptors_t *)kmem_zalloc(sizeof (conn_acceptors_t),
	    KM_SLEEP);

	io_receiver = &uzfs_mock_io_receiver;
	rebuild_scanner = &uzfs_mock_io_receiver;

	conn_accpt_thread = zk_thread_create(NULL, 0,
	    uzfs_zvol_io_conn_acceptor, ca, 0, NULL, TS_RUN,
	    0, PTHREAD_CREATE_DETACHED);
	EXPECT_EQ(NULL, !conn_accpt_thread);
	while (1) {
		if(ca->io_fd == 0)
			sleep(1);
		else
			break;
	}

	/* connect to io_conn_acceptor */
	bzero((char *)&replica_io_addr, sizeof (replica_io_addr));
	rc = uzfs_zvol_get_ip(ip, MAX_IP_LEN);
	EXPECT_NE(rc, -1);

	replica_io_addr.sin_family = AF_INET;
	replica_io_addr.sin_addr.s_addr = inet_addr(ip);
	replica_io_addr.sin_port = htons(IO_SERVER_PORT);

	fd = create_and_bind("", B_FALSE, B_FALSE);
	EXPECT_NE(fd, -1);

	receiver_created = 0;
	rc = connect(fd, (struct sockaddr *)&replica_io_addr,
	    sizeof (replica_io_addr));
	EXPECT_NE(rc, -1);

	while (1) {
		/* wait to create io_thread */
		if (receiver_created != 1)
			sleep(1);
		else
			break;
	}
	shutdown(fd, SHUT_RDWR);
	close(fd);

	/* connect to rebuild_conn_acceptor */
	bzero((char *)&replica_io_addr, sizeof (replica_io_addr));
	rc = uzfs_zvol_get_ip(ip, MAX_IP_LEN);
	EXPECT_NE(rc, -1);

	replica_io_addr.sin_family = AF_INET;
	replica_io_addr.sin_addr.s_addr = inet_addr(ip);
	replica_io_addr.sin_port = htons(REBUILD_IO_SERVER_PORT);

	fd = create_and_bind("", B_FALSE, B_FALSE);
	EXPECT_NE(fd, -1);

	receiver_created = 0;
	rc = connect(fd, (struct sockaddr *)&replica_io_addr,
	    sizeof (replica_io_addr));
	EXPECT_NE(rc, -1);

	while (1) {
		/* wait to create rebuild_thread */
		if (receiver_created != 1)
			sleep(1);
		else
			break;
	}
	shutdown(fd, SHUT_RDWR);
	close(fd);
}

void
uzfs_mock_zvol_rebuild_dw_replica(void *arg)
{
	rebuild_thread_arg_t *rebuild_args = (rebuild_thread_arg_t *)arg;

	struct sockaddr_in replica_ip;

	int		rc = 0;
	int		sfd = -1;
	uint64_t	offset = 0;
	uint64_t	checkpointed_ionum;
	zvol_info_t	*zinfo = NULL;
	zvol_state_t	*zvol_state;
	zvol_io_cmd_t	*zio_cmd = NULL;
	zvol_io_hdr_t 	hdr;
	struct linger lo = { 1, 0 };
	char zvol_name[MAXNAMELEN];

	strncpy(rebuild_args->zvol_name, "vol3", MAXNAMELEN);
	sfd = rebuild_args->fd;
	zinfo = rebuild_args->zinfo;

	if ((rc = setsockopt(sfd, SOL_SOCKET, SO_LINGER, &lo, sizeof (lo)))
	    != 0) {
		LOG_ERRNO("setsockopt failed");
		goto exit;
	}

	bzero(&replica_ip, sizeof (replica_ip));
	replica_ip.sin_family = AF_INET;
	replica_ip.sin_addr.s_addr = inet_addr(rebuild_args->ip);
	replica_ip.sin_port = htons(rebuild_args->port);

	if ((rc = connect(sfd, (struct sockaddr *)&replica_ip,
	    sizeof (replica_ip))) != 0) {
		LOG_ERRNO("connect failed");
		perror("connect");
		goto exit;
	}

	if (rebuild_test_case == 1) {
		rc =-1;
		goto exit;
	}

send_hdr_again:
	/* Set state in-progess state now */
	checkpointed_ionum = uzfs_zvol_get_last_committed_io_no(zinfo->zv);
	zvol_state = zinfo->zv;
	bzero(&hdr, sizeof (hdr));
	hdr.status = ZVOL_OP_STATUS_OK;
	hdr.version = REPLICA_VERSION;
	hdr.opcode = ZVOL_OPCODE_HANDSHAKE;
	hdr.len = strlen(rebuild_args->zvol_name) + 1;
	if (rebuild_test_case == 2)
		hdr.opcode = ZVOL_OPCODE_WRITE;

	rc = uzfs_zvol_socket_write(sfd, (char *)&hdr, sizeof (hdr));
	if (rc != 0) {
		LOG_ERR("Socket hdr write failed");
		goto exit;
	}

	if (rebuild_test_case == 3) {
		rc = -1;
		goto exit;
	}

	strncpy(zvol_name, rebuild_args->zvol_name, hdr.len);
	if (rebuild_test_case == 4)
		strncpy(zvol_name, "X", hdr.len);

	rc = uzfs_zvol_socket_write(sfd, zvol_name, hdr.len);
	if (rc != 0) {
		LOG_ERR("Socket handshake write failed");
		goto exit;
	}

	if (rebuild_test_case == 5)
		goto send_hdr_again;

next_step:

	bzero(&hdr, sizeof (hdr));
	hdr.status = ZVOL_OP_STATUS_OK;
	hdr.version = REPLICA_VERSION;
	hdr.opcode = ZVOL_OPCODE_REBUILD_STEP;
	hdr.checkpointed_io_seq = checkpointed_ionum;
	hdr.offset = 0;
	hdr.len = zvol_rebuild_step_size;

	if (rebuild_test_case == 6) {
		hdr.offset = -1;
		rc = uzfs_zvol_socket_write(sfd, (char *)&hdr, sizeof (hdr));
		if (rc != 0) {
			goto exit;
		}
	} else if ((rebuild_test_case == 7) || (rebuild_test_case == 8) || (rebuild_test_case == 9)) {
		/*
		 * Set offline state on vol3
		 */
#if DEBUG
		if ((rebuild_test_case == 7) || (rebuild_test_case == 8))
			inject_error.delay.helping_replica_rebuild_step = 1;
#endif
		rc = uzfs_zvol_socket_write(sfd, (char *)&hdr, sizeof (hdr));
		if (rc != 0) {
			goto exit;
		}
	} else if (rebuild_test_case == 10) {
		hdr.opcode = ZVOL_OPCODE_REBUILD_COMPLETE;
		rc = uzfs_zvol_socket_write(sfd, (char *)&hdr, sizeof (hdr));
		if (rc != 0) {
			LOG_ERRNO("Socket rebuild_complete write failed, but,"
			    "counting as success with this replica");
			rc = 0;
			goto exit;
		}

		rc = 0;
		LOG_INFO("Rebuilding zvol %s completed", zinfo->name);
		goto exit;
	}

	while (1) {

		if ((rebuild_test_case == 7) || (rebuild_test_case == 8) || (rebuild_test_case == 9))
		{
			sleep(1);
			if (rebuild_test_case == 7)
				zinfo2->state = ZVOL_INFO_STATE_OFFLINE;
			else if (rebuild_test_case == 8)
				zinfo2->is_io_ack_sender_created = B_FALSE;
			else {
				close(data_conn_fd);
				sleep(5);
			}
#if DEBUG
			inject_error.delay.helping_replica_rebuild_step = 0;
#endif
		}

		rc = uzfs_zvol_socket_read(sfd, (char *)&hdr, sizeof (hdr));
		if (rebuild_test_case == 9) {
			if (rc != -1)
				rc = uzfs_zvol_socket_read(sfd, (char *)&hdr, sizeof (hdr));
			EXPECT_EQ(rc, -1);
			sleep(3);
			goto exit;
		}
		if (rc != 0) {
			LOG_ERR("Socket read failed");
			goto exit;
		}

		if (hdr.status != ZVOL_OP_STATUS_OK) {
			LOG_ERR("received err in rebuild.. for %s..",
			    zinfo->name);
			rc = -1;
			goto exit;
		}

		if (hdr.opcode == ZVOL_OPCODE_REBUILD_STEP_DONE) {
			offset += zvol_rebuild_step_size;
			LOG_DEBUG("ZVOL_OPCODE_REBUILD_STEP_DONE received");
			goto next_step;
		}

		ASSERT((hdr.opcode == ZVOL_OPCODE_READ) &&
		    (hdr.flags & ZVOL_OP_FLAG_REBUILD));
		hdr.opcode = ZVOL_OPCODE_WRITE;

		zio_cmd = zio_cmd_alloc(&hdr, sfd);
		rc = uzfs_zvol_socket_read(sfd, (char *)zio_cmd->buf, hdr.len);
		if (rc != 0) {
			LOG_ERR("Socket read writeIO failed");
			goto exit;
		}

		/*
		 * Take refcount for uzfs_zvol_worker to work on it.
		 * Will dropped by uzfs_zvol_worker once cmd is executed.
		 */
		uzfs_zinfo_take_refcnt(zinfo);
		zio_cmd->zv = zinfo;
		uzfs_zvol_worker(zio_cmd);
		if (zio_cmd->hdr.status != ZVOL_OP_STATUS_OK) {
			LOG_ERR("rebuild IO failed.. for %s..", zinfo->name);
			rc = -1;
			goto exit;
		}
		zio_cmd_free(&zio_cmd);
	}

exit:
	mutex_enter(&zinfo->zv->rebuild_mtx);
	if (rc != 0) {
		uzfs_zvol_set_rebuild_status(zinfo->zv,
		    ZVOL_REBUILDING_ERRORED);
		(zinfo->zv->rebuild_info.rebuild_failed_cnt) += 1;
		LOG_ERR("uzfs_zvol_rebuild_dw_replica thread exiting, "
		    "rebuilding failed zvol: %s", zinfo->name);
	}
	(zinfo->zv->rebuild_info.rebuild_done_cnt) += 1;
	if (zinfo->zv->rebuild_info.rebuild_cnt ==
	    zinfo->zv->rebuild_info.rebuild_done_cnt) {
		if (zinfo->zv->rebuild_info.rebuild_failed_cnt != 0)
			uzfs_zvol_set_rebuild_status(zinfo->zv,
			    ZVOL_REBUILDING_FAILED);
		else {
			/* Mark replica healthy now */
			uzfs_zvol_set_rebuild_status(zinfo->zv,
			    ZVOL_REBUILDING_DONE);
			uzfs_zvol_set_status(zinfo->zv, ZVOL_STATUS_HEALTHY);
			uzfs_update_ionum_interval(zinfo, 0);
		}
	}
	mutex_exit(&zinfo->zv->rebuild_mtx);

	kmem_free(arg, sizeof (rebuild_thread_arg_t));
	if (zio_cmd != NULL)
		zio_cmd_free(&zio_cmd);
	if (sfd != -1) {
		shutdown(sfd, SHUT_RDWR);
		close(sfd);
	}
	/* Parent thread have taken refcount, drop it now */
	uzfs_zinfo_drop_refcnt(zinfo);

	rebuild_test_case = 0;
	zk_thread_exit();
}

void execute_rebuild_test_case(const char *s, int test_case,
    zvol_rebuild_status_t status, zvol_rebuild_status_t verify_status)
{
	kthread_t *thrd;
	rebuild_thread_arg_t *rebuild_args;

	rebuild_test_case = test_case;
	create_rebuild_args(&rebuild_args);
	zinfo->zv->zv_status = ZVOL_STATUS_DEGRADED;
	memset(&zinfo->zv->rebuild_info, 0, sizeof (zvol_rebuild_info_t));
	zinfo->zv->rebuild_info.rebuild_cnt = 1;
	uzfs_zinfo_take_refcnt(zinfo);
	uzfs_zvol_set_rebuild_status(zinfo->zv, status);

	thrd = zk_thread_create(NULL, 0, dw_replica_fn,
	    rebuild_args, 0, NULL, TS_RUN, 0, 0);
	zk_thread_join(thrd->t_tid);

	/* wait for rebuild thread to exit */
	while (1) {
		if (rebuild_test_case != 0)
			sleep(1);
		else
			break;
	}

	EXPECT_EQ(2, zinfo->refcnt);

	EXPECT_EQ(verify_status, uzfs_zvol_get_rebuild_status(zinfo->zv));
}

TEST(uZFS, TestRebuildAbrupt) {
	rebuild_scanner = &uzfs_mock_rebuild_scanner;
	dw_replica_fn = &uzfs_zvol_rebuild_dw_replica;

	zvol_rebuild_step_size = (1024ULL * 1024ULL * 1024ULL) / 2 + 1000;
	/* thread that helps rebuilding exits abruptly just after connects */
	execute_rebuild_test_case("rebuild abrupt", 1, ZVOL_REBUILDING_IN_PROGRESS, ZVOL_REBUILDING_FAILED);
}

TEST(uZFS, TestRebuildGrace) {
	/* thread that helps rebuilding exits gracefully just after connects */
	execute_rebuild_test_case("rebuild grace", 2, ZVOL_REBUILDING_IN_PROGRESS, ZVOL_REBUILDING_FAILED);
}

TEST(uZFS, TestRebuildErrorState) {
	/* rebuild state is ERRORED on dw replica */
	execute_rebuild_test_case("rebuild error state", 2, ZVOL_REBUILDING_ERRORED, ZVOL_REBUILDING_FAILED);
}

TEST(uZFS, TestRebuildExitAfterStep) {
	/* thread helping rebuild will exit after reading REBUILD_STEP */
	execute_rebuild_test_case("rebuild exit after step", 3, ZVOL_REBUILDING_IN_PROGRESS, ZVOL_REBUILDING_FAILED);
}

TEST(uZFS, TestRebuildExitAfterInvalidWrite) {
	/* thread helping rebuild will exit after writng invalid write IO */
	execute_rebuild_test_case("rebuild exit after invalid write", 4, ZVOL_REBUILDING_IN_PROGRESS, ZVOL_REBUILDING_FAILED);
}

TEST(uZFS, TestRebuildExitAfterValidWrite) {
	/* thread helping rebuild will exit after writng valid write IO */
	execute_rebuild_test_case("rebuild exit after valid write", 5, ZVOL_REBUILDING_IN_PROGRESS, ZVOL_REBUILDING_FAILED);
}

/*
 * THIS IS COPIED FROM test_zrepl_prot.cc
 */
/*
 * This fn does data conn for a host:ip and volume, and fills data fd
 *
 * NOTE: Return value must be void otherwise we could not use asserts
 * (pecularity of gtest framework).
 */
static void do_data_connection(int &data_fd, std::string host, uint16_t port,
    std::string zvol_name, int bs=512, int timeout=120,
    int res=ZVOL_OP_STATUS_OK) {
	struct sockaddr_in addr;
	zvol_io_hdr_t hdr_in, hdr_out = {0};
	zvol_op_open_data_t open_data;
	int rc;
	char val;
	int fd;

	memset(&addr, 0, sizeof (addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	rc = inet_pton(AF_INET, host.c_str(), &addr.sin_addr);
	ASSERT_TRUE(rc > 0);
retry:
	fd = socket(AF_INET, SOCK_STREAM, 0);
	rc = connect(fd, (struct sockaddr *)&addr, sizeof (addr));
	if (rc != 0) {
		perror("connect");
		ASSERT_EQ(errno, 0);
	}
	hdr_out.version = REPLICA_VERSION;
	hdr_out.opcode = ZVOL_OPCODE_OPEN;
	hdr_out.status = ZVOL_OP_STATUS_OK;
	hdr_out.len = sizeof (open_data);

	rc = write(fd, &hdr_out, sizeof (hdr_out));
	ASSERT_EQ(rc, sizeof (hdr_out));

	open_data.tgt_block_size = bs;
	open_data.timeout = timeout;
	GtestUtils::strlcpy(open_data.volname, zvol_name.c_str(),
	    sizeof (open_data.volname));
	rc = write(fd, &open_data, hdr_out.len);

	rc = read(fd, &hdr_in, sizeof (hdr_in));
	ASSERT_EQ(rc, sizeof (hdr_in));
	ASSERT_EQ(hdr_in.version, REPLICA_VERSION);
	ASSERT_EQ(hdr_in.opcode, ZVOL_OPCODE_OPEN);
	ASSERT_EQ(hdr_in.len, 0);
	if (hdr_in.status != res) {
		sleep(2);
		shutdown(fd, SHUT_WR);
		rc = read(fd, &val, sizeof (val));
		close(fd);
		goto retry;
	}
	data_fd = fd;
}

TEST(uZFS, TestRebuildCompleteWithDataConn) {
	io_receiver = &uzfs_zvol_io_receiver;

	uzfs_update_metadata_granularity(zv, 0);
	uzfs_zvol_set_rebuild_status(zv, ZVOL_REBUILDING_INIT);
	do_data_connection(data_conn_fd, "127.0.0.1", 3232, "vol1");
	/* thread helping rebuild will exit after writing valid write IO and REBUILD_STEP_DONE, and reads REBUILD_STEP, writes REBUILD_STEP_DONE */
	execute_rebuild_test_case("complete rebuild with data conn", 6, ZVOL_REBUILDING_IN_PROGRESS, ZVOL_REBUILDING_INIT);
}

TEST(uZFS, TestRebuildComplete) {
	uzfs_update_metadata_granularity(zv, 512);
	/* thread helping rebuild will exit after writing valid write IO and REBUILD_STEP_DONE, and reads REBUILD_STEP, writes REBUILD_STEP_DONE */
	execute_rebuild_test_case("complete rebuild", 7, ZVOL_REBUILDING_IN_PROGRESS, ZVOL_REBUILDING_DONE);
	EXPECT_EQ(ZVOL_STATUS_HEALTHY, uzfs_zvol_get_status(zinfo->zv));

	memset(&zinfo->zv->rebuild_info, 0, sizeof (zvol_rebuild_info_t));
}

TEST(RebuildScanner, AbruptClose) {
	rebuild_scanner = &uzfs_zvol_rebuild_scanner;
	dw_replica_fn = &uzfs_mock_zvol_rebuild_dw_replica;
	zvol_rebuild_step_size = (1024ULL * 1024ULL * 100);
	zinfo2->state = ZVOL_INFO_STATE_ONLINE;

	/* Rebuild thread exits abruptly just after connect */
	execute_rebuild_test_case("Rebuild abrupt", 1,
	    ZVOL_REBUILDING_IN_PROGRESS, ZVOL_REBUILDING_FAILED);
}

TEST(RebuildScanner, WrongOpcode) {
	/* Rebuild thread sending wrong opcode after connectg */
	execute_rebuild_test_case("Wrong opcode", 2,
	    ZVOL_REBUILDING_IN_PROGRESS, ZVOL_REBUILDING_FAILED);
}

TEST(RebuildScanner, ErrorOut) {
	/* Rebuild thread exits after handshake */
	execute_rebuild_test_case("Rebuild error out", 3,
	    ZVOL_REBUILDING_ERRORED, ZVOL_REBUILDING_FAILED);
}

TEST(RebuildScanner, WrongVolname) {
	/* Rebuild thread sending wrong vol name */
	execute_rebuild_test_case("Wrong vol name", 4,
	    ZVOL_REBUILDING_IN_PROGRESS, ZVOL_REBUILDING_FAILED);
}

TEST(RebuildScanner, HandshakeAgaian) {
	/* Rebuild thread sending handshake again on same volume */
	execute_rebuild_test_case("Send handshake again", 5,
	    ZVOL_REBUILDING_IN_PROGRESS, ZVOL_REBUILDING_FAILED);
}

TEST(RebuildScanner, VolumeTooLargeToHandle) {
	/* Rebuild thread sending handshake again on same volume */
	execute_rebuild_test_case("Volume offset and len too large", 6,
	    ZVOL_REBUILDING_IN_PROGRESS, ZVOL_REBUILDING_FAILED);
}

TEST(RebuildScanner, VolumeOffline) {
	zvol_rebuild_step_size = (1024ULL * 1024ULL * 1);

	/* Set offline state on vol3 */
	zinfo2->state = ZVOL_INFO_STATE_ONLINE;
	execute_rebuild_test_case("Volume offline", 7,
	    ZVOL_REBUILDING_IN_PROGRESS, ZVOL_REBUILDING_FAILED);
	zinfo2->state = ZVOL_INFO_STATE_ONLINE;
}

TEST(RebuildScanner, AckSenderCreatedFalse) {
	/* Set io_ack_sender_created as B_FALSE */
	zinfo2->is_io_ack_sender_created = B_TRUE;
	execute_rebuild_test_case("Ack Sender Created False", 8,
	    ZVOL_REBUILDING_IN_PROGRESS, ZVOL_REBUILDING_FAILED);
	zinfo2->is_io_ack_sender_created = B_FALSE;
}

TEST(RebuildScanner, ShutdownRebuildFd) {
	/* Set io_ack_sender_created as B_FALSE */
	uzfs_update_metadata_granularity(zv2, 0);
	uzfs_zvol_set_rebuild_status(zv2, ZVOL_REBUILDING_INIT);
	do_data_connection(data_conn_fd, "127.0.0.1", 3232, "vol3");
	execute_rebuild_test_case("Shutdown Rebuild FD", 9,
	    ZVOL_REBUILDING_IN_PROGRESS, ZVOL_REBUILDING_FAILED);
}

TEST(RebuildScanner, RebuildSuccess) {
	uzfs_update_metadata_granularity(zv2, 0);
	uzfs_zvol_set_rebuild_status(zv2, ZVOL_REBUILDING_INIT);
	do_data_connection(data_conn_fd, "127.0.0.1", 3232, "vol3");
	zvol_rebuild_step_size = (1024ULL * 1024ULL * 100);

	/* Rebuild thread sendinc complete opcode */
	execute_rebuild_test_case("complete rebuild", 10,
	    ZVOL_REBUILDING_IN_PROGRESS, ZVOL_REBUILDING_DONE);
	EXPECT_EQ(ZVOL_STATUS_HEALTHY, uzfs_zvol_get_status(zinfo->zv));
	memset(&zinfo->zv->rebuild_info, 0, sizeof (zvol_rebuild_info_t));
}

/* Volume name stored in zinfo is "pool1/vol1" */
TEST(VolumeNameCompare, VolumeNameCompareTest) {

	/* Pass NULL string for compare */
	EXPECT_EQ(-1, uzfs_zvol_name_compare(zinfo, ""));

	/* Pass wrong volname but smaller string size */
	EXPECT_EQ(-1, uzfs_zvol_name_compare(zinfo, "vol"));

	/* Pass wrong volname but larger string size */
	EXPECT_EQ(-1, uzfs_zvol_name_compare(zinfo, "vol12345678910"));

	/* Pass correct volname */
	EXPECT_EQ(0, uzfs_zvol_name_compare(zinfo, "vol1"));
}

/* Create clone for snap rebuild */
TEST(SnapRebuild, CloneCreate) {

	zvol_state_t *snap_zv = NULL;
	
	/* Create snapshot and clone it */
	EXPECT_EQ(0, uzfs_zvol_create_snaprebuild_clone(
	    zinfo->zv, &snap_zv));
	
	EXPECT_EQ(0, uzfs_zvol_destroy_snaprebuild_clone(zinfo->zv,
	    snap_zv));

}

/* Retry creating same clone, it should error out with EEXIST */
TEST(SnapRebuild, CloneReCreateFailure) {

	zvol_state_t *snap_zv = NULL;

	/* Create snapshot and clone it */
	EXPECT_EQ(0, uzfs_zvol_create_snaprebuild_clone(
	    zinfo->zv, &snap_zv));

	/* Release dataset and close it */
	uzfs_close_dataset(snap_zv);

	/* Try to create clone, this time it should error out */
	EXPECT_EQ(EEXIST, uzfs_zvol_create_snaprebuild_clone(
	    zinfo->zv, &snap_zv));

	EXPECT_EQ(0, uzfs_zvol_destroy_snaprebuild_clone(zinfo->zv,
	    snap_zv));
}

uint64_t snapshot_io_num = 1000;
char *snapname = (char *)"hello_snap";

/* Snap create failure */
TEST(SnapCreate, SnapCreateFailureHigherIO) {

	/*
	 * By default volume state is marked downgraded
	 * so updation of ZAP attribute would fail
	 */
	uzfs_zvol_set_rebuild_status(zinfo->zv, ZVOL_REBUILDING_INIT);
	uzfs_zvol_set_status(zinfo->zv, ZVOL_STATUS_DEGRADED);

	zinfo->running_ionum = snapshot_io_num + 1;
	/* Create snapshot */
	EXPECT_EQ(-1, uzfs_zvol_create_snapshot_update_zap(zinfo,
	    snapname, snapshot_io_num));
}

/* Snap create failure */
TEST(SnapCreate, SnapCreateFailure) {

	/*
	 * By default volume state is marked downgraded
	 * so updation of ZAP attribute would fail
	 */
	uzfs_zvol_set_rebuild_status(zinfo->zv, ZVOL_REBUILDING_INIT);
	uzfs_zvol_set_status(zinfo->zv, ZVOL_STATUS_DEGRADED);

	zinfo->running_ionum = snapshot_io_num -1;
	/* Create snapshot */
	EXPECT_EQ(-1, uzfs_zvol_create_snapshot_update_zap(zinfo,
	    snapname, snapshot_io_num));
}

/* Snap create success */
TEST(SnapCreate, SnapCreateSuccess) {

	/*
	 * Set volume state to healthy so that we can
	 * upsate ZAP attribute and take snapshot
	 */
	uzfs_zvol_set_rebuild_status(zinfo->zv, ZVOL_REBUILDING_DONE);
	uzfs_zvol_set_status(zinfo->zv, ZVOL_STATUS_HEALTHY);

	zinfo->running_ionum = snapshot_io_num -1;
	/* Create snapshot */
	EXPECT_EQ(0, uzfs_zvol_create_snapshot_update_zap(zinfo,
	    snapname, snapshot_io_num));
}

/* Retrieve Snap dataset and IO number */
TEST(SnapCreate, SnapRetrieve) {

	uint64_t io = 0;
	zvol_state_t *snap_zv = NULL;

	/* Create snapshot */
	EXPECT_EQ(0, uzfs_zvol_get_snap_dataset_with_io(zinfo,
	    snapname, &io, &snap_zv));
	
	EXPECT_EQ(snapshot_io_num -1, io);
}
