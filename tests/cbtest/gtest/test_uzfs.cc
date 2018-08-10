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
int mgmt_test_case = 0;

extern void (*zinfo_create_hook)(zvol_info_t *, nvlist_t *);
extern void (*zinfo_destroy_hook)(zvol_info_t *);
int receiver_created = 0;
extern uint64_t zvol_rebuild_step_size;

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

	if (rebuild_test_case == 6)
		goto exit;

	/* Read REBUILD_STEP */
	rc = uzfs_zvol_socket_read(fd, (char *)&hdr, sizeof (hdr));
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

	uzfs_init();
	init_zrepl();
	setup_unit_test(path);
	ret = uzfs_create_pool(pool, path, &spa);
	EXPECT_EQ(0, ret);

	uzfs_create_dataset(spa, ds_name, 1024*1024*1024, 512, &zv);
	uzfs_hold_dataset(zv);
	uzfs_update_metadata_granularity(zv, 512);

	mutex_init(&conn_list_mtx, NULL, MUTEX_DEFAULT, NULL);
	SLIST_INIT(&uzfs_mgmt_conns);
	mutex_init(&async_tasks_mtx, NULL, MUTEX_DEFAULT, NULL);
	mgmt_eventfd = -1;

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
		rc = -1;
		goto exit;
	} else if (rebuild_test_case == 7) {
		/*
		 * Set offline state on vol3
		 */
		zinfo2->state = ZVOL_INFO_STATE_OFFLINE;
		rc = uzfs_zvol_socket_write(sfd, (char *)&hdr, sizeof (hdr));
		if (rc != 0) {
			goto exit;
		}
	} else if (rebuild_test_case == 8) {
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

		rc = uzfs_zvol_socket_read(sfd, (char *)&hdr, sizeof (hdr));
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
    zvol_rebuild_status_t status, boolean_t is_test_positive,
    boolean_t is_rebuild_scanner)
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

	if (!is_rebuild_scanner)
		thrd = zk_thread_create(NULL, 0, uzfs_zvol_rebuild_dw_replica,
		    rebuild_args, 0, NULL, TS_RUN, 0, 0);
	else
		thrd = zk_thread_create(NULL, 0, uzfs_mock_zvol_rebuild_dw_replica,
		    rebuild_args, 0, NULL, TS_RUN, 0, 0);
	zk_thread_join(thrd->t_tid);

	EXPECT_EQ(2, zinfo->refcnt);

	/* wait for rebuild thread to exit */
	while (1) {
		if (rebuild_test_case != 0)
			sleep(1);
		else
			break;
	}

	if (!is_test_positive)
		EXPECT_EQ(ZVOL_REBUILDING_FAILED, uzfs_zvol_get_rebuild_status(zinfo->zv));
	else
		EXPECT_EQ(ZVOL_REBUILDING_DONE, uzfs_zvol_get_rebuild_status(zinfo->zv));
}

TEST(uZFS, TestRebuild) {
	uzfs_mgmt_conn_t *conn;
	mgmt_ack_t *mack;
	char ip[MAX_IP_LEN];
	kthread_t *thrd;
	rebuild_scanner = &uzfs_mock_rebuild_scanner;
	rebuild_thread_arg_t *rebuild_args;

	zvol_rebuild_step_size = (1024ULL * 1024ULL * 1024ULL) / 2 + 1000;
	/* thread that helps rebuilding exits abruptly just after connects */
	execute_rebuild_test_case("rebuild abrupt", 1, ZVOL_REBUILDING_IN_PROGRESS, B_FALSE, B_FALSE);

	/* thread that helps rebuilding exits gracefully just after connects */
	execute_rebuild_test_case("rebuild grace", 2, ZVOL_REBUILDING_IN_PROGRESS, B_FALSE, B_FALSE);

	/* rebuild state is ERRORED on dw replica */
	execute_rebuild_test_case("rebuild error state", 2, ZVOL_REBUILDING_ERRORED, B_FALSE, B_FALSE);

	/* thread helping rebuild will exit after reading REBUILD_STEP */
	execute_rebuild_test_case("rebuild exit after step", 3, ZVOL_REBUILDING_IN_PROGRESS, B_FALSE, B_FALSE);

	/* thread helping rebuild will exit after writng invalid write IO */
	execute_rebuild_test_case("rebuild exit after invalid write", 4, ZVOL_REBUILDING_IN_PROGRESS, B_FALSE, B_FALSE);

	/* thread helping rebuild will exit after writng valid write IO */
	execute_rebuild_test_case("rebuild exit after valid write", 5, ZVOL_REBUILDING_IN_PROGRESS, B_FALSE, B_FALSE);

	/* thread helping rebuild will exit after writng valid write IO and REBUILD_STEP_DONE */
	execute_rebuild_test_case("rebuild exit after valid write and rebuild_step", 6, ZVOL_REBUILDING_IN_PROGRESS, B_FALSE, B_FALSE);

	/* thread helping rebuild will exit after writing valid write IO and REBUILD_STEP_DONE, and reads REBUILD_STEP, writes REBUILD_STEP_DONE */
	execute_rebuild_test_case("complete rebuild", 7, ZVOL_REBUILDING_IN_PROGRESS, B_TRUE, B_FALSE);
	EXPECT_EQ(ZVOL_STATUS_HEALTHY, uzfs_zvol_get_status(zinfo->zv));

	memset(&zinfo->zv->rebuild_info, 0, sizeof (zvol_rebuild_info_t));
}

TEST(RebuildScanner, AbruptClose) {
	rebuild_scanner = &uzfs_zvol_rebuild_scanner;
	zvol_rebuild_step_size = (1024ULL * 1024ULL * 100);

	/* Rebuild thread exits abruptly just after connect */
	execute_rebuild_test_case("Rebuild abrupt", 1,
	    ZVOL_REBUILDING_IN_PROGRESS, B_FALSE, B_TRUE);
	EXPECT_EQ(ZVOL_REBUILDING_FAILED, uzfs_zvol_get_rebuild_status(zinfo->zv));
}

TEST(RebuildScanner, WrongOpcode) {
	rebuild_scanner = &uzfs_zvol_rebuild_scanner;
	zvol_rebuild_step_size = (1024ULL * 1024ULL * 100);

	/* Rebuild thread sending wrong opcode after connectg */
	execute_rebuild_test_case("Wrong opcode", 2,
	    ZVOL_REBUILDING_IN_PROGRESS, B_FALSE, B_TRUE);
	EXPECT_EQ(ZVOL_REBUILDING_FAILED, uzfs_zvol_get_rebuild_status(zinfo->zv));
}

TEST(RebuildScanner, ErrorOut) {
	rebuild_scanner = &uzfs_zvol_rebuild_scanner;
	zvol_rebuild_step_size = (1024ULL * 1024ULL * 100);

	/* Rebuild thread exits after handshake */
	execute_rebuild_test_case("Rebuild error out", 3,
	    ZVOL_REBUILDING_ERRORED, B_FALSE, B_TRUE);
	EXPECT_EQ(ZVOL_REBUILDING_FAILED, uzfs_zvol_get_rebuild_status(zinfo->zv));
}

TEST(RebuildScanner, WrongVolname) {
	rebuild_scanner = &uzfs_zvol_rebuild_scanner;
	zvol_rebuild_step_size = (1024ULL * 1024ULL * 100);

	/* Rebuild thread sending wrong vol name */
	execute_rebuild_test_case("Wrong vol name", 4,
	    ZVOL_REBUILDING_IN_PROGRESS, B_FALSE, B_TRUE);

	EXPECT_EQ(ZVOL_REBUILDING_FAILED, uzfs_zvol_get_rebuild_status(zinfo->zv));
}

TEST(RebuildScanner, HandshakeAgaian) {
	rebuild_scanner = &uzfs_zvol_rebuild_scanner;
	zvol_rebuild_step_size = (1024ULL * 1024ULL * 100);

	/* Rebuild thread sending handshake again on same volume */
	execute_rebuild_test_case("Send handshake again", 5,
	    ZVOL_REBUILDING_IN_PROGRESS, B_FALSE, B_TRUE);
	EXPECT_EQ(ZVOL_REBUILDING_FAILED, uzfs_zvol_get_rebuild_status(zinfo->zv));
}

TEST(RebuildScanner, VolumeTooLargeToHandle) {
	rebuild_scanner = &uzfs_zvol_rebuild_scanner;
	zvol_rebuild_step_size = (1024ULL * 1024ULL * 1024ULL * 100);

	/* Rebuild thread sending handshake again on same volume */
	execute_rebuild_test_case("Volume offset and len too large", 6,
	    ZVOL_REBUILDING_IN_PROGRESS, B_FALSE, B_TRUE);
	EXPECT_EQ(ZVOL_REBUILDING_FAILED, uzfs_zvol_get_rebuild_status(zinfo->zv));
}

TEST(RebuildScanner, VolumeOffline) {
	rebuild_scanner = &uzfs_zvol_rebuild_scanner;
	zvol_rebuild_step_size = (1024ULL * 1024ULL * 1);

	/* Rebuild thread sending handshake again on same volume */
	execute_rebuild_test_case("Volume offline", 7,
	    ZVOL_REBUILDING_IN_PROGRESS, B_FALSE, B_TRUE);
	EXPECT_EQ(ZVOL_REBUILDING_FAILED, uzfs_zvol_get_rebuild_status(zinfo->zv));
}

TEST(RebuildScanner, RebuildSuccess) {
	rebuild_scanner = &uzfs_zvol_rebuild_scanner;

	zvol_rebuild_step_size = (1024ULL * 1024ULL * 100);

	/* Rebuild thread sendinc complete opcode */
	execute_rebuild_test_case("complete rebuild", 8,
	    ZVOL_REBUILDING_IN_PROGRESS, B_TRUE, B_TRUE);
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

zvol_op_status_t status;
void mock_tgt_thread(void *arg)
{
	int			rc = 0;
	int			mgmt_fd, tgt_fd;
	char 			*p;
	char			*ack;
	zvol_state_t		*zv;
	socklen_t		in_len;
	zvol_io_hdr_t		hdr;
	mgmt_ack_t		mgmt_ack;
	struct sockaddr		in_addr;
	zvol_op_resize_data_t	resize;
	char 			buf[512];
	bool			executed = false;

	p = buf;
	ack = NULL;
	zv = NULL;
	mgmt_fd = tgt_fd = -1;

	tgt_fd = create_and_bind("6060", B_TRUE, B_FALSE);
	if (tgt_fd == -1) {
		LOG_ERRNO("Binding failed");
		goto exit;
	}

	rc = listen(tgt_fd, 10);
	if (rc == -1) {
		LOG_ERRNO("Listen failed");
		goto exit;
	}

	in_len = sizeof (in_addr);
	mgmt_fd = accept(tgt_fd, &in_addr, &in_len);
	if (mgmt_fd == -1) {
		LOG_ERRNO("Unable to accept connection");
		goto exit;
	}
	
	/*
	 * Exit after accepting connection
	 */
	if (mgmt_test_case == 1)
		goto exit;


	bzero(&hdr, sizeof (hdr));
	hdr.version = REPLICA_VERSION;
	hdr.opcode = ZVOL_OPCODE_HANDSHAKE;
	hdr.len = strlen(zinfo->name) + 1;
	strcpy(buf, zinfo->name);

	/* Send wrong protocol version */
	if (mgmt_test_case == 2)
		hdr.version = 3;

	/* Header len is greater than MAX_NAME_LEN */
	if (mgmt_test_case == 4)
		hdr.len = 512;

	/* Header len is zero */
	if (mgmt_test_case == 5)
		hdr.len = 0;

	/* Wrong volume name */	
	if (mgmt_test_case == 6)
		strcpy(buf, "XXXXXXXX");

	/*
	 * Send snap create command and
	 * Header len greater than MAX_NAME_LEN
	 */
	if (mgmt_test_case == 11) {
		hdr.opcode = ZVOL_OPCODE_SNAP_CREATE;
		hdr.len = 512;
	}
	
	/*
	 * Send snap create command and
	 * Header len equal to zero
	 */
	if (mgmt_test_case == 12) {
		hdr.opcode = ZVOL_OPCODE_SNAP_CREATE;
		hdr.len = 0;
	}

	/*
	 * Send snap create command and
	 * Wrong volname
	 */
	if (mgmt_test_case == 13) {
		hdr.opcode = ZVOL_OPCODE_SNAP_CREATE;
		strcpy(buf, zinfo->name);
		strcpy((buf + hdr.len -2), "@snap");
		hdr.len = strlen(buf) + 1;
	}


	/* Snap create success case */	
	if (mgmt_test_case == 14) {
		hdr.opcode = ZVOL_OPCODE_SNAP_CREATE;
		strcpy(buf, zinfo->name);
		strcpy((buf + hdr.len -1), "@snap");
		hdr.len = strlen(buf) + 1;
	}
	
	/* Snap destroy success case */	
	if (mgmt_test_case == 15) {
		hdr.opcode = ZVOL_OPCODE_SNAP_DESTROY;
		strcpy(buf, zinfo->name);
		strcpy((buf + hdr.len -1), "@snap");
		hdr.len = strlen(buf) + 1;
	}
	
	/* Resize wrong payload size */	
	if (mgmt_test_case == 16) {
		hdr.opcode = ZVOL_OPCODE_RESIZE;
		hdr.len = sizeof (zvol_op_resize_data_t) + 10;
	}
	
	/* Resize wrong volume name */	
	if (mgmt_test_case == 17) {
		hdr.opcode = ZVOL_OPCODE_RESIZE;
		hdr.len = sizeof (zvol_op_resize_data_t);
		strcpy(resize.volname, "vol1234556");
		resize.size = 1000000;
		p = (char *)&resize;
	}
	
	/* Resize success */	
	if (mgmt_test_case == 18) {
		hdr.opcode = ZVOL_OPCODE_RESIZE;
		hdr.len = sizeof (zvol_op_resize_data_t);
		strcpy(resize.volname, zinfo->name);
		resize.size = 999936;
		p = (char *)&resize;
	}
	
	/* Rebuild payload size is 0 */	
	if (mgmt_test_case == 19) {
		hdr.opcode = ZVOL_OPCODE_START_REBUILD;
		hdr.len = 0;
	}
	
	/* Rebuild payload mismatch */	
	if (mgmt_test_case == 20) {
		hdr.opcode = ZVOL_OPCODE_START_REBUILD;
		hdr.len = sizeof (mgmt_ack_t) + 1;
	}

	/* Rebuild wrong volume name */	
	if (mgmt_test_case == 21) {
		hdr.opcode = ZVOL_OPCODE_START_REBUILD;
		hdr.len = sizeof (mgmt_ack_t);
		strcpy(mgmt_ack.dw_volname, "XXXXXXX");
		p = (char *)&mgmt_ack;
	}

	/* Rebuild Null zv */	
	if (mgmt_test_case == 22) {
		hdr.opcode = ZVOL_OPCODE_START_REBUILD;
		hdr.len = sizeof (mgmt_ack_t);
		strcpy(mgmt_ack.dw_volname, zinfo->name);
		p = (char *)&mgmt_ack;
		zv = zinfo->zv;
		zinfo->zv = NULL;
	}

	/*Volume is wrong rebuild state */
	if (mgmt_test_case == 23) {
		hdr.opcode = ZVOL_OPCODE_START_REBUILD;
		hdr.len = sizeof (mgmt_ack_t);
		strcpy(mgmt_ack.dw_volname, zinfo->name);
		p = (char *)&mgmt_ack;
		uzfs_zvol_set_rebuild_status(zinfo->zv,
		    ZVOL_REBUILDING_IN_PROGRESS);
	}

	/* Single Replica */
	if (mgmt_test_case == 24) {
		hdr.opcode = ZVOL_OPCODE_START_REBUILD;
		hdr.len = sizeof (mgmt_ack_t);
		bzero(&mgmt_ack, sizeof (mgmt_ack));
		strcpy(mgmt_ack.dw_volname, zinfo->name);
		p = (char *)&mgmt_ack;
	}

send_hdr:
	rc = write(mgmt_fd, (void *)&hdr, sizeof (zvol_io_hdr_t));
	if (rc == -1) {
		LOG_ERRNO("Write error during hdr write");
		goto exit;
	}

	/*
	 * Disconnect after send header
	 */
	if (mgmt_test_case == 3)
		goto exit;

	rc = write(mgmt_fd, p, hdr.len);
	if (rc == -1) {
		LOG_ERRNO("Write error during volname write");
		goto exit;
	}

	rc = read(mgmt_fd, (void *)&hdr, sizeof (zvol_io_hdr_t));
	if (rc == -1) {
		LOG_ERRNO("Read error during hdr read");
		goto exit;
	}

	status = hdr.status;
	/* Reset zv in to zinfo */
	if (mgmt_test_case == 22)
		zinfo->zv = zv;

	if (mgmt_test_case == 23)
		uzfs_zvol_set_rebuild_status(zinfo->zv,
		    ZVOL_REBUILDING_INIT);

	if (hdr.status == ZVOL_OP_STATUS_FAILED) {
		LOG_ERRNO("Status is not ok");
		goto exit;
	}

	ack = (char *) malloc(hdr.len);
	rc = read(mgmt_fd, (void *)ack, hdr.len);
	if (rc == -1) {
		LOG_ERRNO("Read error during ack read");
		goto exit;
	}
	free(ack);

	bzero(&hdr, sizeof (hdr));
	hdr.version = REPLICA_VERSION;
	hdr.len = strlen(zinfo->name) + 1;

	if (!executed && mgmt_test_case == 8) {
		hdr.opcode = ZVOL_OPCODE_PREPARE_FOR_REBUILD;
		executed = true;
		goto send_hdr;
	}

	if (!executed && mgmt_test_case == 9) {
		hdr.opcode = ZVOL_OPCODE_REPLICA_STATUS;
		executed = true;
		goto send_hdr;
	}
		
	if (!executed && mgmt_test_case == 10) {
		hdr.opcode = ZVOL_OPCODE_STATS;
		executed = true;
		goto send_hdr;
	}
exit:
	if (tgt_fd != -1)
		close(tgt_fd);

	if (mgmt_fd != -1)
		close(mgmt_fd);

	mgmt_test_case = 0;
	zk_thread_exit();
}

void mgmt_thread_test_case(int test_case)
{
	kthread_t	*mock_tgt_thrd;
	uzfs_mgmt_conn_t *conn = (uzfs_mgmt_conn_t *)zinfo->mgmt_conn;

	mgmt_test_case = test_case;
	uzfs_zinfo_take_refcnt(zinfo);

	mock_tgt_thrd = zk_thread_create(NULL, 0, mock_tgt_thread,
	    NULL, 0, NULL, TS_RUN, 0, 0);

	/* wait for mock_tgt_thread to exit */
	while (1) {
		if (mgmt_test_case != 0)
			sleep(1);
		else
			break;
	}
}

kthread_t	*mgmt_thread;
TEST(MgmtThreadTest, MgmtThreadCreation) {
	EXPECT_EQ(2, uzfs_mgmt_conn_list_count(&uzfs_mgmt_conns));
	EXPECT_EQ(2, zinfo->refcnt);

	mgmt_thread = zk_thread_create(NULL, 0, uzfs_zvol_mgmt_thread,
	    NULL, 0, NULL, TS_RUN, 0, 0);
	sleep(1);
	uzfs_mgmt_conn_t *conn = (uzfs_mgmt_conn_t *)zinfo->mgmt_conn;
	conn->conn_bufsiz = 0;
	zinfo_destroy_cb(zinfo2);
	EXPECT_EQ(0, !mgmt_thread);
}

/* Disconnect mgmt connection just after connect */
TEST(MgmtThreadTest, ConnBreakFromTGTAfterConnect) {
	uzfs_mgmt_conn_t *conn = (uzfs_mgmt_conn_t *)zinfo->mgmt_conn;
	mgmt_thread_test_case(1);
	EXPECT_EQ(conn->conn_state, CS_READ_VERSION);
}

/* Send wrong protocol version */
TEST(MgmtThreadTest, WrongProtocolVersionFromTGT) {
	uzfs_mgmt_conn_t *conn = (uzfs_mgmt_conn_t *)zinfo->mgmt_conn;
	mgmt_thread_test_case(2);
	EXPECT_EQ(conn->conn_state, CS_CLOSE);
}

/* Disconnect after sending header */
TEST(MgmtThreadTest, DisconnAfterHdrSendFromTGT) {
	uzfs_mgmt_conn_t *conn = (uzfs_mgmt_conn_t *)zinfo->mgmt_conn;
	mgmt_thread_test_case(3);
	EXPECT_EQ(conn->conn_state, CS_READ_PAYLOAD);
}

/* Volume name is too large to handle */
TEST(MgmtThreadTest, VolumeNameTooLargeToHandle) {
	uzfs_mgmt_conn_t *conn = (uzfs_mgmt_conn_t *)zinfo->mgmt_conn;
	mgmt_thread_test_case(4);
	EXPECT_EQ(status, ZVOL_OP_STATUS_FAILED);
}

/* Volume name is too small to handle */
TEST(MgmtThreadTest, VolumeNameTooSmallToHandle) {
	uzfs_mgmt_conn_t *conn = (uzfs_mgmt_conn_t *)zinfo->mgmt_conn;
	mgmt_thread_test_case(5);
	EXPECT_EQ(status, ZVOL_OP_STATUS_FAILED);
}

/* Send wrong volume name */
TEST(MgmtThreadTest, WrongVolumeName) {
	uzfs_mgmt_conn_t *conn = (uzfs_mgmt_conn_t *)zinfo->mgmt_conn;
	mgmt_thread_test_case(6);
	EXPECT_EQ(status, ZVOL_OP_STATUS_FAILED);
}

/* Handshake success case */
TEST(MgmtThreadTest, HandShakeSuccess) {
	uzfs_mgmt_conn_t *conn = (uzfs_mgmt_conn_t *)zinfo->mgmt_conn;
	mgmt_thread_test_case(7);
	EXPECT_EQ(status, ZVOL_OP_STATUS_OK);
}

/* Prepare for rebuild success case */
TEST(MgmtThreadTest, PrePareForRebuildSuccess) {
	uzfs_mgmt_conn_t *conn = (uzfs_mgmt_conn_t *)zinfo->mgmt_conn;
	mgmt_thread_test_case(8);
	EXPECT_EQ(status, ZVOL_OP_STATUS_OK);
}

/* Replica status success case */
TEST(MgmtThreadTest, ReplicaStatusSuccess) {
	uzfs_mgmt_conn_t *conn = (uzfs_mgmt_conn_t *)zinfo->mgmt_conn;
	mgmt_thread_test_case(9);
	EXPECT_EQ(status, ZVOL_OP_STATUS_OK);
}

/* Replica state success case */
TEST(MgmtThreadTest, ReplicaStatsSuccess) {
	uzfs_mgmt_conn_t *conn = (uzfs_mgmt_conn_t *)zinfo->mgmt_conn;
	mgmt_thread_test_case(10);
	EXPECT_EQ(status, ZVOL_OP_STATUS_OK);
}

/* Snapshot create failure, payload is too large to handle */
TEST(MgmtThreadTest, SnapCreateFailurePayloadTooLargeToHandle) {
	uzfs_mgmt_conn_t *conn = (uzfs_mgmt_conn_t *)zinfo->mgmt_conn;
	mgmt_thread_test_case(11);
	EXPECT_EQ(status, ZVOL_OP_STATUS_FAILED);
}

/* Snapshot create failure, payload is too small to handle */
TEST(MgmtThreadTest, SnapCreateFailurePayloadTooSmallToHandle) {
	uzfs_mgmt_conn_t *conn = (uzfs_mgmt_conn_t *)zinfo->mgmt_conn;
	mgmt_thread_test_case(12);
	EXPECT_EQ(status, ZVOL_OP_STATUS_FAILED);
}

/* Snapshot create failure, Wrong volume name */
TEST(MgmtThreadTest, SnapCreateFailureWrongVolName) {
	uzfs_mgmt_conn_t *conn = (uzfs_mgmt_conn_t *)zinfo->mgmt_conn;
	mgmt_thread_test_case(13);
	EXPECT_EQ(status, ZVOL_OP_STATUS_FAILED);
}

/* Snapshot create success */
TEST(MgmtThreadTest, SnapCreateSuccess) {
	uzfs_mgmt_conn_t *conn = (uzfs_mgmt_conn_t *)zinfo->mgmt_conn;
	mgmt_thread_test_case(14);
	EXPECT_EQ(status, ZVOL_OP_STATUS_OK);
}

/* Snapshot destroy success */
TEST(MgmtThreadTest, SnapDestroySuccess) {
	uzfs_mgmt_conn_t *conn = (uzfs_mgmt_conn_t *)zinfo->mgmt_conn;
	mgmt_thread_test_case(15);
	EXPECT_EQ(status, ZVOL_OP_STATUS_OK);
}

/* Volume resize failure, payload mismatch */
TEST(MgmtThreadTest, ResizeFailurePayloadMismatch) {
	uzfs_mgmt_conn_t *conn = (uzfs_mgmt_conn_t *)zinfo->mgmt_conn;
	mgmt_thread_test_case(16);
	EXPECT_EQ(status, ZVOL_OP_STATUS_FAILED);
}

/* Volume resize failure, wrong volume name */
TEST(MgmtThreadTest, ResizeFailureWrongVolName) {
	uzfs_mgmt_conn_t *conn = (uzfs_mgmt_conn_t *)zinfo->mgmt_conn;
	mgmt_thread_test_case(17);
	EXPECT_EQ(status, ZVOL_OP_STATUS_FAILED);
}

/* Volume resize success */
TEST(MgmtThreadTest, ResizeSuccess) {
	uzfs_mgmt_conn_t *conn = (uzfs_mgmt_conn_t *)zinfo->mgmt_conn;
	mgmt_thread_test_case(18);
	EXPECT_EQ(status, ZVOL_OP_STATUS_OK);
}

/* Rebuild failure, payload size too small to handle */
TEST(MgmtThreadTest, RebuildFailurePayloadSizeZero) {
	uzfs_mgmt_conn_t *conn = (uzfs_mgmt_conn_t *)zinfo->mgmt_conn;
	mgmt_thread_test_case(19);
	EXPECT_EQ(status, ZVOL_OP_STATUS_FAILED);
}

/* Rebuild failure, payload size mismatch */
TEST(MgmtThreadTest, RebuildFailurePayloadSizeMismatch) {
	uzfs_mgmt_conn_t *conn = (uzfs_mgmt_conn_t *)zinfo->mgmt_conn;
	mgmt_thread_test_case(20);
	EXPECT_EQ(status, ZVOL_OP_STATUS_FAILED);
}

/* Rebuild failure, wrong volume name */
TEST(MgmtThreadTest, RebuildFailureWrongVolumeName) {
	uzfs_mgmt_conn_t *conn = (uzfs_mgmt_conn_t *)zinfo->mgmt_conn;
	mgmt_thread_test_case(21);
	EXPECT_EQ(status, ZVOL_OP_STATUS_FAILED);
}

/* Rebuild failure, Null zv in zinfo */
TEST(MgmtThreadTest, RebuildFailureNullZV) {
	uzfs_mgmt_conn_t *conn = (uzfs_mgmt_conn_t *)zinfo->mgmt_conn;
	mgmt_thread_test_case(22);
	EXPECT_EQ(status, ZVOL_OP_STATUS_FAILED);
}

/* Rebuild failure, volume is not in REBUILD_INIT state */
TEST(MgmtThreadTest, RebuildFailureWrongRebuildState) {
	uzfs_mgmt_conn_t *conn = (uzfs_mgmt_conn_t *)zinfo->mgmt_conn;
	mgmt_thread_test_case(23);
	EXPECT_EQ(status, ZVOL_OP_STATUS_FAILED);
}

/* Rebuild success, Single replica success */
TEST(MgmtThreadTest, RebuildFailureSingleReplica) {
	uzfs_mgmt_conn_t *conn = (uzfs_mgmt_conn_t *)zinfo->mgmt_conn;
	mgmt_thread_test_case(24);
	EXPECT_EQ(status, ZVOL_OP_STATUS_OK);
=======
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
