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
#include <sys/eventfd.h>
#include <sys/epoll.h>
#include <sys/dsl_destroy.h>
#include <sys/dsl_prop.h>
#include <uzfs_rebuilding.h>

#include "gtest_utils.h"

char *ds_name;
char *ds_name2;
char *ds_name_todelete;
char *pool;
spa_t *spa;
zvol_state_t *zv;
zvol_state_t *zv2;
zvol_state_t *zv_todelete;
zvol_info_t *zinfo;
zvol_info_t *zinfo2;
int rebuild_test_case = 0;
int mgmt_test_case = 0;

#define VOLSIZE		(1024 * 1024 * 1024ULL)
#define BLOCKSIZE	(512)

/* This will be used to identify that clone rebuild thread is also done */
uint64_t started_thread_count = 0;
uint64_t done_thread_count = 0;
pthread_mutex_t done_thread_count_mtx = PTHREAD_MUTEX_INITIALIZER;
int data_conn_fd = -1;
int data_conn_fd_todelete = -1;

extern void (*zinfo_create_hook)(zvol_info_t *, nvlist_t *);
extern void (*zinfo_destroy_hook)(zvol_info_t *);
int receiver_created = 0;
extern uint64_t zvol_rebuild_step_size;
extern void mgmt_thread_test_case(int test_case, zvol_info_t *mzinfo);

/* Global variable to check if status of op */
zvol_op_status_t status;

//void (*dw_replica_fn)(void *);
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
	if (ftruncate(fd, VOLSIZE) != 0) {
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
uzfs_mock_rebuild_scanner_setup_connection(int fd)
{

	int rc;
	int rcvsize = 30;
	int sndsize = 30;
	struct linger lo = { 1, 0 };

	rc = setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvsize, sizeof(int));
	EXPECT_NE(rc, -1);

	rc = setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sndsize, sizeof(int));
	EXPECT_NE(rc, -1);

	rc = setsockopt(fd, SOL_SOCKET, SO_LINGER, &lo, sizeof(lo));
	EXPECT_NE(rc, -1);
}

void
uzfs_mock_rebuild_scanner_handshake(int fd, zvol_io_hdr_t *hdrp)
{
	int rc = 0;
	char *buf;
	rc = uzfs_zvol_socket_read(fd, (char *)hdrp, sizeof (*hdrp));
	EXPECT_NE(rc, -1);
	EXPECT_EQ(hdrp->opcode, ZVOL_OPCODE_HANDSHAKE);

	buf = (char *)malloc(hdrp->len);
	rc = uzfs_zvol_socket_read(fd, (char *)buf, hdrp->len);
	EXPECT_NE(rc, -1);
	free(buf);
}

void
uzfs_mock_rebuild_scanner_read_rebuild_step(int fd, zvol_io_hdr_t *hdrp)
{
	int rc = 0;
	/* Read ZVOL_OPCODE_REBUILD_STEP */
	rc = uzfs_zvol_socket_read(fd, (char *)hdrp, sizeof (*hdrp));
	EXPECT_NE(rc, -1);
	EXPECT_EQ(hdrp->opcode, ZVOL_OPCODE_REBUILD_STEP);
	EXPECT_EQ(hdrp->status, ZVOL_OP_STATUS_OK);
	EXPECT_EQ(hdrp->len, zvol_rebuild_step_size);
}

void
uzfs_mock_rebuild_scanner_write_snap_done(int fd, zvol_io_hdr_t *hdrp)
{
	int rc = 0;
	hdrp->opcode = ZVOL_OPCODE_REBUILD_ALL_SNAP_DONE;
	hdrp->status = ZVOL_OP_STATUS_OK;
	hdrp->version = REPLICA_VERSION;

	/* Write ZVOL_OPCODE_REBUILD_ALL_SNAP_DONE */
	rc = uzfs_zvol_socket_write(fd, (char *)hdrp, sizeof (*hdrp));
	EXPECT_NE(rc, -1);

	rc = uzfs_zvol_socket_read(fd, (char *)hdrp, sizeof (*hdrp));
	EXPECT_NE(rc, -1);
	EXPECT_EQ(hdrp->opcode, ZVOL_OPCODE_AFS_STARTED);
}

void
uzfs_mock_rebuild_scanner_abrupt_conn_close(void *arg)
{
	int fd = (int)(uintptr_t)arg;
	uzfs_mock_rebuild_scanner_setup_connection(fd);

	close(fd);
	rebuild_test_case = 0;
	zk_thread_exit();
}

void
uzfs_mock_rebuild_scanner_graceful_conn_close(void *arg)
{
	int fd = (int)(uintptr_t)arg;
	uzfs_mock_rebuild_scanner_setup_connection(fd);

	shutdown(fd, SHUT_RDWR);
	close(fd);
	rebuild_test_case = 0;
	zk_thread_exit();
}

void
uzfs_mock_rebuild_scanner_exit_after_rebuild_step(void *arg)
{
	int rc = 0;
	zvol_io_hdr_t hdr;
	int fd = (int)(uintptr_t)arg;

	/* Establish a connection with DW replica */
	uzfs_mock_rebuild_scanner_setup_connection(fd);

	/* Read HANDSHAKE */
	uzfs_mock_rebuild_scanner_handshake(fd, &hdr);

	/* Read ZVOL_OPCODE_REBUILD_STEP */
	uzfs_mock_rebuild_scanner_read_rebuild_step(fd, &hdr);

	hdr.opcode = ZVOL_OPCODE_READ;
	hdr.flags = ZVOL_OP_FLAG_REBUILD;
	hdr.status = ZVOL_OP_STATUS_FAILED;
	hdr.len = 512;
	hdr.offset = 0;

	rc = uzfs_zvol_socket_write(fd, (char *)&hdr, sizeof(hdr));
	EXPECT_NE(rc, -1);

	rc = uzfs_zvol_socket_read(fd, (char *)&hdr, sizeof (hdr));
	EXPECT_EQ(rc, -1);

	shutdown(fd, SHUT_RDWR);
	close(fd);
	rebuild_test_case = 0;
	zk_thread_exit();
}

void
uzfs_mock_rebuild_scanner_min_version(void *arg)
{
	int rc = 0;
	zvol_io_hdr_t hdr;
	int fd = (int)(uintptr_t)arg;

	/* Establish a connection with DW replica */
	uzfs_mock_rebuild_scanner_setup_connection(fd);

	/* Read HANDSHAKE */
	uzfs_mock_rebuild_scanner_handshake(fd, &hdr);

	// Close fd to simulate min version
	shutdown(fd, SHUT_RDWR);
	close(fd);
	rebuild_test_case = 0;
	zk_thread_exit();
}

void
uzfs_mock_rebuild_scanner_exit_after_write(void *arg)
{
	int rc = 0;
	char *buf;
	uint64_t cnt;
	zvol_io_hdr_t hdr;
	struct zvol_io_rw_hdr *io_hdr;
	int fd = (int)(uintptr_t)arg;

	/* Establish a connection with DW replica */
	uzfs_mock_rebuild_scanner_setup_connection(fd);

	/* Read HANDSHAKE */
	uzfs_mock_rebuild_scanner_handshake(fd, &hdr);

	/* Read ZVOL_OPCODE_REBUILD_STEP */
	uzfs_mock_rebuild_scanner_read_rebuild_step(fd, &hdr);

	hdr.opcode = ZVOL_OPCODE_READ;
	hdr.flags = ZVOL_OP_FLAG_REBUILD;
	hdr.status = ZVOL_OP_STATUS_OK;
	hdr.len = 512;
	hdr.offset = 0;

	/* Write hdr with invalid write IO */
	if (rebuild_test_case == 5)
		hdr.len = 512 + sizeof (struct zvol_io_rw_hdr);

	rc = uzfs_zvol_socket_write(fd, (char *)&hdr, sizeof(hdr));
	EXPECT_NE(rc, -1);

	buf = (char *)malloc(hdr.len);
	cnt = zinfo->write_req_received_cnt;

	if (rebuild_test_case == 5) {
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

	shutdown(fd, SHUT_RDWR);
	close(fd);
	rebuild_test_case = 0;
	zk_thread_exit();
}

void
uzfs_mock_rebuild_scanner_rebuild_comp(void *arg)
{
	int rc = 0;
	char *buf;
	uint64_t cnt;
	zvol_io_hdr_t hdr;
	struct zvol_io_rw_hdr *io_hdr;
	int fd = (int)(uintptr_t)arg;
	int conn_fd;

	/* Establish a connection with DW replica */
	uzfs_mock_rebuild_scanner_setup_connection(fd);

	/* Read HANDSHAKE */
	uzfs_mock_rebuild_scanner_handshake(fd, &hdr);

	/* Read ZVOL_OPCODE_REBUILD_STEP */
	uzfs_mock_rebuild_scanner_read_rebuild_step(fd, &hdr);

	/* Write ZVOL_OPCODE_REBUILD_ALL_SNAP_DONE */
	/* For testcase 6, data connection will be broken.
	 * So, if ALL_SNAP_DONE is sent, socket error can come for
	 * clone rebuild thread at any place. Instead, avoid sending
	 * ALL_SNAP_DONE for testcase 6 */
	if (rebuild_test_case != 6) {
		uzfs_mock_rebuild_scanner_write_snap_done(fd, &hdr);
		while (1) {
			if (ZVOL_REBUILDING_AFS !=
			    uzfs_zvol_get_rebuild_status(zinfo->main_zv))
				sleep(1);
			else
				break;
		}
	}

	hdr.opcode = ZVOL_OPCODE_READ;
	hdr.flags = ZVOL_OP_FLAG_REBUILD;
	hdr.status = ZVOL_OP_STATUS_OK;
	hdr.len = 512;
	hdr.offset = 0;

	hdr.len = 512 + sizeof (struct zvol_io_rw_hdr);

	rc = uzfs_zvol_socket_write(fd, (char *)&hdr, sizeof(hdr));
	EXPECT_NE(rc, -1);

	buf = (char *)malloc(hdr.len);
	cnt = zinfo->write_req_received_cnt;

	io_hdr = (struct zvol_io_rw_hdr *)buf;
	io_hdr->io_num = 1000;
	io_hdr->len = 512;

	rc = uzfs_zvol_socket_write(fd, (char *)buf, hdr.len);
	EXPECT_NE(rc, -1);
	/* check for write cnt */
	while (1) {
		if ((zinfo->write_req_received_cnt != (cnt + 1)) &&
		    (zinfo->write_req_received_cnt != (cnt + 2)))
			sleep(1);
		else
			break;
	}

	free(buf);
	
	/* Write REBUILD_STEP_DONE */
	hdr.opcode = ZVOL_OPCODE_REBUILD_STEP_DONE;
	hdr.status = ZVOL_OP_STATUS_OK;
	hdr.len = 0;
	rc = uzfs_zvol_socket_write(fd, (char *)&hdr, sizeof(hdr));
	EXPECT_NE(rc, -1);
	if (rebuild_test_case == 6) {
		conn_fd = data_conn_fd;
		data_conn_fd = -1;
		close(conn_fd);
		while (zinfo->is_io_receiver_created)
			sleep(2);
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
	close(fd);
	pthread_mutex_lock(&done_thread_count_mtx);
	atomic_inc_64(&done_thread_count);
	if (rebuild_test_case != 6) {
		if (done_thread_count == 2)
			rebuild_test_case = 0;
	} else {
		rebuild_test_case = 0;
	}
	pthread_mutex_unlock(&done_thread_count_mtx);
	zk_thread_exit();
}

void
verify_rebuild_io(int rebuild_fd, zvol_info_t *zinfo)
{
	int rc;
	char *write_buf, *read_buf, *send_buf;
	char *cbuf;
	int clen;
	int len = 4096;
	metadata_desc_t *md;
	time_t now;
	uint64_t cnt;
	zvol_io_hdr_t rebuild_hdr = { 0 };
	struct zvol_io_rw_hdr *rw_hdr;

	now = time(0);
	cbuf = ctime(&now);
	clen = strlen(cbuf) - 1;

	rebuild_hdr.opcode = ZVOL_OPCODE_READ;
	rebuild_hdr.flags = ZVOL_OP_FLAG_REBUILD;
	rebuild_hdr.status = ZVOL_OP_STATUS_OK;
	rebuild_hdr.offset = 4096;
	rebuild_hdr.len = len + sizeof (struct zvol_io_rw_hdr);

	rc = uzfs_zvol_socket_write(rebuild_fd, (char *)&rebuild_hdr, sizeof(rebuild_hdr));
        EXPECT_NE(rc, -1);

	send_buf = (char *)malloc(rebuild_hdr.len);
	write_buf = send_buf + sizeof (struct zvol_io_rw_hdr);

	for (int i = 0; (i + clen) < len; i += clen) {
		memcpy(write_buf + i, cbuf, clen);
	}

        cnt = zinfo->write_req_received_cnt;

        rw_hdr = (struct zvol_io_rw_hdr *)send_buf;
        rw_hdr->io_num = rand();
        rw_hdr->len = len;

        rc = uzfs_zvol_socket_write(rebuild_fd, (char *)send_buf, rebuild_hdr.len);
        EXPECT_NE(rc, -1);

        /* check for write cnt */
        while (1) {
                if ((zinfo->write_req_received_cnt != (cnt + 1)) &&
                    (zinfo->write_req_received_cnt != (cnt + 2)))
                        sleep(1);
                else
                        break;
        }

	/* Verify if rebuilding replica has written data to correct dataset */
	read_buf = (char *)malloc(rw_hdr->len);
	uzfs_read_data(zinfo->main_zv, read_buf, rebuild_hdr.offset, rw_hdr->len, &md);
	EXPECT_EQ(NULL, md->next);
	EXPECT_EQ(md->metadata.io_num, rw_hdr->io_num);
	EXPECT_EQ(memcmp(write_buf, read_buf, rw_hdr->len), 0);
	FREE_METADATA_LIST(md);

        free(send_buf);
        free(read_buf);
}

void
verify_app_io_read_write(int fd, zvol_info_t *zinfo)
{
	int rc;
	char write_buf[4096] = { 0 }, read_buf[4096] = { 0 };
	char *cbuf;
	uint64_t ioseq, clen;
	uint64_t io_num;
	int len = 4096;
	zvol_state_t *read_zv;
	uint64_t offset = 4096;
	metadata_desc_t *md;
	time_t now;

	ioseq = 123;
	io_num = rand();

	switch (uzfs_zvol_get_rebuild_status(zinfo->main_zv)) {
		case ZVOL_REBUILDING_INIT:
		case ZVOL_REBUILDING_SNAP:
		case ZVOL_REBUILDING_AFS:
			read_zv = zinfo->clone_zv;
		break;

		default:
			if (uzfs_zinfo_get_status(zinfo) == ZVOL_STATUS_HEALTHY)
				read_zv = zinfo->main_zv;
			else
				return;
		break;
	}

	now = time(0);
	cbuf = ctime(&now);
	clen = strlen(cbuf) - 1;

	for (int i = 0; (i + clen) < sizeof (write_buf); i += clen) {
		memcpy(write_buf + i, cbuf, clen);
	}

	pthread_mutex_lock(&done_thread_count_mtx);

	GtestUtils::write_data_and_verify_resp(fd, ioseq, write_buf, offset, len, io_num);

	uzfs_read_data(read_zv, read_buf, offset, len, &md);
	EXPECT_EQ(NULL, md->next);
	EXPECT_EQ(md->metadata.io_num, io_num);
	EXPECT_EQ(memcmp(write_buf, read_buf, sizeof (read_buf)), 0);
	FREE_METADATA_LIST(md);

	if (uzfs_zvol_get_rebuild_status(zinfo->main_zv) == ZVOL_REBUILDING_AFS) {
		read_zv = zinfo->main_zv;
		memset(read_buf, 0, sizeof (read_buf));
		uzfs_read_data(read_zv, read_buf, offset, len, &md);
		EXPECT_EQ(NULL, md->next);
		EXPECT_EQ(md->metadata.io_num, io_num);
		EXPECT_EQ(memcmp(write_buf, read_buf, sizeof (read_buf)), 0);
		FREE_METADATA_LIST(md);
	}
	pthread_mutex_unlock(&done_thread_count_mtx);
}

void
uzfs_mock_rebuild_scanner_snap_rebuild_related(void *arg)
{
	int fd = (int)(uintptr_t)arg;
	zvol_io_hdr_t hdr;
	int rc;
	char *buf;
	uint64_t cnt;
	struct zvol_io_rw_hdr *io_hdr;

	uzfs_mock_rebuild_scanner_setup_connection(fd);

	/* Read HANDSHAKE */
	uzfs_mock_rebuild_scanner_handshake(fd, &hdr);

	/* Read REBUILD_STEP */
	uzfs_mock_rebuild_scanner_read_rebuild_step(fd, &hdr);

	/* Send snap_done opcode */
	if ((rebuild_test_case >= 8) && (rebuild_test_case <= 12)) {
#ifdef DEBUG
		inject_error.delay.downgraded_replica_rebuild_size_set = 1;
#endif
		hdr.opcode = ZVOL_OPCODE_REBUILD_SNAP_DONE;
		hdr.status = ZVOL_OP_STATUS_OK;
		buf = (char *)malloc(MAX_NAME_LEN + 1);

		/* Prepare snapname */
		strncpy(buf, zinfo->name, MAXNAMELEN);
		strncat(buf, "@test_snap", strlen("@test_snap"));
		hdr.len = strlen(buf) + 1;
		hdr.io_seq = 10000;

		/* Send zero hdr.len for negative case */
		if (rebuild_test_case == 8)
			hdr.len = 0;
	
		/* Send hdr.len more than expected */
		if (rebuild_test_case == 9)
			hdr.len = MAX_NAME_LEN + 20;
		
		/* Wrong snapshot name */
		if (rebuild_test_case == 10) {
			buf[strlen(zinfo->name)] = '\0';
			hdr.len = strlen(buf) + 1;
		}
	
		if (rebuild_test_case == 11) {
			strncpy(buf, "hello", MAXNAMELEN);
			strncat(buf, "@test_snap", strlen("@test_snap"));
			hdr.len = strlen(buf) + 1;
		}

		/*
		 * Send ZVOL_OPCODE_REBUILD_SNAP_DONE opcode
		 * with snapshot io_seq number 10000
		 */
		rc = uzfs_zvol_socket_write(fd, (char *)&hdr, sizeof(hdr));
		EXPECT_NE(rc, -1);
		if ((rebuild_test_case == 8) ||
		    (rebuild_test_case == 9)) {
			free(buf);
			while (1) {
				if (ZVOL_REBUILDING_FAILED !=
				    uzfs_zvol_get_rebuild_status(zinfo->main_zv))
					sleep(1);
				else
					goto exit;
			}
		}
		rc = uzfs_zvol_socket_write(fd, buf, hdr.len);
		EXPECT_NE(rc, -1);
		free(buf);
		/*
		 * Read REBUILD_STEP, checkpoint_io_seq
		 * should be one less than snapshot io_seq
		 */
		rc = uzfs_zvol_socket_read(fd, (char *)&hdr, sizeof (hdr));
		if ((rebuild_test_case == 10) || (rebuild_test_case == 11)) {
			EXPECT_EQ(rc, -1);
			goto exit;
		}

		EXPECT_NE(rc, -1);
		EXPECT_EQ(hdr.opcode, ZVOL_OPCODE_REBUILD_STEP);
		EXPECT_EQ(hdr.status, ZVOL_OP_STATUS_OK);
		EXPECT_EQ(hdr.len, zvol_rebuild_step_size);
		EXPECT_EQ(hdr.io_seq, 9999);
		goto exit;
	}

	/* Send opcode ALL_SNAP_DONE */
	if (rebuild_test_case == 13) {
		uzfs_mock_rebuild_scanner_write_snap_done(fd, &hdr);
		while (1) {
			if ((ZVOL_REBUILDING_AFS !=
			    uzfs_zvol_get_rebuild_status(zinfo->main_zv)) &&
			    (ZVOL_REBUILDING_ERRORED !=
			    uzfs_zvol_get_rebuild_status(zinfo->main_zv)))
				sleep(1);
			else
				break;
		}
	}
#ifdef DEBUG
	inject_error.delay.downgraded_replica_rebuild_size_set = 0;
#endif

exit:
	pthread_mutex_lock(&done_thread_count_mtx);
	atomic_inc_64(&done_thread_count);
	if (rebuild_test_case == 13) {
		if (done_thread_count == 2)
			rebuild_test_case = 0;
	} else {
		rebuild_test_case = 0;
	}

	while (rebuild_test_case) {
		pthread_mutex_unlock(&done_thread_count_mtx);
		sleep(1);
		pthread_mutex_lock(&done_thread_count_mtx);
	}
	pthread_mutex_unlock(&done_thread_count_mtx);

	shutdown(fd, SHUT_RDWR);
	close(fd);

	zk_thread_exit();
}

void
uzfs_mock_rebuild_scanner_full(void *arg)
{
	int fd = (int)(uintptr_t)arg;
	zvol_io_hdr_t hdr;
	int rc;
	char *buf;
	uint64_t cnt;
	struct zvol_io_rw_hdr *io_hdr;

	uzfs_mock_rebuild_scanner_setup_connection(fd);

	/* Read HANDSHAKE */
	uzfs_mock_rebuild_scanner_handshake(fd, &hdr);

	/* Read REBUILD_STEP */
	uzfs_mock_rebuild_scanner_read_rebuild_step(fd, &hdr);
	verify_app_io_read_write(data_conn_fd, zinfo);

	if (ZVOL_IS_REBUILDING(zinfo->main_zv) && !ZVOL_IS_REBUILDING_AFS(zinfo->main_zv)) {
		verify_rebuild_io(fd, zinfo);
	}

	/* Send REBUILD_SNAP_START */
	uint64_t volsize = ZVOL_VOLUME_SIZE(zinfo->main_zv);
	hdr.opcode = ZVOL_OPCODE_REBUILD_SNAP_START;
	hdr.status = ZVOL_OP_STATUS_OK;
	hdr.len = sizeof(volsize);
	rc = uzfs_zvol_socket_write(fd, (char *)&hdr, sizeof(hdr));
	EXPECT_NE(rc, -1);

	rc = uzfs_zvol_socket_write(fd, (char *)&volsize, sizeof(volsize));
	EXPECT_NE(rc, -1);

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
	verify_app_io_read_write(data_conn_fd, zinfo);

	/* Write REBUILD_STEP_DONE */
	hdr.opcode = ZVOL_OPCODE_REBUILD_ALL_SNAP_DONE;
	hdr.status = ZVOL_OP_STATUS_OK;
	hdr.len = 0;
	rc = uzfs_zvol_socket_write(fd, (char *)&hdr, sizeof(hdr));
	EXPECT_NE(rc, -1);

	rc = uzfs_zvol_socket_read(fd, (char *)&hdr, sizeof (hdr));
	EXPECT_NE(rc, -1);
	EXPECT_EQ(hdr.opcode, ZVOL_OPCODE_AFS_STARTED);

	while (1) {
		if ((ZVOL_REBUILDING_AFS !=
		    uzfs_zvol_get_rebuild_status(zinfo->main_zv)) &&
		    (ZVOL_REBUILDING_ERRORED !=
		    uzfs_zvol_get_rebuild_status(zinfo->main_zv)))
			sleep(1);
		else
			break;
	}

	verify_app_io_read_write(data_conn_fd, zinfo);

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

#ifdef DEBUG
	inject_error.delay.downgraded_replica_rebuild_size_set = 0;
#endif

exit:
	shutdown(fd, SHUT_RDWR);
	close(fd);

	pthread_mutex_lock(&done_thread_count_mtx);
	atomic_inc_64(&done_thread_count);
	if (rebuild_test_case == 14) {
		if (done_thread_count == 2)
			rebuild_test_case = 0;
	} else {
		rebuild_test_case = 0;
	}
	pthread_mutex_unlock(&done_thread_count_mtx);

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
	char *pool_ds_todelete;
	ds_name = (char *)malloc(MAXNAMELEN);
	ds_name2 = (char *)malloc(MAXNAMELEN);
	ds_name_todelete = (char *)malloc(MAXNAMELEN);
	pool_ds = (char *)malloc(MAXNAMELEN);
	pool_ds2 = (char *)malloc(MAXNAMELEN);
	pool_ds_todelete = (char *)malloc(MAXNAMELEN);
	path = (char *)malloc(MAXNAMELEN);
	pool = (char *)malloc(MAXNAMELEN);

	GtestUtils::strlcpy(path, "/tmp/uztest.1a", MAXNAMELEN);
	GtestUtils::strlcpy(pool, "pool1", MAXNAMELEN);
	GtestUtils::strlcpy(ds_name, "vol1", MAXNAMELEN);
	GtestUtils::strlcpy(ds_name2, "vol3", MAXNAMELEN);
	GtestUtils::strlcpy(ds_name_todelete, "vol_todelete", MAXNAMELEN);
	GtestUtils::strlcpy(pool_ds, "pool1/vol1", MAXNAMELEN);
	GtestUtils::strlcpy(pool_ds2, "pool1/vol3", MAXNAMELEN);
	GtestUtils::strlcpy(pool_ds_todelete, "pool1/vol_todelete", MAXNAMELEN);
	signal(SIGPIPE, SIG_IGN);

	mutex_init(&conn_list_mtx, NULL, MUTEX_DEFAULT, NULL);
	SLIST_INIT(&uzfs_mgmt_conns);
	mutex_init(&async_tasks_mtx, NULL, MUTEX_DEFAULT, NULL);

	mgmt_eventfd = eventfd(0, EFD_NONBLOCK);

	uzfs_init();
	init_zrepl();
	setup_unit_test(path);
	ret = uzfs_create_pool(pool, path, &spa);
	EXPECT_EQ(0, ret);

	uzfs_create_dataset(spa, ds_name, VOLSIZE, BLOCKSIZE, &zv);
	uzfs_hold_dataset(zv);
	uzfs_update_metadata_granularity(zv, 512);

	zinfo_create_hook = &zinfo_create_cb;
	zinfo_destroy_hook = &zinfo_destroy_cb;

	io_receiver = &uzfs_mock_io_receiver;
	rebuild_scanner = &uzfs_mock_io_receiver;
	dw_replica_fn = &uzfs_zvol_rebuild_dw_replica;

	zrepl_log_level = LOG_LEVEL_DEBUG;

	/* give time to get the zfs threads created */
	sleep(5);
	/*Create vol3 */
	uzfs_create_dataset(spa, ds_name2, VOLSIZE, BLOCKSIZE, &zv2);
	uzfs_hold_dataset(zv2);
	uzfs_update_metadata_granularity(zv2, 512);
	strncpy(zv2->zv_target_host,"127.0.0.1:5050", MAXNAMELEN);
	uzfs_zinfo_init(zv2, pool_ds2, NULL);
	zinfo2 = uzfs_zinfo_lookup(ds_name2);
	EXPECT_EQ(0, !zinfo2);

	uzfs_create_dataset(spa, ds_name_todelete, VOLSIZE, BLOCKSIZE, &zv_todelete);
	uzfs_hold_dataset(zv_todelete);
	uzfs_update_metadata_granularity(zv_todelete, 512);
	strncpy(zv_todelete->zv_target_host,"127.0.0.1:5959", MAXNAMELEN);
	uzfs_zinfo_init(zv_todelete, pool_ds_todelete, NULL);

	uzfs_zinfo_init(zv, pool_ds, NULL);
	zinfo = uzfs_zinfo_lookup(ds_name);
	EXPECT_EQ(0, !zinfo);

	EXPECT_GT(kthread_nr, 0);

	uint64_t quorum = -1;
	EXPECT_EQ(0, dsl_prop_get_integer("pool1/vol1",
	    zfs_prop_to_name(ZFS_PROP_QUORUM), &quorum, NULL));
	EXPECT_EQ(quorum, 0);
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

static int
complete_q_list_count(zvol_info_t *zinfo)
{
	int count = 0;
	zvol_io_cmd_t *zio_cmd;

	STAILQ_FOREACH(zio_cmd, &zinfo->complete_queue, cmd_link)
		count++;

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

	EXPECT_EQ(3, uzfs_mgmt_conn_list_count(&uzfs_mgmt_conns));
	conn = SLIST_FIRST(&uzfs_mgmt_conns);
	EXPECT_EQ(1, conn->conn_refcount);

	zinfo_create_cb(zinfo, NULL);
	EXPECT_EQ(3, uzfs_mgmt_conn_list_count(&uzfs_mgmt_conns));
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

/* Internal clone create API testing */
TEST(SnapRebuild, CloneCreate) {

	int ret_val = 0;
	zvol_state_t *snap_zv, *clone_zv;

	/* Create snapshot and clone it */
	EXPECT_EQ(0, uzfs_zvol_get_or_create_internal_clone(
	    zinfo->main_zv, &zinfo->snapshot_zv, &zinfo->clone_zv, &ret_val));
	EXPECT_EQ(NULL, !zinfo->snapshot_zv);
	EXPECT_EQ(NULL, !zinfo->clone_zv);
	EXPECT_EQ(0, ret_val);

	EXPECT_EQ(B_FALSE, is_stale_clone(zinfo->clone_zv));

	/* Release clone and snapshot */
	EXPECT_EQ(0, uzfs_zvol_release_internal_clone(zinfo->main_zv,
	    zinfo->snapshot_zv, zinfo->clone_zv));

	/* Create clone, this time it should load existing clone */
	EXPECT_EQ(0, uzfs_zvol_get_or_create_internal_clone(
	    zinfo->main_zv, &zinfo->snapshot_zv, &zinfo->clone_zv, &ret_val));
	EXPECT_EQ(NULL, !zinfo->snapshot_zv);
	EXPECT_EQ(NULL, !zinfo->clone_zv);
	EXPECT_EQ(EEXIST, ret_val);

	uzfs_zvol_store_kv_pair(zinfo->clone_zv, (char *)STALE, 1);
	EXPECT_EQ(B_TRUE, is_stale_clone(zinfo->clone_zv));

	/* Create clone, this time it should try to delete, but, error out as release is not done */
	snap_zv = zinfo->snapshot_zv;
	clone_zv = zinfo->clone_zv;
	EXPECT_NE(0, uzfs_zvol_get_or_create_internal_clone(
	    zinfo->main_zv, &zinfo->snapshot_zv, &zinfo->clone_zv, &ret_val));
	EXPECT_EQ(NULL, zinfo->snapshot_zv);
	EXPECT_EQ(NULL, zinfo->clone_zv);

	/* Release clone and snapshot */
	zinfo->snapshot_zv = snap_zv;
	zinfo->clone_zv = clone_zv;
	EXPECT_EQ(0, uzfs_zvol_release_internal_clone(zinfo->main_zv,
	    zinfo->snapshot_zv, zinfo->clone_zv));

	/* Create clone, this time it should delete stale and create new one */
	EXPECT_EQ(0, uzfs_zvol_get_or_create_internal_clone(
	    zinfo->main_zv, &zinfo->snapshot_zv, &zinfo->clone_zv, &ret_val));
	EXPECT_EQ(NULL, !zinfo->snapshot_zv);
	EXPECT_EQ(NULL, !zinfo->clone_zv);
	EXPECT_EQ(0, ret_val);

	/* Destroy internal clone and internal snapshot */
	EXPECT_EQ(0, uzfs_zinfo_destroy_internal_clone(zinfo));
	EXPECT_EQ(NULL, zinfo->snapshot_zv);
	EXPECT_EQ(NULL, zinfo->clone_zv);
}

uint64_t snapshot_io_num = 1000;
char *snapname = (char *)"hello_snap";

/* Snap create failure */
TEST(SnapCreate, SnapCreateFailureHigherIO) {

	/*
	 * By default volume state is marked downgraded
	 * so updation of ZAP attribute would fail
	 */
	uzfs_zvol_set_rebuild_status(zinfo->main_zv, ZVOL_REBUILDING_DONE);
	uzfs_zvol_set_status(zinfo->main_zv, ZVOL_STATUS_HEALTHY);

	zinfo->running_ionum = snapshot_io_num + 1;
	/* Create snapshot */
	EXPECT_EQ(-1, uzfs_zvol_create_snapshot_update_zap(zinfo,
	    snapname, snapshot_io_num));
}

/* Snap create success */
TEST(SnapCreate, SnapCreateSuccess) {
	uint64_t ionum;
	char *snapname1 = (char *)"snapa";
	char *snapname2 = (char *)"snapb";
	char *snapname3 = (char *)"snapc";
	/*
	 * Set volume state to healthy so that we can
	 * update ZAP attribute and take snapshot
	 */
	uzfs_zvol_set_rebuild_status(zinfo->main_zv, ZVOL_REBUILDING_DONE);
	uzfs_zvol_set_status(zinfo->main_zv, ZVOL_STATUS_HEALTHY);

	zinfo->running_ionum = snapshot_io_num -1;

	/* Create snapshot */
	EXPECT_EQ(0, uzfs_zvol_create_snapshot_update_zap(zinfo,
	    snapname, snapshot_io_num));
	EXPECT_EQ(0, uzfs_zvol_get_last_committed_io_no(zinfo->main_zv,
	    (char *)HEALTHY_IO_SEQNUM, &ionum));
	EXPECT_EQ(999, ionum);

	EXPECT_EQ(0, uzfs_zvol_create_snapshot_update_zap(zinfo,
	    (char *)REBUILD_SNAPSHOT_SNAPNAME, 1800));
	EXPECT_EQ(0, uzfs_zvol_get_last_committed_io_no(zinfo->main_zv,
	    (char *)HEALTHY_IO_SEQNUM, &ionum));
	EXPECT_EQ(1799, ionum);

	EXPECT_EQ(0, uzfs_zvol_create_snapshot_update_zap(zinfo,
	    snapname1, 2000));
	EXPECT_EQ(0, uzfs_zvol_get_last_committed_io_no(zinfo->main_zv,
	    (char *)HEALTHY_IO_SEQNUM, &ionum));
	EXPECT_EQ(1999, ionum);

	EXPECT_EQ(0, uzfs_zvol_create_snapshot_update_zap(zinfo,
	    (char *)".io_snap100", 2800));
	EXPECT_EQ(0, uzfs_zvol_get_last_committed_io_no(zinfo->main_zv,
	    (char *)HEALTHY_IO_SEQNUM, &ionum));
	EXPECT_EQ(2799, ionum);

	EXPECT_EQ(0, uzfs_zvol_create_snapshot_update_zap(zinfo,
	    snapname2, 3000));
	EXPECT_EQ(0, uzfs_zvol_get_last_committed_io_no(zinfo->main_zv,
	    (char *)HEALTHY_IO_SEQNUM, &ionum));
	EXPECT_EQ(2999, ionum);

	EXPECT_EQ(0, uzfs_zvol_create_snapshot_update_zap(zinfo,
	    snapname3, 4000));
	EXPECT_EQ(0, uzfs_zvol_get_last_committed_io_no(zinfo->main_zv,
	    (char *)HEALTHY_IO_SEQNUM, &ionum));
	EXPECT_EQ(3999, ionum);
}

TEST(GetSnapFromIO, GetSnap) {
	zvol_state_t *zv;
	int ret;

	EXPECT_EQ(0, uzfs_get_snap_zv_ionum(zinfo, 1698, &zv));
	ret = strcmp(zv->zv_name, "pool1/vol1@snapa");
	EXPECT_EQ(ret, 0);
	uzfs_close_dataset(zv);

	EXPECT_EQ(0, uzfs_get_snap_zv_ionum(zinfo, 1998, &zv));
	ret = strcmp(zv->zv_name, "pool1/vol1@snapa");
	EXPECT_EQ(ret, 0);
	uzfs_close_dataset(zv);

	EXPECT_EQ(0, uzfs_get_snap_zv_ionum(zinfo, 1999, &zv));
	ret = strcmp(zv->zv_name, "pool1/vol1@snapb");
	EXPECT_EQ(ret, 0);
	uzfs_close_dataset(zv);

	EXPECT_EQ(0, uzfs_get_snap_zv_ionum(zinfo, 3000, &zv));
	ret = strcmp(zv->zv_name, "pool1/vol1@snapc");
	EXPECT_EQ(ret, 0);
	uzfs_close_dataset(zv);

	EXPECT_EQ(0, uzfs_get_snap_zv_ionum(zinfo, 3999, &zv));
	ret = (zv == NULL) ? 0 : 1;
	EXPECT_EQ(ret, 0);

	EXPECT_EQ(0, dsl_destroy_snapshot("pool1/vol1@snapb", B_FALSE));
	EXPECT_EQ(0, dsl_destroy_snapshot("pool1/vol1@snapa", B_FALSE));
	EXPECT_EQ(0, dsl_destroy_snapshot("pool1/vol1@snapc", B_FALSE));
}

TEST(GetSnapFromIO, CreateInternalSnap) {
	zvol_state *zv1, *zv2;
	int ret;
	char *snap_name;

	EXPECT_EQ(0, uzfs_zvol_create_internal_snapshot(zinfo->main_zv, &zv1, 100));
	snap_name = kmem_asprintf("%s", strchr(zv1->zv_name, '@') + 1);
	uzfs_close_dataset(zv1);

	EXPECT_EQ(EEXIST, get_snapshot_zv(zinfo->main_zv, snap_name, &zv2, B_TRUE, B_FALSE));
	get_snapshot_zv(zinfo->main_zv, snap_name + 1, &zv2, B_FALSE, B_FALSE);
	ret = (zv2 == NULL) ? 0 : 1;
	EXPECT_EQ(ret, 1);
	strfree(snap_name);
	snap_name = kmem_asprintf("%s", zv2->zv_name);
	uzfs_close_dataset(zv2);

	EXPECT_EQ(ENOENT, get_snapshot_zv(zinfo->main_zv, "snapz", &zv1, B_TRUE, B_TRUE));
	get_snapshot_zv(zinfo->main_zv, "snapz", &zv1, B_FALSE, B_FALSE);
	ret = (zv1 == NULL) ? 0 : 1;
	EXPECT_EQ(ret, 1);
	uzfs_close_dataset(zv1);

	EXPECT_EQ(0, dsl_destroy_snapshot(snap_name, B_FALSE));
	strfree(snap_name);

	EXPECT_EQ(0, dsl_destroy_snapshot("pool1/vol1@snapz", B_FALSE));
}

/* Retrieve Snap dataset and IO number */
TEST(SnapCreate, SnapRetrieve) {

	uint64_t io = 0;
	zvol_state_t	*snap_zv = NULL;

	/* Create snapshot */
	EXPECT_EQ(0, uzfs_zvol_get_snap_dataset_with_io(zinfo,
	    snapname, &io, &snap_zv));

	EXPECT_EQ(snapshot_io_num -1, io);
	EXPECT_EQ(NULL, !snap_zv);

	/* Release dataset and close it */
	uzfs_close_dataset(snap_zv);
	char *longsnap = kmem_asprintf("%s@%s", zinfo->name, snapname);
	EXPECT_EQ(0, dsl_destroy_snapshot(longsnap, B_FALSE));
	strfree(longsnap);
}

void
set_start_rebuild_mgmt_ack(rebuild_req_t *req, const char *dw_name, const char *volname, uint64_t ioseq=0)
{
	GtestUtils::strlcpy(req->dw_volname, dw_name, MAXNAMELEN);
	if (volname != NULL)
		GtestUtils::strlcpy(req->volname, volname, MAXNAMELEN);
	req->checkpointed_io_seq = ioseq;
}

void
set_mgmt_ack_ip_port(mgmt_ack_t *mack, const char *ip, uint16_t port)
{
	GtestUtils::strlcpy(mack->ip, ip, MAX_IP_LEN);
	mack->port = port;
}

void
set_zvol_io_hdr(zvol_io_hdr_t *hdrp, zvol_op_status_t status,
    zvol_op_code_t opcode, int len, uint16_t version)
{
	hdrp->version = version;
	hdrp->status = status;
	hdrp->opcode = opcode;
	hdrp->len = len;
}
TEST(uZFSRebuildStart, TestStartRebuild) {
	int i;
	uzfs_mgmt_conn_t *conn;
	rebuild_req_t *req;

	zvol_rebuild_status_t rebuild_status[5];
	rebuild_status[0] = ZVOL_REBUILDING_INIT;
	rebuild_status[1] = ZVOL_REBUILDING_SNAP;
	rebuild_status[2] = ZVOL_REBUILDING_DONE;
	rebuild_status[3] = ZVOL_REBUILDING_ERRORED;
	rebuild_status[4] = ZVOL_REBUILDING_FAILED;

	EXPECT_EQ(3, uzfs_mgmt_conn_list_count(&uzfs_mgmt_conns));
	EXPECT_EQ(2, zinfo->refcnt);
	conn = SLIST_FIRST(&uzfs_mgmt_conns);

	zvol_io_hdr_t *hdrp = (zvol_io_hdr_t *)kmem_zalloc(sizeof (*hdrp), KM_SLEEP);
	void *payload = kmem_zalloc(sizeof (rebuild_req_t) * 5, KM_SLEEP);
	req = (rebuild_req_t *)payload;
	set_zvol_io_hdr(hdrp, ZVOL_OP_STATUS_OK, ZVOL_OPCODE_PREPARE_FOR_REBUILD, 0, REPLICA_VERSION);

	/* payload is 0 */
	conn->conn_buf = NULL;
	handle_start_rebuild_req(conn, hdrp, NULL, 0);
	EXPECT_EQ(ZVOL_OP_STATUS_FAILED, ((zvol_io_hdr_t *)conn->conn_buf)->status);
	EXPECT_EQ(2, zinfo->refcnt);

	/* NULL name in payload */
	conn->conn_buf = NULL;
	handle_start_rebuild_req(conn, hdrp, payload, sizeof (rebuild_req_t));
	EXPECT_EQ(ZVOL_OP_STATUS_FAILED, ((zvol_io_hdr_t *)conn->conn_buf)->status);
	EXPECT_EQ(2, zinfo->refcnt);

	/* invalid name in payload */
	conn->conn_buf = NULL;
	set_start_rebuild_mgmt_ack(req, "vol2", NULL);
	handle_start_rebuild_req(conn, hdrp, payload, sizeof (rebuild_req_t));
	EXPECT_EQ(ZVOL_OP_STATUS_FAILED, ((zvol_io_hdr_t *)conn->conn_buf)->status);
	EXPECT_EQ(2, zinfo->refcnt);

	uzfs_zinfo_set_status(zinfo, ZVOL_STATUS_DEGRADED);
	/* invalid rebuild state */
	for (i = 1; i < 5; i++) {
		conn->conn_buf = NULL;
		uzfs_zvol_set_rebuild_status(zinfo->main_zv,
		    rebuild_status[i]);
		set_start_rebuild_mgmt_ack(req, "vol1", NULL);
		handle_start_rebuild_req(conn, hdrp, payload, sizeof (rebuild_req_t));
		EXPECT_EQ(ZVOL_OP_STATUS_FAILED, ((zvol_io_hdr_t *)conn->conn_buf)->status);
		EXPECT_EQ(2, zinfo->refcnt);
	}

	/* We are covering this code path from zrepl_rebuild test case */
#if 0
	/* rebuild for single replica case */
	conn->conn_buf = NULL;
	uzfs_zvol_set_rebuild_status(zinfo->main_zv,
	    ZVOL_REBUILDING_INIT);
	set_start_rebuild_mgmt_ack(mack, "vol1", NULL);
	handle_start_rebuild_req(conn, hdrp, payload, sizeof (mgmt_ack_t));
	EXPECT_EQ(ZVOL_OP_STATUS_OK, ((zvol_io_hdr_t *)conn->conn_buf)->status);
	EXPECT_EQ(ZVOL_REBUILDING_DONE, uzfs_zvol_get_rebuild_status(zinfo->main_zv));
	EXPECT_EQ(ZVOL_STATUS_HEALTHY, uzfs_zvol_get_status(zinfo->main_zv));
	EXPECT_EQ(2, zinfo->refcnt);
#endif
	/* rebuild in two replicas case with 'connect' failure */
	conn->conn_buf = NULL;
	uzfs_zinfo_set_status(zinfo, ZVOL_STATUS_DEGRADED);
	uzfs_zvol_set_rebuild_status(zinfo->main_zv,
	    ZVOL_REBUILDING_INIT);
	set_start_rebuild_mgmt_ack(req, "pool1/vol1", "vol2");
	handle_start_rebuild_req(conn, hdrp, payload, sizeof (rebuild_req_t));
	EXPECT_EQ(ZVOL_OP_STATUS_OK, ((zvol_io_hdr_t *)conn->conn_buf)->status);
	while (1) {
		/* wait to get FAILD status, and threads to return with refcnt to 2 */
		if (ZVOL_REBUILDING_FAILED != uzfs_zvol_get_rebuild_status(zinfo->main_zv))
			sleep(1);
		else if (2 != zinfo->refcnt)
			sleep(1);
		else
			break;
	}

	/* rebuild in three replicas case with invalid volname to rebuild */
	conn->conn_buf = NULL;
	uzfs_zinfo_set_status(zinfo, ZVOL_STATUS_DEGRADED);
	uzfs_zvol_set_rebuild_status(zinfo->main_zv,
	    ZVOL_REBUILDING_INIT);
	set_start_rebuild_mgmt_ack(req, "pool1/vol1", "vol3");
	set_start_rebuild_mgmt_ack(req + 1, "vol2", "vol3");
	handle_start_rebuild_req(conn, hdrp, payload, sizeof (rebuild_req_t)*2);
	EXPECT_EQ(ZVOL_OP_STATUS_FAILED, ((zvol_io_hdr_t *)conn->conn_buf)->status);
	while (1) {
		/* wait to get FAILD status, and threads to return with refcnt to 2 */
		if (ZVOL_REBUILDING_FAILED != uzfs_zvol_get_rebuild_status(zinfo->main_zv))
			sleep(1);
		else if (2 != zinfo->refcnt)
			sleep(1);
		else
			break;
	}

	/* rebuild in three replicas case with 'connect' failing and mesh rebuild */
	conn->conn_buf = NULL;
	uzfs_zinfo_set_status(zinfo, ZVOL_STATUS_DEGRADED);
	uzfs_zvol_set_rebuild_status(zinfo->main_zv,
	    ZVOL_REBUILDING_INIT);
	set_start_rebuild_mgmt_ack(req, "pool1/vol1", "vol3", 1000);
	set_start_rebuild_mgmt_ack(req + 1, "pool1/vol1", "vol3", 2000);
	zinfo->checkpointed_ionum = 3000;
	handle_start_rebuild_req(conn, hdrp, payload, sizeof (rebuild_req_t)*2);
	EXPECT_EQ(ZVOL_OP_STATUS_OK, ((zvol_io_hdr_t *)conn->conn_buf)->status);
	while (1) {
		/* wait to get FAILD status, and threads to return with refcnt to 2 */
		if (ZVOL_REBUILDING_FAILED != uzfs_zvol_get_rebuild_status(zinfo->main_zv))
			sleep(1);
		else if (2 != zinfo->refcnt)
			sleep(1);
		else
			break;
	}

	/* rebuild in three replicas case with selecting replica of lower ioseq and mesh rebuild */
	conn->conn_buf = NULL;
	uzfs_zinfo_set_status(zinfo, ZVOL_STATUS_DEGRADED);
	uzfs_zvol_set_rebuild_status(zinfo->main_zv,
	    ZVOL_REBUILDING_INIT);
	set_start_rebuild_mgmt_ack(req, "pool1/vol1", "vol3", 1000);
	set_start_rebuild_mgmt_ack(req + 1, "pool1/vol1", "vol3", 2000);
	zinfo->checkpointed_ionum = 300;
	handle_start_rebuild_req(conn, hdrp, payload, sizeof (rebuild_req_t)*2);
	EXPECT_EQ(ZVOL_OP_STATUS_FAILED, ((zvol_io_hdr_t *)conn->conn_buf)->status);
	while (1) {
		/* Wait for refcnt to 2 */
		if (2 != zinfo->refcnt)
			sleep(1);
		else
			break;
	}
}

void
create_rebuild_args(rebuild_thread_arg_t **r, std::string helping_vol = "vol2")
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

	GtestUtils::strlcpy(rebuild_args->zvol_name, helping_vol.c_str(), MAXNAMELEN);
	*r = rebuild_args;
}

extern uint16_t io_server_port;
extern uint16_t rebuild_io_server_port;

TEST(uZFSIOConnAccept, TestIOConnAcceptor) {
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

	int		rebuild_io_cnt = 0;
	struct sockaddr_in replica_ip;
	int		all_snap_done_received = 0;
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
	int writelen = 0;
	int thread_num = 0;
	uint16_t	version = REPLICA_VERSION;

	atomic_inc_64(&started_thread_count);
	thread_num = started_thread_count;

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

	if (rebuild_test_case == 12)
		version = MIN_SUPPORTED_REPLICA_VERSION;

	if ((thread_num == 2) && (rebuild_test_case == 13))
		sleep(5);
send_hdr_again:
	/* Set state in-progess state now */
	uzfs_zvol_get_last_committed_io_no(zinfo->main_zv,
	    (char *)HEALTHY_IO_SEQNUM, &checkpointed_ionum);
	if ((thread_num == 1) && (rebuild_test_case == 13))
		checkpointed_ionum = 100000350;
	zvol_state = zinfo->main_zv;
	bzero(&hdr, sizeof (hdr));
	hdr.status = ZVOL_OP_STATUS_OK;
	if (rebuild_test_case == 11) {
		hdr.version = REPLICA_VERSION + 1;
		writelen = 4;
	} else {
		hdr.version = version;
		hdr.opcode = ZVOL_OPCODE_HANDSHAKE;
		hdr.len = strlen(rebuild_args->zvol_name) + 1;
		if (rebuild_test_case == 2)
			hdr.opcode = ZVOL_OPCODE_WRITE;
		writelen = sizeof(hdr);
	}
	rc = uzfs_zvol_socket_write(sfd, (char *)&hdr, writelen);
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

	offset = 0;

next_step:
	bzero(&hdr, sizeof (hdr));
	hdr.status = ZVOL_OP_STATUS_OK;
	hdr.version = version;
	hdr.opcode = ZVOL_OPCODE_REBUILD_STEP;
	hdr.io_seq = checkpointed_ionum;
	hdr.offset = offset;
	if ((offset + zvol_rebuild_step_size) >
	    ZVOL_VOLUME_SIZE(zvol_state))
		hdr.len = ZVOL_VOLUME_SIZE(zvol_state) - offset;
	else
		hdr.len = zvol_rebuild_step_size;

	if (rebuild_test_case == 6) {
		hdr.offset = -1;
		rc = uzfs_zvol_socket_write(sfd, (char *)&hdr, sizeof (hdr));
		if (rc != 0) {
			goto exit;
		}
	} else if ((rebuild_test_case == 7) || (rebuild_test_case == 8) || (rebuild_test_case == 9)) {
#if DEBUG
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
	} else if ((rebuild_test_case == 12) || (rebuild_test_case == 13) || (rebuild_test_case == 16)) {
	    	if (offset >= ZVOL_VOLUME_SIZE(zvol_state))
			hdr.opcode = ZVOL_OPCODE_REBUILD_COMPLETE;
		rc = uzfs_zvol_socket_write(sfd, (char *)&hdr, sizeof (hdr));
		if (rc != 0) {
			goto exit;
		}
		if ((all_snap_done_received == 1) && (offset >= ZVOL_VOLUME_SIZE(zvol_state))) {
			LOG_INFO("Rebuilding zvol %s completed", zinfo->name);
			goto exit;
		}
	}

#if DEBUG
	if ((thread_num == 2) && (rebuild_test_case == 13))
		inject_error.delay.helping_replica_ack_sender = 1;
#endif

	rebuild_io_cnt = 0;
	while (1) {
		if (ZVOL_IS_REBUILDING_ERRORED(zinfo->main_zv)) {
			LOG_ERR("rebuilding errored.. for %s.. on sock(%d)",
			    zinfo->name, sfd);
			goto exit;
		}
		if ((rebuild_test_case == 7) || (rebuild_test_case == 8) || (rebuild_test_case == 9))
		{
			/*
			 * Set offline state on vol3
			 */
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
			LOG_INFO("Resetting delay to zero");
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

		if (hdr.version != version) {
			LOG_ERR("received mismatch %d:%d in version.. for %s..",
			    hdr.version, version, zinfo->name);
			rc = -1;
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

		if (hdr.opcode == ZVOL_OPCODE_REBUILD_SNAP_DONE) {
			LOG_INFO("ZVOL_OPCODE_REBUILD_SNAP_DONE received");
			//offset += zvol_rebuild_step_size;
			VERIFY(offset >= ZVOL_VOLUME_SIZE(zvol_state));
			offset = 0;
			rc = uzfs_zvol_handle_rebuild_snap_done(&hdr, sfd,
			    zinfo);
			checkpointed_ionum = hdr.io_seq - 1;
			goto next_step;
		}

		if (hdr.opcode == ZVOL_OPCODE_REBUILD_ALL_SNAP_DONE) {
			all_snap_done_received = 1;
			if (version >= RESIZE_REBUILD_MIN_VERSION) {
				if (rebuild_test_case == 16) {
					/*
					 * snapshot should fail if we
					 * are transitioning to AFS
					 * sending snapshot command to
					 * scanner (zinfo2)
					 */
					mgmt_thread_test_case(14, zinfo2);
					EXPECT_EQ(status, ZVOL_OP_STATUS_FAILED);
					hdr.opcode = ZVOL_OPCODE_REBUILD_COMPLETE;
				} else {
					hdr.opcode = ZVOL_OPCODE_AFS_STARTED;
				}
				rc = uzfs_zvol_socket_write(sfd,
				    (char *)&hdr, sizeof (hdr));
				if (rc != 0) {
					LOG_ERR("Socket write failed err(%d)", rc);
					goto exit;
				}
			}
			if (uzfs_zvol_get_rebuild_status(zinfo->main_zv) !=
			    ZVOL_REBUILDING_AFS) {
				uzfs_zvol_set_rebuild_status(zinfo->main_zv,
				    ZVOL_REBUILDING_AFS);
				uzfs_zinfo_rebuild_from_clone(zinfo);
			}
			continue;
		}

		if (hdr.opcode == ZVOL_OPCODE_REBUILD_SNAP_START) {
			LOG_INFO("ZVOL_OPCODE_REBUILD_SNAP_START received");
			rc = uzfs_zvol_handle_rebuild_snap_start(&hdr,
			    sfd, zinfo);
			if (rc != 0) {
				LOG_ERR("Rebuild snap start failed.."
				    "for %s on fd(%d)",
				    zinfo->name, sfd);
				goto exit;
			}
			continue;
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
		LOG_INFO("completed rebuild IO %lu %lu for cnt %d %s", hdr.io_seq, hdr.offset, rebuild_io_cnt, zinfo->name);

		/*
		 * Take refcount for uzfs_zvol_worker to work on it.
		 * Will dropped by uzfs_zvol_worker once cmd is executed.
		 */
		uzfs_zinfo_take_refcnt(zinfo);
		zio_cmd->zinfo = zinfo;
		uzfs_zvol_worker(zio_cmd);
		if (zio_cmd->hdr.status != ZVOL_OP_STATUS_OK) {
			LOG_ERR("rebuild IO failed.. for %s..", zinfo->name);
			rc = -1;
			goto exit;
		}
		zio_cmd_free(&zio_cmd);
		if ((thread_num == 2) && (rebuild_io_cnt >= 5) && (rebuild_test_case == 13)) {
			LOG_ERR("failing dw_replica rebuild from clone for %s..", zinfo->name);
			rc = -1;
			goto exit;
		}
		rebuild_io_cnt++;
	}
exit:

	mutex_enter(&zinfo->main_zv->rebuild_mtx);
	if (rc != 0) {
		uzfs_zvol_set_rebuild_status(zinfo->main_zv,
		    ZVOL_REBUILDING_ERRORED);
		(zinfo->main_zv->rebuild_info.rebuild_failed_cnt) += 1;
		LOG_ERR("uzfs_zvol_rebuild_dw_replica thread exiting, "
		    "rebuilding failed zvol: %s", zinfo->name);
	}
	(zinfo->main_zv->rebuild_info.rebuild_done_cnt) += 1;
	if (zinfo->main_zv->rebuild_info.rebuild_cnt ==
	    zinfo->main_zv->rebuild_info.rebuild_done_cnt) {
		if (zinfo->main_zv->rebuild_info.rebuild_failed_cnt != 0)
			uzfs_zvol_set_rebuild_status(zinfo->main_zv,
			    ZVOL_REBUILDING_FAILED);
		else {
			/* Mark replica healthy now */
			uzfs_zvol_set_rebuild_status(zinfo->main_zv,
			    ZVOL_REBUILDING_DONE);
			uzfs_zvol_set_status(zinfo->main_zv, ZVOL_STATUS_HEALTHY);
			uzfs_update_ionum_interval(zinfo, 0);
		}
	}
	mutex_exit(&zinfo->main_zv->rebuild_mtx);

	kmem_free(arg, sizeof (rebuild_thread_arg_t));
	if (zio_cmd != NULL)
		zio_cmd_free(&zio_cmd);
	if (sfd != -1) {
		shutdown(sfd, SHUT_RDWR);
		close(sfd);
	}
	/* Parent thread have taken refcount, drop it now */
	uzfs_zinfo_drop_refcnt(zinfo);

	atomic_inc_64(&done_thread_count);
	/* Testcase 12 is for success. So, delete the internal clone */
	if ((rebuild_test_case == 12) || (rebuild_test_case == 13) || (rebuild_test_case == 16)) {
		if (done_thread_count == 2) {
			if (rebuild_test_case == 12) {
				uzfs_zvol_store_kv_pair(zinfo2->clone_zv, (char *)STALE, 1);
				uzfs_zinfo_destroy_internal_clone(zinfo2);
			}
			rebuild_test_case = 0;
		}
	} else {
		rebuild_test_case = 0;
	}

	zk_thread_exit();
}

/*
 * THIS IS COPIED FROM test_zrepl_prot.cc
 */
/*
 * This fn does data conn for a host:ip and volume, and fills data fd
 *
 * NOTE: Return value must be void otherwise we could not use asserts
 * (peculiarity of gtest framework).
 */
static void do_data_connection(int &data_fd, std::string host, uint16_t port,
    std::string zvol_name, int bs=512, int timeout=120,
    int res=ZVOL_OP_STATUS_OK, int rep_factor = 3, int version = REPLICA_VERSION) {
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
	if (version == 3)
		hdr_out.len = sizeof (zvol_op_open_data_ver_3_t);
	else
		hdr_out.len = sizeof (open_data);

	rc = write(fd, &hdr_out, sizeof (hdr_out));
	ASSERT_EQ(rc, sizeof (hdr_out));

	open_data.tgt_block_size = bs;
	open_data.timeout = timeout;
	GtestUtils::strlcpy(open_data.volname, zvol_name.c_str(),
	    sizeof (open_data.volname));
	open_data.replication_factor = rep_factor;
	rc = write(fd, &open_data, hdr_out.len);

	rc = read(fd, &hdr_in, sizeof (hdr_in));
	ASSERT_EQ(rc, sizeof (hdr_in));
	ASSERT_EQ(hdr_in.version, hdr_out.version);
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

void execute_rebuild_test_case(const char *s, int test_case,
    zvol_rebuild_status_t status, zvol_rebuild_status_t verify_status,
    int verify_refcnt = 2, std::string helping_vol="vol2")
{
	kthread_t *thrd;
	rebuild_thread_arg_t *rebuild_args;

	started_thread_count = 0;
	done_thread_count = 0;
	rebuild_test_case = test_case;
	create_rebuild_args(&rebuild_args, helping_vol);
	zinfo->main_zv->zv_status = ZVOL_STATUS_DEGRADED;
	memset(&zinfo->main_zv->rebuild_info, 0, sizeof (zvol_rebuild_info_t));
	zinfo->main_zv->rebuild_info.rebuild_cnt = 1;
	uzfs_zinfo_take_refcnt(zinfo);
	uzfs_zvol_set_rebuild_status(zinfo->main_zv, status);

	thrd = zk_thread_create(NULL, 0, dw_replica_fn,
	    rebuild_args, 0, NULL, TS_RUN, 0, 0);
	zk_thread_join(thrd->t_tid);

	/* wait for rebuild thread to exit */
	while (test_case != 15) {
		if(rebuild_test_case != 0)
			sleep(1);
		else
			break;
	}

	while (test_case == 15) {
		if ((ZVOL_REBUILDING_DONE !=
		    uzfs_zvol_get_rebuild_status(zinfo->main_zv)) &&
		    (ZVOL_REBUILDING_FAILED !=
		    uzfs_zvol_get_rebuild_status(zinfo->main_zv)))
			sleep(1);
		else
			break;
	}

	if (test_case != 15) {
		EXPECT_EQ(verify_refcnt, zinfo->refcnt);
		EXPECT_EQ(verify_status, uzfs_zvol_get_rebuild_status(zinfo->main_zv));
	}
}

typedef struct replica_writes_io_s {
	int r1_fd;
	int r2_fd;
	uint64_t io_num;
	uint64_t start_offset;
	uint64_t total_len;
	uint64_t write_cnt;
	uint64_t read_cnt;
} replica_writes_io_t;

void send_ios_to_replicas(void *arg)
{
	replica_writes_io_t *wargs = (replica_writes_io_t *)arg;
	char wbuf[4096];
	time_t now;
	char *cbuf;
	int clen;
	uint64_t offset, end;
	uint64_t count, max_count;
	uint64_t ioseq = 0;

	max_count = (wargs->total_len / 4096) - 1;
	ASSERT0(wargs->total_len % 4096);
	count = 0;
	end = wargs->start_offset + wargs->total_len;

	while (offset < end) {
		now = time(0);
		cbuf = ctime(&now);
		clen = strlen(cbuf) - 1;

		offset = wargs->start_offset + count++ * sizeof (wbuf);

		for (int i = 0; (i + clen) < sizeof (wbuf); i += clen) {
			memcpy(wbuf + i, cbuf, clen);
		}

		if (wargs->r1_fd != -1)
			GtestUtils::write_data_and_verify_resp(wargs->r1_fd, ioseq, wbuf, offset, sizeof (wbuf), wargs->io_num);

		if (wargs->r2_fd != -1)
			GtestUtils::write_data_and_verify_resp(wargs->r2_fd, --ioseq, wbuf, offset, sizeof (wbuf), wargs->io_num);
		wargs->write_cnt++;
		wargs->io_num++;
	}
	zk_thread_exit();
}

void verify_ios_from_two_replica(void *arg)
{
	replica_writes_io_t *wargs = (replica_writes_io_t *)arg;
	char rbuf1[4096], rbuf2[4096];
	uint64_t offset, end;
	uint64_t count, max_count;
	uint64_t ioseq = 0;
	struct zvol_io_rw_hdr rw_hdr1, rw_hdr2;
	zvol_io_hdr_t hdr_in;
	int rc;

	max_count = (wargs->total_len / 4096) - 1;
	ASSERT0(wargs->total_len % 4096);
	count = 0;
	end = wargs->start_offset + wargs->total_len;

	while (offset < end) {
		offset = wargs->start_offset + count++ * 4096;

		// read from R1
		memset(&hdr_in, 0, sizeof (hdr_in));
		memset(&rw_hdr1, 0, sizeof (rw_hdr1));
		GtestUtils::read_data_start(wargs->r1_fd, ioseq, offset, sizeof (rbuf1), &hdr_in, &rw_hdr1, ZVOL_OP_FLAG_READ_METADATA);
		ASSERT_EQ(hdr_in.status, ZVOL_OP_STATUS_OK);
		ASSERT_EQ(hdr_in.len, sizeof (rw_hdr1) + sizeof (rbuf1));
		ASSERT_EQ(rw_hdr1.len, sizeof (rbuf1));

		memset(rbuf1, 0, sizeof (rbuf1));
		rc = read(wargs->r1_fd, rbuf1, sizeof (rbuf1));
		ASSERT_ERRNO("read", rc >= 0);
		ASSERT_EQ(rc, sizeof (rbuf1));


		// read from R2
		memset(&hdr_in, 0, sizeof (hdr_in));
		memset(&rw_hdr2, 0, sizeof (rw_hdr2));
		GtestUtils::read_data_start(wargs->r2_fd, ioseq, offset, sizeof (rbuf2), &hdr_in, &rw_hdr2, ZVOL_OP_FLAG_READ_METADATA);
		ASSERT_EQ(hdr_in.status, ZVOL_OP_STATUS_OK);
		ASSERT_EQ(hdr_in.len, sizeof (rw_hdr2) + sizeof (rbuf2));
		ASSERT_EQ(rw_hdr2.len, sizeof (rbuf2));

		memset(rbuf2, 0, sizeof (rbuf1));
		rc = read(wargs->r2_fd, rbuf2, sizeof (rbuf2));
		ASSERT_ERRNO("read", rc >= 0);
		ASSERT_EQ(rc, sizeof (rbuf2));

		EXPECT_EQ(memcmp(rbuf1, rbuf2, sizeof (rbuf1)), 0);
		wargs->read_cnt++;
		wargs->io_num++;
	}
	zk_thread_exit();
}

static int
check_if_snap_exist(zvol_state_t *zv, char *snap)
{
	int ret;
	char snapname[MAXNAMELEN];
	objset_t *os;
	uint64_t obj = 0, cookie = 0;

	if (!zv || !zv->zv_objset)
		return (-1);

	os = zv->zv_objset;
	while (1) {
		dsl_pool_config_enter(spa_get_dsl(zv->zv_spa), FTAG);
		ret = dmu_snapshot_list_next(os, sizeof (snapname) - 1,
		    snapname, &obj, &cookie, NULL);
		dsl_pool_config_exit(spa_get_dsl(zv->zv_spa), FTAG);

		if (ret) {
			if (ret == ENOENT)
				ret = 0;
			break;
		}
		if (strcmp(snapname, snap) == 0) {
			ret = 1;
			break;
		}
	}

	return (ret);
}

TEST(uZFSRebuild, TestRebuildSnapDeletion) {
	int data_conn_fd1, data_conn_fd3;
	rebuild_scanner = &uzfs_mock_rebuild_scanner_abrupt_conn_close;
	dw_replica_fn = &uzfs_zvol_rebuild_dw_replica;
	io_receiver = &uzfs_zvol_io_receiver;

	zinfo->main_zv->zv_status = ZVOL_STATUS_DEGRADED;
	zvol_rebuild_step_size = VOLSIZE / 2 + 1000;
	do_data_connection(data_conn_fd1, "127.0.0.1", IO_SERVER_PORT, "vol1");
	do_data_connection(data_conn_fd3, "127.0.0.1", IO_SERVER_PORT, "vol3");

	uint64_t quorum = -1;
	EXPECT_EQ(0, dsl_prop_get_integer(zinfo->main_zv->zv_name,
	    zfs_prop_to_name(ZFS_PROP_QUORUM), &quorum, NULL));
	EXPECT_EQ(quorum, 0);

	/* thread that helps rebuilding exits abruptly just after connects */
	execute_rebuild_test_case("rebuild abrupt", 1, ZVOL_REBUILDING_SNAP,
	    ZVOL_REBUILDING_FAILED, 4, "vol3");
        close(data_conn_fd1);

	EXPECT_EQ(NULL, !zinfo->clone_zv);
	EXPECT_EQ(0, dmu_objset_snapshot_one(zinfo->clone_zv->zv_name, ".io_snap100.2"));
	EXPECT_EQ(0, dmu_objset_snapshot_one(zinfo->clone_zv->zv_name, ".io_snap100.1"));

	rebuild_scanner = &uzfs_zvol_rebuild_scanner;
        zinfo->main_zv->zv_status = ZVOL_STATUS_DEGRADED;
#ifdef	DEBUG
	inject_error.delay.rebuild_complete = 1;
#endif
	do_data_connection(data_conn_fd1, "127.0.0.1", IO_SERVER_PORT, "vol1");
        execute_rebuild_test_case("complete rebuild with data conn", 15,
            ZVOL_REBUILDING_SNAP, ZVOL_REBUILDING_DONE, 4, "vol3");

	sleep(12);
#ifdef	DEBUG
	inject_error.delay.rebuild_complete = 0;
#endif

	EXPECT_EQ(0, dsl_prop_get_integer(zinfo->main_zv->zv_name,
	    zfs_prop_to_name(ZFS_PROP_QUORUM), &quorum, NULL));
	EXPECT_EQ(quorum, 1);

	EXPECT_EQ(0, check_if_snap_exist(zinfo->main_zv, (char *)REBUILD_SNAPSHOT_SNAPNAME));
	close(data_conn_fd1);
	close(data_conn_fd3);
	sleep(10);
}

TEST(uZFSRebuild, TestErroredRebuild) {
	replica_writes_io_t wargs = { 0 };
	kthread_t *writer_thread, *reader_thread;
	uint64_t total_ios = 100;

	ASSERT0(total_ios % 4);

	io_receiver = &uzfs_zvol_io_receiver;
	rebuild_scanner = &uzfs_zvol_rebuild_scanner;
	dw_replica_fn = &uzfs_zvol_rebuild_dw_replica;

	zinfo->main_zv->zv_status = ZVOL_STATUS_DEGRADED;
	do_data_connection(wargs.r1_fd, "127.0.0.1", IO_SERVER_PORT, "vol1");
	do_data_connection(wargs.r2_fd, "127.0.0.1", IO_SERVER_PORT, "vol3");

	wargs.io_num = 100000000;
	wargs.start_offset = 0;
	wargs.total_len = total_ios *4096;
	writer_thread = zk_thread_create(NULL, 0,
	    send_ios_to_replicas, &wargs, 0, NULL, TS_RUN,
	    0, 0);

	zk_thread_join(writer_thread->t_tid);

	zvol_rebuild_step_size = ((total_ios/10) + 1) * 4096;
#ifdef DEBUG
	inject_error.inject_rebuild_error.dw_replica_rebuild_error_io = (total_ios) / 4;
#endif
	execute_rebuild_test_case("errored rebuild with data conn", 15,
	    ZVOL_REBUILDING_SNAP, ZVOL_REBUILDING_FAILED, 4, "vol3");
	close(wargs.r1_fd);
	wargs.r1_fd = -1;
	sleep(10);

	wargs.start_offset = (total_ios / 2) * 4096;
	wargs.total_len = (total_ios) *4096;
	writer_thread = zk_thread_create(NULL, 0,
	    send_ios_to_replicas, &wargs, 0, NULL, TS_RUN,
	    0, 0);
	zk_thread_join(writer_thread->t_tid);

	do_data_connection(wargs.r1_fd, "127.0.0.1", IO_SERVER_PORT, "vol1");
	sleep(2);

	wargs.start_offset = (total_ios * 3 * 4096) / 4;
	wargs.total_len = (total_ios) *4096;
	writer_thread = zk_thread_create(NULL, 0,
	    send_ios_to_replicas, &wargs, 0, NULL, TS_RUN,
	    0, 0);
    zk_thread_join(writer_thread->t_tid);
	zvol_rebuild_step_size =  (10 * 1024ULL * 1024ULL * 1024ULL);
#ifdef DEBUG
	inject_error.inject_rebuild_error.dw_replica_rebuild_error_io = 0;
#endif
	execute_rebuild_test_case("complete rebuild with data conn", 15,
	    ZVOL_REBUILDING_SNAP, ZVOL_REBUILDING_DONE, 6, "vol3");

	wargs.start_offset = 0;
	wargs.total_len = (2 * total_ios) *4096;
	reader_thread = zk_thread_create(NULL, 0,
	    verify_ios_from_two_replica, &wargs, 0, NULL, TS_RUN,
	    0, 0);
	zk_thread_join(reader_thread->t_tid);

	uint64_t quorum = 0;
	EXPECT_EQ(0, dsl_prop_get_integer(zinfo->main_zv->zv_name,
	    zfs_prop_to_name(ZFS_PROP_QUORUM), &quorum, NULL));
	EXPECT_EQ(quorum, 1);

	close(wargs.r1_fd);
	close(wargs.r2_fd);
	sleep(10);
}

TEST(uZFSRebuild, TestAppIO) {
	io_receiver = &uzfs_zvol_io_receiver;
	rebuild_scanner = &uzfs_mock_rebuild_scanner_full;
	dw_replica_fn = &uzfs_zvol_rebuild_dw_replica;

	zinfo->main_zv->zv_status = ZVOL_STATUS_DEGRADED;
	do_data_connection(data_conn_fd, "127.0.0.1", IO_SERVER_PORT, "vol1");
	verify_app_io_read_write(data_conn_fd, zinfo);

	zvol_rebuild_step_size = ZVOL_VOLUME_SIZE(zinfo->main_zv);

	execute_rebuild_test_case("complete rebuild with data conn", 14,
	    ZVOL_REBUILDING_SNAP, ZVOL_REBUILDING_DONE, 4);
	verify_app_io_read_write(data_conn_fd, zinfo);
	close(data_conn_fd);
	sleep(10);
}

TEST(uZFSRebuild, TestRebuildAbrupt) {
	rebuild_scanner = &uzfs_mock_rebuild_scanner_abrupt_conn_close;
	dw_replica_fn = &uzfs_zvol_rebuild_dw_replica;

	zvol_rebuild_step_size = (1024ULL * 1024ULL * 1024ULL) / 2 + 1000;

	/* thread that helps rebuilding exits abruptly just after connects */
	execute_rebuild_test_case("rebuild abrupt", 1, ZVOL_REBUILDING_SNAP,
	    ZVOL_REBUILDING_FAILED);
}

TEST(uZFSRebuild, TestRebuildGrace) {
	rebuild_scanner = &uzfs_mock_rebuild_scanner_graceful_conn_close;
	dw_replica_fn = &uzfs_zvol_rebuild_dw_replica;

	/* thread that helps rebuilding exits gracefully just after connects */
	execute_rebuild_test_case("rebuild grace", 2, ZVOL_REBUILDING_SNAP,
	    ZVOL_REBUILDING_FAILED);
}

TEST(uZFSRebuild, TestRebuildErrorState) {

	/* rebuild state is ERRORED on dw replica */
	execute_rebuild_test_case("rebuild error state", 2,
	    ZVOL_REBUILDING_ERRORED, ZVOL_REBUILDING_FAILED);
}

TEST(uZFSRebuild, TestRebuildScannerMinVersion) {
	rebuild_scanner = &uzfs_mock_rebuild_scanner_min_version;
	dw_replica_fn = &uzfs_zvol_rebuild_dw_replica;

	/* thread helping rebuild will exit after reading REBUILD_STEP */
	execute_rebuild_test_case("rebuild scanner min version", 14,
	    ZVOL_REBUILDING_SNAP, ZVOL_REBUILDING_FAILED);
}


TEST(uZFSRebuild, TestRebuildExitAfterStep) {
	rebuild_scanner = &uzfs_mock_rebuild_scanner_exit_after_rebuild_step;
	dw_replica_fn = &uzfs_zvol_rebuild_dw_replica;

	/* thread helping rebuild will exit after reading REBUILD_STEP */
	execute_rebuild_test_case("rebuild exit after step", 3,
	    ZVOL_REBUILDING_SNAP, ZVOL_REBUILDING_FAILED);
}

TEST(uZFSRebuild, TestRebuildExitAfterInvalidWrite) {
	rebuild_scanner = &uzfs_mock_rebuild_scanner_exit_after_write;
	dw_replica_fn = &uzfs_zvol_rebuild_dw_replica;

	/* thread helping rebuild will exit after writng invalid write IO */
	execute_rebuild_test_case("rebuild exit after invalid write", 4,
	    ZVOL_REBUILDING_SNAP, ZVOL_REBUILDING_FAILED);
}

TEST(uZFSRebuild, TestRebuildExitAfterValidWrite) {
	rebuild_scanner = &uzfs_mock_rebuild_scanner_exit_after_write;
	dw_replica_fn = &uzfs_zvol_rebuild_dw_replica;

	/* thread helping rebuild will exit after writng valid write IO */
	execute_rebuild_test_case("rebuild exit after valid write", 5,
	    ZVOL_REBUILDING_SNAP, ZVOL_REBUILDING_FAILED);
}

TEST(uZFSIOConnAccept, CreateAndDestroyDelayIOReceiverExit) {
	io_receiver = &uzfs_zvol_io_receiver;
	do_data_connection(data_conn_fd_todelete, "127.0.0.1", IO_SERVER_PORT, "vol_todelete");
#if DEBUG
	inject_error.delay.io_receiver_exit = 1;
#endif
	close(data_conn_fd_todelete);
	uzfs_zinfo_destroy("pool1/vol_todelete", spa);
#if DEBUG
	sleep(5);
	inject_error.delay.io_receiver_exit = 0;
#endif
}

TEST(uZFSRebuild, TestRebuildCompleteWithDataConn) {
	io_receiver = &uzfs_zvol_io_receiver;
	rebuild_scanner = &uzfs_mock_rebuild_scanner_rebuild_comp;
	dw_replica_fn = &uzfs_zvol_rebuild_dw_replica;

	uzfs_zvol_set_rebuild_status(zv, ZVOL_REBUILDING_INIT);
	do_data_connection(data_conn_fd, "127.0.0.1", IO_SERVER_PORT, "vol1");

	/*
	 * thread helping rebuild will exit after writing
	 * valid write IO and REBUILD_STEP_DONE, and reads
	 * REBUILD_STEP, writes REBUILD_STEP_DONE
	 */
	execute_rebuild_test_case("complete rebuild with data conn", 6,
	    ZVOL_REBUILDING_SNAP, ZVOL_REBUILDING_INIT);
}

TEST(uZFSRebuild, TestRebuildComplete) {
	io_receiver = &uzfs_zvol_io_receiver;
	rebuild_scanner = &uzfs_mock_rebuild_scanner_rebuild_comp;
	dw_replica_fn = &uzfs_zvol_rebuild_dw_replica;

	uzfs_zvol_set_rebuild_status(zv, ZVOL_REBUILDING_INIT);
	do_data_connection(data_conn_fd, "127.0.0.1", IO_SERVER_PORT, "vol1");
	EXPECT_EQ(NULL, !zinfo->clone_zv);
	EXPECT_EQ(NULL, !zinfo->snapshot_zv);
	/*
	 * thread helping rebuild will exit after writing
	 * valid write IO and REBUILD_STEP_DONE, and reads
	 * REBUILD_STEP, writes REBUILD_STEP_DONE
	 */
	execute_rebuild_test_case("complete rebuild", 7, ZVOL_REBUILDING_SNAP,
	    ZVOL_REBUILDING_DONE, 4);

	EXPECT_EQ(ZVOL_STATUS_HEALTHY, uzfs_zvol_get_status(zinfo->main_zv));

	close(data_conn_fd);
	while (zinfo->is_io_receiver_created)
		sleep(2);
	sleep(5);

	EXPECT_EQ(NULL, zinfo->clone_zv);
	EXPECT_EQ(NULL, zinfo->snapshot_zv);
	memset(&zinfo->main_zv->rebuild_info, 0, sizeof (zvol_rebuild_info_t));
}

TEST(uZFSRebuild, TestRebuildSnapDoneFailureZeroHdrLen) {
	rebuild_scanner = &uzfs_mock_rebuild_scanner_snap_rebuild_related;
	dw_replica_fn = &uzfs_zvol_rebuild_dw_replica;

	zvol_rebuild_step_size = (1024ULL * 1024ULL * 1024ULL) / 2 + 1000;

	/* send ZVOL_OPCODE_REBUILD_SNAP_DONE with zero hdr.len */
	execute_rebuild_test_case("rebuild snap_done zero hdr.len", 8,
	    ZVOL_REBUILDING_SNAP, ZVOL_REBUILDING_FAILED);
}

TEST(uZFSRebuild, TestRebuildSnapDoneFailureWrongHdrLen) {
	rebuild_scanner = &uzfs_mock_rebuild_scanner_snap_rebuild_related;
	dw_replica_fn = &uzfs_zvol_rebuild_dw_replica;

	zvol_rebuild_step_size = (1024ULL * 1024ULL * 1024ULL) / 2 + 1000;
	/*
	 * Send ZVOL_OPCODE_REBUILD_SNAP_DONE
	 * with hdr.len more than MAX_NAME_LEN
	 */
	execute_rebuild_test_case("rebuild snap_done wrong hdr.len", 9,
	    ZVOL_REBUILDING_SNAP, ZVOL_REBUILDING_FAILED);
}

TEST(uZFSRebuild, TestRebuildSnapDoneFailureWrongSnapName) {
	rebuild_scanner = &uzfs_mock_rebuild_scanner_snap_rebuild_related;
	dw_replica_fn = &uzfs_zvol_rebuild_dw_replica;

	zvol_rebuild_step_size = (1024ULL * 1024ULL * 1024ULL) / 2 + 1000;
	/*
	 * Send ZVOL_OPCODE_REBUILD_SNAP_DONE
	 * with wrong snapname format
	 */
	execute_rebuild_test_case("rebuild snap_done wrong snapname", 10,
	    ZVOL_REBUILDING_SNAP, ZVOL_REBUILDING_FAILED);
}

#if 0
/*
 * TODO: Since we have removed volume name check from
 * snap_done function, we have to live without it until
 * we find a better way to make this check work
 */
TEST(uZFSRebuild, TestRebuildSnapDoneFailureWrongVolName) {
	rebuild_scanner = &uzfs_mock_rebuild_scanner_snap_rebuild_related;
	dw_replica_fn = &uzfs_zvol_rebuild_dw_replica;

	zvol_rebuild_step_size = (1024ULL * 1024ULL * 1024ULL) / 2 + 1000;
	/*
	 * Send ZVOL_OPCODE_REBUILD_SNAP_DONE
	 * with wrong volname
	 */
	execute_rebuild_test_case("rebuild snap_done wrong volname", 11,
	    ZVOL_REBUILDING_SNAP, ZVOL_REBUILDING_FAILED);
}
#endif

TEST(uZFSRebuild, TestRebuildSnapDoneSuccess) {
	rebuild_scanner = &uzfs_mock_rebuild_scanner_snap_rebuild_related;
	dw_replica_fn = &uzfs_zvol_rebuild_dw_replica;

	zvol_rebuild_step_size = (1024ULL * 1024ULL * 1024ULL) / 2 + 1000;
	/* send ZVOL_OPCODE_REBUILD_SNAP_DONE success case */
	execute_rebuild_test_case("rebuild snap_done success", 12,
	    ZVOL_REBUILDING_SNAP, ZVOL_REBUILDING_FAILED);
}

TEST(uZFSRebuild, TestRebuildSnapDoneAllSuccess) {
	rebuild_scanner = &uzfs_mock_rebuild_scanner_snap_rebuild_related;
	dw_replica_fn = &uzfs_zvol_rebuild_dw_replica;

	zvol_rebuild_step_size = (1024ULL * 1024ULL * 1024ULL) / 2 + 1000;
	/* send ZVOL_OPCODE_REBUILD_ALL_SNAP_DONE success case */
	execute_rebuild_test_case("rebuild all_snap_done success", 13,
	    ZVOL_REBUILDING_SNAP, ZVOL_REBUILDING_FAILED);
}

TEST(RebuildScanner, AbruptClose) {
	rebuild_scanner = &uzfs_zvol_rebuild_scanner;
	dw_replica_fn = &uzfs_mock_zvol_rebuild_dw_replica;
	io_receiver = &uzfs_zvol_io_receiver;
	zvol_rebuild_step_size = (1024ULL * 1024ULL * 100);
	zinfo2->state = ZVOL_INFO_STATE_ONLINE;

	/* Rebuild thread exits abruptly just after connect */
	execute_rebuild_test_case("Rebuild abrupt", 1,
	    ZVOL_REBUILDING_SNAP, ZVOL_REBUILDING_FAILED);
}

TEST(RebuildScanner, WrongVersion) {
	rebuild_scanner = &uzfs_zvol_rebuild_scanner;
	dw_replica_fn = &uzfs_mock_zvol_rebuild_dw_replica;
	io_receiver = &uzfs_zvol_io_receiver;
	/* Rebuild thread sending wrong opcode after connectg */
	execute_rebuild_test_case("Wrong version", 11,
	    ZVOL_REBUILDING_SNAP, ZVOL_REBUILDING_FAILED);
}

TEST(RebuildScanner, WrongOpcode) {
	rebuild_scanner = &uzfs_zvol_rebuild_scanner;
	dw_replica_fn = &uzfs_mock_zvol_rebuild_dw_replica;
	io_receiver = &uzfs_zvol_io_receiver;
	/* Rebuild thread sending wrong opcode after connectg */
	execute_rebuild_test_case("Wrong opcode", 2,
	    ZVOL_REBUILDING_SNAP, ZVOL_REBUILDING_FAILED);
}

TEST(RebuildScanner, ErrorOut) {
	rebuild_scanner = &uzfs_zvol_rebuild_scanner;
	dw_replica_fn = &uzfs_mock_zvol_rebuild_dw_replica;
	io_receiver = &uzfs_zvol_io_receiver;
	/* Rebuild thread exits after handshake */
	execute_rebuild_test_case("Rebuild error out", 3,
	    ZVOL_REBUILDING_ERRORED, ZVOL_REBUILDING_FAILED);
}

TEST(RebuildScanner, WrongVolname) {
	rebuild_scanner = &uzfs_zvol_rebuild_scanner;
	dw_replica_fn = &uzfs_mock_zvol_rebuild_dw_replica;
	io_receiver = &uzfs_zvol_io_receiver;
	/* Rebuild thread sending wrong vol name */
	execute_rebuild_test_case("Wrong vol name", 4,
	    ZVOL_REBUILDING_SNAP, ZVOL_REBUILDING_FAILED);
}

TEST(RebuildScanner, HandshakeAgaian) {
	rebuild_scanner = &uzfs_zvol_rebuild_scanner;
	dw_replica_fn = &uzfs_mock_zvol_rebuild_dw_replica;
	io_receiver = &uzfs_zvol_io_receiver;
	/* Rebuild thread sending handshake again on same volume */
	execute_rebuild_test_case("Send handshake again", 5,
	    ZVOL_REBUILDING_SNAP, ZVOL_REBUILDING_FAILED);
}

TEST(RebuildScanner, VolumeTooLargeToHandle) {
	rebuild_scanner = &uzfs_zvol_rebuild_scanner;
	dw_replica_fn = &uzfs_mock_zvol_rebuild_dw_replica;
	io_receiver = &uzfs_zvol_io_receiver;
	/* Rebuild thread sending handshake again on same volume */
	execute_rebuild_test_case("Volume offset and len too large", 6,
	    ZVOL_REBUILDING_SNAP, ZVOL_REBUILDING_FAILED);
}

TEST(RebuildScanner, VolumeOffline) {
	rebuild_scanner = &uzfs_zvol_rebuild_scanner;
	dw_replica_fn = &uzfs_mock_zvol_rebuild_dw_replica;
	io_receiver = &uzfs_zvol_io_receiver;
	zvol_rebuild_step_size = (1024ULL * 1024ULL * 1);

	/* Set offline state on vol3 */
	zinfo2->state = ZVOL_INFO_STATE_ONLINE;
	execute_rebuild_test_case("Volume offline", 7,
	    ZVOL_REBUILDING_SNAP, ZVOL_REBUILDING_FAILED);
	zinfo2->state = ZVOL_INFO_STATE_ONLINE;
}

TEST(RebuildScanner, AckSenderCreatedFalse) {
	rebuild_scanner = &uzfs_zvol_rebuild_scanner;
	dw_replica_fn = &uzfs_mock_zvol_rebuild_dw_replica;
	io_receiver = &uzfs_zvol_io_receiver;
	/* Set io_ack_sender_created as B_FALSE */
	zinfo2->is_io_ack_sender_created = B_TRUE;
	execute_rebuild_test_case("Ack Sender Created False", 8,
	    ZVOL_REBUILDING_SNAP, ZVOL_REBUILDING_FAILED);
	zinfo2->is_io_ack_sender_created = B_TRUE;
}

TEST(RebuildScanner, ShutdownRebuildFd) {
	rebuild_scanner = &uzfs_zvol_rebuild_scanner;
	dw_replica_fn = &uzfs_mock_zvol_rebuild_dw_replica;
	io_receiver = &uzfs_zvol_io_receiver;
	/* Set io_ack_sender_created as B_FALSE */
	zinfo2->is_io_ack_sender_created = B_FALSE;
	uzfs_zvol_set_rebuild_status(zv2, ZVOL_REBUILDING_INIT);
	do_data_connection(data_conn_fd, "127.0.0.1", IO_SERVER_PORT, "vol3");
	execute_rebuild_test_case("Shutdown Rebuild FD", 9,
	    ZVOL_REBUILDING_SNAP, ZVOL_REBUILDING_FAILED);
}

TEST(RebuildScanner, RebuildFailureWithAFS) {
	rebuild_scanner = &uzfs_zvol_rebuild_scanner;
	dw_replica_fn = &uzfs_mock_zvol_rebuild_dw_replica;
	io_receiver = &uzfs_zvol_io_receiver;
	uzfs_zvol_set_rebuild_status(zv2, ZVOL_REBUILDING_INIT);
	do_data_connection(data_conn_fd, "127.0.0.1", IO_SERVER_PORT, "vol3");
	zvol_rebuild_step_size = (1024ULL * 1024ULL * 1024ULL);
	execute_rebuild_test_case("Rebuild Failure with AFS", 13,
	    ZVOL_REBUILDING_SNAP, ZVOL_REBUILDING_FAILED);
}

TEST(RebuildScanner, RebuildSuccessWithAFS) {
	int rc;
	size_t snaplist_len;
	void *snap_list;
	std::string snapname="rebuildsuccesswithafs";
	sleep(10);
#if DEBUG
	inject_error.delay.helping_replica_ack_sender = 0;
#endif
	sleep(5);
	close(data_conn_fd);
	data_conn_fd = -1;

	rc = uzfs_zvol_create_snapshot_update_zap(zinfo2, (char *)snapname.c_str(), 15000);
	EXPECT_EQ(rc, 0);

	rc = uzfs_zvol_create_snapshot_update_zap(zinfo, (char *)snapname.c_str(), 500);
	EXPECT_EQ(rc, 0);

	EXPECT_EQ(0, dsl_destroy_snapshot("pool1/vol1@rebuildsuccesswithafs", B_FALSE));

	uzfs_zvol_set_rebuild_status(zv2, ZVOL_REBUILDING_INIT);
	do_data_connection(data_conn_fd, "127.0.0.1", IO_SERVER_PORT, "vol3");
	zvol_rebuild_step_size = (1024ULL * 1024ULL * 100);

#if DEBUG
	inject_error.delay.helping_replica_rebuild_complete = 1;
#endif
	/* Rebuild thread sending complete opcode */
	execute_rebuild_test_case("complete rebuild", 12,
	    ZVOL_REBUILDING_SNAP, ZVOL_REBUILDING_DONE);
	EXPECT_EQ(ZVOL_STATUS_HEALTHY, uzfs_zvol_get_status(zinfo->main_zv));
#if DEBUG
	sleep(10);
	inject_error.delay.helping_replica_rebuild_complete = 0;
#endif

	rc = uzfs_zvol_create_snapshot_update_zap(zinfo, (char *)snapname.c_str(), 15000);
	EXPECT_EQ(rc, 17);

	uint64_t quorum = 0;
	EXPECT_EQ(0, dsl_prop_get_integer(zinfo->main_zv->zv_name,
	    zfs_prop_to_name(ZFS_PROP_QUORUM), &quorum, NULL));
	EXPECT_EQ(quorum, 1);
	memset(&zinfo->main_zv->rebuild_info, 0, sizeof (zvol_rebuild_info_t));
	close(data_conn_fd);
	data_conn_fd = -1;
}

TEST(RebuildScanner, RebuildSuccess) {
	uzfs_zvol_set_rebuild_status(zv2, ZVOL_REBUILDING_INIT);
	do_data_connection(data_conn_fd, "127.0.0.1", IO_SERVER_PORT, "vol3");
	zvol_rebuild_step_size = (1024ULL * 1024ULL * 100);

	/* Rebuild thread sending complete opcode */
	execute_rebuild_test_case("complete rebuild", 10,
	    ZVOL_REBUILDING_SNAP, ZVOL_REBUILDING_DONE);
	EXPECT_EQ(ZVOL_STATUS_HEALTHY, uzfs_zvol_get_status(zinfo->main_zv));

	uint64_t quorum = 0;
	EXPECT_EQ(0, dsl_prop_get_integer(zinfo->main_zv->zv_name,
	    zfs_prop_to_name(ZFS_PROP_QUORUM), &quorum, NULL));
	EXPECT_EQ(quorum, 1);
	memset(&zinfo->main_zv->rebuild_info, 0, sizeof (zvol_rebuild_info_t));
	close(data_conn_fd);
	data_conn_fd = -1;
}

TEST(Misc, DelayWriteAndBreakConn) {
	struct zvol_io_rw_hdr *io_hdr;
	zvol_io_cmd_t *zio_cmd;

#if DEBUG
	inject_error.delay.pre_uzfs_write_data = 1;
#endif
	zvol_io_hdr_t hdr;
	bzero(&hdr, sizeof (hdr));
	hdr.status = ZVOL_OP_STATUS_OK;
	hdr.version = REPLICA_VERSION;
	hdr.opcode = ZVOL_OPCODE_WRITE;
	hdr.len = 512 + sizeof(struct zvol_io_rw_hdr);
	zio_cmd = zio_cmd_alloc(&hdr, -1);

	io_hdr = (struct zvol_io_rw_hdr *)zio_cmd->buf;
	io_hdr->io_num = 100;
	io_hdr->len = 512;

	uzfs_zinfo_take_refcnt(zinfo2);
	zio_cmd->zinfo = zinfo2;

	taskq_dispatch(zinfo2->uzfs_zvol_taskq, uzfs_zvol_worker, zio_cmd, TQ_SLEEP);
	sleep(5);
	GtestUtils::graceful_close(data_conn_fd);
	sleep(10);
#if DEBUG
	inject_error.delay.pre_uzfs_write_data = 0;
#endif
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

void mock_tgt_thread(void *arg)
{
	int			rc = 0;
	int			mgmt_fd, tgt_fd;
	char 			*p;
	char			*ack;
	zvol_state_t		*zv;
	socklen_t		in_len;
	zvol_io_hdr_t		hdr, phdr;
	rebuild_req_t		req;
	struct sockaddr		in_addr;
	zvol_op_resize_data_t	resize;
	char 			buf[512];
	bool			executed = false;
	zvol_info_t 		*zinfo = (zvol_info_t *)arg;

	p = buf;
	ack = NULL;
	zv = NULL;
	mgmt_fd = tgt_fd = -1;

	uint64_t io_seq = zinfo->running_ionum + 1;

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
	hdr.io_seq = io_seq;
	strcpy(buf, zinfo->name);

	bzero(&phdr, sizeof (phdr));
	phdr.version = REPLICA_VERSION;

	/* Send wrong protocol version */
	if (mgmt_test_case == 2)
		hdr.version = -1;

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
		phdr.opcode = ZVOL_OPCODE_SNAP_PREPARE;
		phdr.len = hdr.len;
	}
	
	/*
	 * Send snap create command and
	 * Header len equal to zero
	 */
	if (mgmt_test_case == 12) {
		hdr.opcode = ZVOL_OPCODE_SNAP_CREATE;
		hdr.len = 0;
		phdr.opcode = ZVOL_OPCODE_SNAP_PREPARE;
		phdr.len = hdr.len;
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
		phdr.opcode = ZVOL_OPCODE_SNAP_PREPARE;
		phdr.len = hdr.len;
	}


	/* Snap create success case */	
	if (mgmt_test_case == 14) {
		hdr.opcode = ZVOL_OPCODE_SNAP_CREATE;
		strcpy(buf, zinfo->name);
		strcpy((buf + hdr.len -1), "@snap");
		hdr.len = strlen(buf) + 1;
		phdr.opcode = ZVOL_OPCODE_SNAP_PREPARE;
		phdr.len = hdr.len;
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
		resize.size = VOLSIZE + BLOCKSIZE;
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
		hdr.len = sizeof (rebuild_req_t) + 1;
	}

	/* Rebuild wrong volume name */	
	if (mgmt_test_case == 21) {
		hdr.opcode = ZVOL_OPCODE_START_REBUILD;
		hdr.len = sizeof (rebuild_req_t);
		strcpy(req.dw_volname, "XXXXXXX");
		p = (char *)&req;
	}

	/* Rebuild Null zv */	
	if (mgmt_test_case == 22) {
		hdr.opcode = ZVOL_OPCODE_START_REBUILD;
		hdr.len = sizeof (rebuild_req_t);
		strcpy(req.dw_volname, zinfo->name);
		p = (char *)&req;
		zv = zinfo->main_zv;
		zinfo->main_zv = NULL;
	}

	/*Volume is wrong rebuild state */
	if (mgmt_test_case == 23) {
		hdr.opcode = ZVOL_OPCODE_START_REBUILD;
		hdr.len = sizeof (rebuild_req_t);
		strcpy(req.dw_volname, zinfo->name);
		p = (char *)&req;
		uzfs_zvol_set_rebuild_status(zinfo->main_zv,
		    ZVOL_REBUILDING_SNAP);
	}

	/* Single Replica */
	if (mgmt_test_case == 24) {
		hdr.opcode = ZVOL_OPCODE_START_REBUILD;
		hdr.len = sizeof (rebuild_req_t);
		bzero(&req, sizeof (rebuild_req_t));
		strcpy(req.dw_volname, zinfo->name);
		p = (char *)&req;
	}

	/* Single Replica when volumes are healthy */
	if (mgmt_test_case == 25) {
		hdr.opcode = ZVOL_OPCODE_START_REBUILD;
		hdr.len = sizeof (rebuild_req_t);
		bzero(&req, sizeof (rebuild_req_t));
		strcpy(req.dw_volname, zinfo->name);
		p = (char *)&req;
	}

send_hdr:

	if (phdr.opcode == ZVOL_OPCODE_SNAP_PREPARE) {
		rc = write(mgmt_fd, (void *)&phdr, sizeof (zvol_io_hdr_t));
		if (rc != sizeof (zvol_io_hdr_t)) {
			LOG_ERRNO("Write error during phdr write");
			goto exit;
		}
		rc = write(mgmt_fd, buf, phdr.len);
		if (rc != phdr.len) {
			LOG_ERRNO("Write err during prep snapshot vol write");
			goto exit;
		}
		rc = read(mgmt_fd, (void *)&phdr, sizeof (zvol_io_hdr_t));
		if (rc != sizeof (zvol_io_hdr_t)) {
			LOG_ERRNO("Read error during phdr read");
			goto exit;
		}
	}

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
		zinfo->main_zv = zv;

	if (mgmt_test_case == 23)
		uzfs_zvol_set_rebuild_status(zinfo->main_zv,
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

void mgmt_thread_test_case(int test_case, zvol_info_t *mzinfo = zinfo)
{
	kthread_t	*mock_tgt_thrd;

	mgmt_test_case = test_case;
	uzfs_zinfo_take_refcnt(mzinfo);

	mock_tgt_thrd = zk_thread_create(NULL, 0, mock_tgt_thread,
	    mzinfo, 0, NULL, TS_RUN, 0, 0);

	/* wait for mock_tgt_thread to exit */
	while (1) {
		if (mgmt_test_case != 0)
			sleep(1);
		else
			break;
	}
	uzfs_zinfo_drop_refcnt(mzinfo);
}

kthread_t	*mgmt_thread;
TEST(MgmtThreadTest, MgmtThreadCreation) {
	EXPECT_EQ(3, uzfs_mgmt_conn_list_count(&uzfs_mgmt_conns));
	EXPECT_EQ(2, zinfo->refcnt);

	mgmt_thread = zk_thread_create(NULL, 0, uzfs_zvol_mgmt_thread,
	    NULL, 0, NULL, TS_RUN, 0, 0);
	sleep(1);
	uzfs_mgmt_conn_t *conn = (uzfs_mgmt_conn_t *)zinfo->mgmt_conn;
	conn->conn_bufsiz = 0;
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

/* Snapshot create failure, replica is not healthy & rebuild is in INIT state */
TEST(MgmtThreadTest, SnapCreateFailedReplicaInRebuildInitState) {
	uzfs_zvol_set_status(zinfo->main_zv, ZVOL_STATUS_DEGRADED);
	uzfs_zvol_set_rebuild_status(zinfo->main_zv, ZVOL_REBUILDING_INIT);

	uzfs_mgmt_conn_t *conn = (uzfs_mgmt_conn_t *)zinfo->mgmt_conn;
	mgmt_thread_test_case(14);
	EXPECT_EQ(status, ZVOL_OP_STATUS_FAILED);
	EXPECT_EQ(ZVOL_REBUILDING_INIT,
	    uzfs_zvol_get_rebuild_status(zinfo->main_zv));
}

/*
 * Snapshot create failure, replica is not healthy
 * and rebuild is in rebuild_snap state
 */
TEST(MgmtThreadTest, SnapCreateFailedReplicaInRebuildSnapState) {
	uzfs_zvol_set_status(zinfo->main_zv, ZVOL_STATUS_DEGRADED);
	uzfs_zvol_set_rebuild_status(zinfo->main_zv, ZVOL_REBUILDING_SNAP);

	uzfs_mgmt_conn_t *conn = (uzfs_mgmt_conn_t *)zinfo->mgmt_conn;
	mgmt_thread_test_case(14);
	EXPECT_EQ(status, ZVOL_OP_STATUS_FAILED);
	EXPECT_EQ(ZVOL_REBUILDING_SNAP,
	    uzfs_zvol_get_rebuild_status(zinfo->main_zv));
}


/*
 * Snapshot create failure, replica is not healthy
 * and rebuild is in rebuild_afs state
 */
TEST(MgmtThreadTest, SnapCreateFailedReplicaInRebuildAfsState) {
	uzfs_zvol_set_status(zinfo->main_zv, ZVOL_STATUS_DEGRADED);
	uzfs_zvol_set_rebuild_status(zinfo->main_zv, ZVOL_REBUILDING_AFS);

	uzfs_mgmt_conn_t *conn = (uzfs_mgmt_conn_t *)zinfo->mgmt_conn;
	mgmt_thread_test_case(14);
	EXPECT_EQ(status, ZVOL_OP_STATUS_FAILED);
	EXPECT_EQ(ZVOL_REBUILDING_ERRORED,
	    uzfs_zvol_get_rebuild_status(zinfo->main_zv));
}

/* Snapshot create success */
TEST(MgmtThreadTest, SnapCreateSuccess) {
	uzfs_zvol_set_status(zinfo->main_zv, ZVOL_STATUS_HEALTHY);
	uzfs_zvol_set_rebuild_status(zinfo->main_zv, ZVOL_REBUILDING_DONE);

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
	mgmt_thread_test_case(18, zinfo);
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

/* Rebuild failed, Single replica */
TEST(MgmtThreadTest, RebuildFailureSingleReplica) {
	uzfs_mgmt_conn_t *conn = (uzfs_mgmt_conn_t *)zinfo->mgmt_conn;
	mgmt_thread_test_case(24);
	EXPECT_EQ(status, ZVOL_OP_STATUS_FAILED); // errout on healthy replica
}

/* Rebuild success, Single replica case when volumes are healthy but quorum is off*/
TEST(MgmtThreadTest, RebuildFailureNonQuorumSingleHealthyReplica) {
	uzfs_zinfo_set_status(zinfo, ZVOL_STATUS_HEALTHY);
	uzfs_zvol_set_rebuild_status(zinfo->main_zv, ZVOL_REBUILDING_DONE);

	uint64_t quorum = 0;
	EXPECT_EQ(0, dsl_prop_set_int(zinfo->main_zv->zv_name,
	    zfs_prop_to_name(ZFS_PROP_QUORUM), ZPROP_SRC_LOCAL, quorum));

	uzfs_mgmt_conn_t *conn = (uzfs_mgmt_conn_t *)zinfo->mgmt_conn;
	mgmt_thread_test_case(25);
	EXPECT_EQ(status, ZVOL_OP_STATUS_FAILED);
}

TEST(RebuildMgmtTest, RebuildFailureOldDegraded) {
	rebuild_scanner = &uzfs_zvol_rebuild_scanner;
	dw_replica_fn = &uzfs_mock_zvol_rebuild_dw_replica;
	io_receiver = &uzfs_zvol_io_receiver;
	uzfs_zvol_set_rebuild_status(zv2, ZVOL_REBUILDING_INIT);
	do_data_connection(data_conn_fd, "127.0.0.1", IO_SERVER_PORT, "vol3");

	uzfs_zvol_set_rebuild_status(zv2, ZVOL_REBUILDING_DONE);
	uzfs_zvol_set_status(zinfo2->main_zv, ZVOL_STATUS_HEALTHY);

	uzfs_mgmt_conn_t *conn1 = (uzfs_mgmt_conn_t *)zinfo->mgmt_conn;
	uint16_t port1 = conn1->conn_port;
	// change the port so that it can not connect to mgmt
	conn1->conn_port = 5959;
	uzfs_mgmt_conn_t *conn2 = (uzfs_mgmt_conn_t *)zinfo2->mgmt_conn;
	uint16_t port2 = conn2->conn_port;
	// change the port so that it can connect to mgmt
	conn2->conn_port = 6060;
	zvol_rebuild_step_size = VOLSIZE;
	execute_rebuild_test_case("Rebuild Failure with old helper version", 16,
	    ZVOL_REBUILDING_SNAP, ZVOL_REBUILDING_FAILED);
	close(data_conn_fd);
	//restore the port numbers
	conn1->conn_port = port1;
	conn2->conn_port = port2;
}

TEST(RebuildMgmtTest, SnapRebuildResizeTest) {
	int data_conn_fd, data_conn_fd1;
	rebuild_scanner = &uzfs_zvol_rebuild_scanner;
	dw_replica_fn = &uzfs_zvol_rebuild_dw_replica;
	io_receiver = &uzfs_zvol_io_receiver;
	uzfs_zvol_set_rebuild_status(zv2, ZVOL_REBUILDING_INIT);
	do_data_connection(data_conn_fd, "127.0.0.1", IO_SERVER_PORT, "vol3");

	uzfs_zvol_set_rebuild_status(zv2, ZVOL_REBUILDING_DONE);
	uzfs_zvol_set_status(zinfo2->main_zv, ZVOL_STATUS_HEALTHY);

	uzfs_zvol_set_rebuild_status(zv, ZVOL_REBUILDING_INIT);
	zinfo->main_zv->zv_status = ZVOL_STATUS_DEGRADED;
	do_data_connection(data_conn_fd1, "127.0.0.1", IO_SERVER_PORT, "vol1");

	uint64_t ionum = zinfo2->running_ionum;
	zvol_state_t *snap1 = NULL, *snap2 = NULL;
	int rc, err;

	// resize the volume
	uint64_t size1 = zv2->zv_volsize + VOLSIZE;
	rc = uzfs_zvol_resize(zv2, size1);
	EXPECT_EQ(rc, 0);
	// take the snapshot
	rc = uzfs_zvol_create_snapshot_update_zap(zinfo2, (char *)"rebuildsize1", ionum + 1);
	EXPECT_EQ(rc, 0);
	// resize the volume
	uint64_t size2 = size1 + BLOCKSIZE;
	rc = uzfs_zvol_resize(zv2, size2);
	EXPECT_EQ(rc, 0);
	// take the snapshot
	rc = uzfs_zvol_create_snapshot_update_zap(zinfo2, (char *)"rebuildsize2", ionum + 2);
	EXPECT_EQ(rc, 0);

	/* Rebuild thread sending complete opcode */
	zvol_rebuild_step_size = VOLSIZE;
	execute_rebuild_test_case("complete rebuild", 15,
	    ZVOL_REBUILDING_SNAP, ZVOL_REBUILDING_DONE, 4, "vol3");
	EXPECT_EQ(ZVOL_STATUS_HEALTHY, uzfs_zvol_get_status(zinfo->main_zv));

	err = uzfs_open_dataset(spa, "vol1@rebuildsize1", &snap1);
	EXPECT_EQ(err, 0);
	// old snapshot should have old size
	EXPECT_EQ(snap1->zv_volsize, size1);
	err = uzfs_open_dataset(spa, "vol1@rebuildsize2", &snap2);
	EXPECT_EQ(err, 0);
	// new snapshot should have resized volsize
	EXPECT_EQ(snap2->zv_volsize, size2);
	// volume should have resized volsize
	EXPECT_EQ(zv->zv_volsize, size2);

	uzfs_close_dataset(snap1);
	uzfs_close_dataset(snap2);

	close(data_conn_fd);
	close(data_conn_fd1);
}
