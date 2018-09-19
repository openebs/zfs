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
 * Copyright (c) 2018 Cloudbyte. All rights reserved.
 */

#ifndef	_MGMT_CONN_H
#define	_MGMT_CONN_H

#include <zrepl_mgmt.h>

#ifdef __cplusplus
extern "C" {
#endif

#define	timesdiff(_clockid, _st, _now, _re)				\
{									\
	clock_gettime(_clockid, &_now);					\
	if ((_now.tv_nsec - _st.tv_nsec) < 0) {				\
		_re.tv_sec  = _now.tv_sec - _st.tv_sec - 1;		\
		_re.tv_nsec = 1000000000 + _now.tv_nsec - _st.tv_nsec;	\
	} else {							\
		_re.tv_sec  = _now.tv_sec - _st.tv_sec;			\
		_re.tv_nsec = _now.tv_nsec - _st.tv_nsec;		\
	}								\
}

/*
 * Mgmt connection states.
 */
enum conn_state {
	CS_CONNECT,		// tcp connect is in progress
	CS_INIT,		// initial state or state after sending reply
	CS_READ_VERSION,	// reading request version
	CS_READ_HEADER,		// reading request header
	CS_READ_PAYLOAD,	// reading request payload
	CS_CLOSE,		// closing connection - final state
};

/*
 * Structure representing mgmt connection and all its reading/writing state.
 */
typedef struct uzfs_mgmt_conn {
	SLIST_ENTRY(uzfs_mgmt_conn) conn_next;
	int		conn_fd;	// network socket FD
	int		conn_refcount;	// should be 0 or 1
	char		conn_host[MAX_IP_LEN];
	uint16_t	conn_port;
	enum conn_state	conn_state;
	void		*conn_buf;	// buffer to hold network data
	int		conn_bufsiz;    // bytes to read/write in total
	int		conn_procn;	// bytes already read/written
	zvol_io_hdr_t	*conn_hdr;	// header of currently processed cmd
	time_t		conn_last_connect;  // time of last attempted connect()
} uzfs_mgmt_conn_t;

/*
 * Blocking or lengthy operations must be executed asynchronously not to block
 * the main event loop. Following structure describes asynchronous task.
 */
typedef struct async_task {
	SLIST_ENTRY(async_task) task_next;
	uzfs_mgmt_conn_t *conn;	// conn ptr can be invalid if closed = true
	boolean_t conn_closed;	// conn was closed before task finished
	boolean_t finished;	// async cmd has finished
	zvol_info_t *zinfo;
	zvol_io_hdr_t hdr;	// header of the incoming request
	void *payload;		// snapshot name
	void *response;		// response of async task
	int payload_length;	// length of payload in bytes
	int response_length;	// length of response data in bytes
	int status;		// status which should be sent back
} async_task_t;

SLIST_HEAD(, async_task) async_tasks;

extern char *target_addr;
extern int mgmt_eventfd;
extern kmutex_t conn_list_mtx;
extern kmutex_t async_tasks_mtx;
SLIST_HEAD(uzfs_mgmt_conn_list, uzfs_mgmt_conn);

extern struct uzfs_mgmt_conn_list uzfs_mgmt_conns;

int handle_start_rebuild_req(uzfs_mgmt_conn_t *conn, zvol_io_hdr_t *hdrp,
	void *payload, size_t payload_size);
void zinfo_create_cb(zvol_info_t *zinfo, nvlist_t *create_props);
void zinfo_destroy_cb(zvol_info_t *zinfo);
void uzfs_zvol_mgmt_thread(void *arg);
int finish_async_tasks(void);

int uzfs_zvol_create_snapshot_update_zap(zvol_info_t *zinfo,
    char *snapname, uint64_t snapshot_io_num);

int uzfs_zvol_get_snap_dataset_with_io(zvol_info_t *zinfo,
    char *snapname, uint64_t *snapshot_io_num, zvol_state_t **snap_zv);

#ifdef __cplusplus
}
#endif

#endif	/* _MGMT_CONN_H */
