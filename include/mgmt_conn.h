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

#ifndef _MGMT_CONN_H
#define	_MGMT_CONN_H

#include <zrepl_mgmt.h>

#ifdef __cplusplus
extern "C" {
#endif

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

extern char *target_addr;
extern int mgmt_eventfd;
extern kmutex_t conn_list_mtx;
SLIST_HEAD(uzfs_mgmt_conn_list, uzfs_mgmt_conn);

extern struct uzfs_mgmt_conn_list uzfs_mgmt_conns;

int handle_start_rebuild_req(uzfs_mgmt_conn_t *conn, zvol_io_hdr_t *hdrp, void *payload, size_t payload_size);
void zinfo_create_cb(zvol_info_t *zinfo, nvlist_t *create_props);
void zinfo_destroy_cb(zvol_info_t *zinfo);
void uzfs_zvol_mgmt_thread(void *arg);

#ifdef __cplusplus
}
#endif

#endif	/* _MGMT_CONN_H */
