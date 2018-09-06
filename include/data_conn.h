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

#ifndef _REBUILD_H
#define	_REBUILD_H

#include <zrepl_prot.h>
#include <zrepl_mgmt.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct rebuild_thread_arg {
	zvol_info_t	*zinfo;
	char		zvol_name[MAX_NAME_LEN];
	int		fd;
	char		ip[MAX_IP_LEN];
	uint16_t	port;
	rebuild_stats_t *rebuild_stats;
} rebuild_thread_arg_t;

typedef struct conn_acceptors {
	int io_fd;
	int rebuild_fd;
} conn_acceptors_t;

thread_func_t io_receiver;
thread_func_t rebuild_scanner;

extern void (*io_receiver)(void *arg);
extern void (*rebuild_scanner)(void *arg);

extern void uzfs_zvol_io_receiver(void *);

extern uint16_t io_server_port;
extern uint16_t rebuild_io_server_port;
extern uint64_t zvol_rebuild_step_size;

int uzfs_zvol_get_ip(char *host, size_t host_len);
void uzfs_zvol_io_conn_acceptor(void *arg);
void init_zrepl(void);
void remove_pending_cmds_to_ack(int fd, zvol_info_t *zinfo);
zvol_io_cmd_t *zio_cmd_alloc(zvol_info_t *zinfo, zvol_io_hdr_t *hdr, int fd);
void zio_cmd_free(zvol_info_t *zinfo, zvol_io_cmd_t **cmd);
int uzfs_zvol_socket_read(int fd, char *buf, uint64_t nbytes);
int uzfs_zvol_read_header(int fd, zvol_io_hdr_t *hdr);
int uzfs_zvol_socket_write(int fd, char *buf, uint64_t nbytes);
void uzfs_zvol_worker(void *arg);
void uzfs_zvol_rebuild_dw_replica(void *arg);
void uzfs_zvol_rebuild_scanner(void *arg);
void uzfs_update_ionum_interval(zvol_info_t *zinfo, uint32_t timeout);
void uzfs_zvol_timer_thread(void);

void signal_fds_related_to_zinfo(zvol_info_t *zinfo);

#ifdef __cplusplus
}
#endif

#endif /* _REBUILD_H */
