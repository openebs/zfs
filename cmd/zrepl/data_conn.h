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

typedef struct rebuild_thread_arg {
	zvol_info_t	*zinfo;
	char		zvol_name[MAX_NAME_LEN];
	int		fd;
	char		ip[MAX_IP_LEN];
	uint16_t	port;
} rebuild_thread_arg_t;

zvol_io_cmd_t *zio_cmd_alloc(zvol_io_hdr_t *hdr, int fd);
void zio_cmd_free(zvol_io_cmd_t **cmd);
int uzfs_zvol_socket_read(int fd, char *buf, uint64_t nbytes);
int uzfs_zvol_socket_write(int fd, char *buf, uint64_t nbytes);
void uzfs_zvol_worker(void *arg);
void uzfs_zvol_rebuild_dw_replica(void *arg);
void uzfs_update_ionum_interval(zvol_info_t *zinfo, uint32_t timeout);
void uzfs_zvol_timer_thread(void);

#endif /* _REBUILD_H */
