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

#ifndef	ZREPL_MGMT_H
#define	ZREPL_MGMT_H

#include <pthread.h>
#include <sys/queue.h>
#include <uzfs_io.h>
#include "zrepl_prot.h"
#include <sys/zfs_context.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	uZFS_ZVOL_WORKERS_MAX 128
#define	uZFS_ZVOL_WORKERS_DEFAULT 6

extern kmutex_t zvol_list_mutex;
struct zvol_io_cmd_s;

typedef enum zvol_info_state_e {
	ZVOL_INFO_STATE_ONLINE,
	ZVOL_INFO_STATE_OFFLINE,
} zvol_info_state_t;

typedef struct thread_args_s {
	char zvol_name[MAXNAMELEN];
	int fd;
} thread_args_t;

typedef struct zvol_info_s {

	SLIST_ENTRY(zvol_info_s) zinfo_next;

	/* Logical Unit related fields */
	zvol_info_state_t	state;
	char 		name[MAXPATHLEN];
	zvol_state_t	*zv;
	int 		refcnt;
	int		is_io_ack_sender_created;
	uint64_t	checkpointed_io_seq;
	taskq_t		*uzfs_zvol_taskq;	/* Taskq for minor management */

	/* Thread sync related */

	/* For protection of complete_queue */
	pthread_mutex_t	zinfo_mutex;
	pthread_mutex_t	complete_queue_mutex;
	pthread_cond_t	io_ack_cond;

	pthread_t 	io_receiver_thread;
	pthread_t 	io_ack_sender_thread;

	/* All cmds after execution will go here for ack */
	STAILQ_HEAD(, zvol_io_cmd_s)	complete_queue;

	uint8_t		io_ack_waiting;
	uint8_t		error_count;

	/* Will be used to singal ack-sender to exit */
	uint8_t		conn_closed;

	/* Perfromance counter */

	/* Debug counters */
	int 		read_req_received_cnt;
	int 		write_req_received_cnt;
	int 		read_req_ack_cnt;
	int 		write_req_ack_cnt;
} zvol_info_t;

typedef struct zvol_io_cmd_s {
	STAILQ_ENTRY(zvol_io_cmd_s) cmd_link;
	zvol_io_hdr_t 	hdr;
	void		*zv;
	void		*buf;
	metadata_desc_t	*metadata_desc;
	int		conn;
} zvol_io_cmd_t;

extern int uzfs_zinfo_init(void *zv, const char *ds_name);
extern zvol_info_t *uzfs_zinfo_lookup(const char *name);
extern void uzfs_zinfo_drop_refcnt(zvol_info_t *zinfo, int locked);
extern void uzfs_zinfo_take_refcnt(zvol_info_t *zinfo, int locked);
extern void uzfs_zinfo_replay_zil_all(void);
extern int uzfs_zinfo_destroy(const char *ds_name, spa_t *spa);
extern void uzfs_zinfo_update_io_seq_for_all_volumes(void);
void uzfs_zvol_get_last_committed_io_no(zvol_state_t *zv,
    uint64_t *io_seq);
void uzfs_zvol_store_last_committed_io_no(zvol_state_t *zv,
    uint64_t io_seq);
extern int create_and_bind(const char *port, int bind_needed);

#define	ZREPL_LOG(fmt, ...)  syslog(LOG_NOTICE,				\
		"%-18.18s:%4d: %-20.20s: " fmt, __func__, __LINE__,	\
    tinfo, ##__VA_ARGS__)

#define	ZREPL_NOTICELOG(fmt, ...) syslog(LOG_NOTICE,			\
		"%-18.18s:%4d: %-20.20s: " fmt, __func__, __LINE__,	\
    tinfo, ##__VA_ARGS__)

#define	ZREPL_ERRLOG(fmt, ...) syslog(LOG_ERR,				\
		"%-18.18s:%4d: %-20.20s: " fmt, __func__, __LINE__,	\
    tinfo, ##__VA_ARGS__)

#define	ZREPL_WARNLOG(fmt, ...) syslog(LOG_ERR,				\
		"%-18.18s:%4d: %-20.20s: " fmt, __func__, __LINE__,	\
    tinfo, ##__VA_ARGS__)

#define	ZREPL_TRACELOG(FLAG, fmt, ...)					\
	do {								\
		syslog(LOG_NOTICE, "%-18.18s:%4d: %-20.20s: "		\
		    fmt, __func__, __LINE__, tinfo, ##__VA_ARGS__);	\
	} while (0)

#ifdef	__cplusplus
}
#endif

#endif /* ZREPL_MGMT_H */
