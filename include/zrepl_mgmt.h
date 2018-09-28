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

#include <stdio.h>
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
#define	ZFS_PROP_TARGET_IP	"io.openebs:targetip"

#define	REBUILD_IO_SERVER_PORT	3233
#define	IO_SERVER_PORT	3232

enum zrepl_log_level {
	LOG_LEVEL_DEBUG,
	LOG_LEVEL_INFO,
	LOG_LEVEL_ERR,
};

extern enum zrepl_log_level zrepl_log_level;
void zrepl_log(enum zrepl_log_level lvl, const char *fmt, ...);

/* shortcuts to invoke log function with given log level */
#define	LOG_DEBUG(fmt, ...)	\
	do { \
		if (unlikely(zrepl_log_level <= LOG_LEVEL_DEBUG)) \
			zrepl_log(LOG_LEVEL_DEBUG, fmt, ##__VA_ARGS__); \
	} while (0)
#define	LOG_INFO(fmt, ...)	zrepl_log(LOG_LEVEL_INFO, fmt, ##__VA_ARGS__)
#define	LOG_ERR(fmt, ...)	zrepl_log(LOG_LEVEL_ERR, fmt, ##__VA_ARGS__)
#define	LOG_ERRNO(fmt, ...)	zrepl_log(LOG_LEVEL_ERR, \
				    fmt ": %s", ##__VA_ARGS__, strerror(errno))

SLIST_HEAD(zvol_list, zvol_info_s);
extern kmutex_t zvol_list_mutex;
extern struct zvol_list zvol_list;
struct zvol_io_cmd_s;

#if DEBUG
typedef struct inject_delay_s {
	int helping_replica_rebuild_step;
	int pre_uzfs_write_data;
} inject_delay_t;

typedef struct inject_error_s {
	inject_delay_t delay;
} inject_error_t;

extern inject_error_t inject_error;
#endif

typedef enum zvol_info_state_e {
	ZVOL_INFO_STATE_ONLINE,
	ZVOL_INFO_STATE_OFFLINE,
} zvol_info_state_t;

typedef struct zvol_info_s {

	SLIST_ENTRY(zvol_info_s) zinfo_next;

	/* Logical Unit related fields */
	zvol_info_state_t	state;
	char 		name[MAXPATHLEN];
	zvol_state_t	*main_zv; // original volume
	zvol_state_t	*clone_zv; // cloned volume for rebuilding
	zvol_state_t	*snap_zv; // snap volume from where clone is created
	zvol_state_t    *rebuild_zv; // current snapshot which is rebuilding
	uint64_t	refcnt;

	union {
		struct {
			int	is_io_ack_sender_created	: 1;
			int	is_io_receiver_created		: 1;
		};
		int flags;
	};

	uint32_t	timeout;	/* iSCSI timeout val for this zvol */
	uint64_t	zvol_guid;

	/* Highest IO num of received write IOs */
	uint64_t	running_ionum;

	/* IO num that is stored to ZAP as healthy_ionum when vol is healthy */
	uint64_t	stored_healthy_ionum;

	/*
	 * IO num that will be written to ZAP as healthy_ionum
	 * This tells that all IOs lesser than this are committed to replica
	 * So, running_ionum will be made as checkpointed_ionum and will be
	 * stored to ZAP after 'update_ionum_interval' time period.
	 */
	uint64_t	checkpointed_ionum;

	/* running_ionum that is stored to ZAP when vol is degraded */
	uint64_t	degraded_checkpointed_ionum;

	time_t		checkpointed_time;	/* time of the last chkpoint */
	uint64_t	rebuild_cmd_queued_cnt;
	uint64_t	rebuild_cmd_acked_cnt;
	/*
	 * time of the last stored checkedpointed io sequence number
	 * when ZVOL was in degraded state
	 */
	time_t		degraded_checkpointed_time;
	uint32_t	update_ionum_interval;	/* how often to update io seq */
	taskq_t		*uzfs_zvol_taskq;	/* Taskq for minor management */

	/* Thread sync related */

	/*
	 * For protection of all fields accessed concurrently in this struct
	 */
	pthread_mutex_t	zinfo_mutex;
	pthread_cond_t	io_ack_cond;
	pthread_mutex_t	zinfo_ionum_mutex;

	/* All cmds after execution will go here for ack */
	STAILQ_HEAD(, zvol_io_cmd_s)	complete_queue;

	/* fds related to this zinfo on which threads are waiting */
	STAILQ_HEAD(, zinfo_fd_s)	fd_list;

	uint8_t		io_ack_waiting;

	/* Will be used to singal ack-sender to exit */
	uint8_t		conn_closed;
	/* Pointer to mgmt connection for this zinfo */
	void		*mgmt_conn;

	/* ongoing command that is being worked on to ack to its sender */
	void		*zio_cmd_in_ack;

	/* Performance counter */

	/* Debug counters */
	uint64_t 	read_req_received_cnt;
	uint64_t 	write_req_received_cnt;
	uint64_t 	sync_req_received_cnt;
	uint64_t 	unmap_req_received_cnt;
	uint64_t 	read_req_ack_cnt;
	uint64_t	write_req_ack_cnt;
	uint64_t	sync_req_ack_cnt;
	uint64_t	unmap_req_ack_cnt;
} zvol_info_t;

typedef struct thread_args_s {
	char zvol_name[MAXNAMELEN];
	zvol_info_t *zinfo;
	int fd;
} thread_args_t;

extern void (*zinfo_create_hook)(zvol_info_t *, nvlist_t *);
extern void (*zinfo_destroy_hook)(zvol_info_t *);

typedef struct zinfo_fd_s {
	STAILQ_ENTRY(zinfo_fd_s) fd_link;
	int fd;
} zinfo_fd_t;

typedef struct zvol_io_cmd_s {
	STAILQ_ENTRY(zvol_io_cmd_s) cmd_link;
	zvol_io_hdr_t 	hdr;
	zvol_info_t	*zinfo;
	void		*buf;
	uint64_t	buf_len;
	metadata_desc_t	*metadata_desc;
	int		conn;
} zvol_io_cmd_t;

typedef struct zvol_rebuild_s {
	zvol_info_t	*zinfo;
	int		fd;
} zvol_rebuild_t;

extern int uzfs_zinfo_init(void *zv, const char *ds_name,
    nvlist_t *create_props);
extern zvol_info_t *uzfs_zinfo_lookup(const char *name);
extern void uzfs_zinfo_replay_zil_all(void);
extern int uzfs_zinfo_destroy(const char *ds_name, spa_t *spa);
uint64_t uzfs_zvol_get_last_committed_io_no(zvol_state_t *zv, char *key);
void uzfs_zvol_store_last_committed_healthy_io_no(zvol_info_t *zinfo,
    uint64_t io_seq);
void uzfs_zvol_store_last_committed_degraded_io_no(zvol_info_t *zv,
    uint64_t io_seq);
extern int set_socket_keepalive(int sfd);
extern int create_and_bind(const char *port, int bind_needed,
    boolean_t nonblocking);
int uzfs_zvol_name_compare(zvol_info_t *zv, const char *name);
void shutdown_fds_related_to_zinfo(zvol_info_t *zinfo);

/*
 * API to drop refcnt on zinfo. If refcnt
 * dropped to zero then free zinfo.
 */
static inline void
uzfs_zinfo_drop_refcnt(zvol_info_t *zinfo)
{
	atomic_dec_64(&zinfo->refcnt);
}

/*
 * API to take refcount on zinfo.
 */
static inline void
uzfs_zinfo_take_refcnt(zvol_info_t *zinfo)
{
	atomic_inc_64(&zinfo->refcnt);
}

/*
 * ZAP key for io sequence number
 */
#define	HEALTHY_IO_SEQNUM	"io_seq"
#define	DEGRADED_IO_SEQNUM	"degraded_io_seq"

/*
 * update interval for io_sequence number in degraded mode
 */
#define	DEGRADED_IO_UPDATE_INTERVAL	5

/*
 * create io sequence number for unmap operation
 */
#define	CREATE_UNMAP_IOSEQ(_x)		((_x) | (1ULL << 63))
/*
 * Check if io sequence number is meant for unmap
 */
#define	CHECK_UNMAP_IOSEQ(_x)		((_x >> 63) & 1)
/*
 * Get unmap io sequence number
 */
#define	DECODE_IF_UNMAP_IOSEQ(_x)	((_x) &  (~(1ULL <<  63)))

#ifdef	__cplusplus
}
#endif

#endif /* ZREPL_MGMT_H */
