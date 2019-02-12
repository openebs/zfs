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

#include <time.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <sys/epoll.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/eventfd.h>
#include <sys/prctl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#include <sys/dsl_dataset.h>
#include <sys/dsl_destroy.h>
#include <sys/dsl_dir.h>
#include <sys/dmu_objset.h>
#include <sys/dsl_prop.h>
#include <string.h>
#include <zrepl_prot.h>
#include <uzfs_mgmt.h>
#include <json-c/json_object.h>
#include <libnvpair.h>

#include <mgmt_conn.h>
#include "data_conn.h"
#include "uzfs_rebuilding.h"

/*
 * This file contains implementation of event loop (uzfs_zvol_mgmt_thread).
 * Event loop is run by a single thread and it has exclusive access to
 * file descriptors which simplifies locking. The only synchronization
 * problem which needs to be taken care of is adding new connections and
 * removing/closing existing ones, which is done by other threads.
 * For that purpose there is:
 *
 *      list of connections
 *      eventfd file descriptor for signaling changes in connection list
 *      connection list mutex which protects both entities mentioned above
 *
 * zinfo_create_cb - uzfs callback which adds entry to connection list
 *                   (connect is async - it does not block creation)
 * zinfo_destroy_cb - uzfs callback which removes entry from connection list
 *                   (it blocks until the connection FD is really closed
 *                    to guarantee no activity related to zinfo after it
 *                    is destroyed)
 * event loop thread never adds or removes list entries but only updates
 *     their state.
 */

/* log wrappers which prefix log message by iscsi target address */
#define	DBGCONN(c, fmt, ...)	LOG_DEBUG("[tgt %s:%u:%d]: " fmt, \
				(c)->conn_host, (c)->conn_port, \
				c->conn_fd, ##__VA_ARGS__)
#define	LOGCONN(c, fmt, ...)	LOG_INFO("[tgt %s:%u:%d]: " fmt, \
				(c)->conn_host, (c)->conn_port, \
				c->conn_fd, ##__VA_ARGS__)
#define	LOGERRCONN(c, fmt, ...)	LOG_ERR("[tgt %s:%u:%d]: " fmt, \
				(c)->conn_host, (c)->conn_port, \
				c->conn_fd, ##__VA_ARGS__)

/* Max # of events from epoll processed at once */
#define	MAX_EVENTS	10
#define	MGMT_PORT	"12000"
#define	RECONNECT_DELAY	4	// 4 seconds

/* conn list can be traversed or changed only when holding the mutex */
kmutex_t conn_list_mtx;
struct uzfs_mgmt_conn_list uzfs_mgmt_conns;

/*
 * Blocking or lengthy operations must be executed asynchronously not to block
 * the main event loop. Following structure describes asynchronous task.
 */
kmutex_t async_tasks_mtx;

/* event FD for waking up event loop thread blocked in epoll_wait */
int mgmt_eventfd = -1;
int epollfd = -1;
/* default iSCSI target IP address */
char *target_addr;

static int move_to_next_state(uzfs_mgmt_conn_t *conn);

/*
 * Remove connection FD from poll set and close the FD.
 */
static int
close_conn(uzfs_mgmt_conn_t *conn)
{
	async_task_t *async_task;

	if (conn->conn_state != CS_CONNECT)
		LOGCONN(conn, "Closing the connection");

	/* Release resources tight to the conn */
	if (conn->conn_buf != NULL) {
		kmem_free(conn->conn_buf, conn->conn_bufsiz);
		conn->conn_buf = NULL;
	}
	conn->conn_bufsiz = 0;
	conn->conn_procn = 0;
	if (conn->conn_hdr != NULL) {
		kmem_free(conn->conn_hdr, sizeof (zvol_io_hdr_t));
		conn->conn_hdr = NULL;
	}

	if (epoll_ctl(epollfd, EPOLL_CTL_DEL, conn->conn_fd, NULL) == -1) {
		perror("epoll_ctl del");
		return (-1);
	}
	(void) close(conn->conn_fd);
	conn->conn_fd = -1;

	mutex_enter(&async_tasks_mtx);
	SLIST_FOREACH(async_task, &async_tasks, task_next) {
		if (async_task->conn == conn) {
			async_task->conn_closed = B_TRUE;
		}
	}
	mutex_exit(&async_tasks_mtx);

	return (0);
}

/*
 * Complete destruction of conn struct. conn list mtx must be held when calling
 * this function.
 * Close connection if still open, remove conn from list of conns and free it.
 */
static int
destroy_conn(uzfs_mgmt_conn_t *conn)
{
	ASSERT(MUTEX_HELD(&conn_list_mtx));

	if (conn->conn_fd >= 0) {
		if (close_conn(conn) != 0)
			return (-1);
	}
	DBGCONN(conn, "Destroying the connection");
	SLIST_REMOVE(&uzfs_mgmt_conns, conn, uzfs_mgmt_conn, conn_next);
	kmem_free(conn, sizeof (*conn));
	return (0);
}

/*
 * Create non-blocking socket and initiate connection to the target.
 * Returns the new FD or -1.
 */
static int
connect_to_tgt(uzfs_mgmt_conn_t *conn)
{
	struct sockaddr_in istgt_addr;
	int sfd, rc;
	int synretries = 3;

	conn->conn_last_connect = time(NULL);

	bzero((char *)&istgt_addr, sizeof (istgt_addr));
	istgt_addr.sin_family = AF_INET;
	istgt_addr.sin_addr.s_addr = inet_addr(conn->conn_host);
	istgt_addr.sin_port = htons(conn->conn_port);

	sfd = create_and_bind(MGMT_PORT, B_FALSE, B_TRUE);
	if (sfd < 0)
		return (-1);

	/*
	 * synretry count is usually 6, which takes > 2 minutes.
	 * kernel retries syn at 1, 2, 4, 8, 16, 32 and 64 seconds.
	 * Due to some reason, even if listener at tgt is available,
	 * until these retransmissions are complete and start new connect
	 * call, connection is not getting established, and this is causing
	 * volume to get into RO state.
	 * By reducing synretries to 3, next connect call is made in less
	 * than 20 seconds.
	 */
	if (setsockopt(sfd, IPPROTO_TCP, TCP_SYNCNT, &synretries,
	    sizeof (int)) < 0) {
		perror("setsockopt(TCP_SYNCNT) failed");
	}

	rc = connect(sfd, (struct sockaddr *)&istgt_addr, sizeof (istgt_addr));
	/* EINPROGRESS means that EPOLLOUT will tell us when connect is done */
	if (rc != 0 && errno != EINPROGRESS) {
		close(sfd);
		LOG_ERRNO("Failed to connect to %s:%d", conn->conn_host,
		    conn->conn_port);
		return (-1);
	}

	return (sfd);
}

/*
 * Scan mgmt connection list and create new connections or close unused ones
 * as needed.
 */
static int
scan_conn_list(void)
{
	uzfs_mgmt_conn_t *conn, *conn_tmp;
	struct epoll_event ev;
	int rc = 0;

	mutex_enter(&conn_list_mtx);
	/* iterate safely because entries can be destroyed while iterating */
	conn = SLIST_FIRST(&uzfs_mgmt_conns);
	while (conn != NULL) {
		conn_tmp = SLIST_NEXT(conn, conn_next);
		/* we need to create new connection */
		if (conn->conn_refcount > 0 && conn->conn_fd < 0 &&
		    time(NULL) - conn->conn_last_connect >= RECONNECT_DELAY) {
			conn->conn_fd = connect_to_tgt(conn);
			if (conn->conn_fd >= 0) {
				conn->conn_state = CS_CONNECT;
				ev.events = EPOLLOUT;
				ev.data.ptr = conn;
				if (epoll_ctl(epollfd, EPOLL_CTL_ADD,
				    conn->conn_fd, &ev) == -1) {
					perror("epoll_ctl add");
					close(conn->conn_fd);
					conn->conn_fd = -1;
					rc = -1;
					break;
				}
			}
		/* we need to close unused connection */
		} else if (conn->conn_refcount == 0) {
			if (destroy_conn(conn) != 0) {
				rc = -1;
				break;
			}
		}
		conn = conn_tmp;
	}
	mutex_exit(&conn_list_mtx);

	return (rc);
}

/*
 * This gets called whenever a new zinfo is created. We might need to create
 * a new mgmt connection to iscsi target in response to this event.
 */
void
zinfo_create_cb(zvol_info_t *zinfo, nvlist_t *create_props)
{
	char target_host[MAXNAMELEN];
	uint16_t target_port;
	uzfs_mgmt_conn_t *conn, *new_mgmt_conn;
	zvol_state_t *zv = zinfo->main_zv;
	char *delim, *ip;
	uint64_t val = 1;
	int rc;

	/* if zvol is being created the zvol property does not exist yet */
	if (create_props != NULL &&
	    nvlist_lookup_string(create_props, ZFS_PROP_TARGET_IP, &ip) == 0) {
		strlcpy(target_host, ip, sizeof (target_host));
	} else {
		/* get it from zvol properties */
		if (zv->zv_target_host[0] == 0) {
			/* in case of missing property take the default IP */
			strlcpy(target_host, "127.0.0.1", sizeof ("127.0.0.1"));
			target_port = TARGET_PORT;
		}
		else
			strlcpy(target_host, zv->zv_target_host, MAXNAMELEN);
	}

	delim = strchr(target_host, ':');
	if (delim == NULL) {
		target_port = TARGET_PORT;
	} else {
		*delim = '\0';
		target_port = atoi(++delim);
	}

	/*
	 * It is allocated before we enter the mutex even if it might not be
	 * used because, because in 99% of cases it will be needed (normally
	 * each zvol has a different iSCSI target).
	 */
	new_mgmt_conn = kmem_zalloc(sizeof (*new_mgmt_conn), KM_SLEEP);

	mutex_enter(&conn_list_mtx);
	SLIST_FOREACH(conn, &uzfs_mgmt_conns, conn_next) {
		if (strcmp(conn->conn_host, target_host) == 0 &&
		    conn->conn_port == target_port) {
			/* we already have conn for this target */
			conn->conn_refcount++;
			zinfo->mgmt_conn = conn;
			mutex_exit(&conn_list_mtx);
			kmem_free(new_mgmt_conn, sizeof (*new_mgmt_conn));
			return;
		}
	}

	new_mgmt_conn->conn_fd = -1;
	new_mgmt_conn->conn_refcount = 1;
	new_mgmt_conn->conn_port = target_port;
	strlcpy(new_mgmt_conn->conn_host, target_host,
	    sizeof (new_mgmt_conn->conn_host));

	zinfo->mgmt_conn = new_mgmt_conn;
	SLIST_INSERT_HEAD(&uzfs_mgmt_conns, new_mgmt_conn, conn_next);
	/* signal the event loop thread */
	if (mgmt_eventfd >= 0) {
		rc = write(mgmt_eventfd, &val, sizeof (val));
		ASSERT3S(rc, ==, sizeof (val));
	}
	mutex_exit(&conn_list_mtx);
}

/*
 * This gets called whenever a zinfo is destroyed. We might need to close
 * the mgmt connection to iscsi target if this was the last zinfo using it.
 */
void
zinfo_destroy_cb(zvol_info_t *zinfo)
{
	uzfs_mgmt_conn_t *conn;
	uint64_t val = 1;
	int rc;

	mutex_enter(&conn_list_mtx);
	SLIST_FOREACH(conn, &uzfs_mgmt_conns, conn_next) {
		if (conn == (uzfs_mgmt_conn_t *)zinfo->mgmt_conn)
			break;
	}
	ASSERT3P(conn, !=, NULL);
	zinfo->mgmt_conn = NULL;

	if (--conn->conn_refcount == 0) {
		/* signal the event loop thread to close FD and destroy conn */
		ASSERT3S(mgmt_eventfd, >=, 0);
		rc = write(mgmt_eventfd, &val, sizeof (val));
		ASSERT3S(rc, ==, sizeof (val));
	}
	mutex_exit(&conn_list_mtx);
}

/*
 * Send simple reply without any payload to the client.
 */
static int
reply_nodata(uzfs_mgmt_conn_t *conn, zvol_op_status_t status,
    int opcode, uint64_t io_seq)
{
	zvol_io_hdr_t *hdrp;
	struct epoll_event ev;

	if (status != ZVOL_OP_STATUS_OK) {
		LOGERRCONN(conn, "Error reply with status %d for OP %d",
		    status, opcode);
	} else {
		DBGCONN(conn, "Reply without payload for OP %d", opcode);
	}

	hdrp = kmem_zalloc(sizeof (*hdrp), KM_SLEEP);
	hdrp->version = REPLICA_VERSION;
	hdrp->opcode = opcode;
	hdrp->io_seq = io_seq;
	hdrp->status = status;
	hdrp->len = 0;
	ASSERT3P(conn->conn_buf, ==, NULL);
	conn->conn_buf = hdrp;
	conn->conn_bufsiz = sizeof (*hdrp);
	conn->conn_procn = 0;
	conn->conn_state = CS_INIT;

	ev.events = EPOLLOUT;
	ev.data.ptr = conn;
	return (epoll_ctl(epollfd, EPOLL_CTL_MOD, conn->conn_fd, &ev));
}

/*
 * Send reply to client which consists of a header and opaque payload.
 */
static int
reply_data(uzfs_mgmt_conn_t *conn, zvol_io_hdr_t *hdrp, void *buf, int size)
{
	struct epoll_event ev;

	DBGCONN(conn, "Data reply");

	conn->conn_procn = 0;
	conn->conn_state = CS_INIT;
	ASSERT3P(conn->conn_buf, ==, NULL);
	conn->conn_bufsiz = sizeof (*hdrp) + size;
	conn->conn_buf = kmem_zalloc(conn->conn_bufsiz, KM_SLEEP);
	memcpy(conn->conn_buf, hdrp, sizeof (*hdrp));
	memcpy((char *)conn->conn_buf + sizeof (*hdrp), buf, size);

	ev.events = EPOLLOUT;
	ev.data.ptr = conn;
	return (epoll_ctl(epollfd, EPOLL_CTL_MOD, conn->conn_fd, &ev));
}

/*
 * Get IP address of first external network interface we encounter.
 */
int
uzfs_zvol_get_ip(char *host, size_t host_len)
{
	struct ifaddrs *ifaddr, *ifa;
	int family, n;
	int rc = -1;

	if (getifaddrs(&ifaddr) == -1) {
		perror("getifaddrs");
		return (-1);
	}

	/*
	 * Walk through linked list, maintaining head
	 * pointer so we can free list later
	 */
	for (ifa = ifaddr, n = 0; ifa != NULL; ifa = ifa->ifa_next, n++) {
		if (ifa->ifa_addr == NULL)
			continue;

		family = ifa->ifa_addr->sa_family;

		if (family == AF_INET || family == AF_INET6) {
			rc = getnameinfo(ifa->ifa_addr, (family == AF_INET) ?
			    sizeof (struct sockaddr_in) :
			    sizeof (struct sockaddr_in6),
			    host, host_len,
			    NULL, 0, NI_NUMERICHOST);
			if (rc != 0) {
				perror("getnameinfo");
				break;
			}

			if (family == AF_INET) {
				if (strcmp(host, "127.0.0.1") == 0)
					continue;
				break;
			}
		}
	}

	freeifaddrs(ifaddr);
	return (rc);
}

int
uzfs_zvol_mgmt_get_handshake_info(zvol_io_hdr_t *in_hdr, const char *name,
    zvol_info_t *zinfo, zvol_io_hdr_t *out_hdr, mgmt_ack_t *mgmt_ack)
{
	zvol_state_t	*zv = zinfo->main_zv;
	int error1, error2;
	bzero(mgmt_ack, sizeof (*mgmt_ack));
	if (uzfs_zvol_get_ip(mgmt_ack->ip, MAX_IP_LEN) == -1) {
		LOG_ERRNO("Unable to get IP");
		return (-1);
	}

	strlcpy(mgmt_ack->volname, name, sizeof (mgmt_ack->volname));
	mgmt_ack->port = (in_hdr->opcode == ZVOL_OPCODE_PREPARE_FOR_REBUILD) ?
	    REBUILD_IO_SERVER_PORT : IO_SERVER_PORT;
	mgmt_ack->pool_guid = spa_guid(zv->zv_spa);

	/*
	 * hold dataset during handshake if objset is NULL
	 * no critical section here as rebuild & handshake won't come at a time
	 */
	if (zv->zv_objset == NULL) {
		if (uzfs_hold_dataset(zv) != 0) {
			LOG_ERR("Failed to hold zvol %s", zinfo->name);
			return (-1);
		}
	}

	error1 = uzfs_zvol_get_last_committed_io_no(zv, HEALTHY_IO_SEQNUM,
	    &zinfo->checkpointed_ionum);
	error2 = uzfs_zvol_get_last_committed_io_no(zv, DEGRADED_IO_SEQNUM,
	    &zinfo->degraded_checkpointed_ionum);
	if (error1 != 0) {
		LOG_ERR("Failed to read io_seqnum %s, err1: %d err2: %d",
		    zinfo->name, error1, error2);
		return (-1);
	}

	/*
	 * Success condition for error2
	 * error2 can be 0 (or)
	 * error2 can be ENOENT when REPLICA_VERSION <= 3
	 */
	if (!((error2 == 0) || (error2 == ENOENT && REPLICA_VERSION <= 3))) {
		LOG_ERR("Failed to read degraded_io %s, err1: %d err2: %d",
		    zinfo->name, error1, error2);
		return (-1);
	}

	if (error2 != 0) {
		LOG_ERR("Failed to read degraded_io %sd err: %d", zinfo->name,
		    error2);
		zinfo->degraded_checkpointed_ionum = 0;
	}

	/*
	 * We don't use fsid_guid because that one is not guaranteed
	 * to stay the same (it is changed in case of conflicts).
	 */
	mgmt_ack->zvol_guid = dsl_dataset_phys(
	    zv->zv_objset->os_dsl_dataset)->ds_guid;
	if (zinfo->zvol_guid == 0)
		zinfo->zvol_guid = mgmt_ack->zvol_guid;
	LOG_INFO("Volume:%s has zvol_guid:%lu", zinfo->name, zinfo->zvol_guid);

	bzero(out_hdr, sizeof (*out_hdr));
	out_hdr->version = REPLICA_VERSION;
	out_hdr->opcode = in_hdr->opcode; // HANDSHAKE or PREPARE_FOR_REBUILD
	out_hdr->io_seq = in_hdr->io_seq;
	out_hdr->len = sizeof (*mgmt_ack);
	out_hdr->status = ZVOL_OP_STATUS_OK;

	zinfo->stored_healthy_ionum = zinfo->checkpointed_ionum;
	zinfo->running_ionum = zinfo->degraded_checkpointed_ionum;
	LOG_INFO("IO sequence number:%lu Degraded IO sequence number:%lu",
	    zinfo->checkpointed_ionum, zinfo->degraded_checkpointed_ionum);

	mgmt_ack->checkpointed_io_seq = zinfo->checkpointed_ionum;
	mgmt_ack->checkpointed_degraded_io_seq =
	    zinfo->degraded_checkpointed_ionum;
	mgmt_ack->quorum = uzfs_zinfo_get_quorum(zinfo);

	return (0);
}

/*
 * This function suppose to lookup into zvol list to find if LUN presented for
 * identification is available/online or not. This function also need to send
 * back IP address of replica along with port so that ISTGT controller can open
 * a connection for IOs.
 */
static int
uzfs_zvol_mgmt_do_handshake(uzfs_mgmt_conn_t *conn, zvol_io_hdr_t *hdrp,
    const char *name, zvol_info_t *zinfo)
{
	mgmt_ack_t 	mgmt_ack;
	zvol_io_hdr_t	hdr;
	if (uzfs_zvol_mgmt_get_handshake_info(hdrp, name, zinfo, &hdr,
	    &mgmt_ack) != 0)
		return (reply_nodata(conn, ZVOL_OP_STATUS_FAILED, hdrp->opcode,
		    hdrp->io_seq));
	return (reply_data(conn, &hdr, &mgmt_ack, sizeof (mgmt_ack)));
}

static int
uzfs_zvol_rebuild_status(uzfs_mgmt_conn_t *conn, zvol_io_hdr_t *hdrp,
    const char *name, zvol_info_t *zinfo)
{
	zrepl_status_ack_t	status_ack;
	zvol_io_hdr_t		hdr;

	status_ack.state = uzfs_zvol_get_status(zinfo->main_zv);

	bzero(&hdr, sizeof (hdr));
	hdr.version = REPLICA_VERSION;
	hdr.opcode = hdrp->opcode;
	hdr.io_seq = hdrp->io_seq;
	hdr.len = sizeof (status_ack);
	hdr.status = ZVOL_OP_STATUS_OK;

	mutex_enter(&zinfo->main_zv->rebuild_mtx);
	status_ack.rebuild_status = uzfs_zvol_get_rebuild_status(
	    zinfo->main_zv);

	/*
	 * Once the REBUILD_FAILED status is sent to target, rebuild status
	 * need to be set to INIT so that rebuild can be retriggered
	 */
	if (uzfs_zvol_get_rebuild_status(zinfo->main_zv) ==
	    ZVOL_REBUILDING_FAILED) {
		memset(&zinfo->main_zv->rebuild_info, 0,
		    sizeof (zvol_rebuild_info_t));
		uzfs_zvol_set_rebuild_status(zinfo->main_zv,
		    ZVOL_REBUILDING_INIT);
	}
	mutex_exit(&zinfo->main_zv->rebuild_mtx);
	return (reply_data(conn, &hdr, &status_ack, sizeof (status_ack)));
}

static int
uzfs_zvol_stats(uzfs_mgmt_conn_t *conn, zvol_io_hdr_t *hdrp, zvol_info_t *zinfo)
{
	zvol_io_hdr_t	hdr;
	zvol_op_stat_t	stat;
	objset_t	*zv_objset = zinfo->main_zv->zv_objset;

	strlcpy(stat.label, "used", sizeof (stat.label));
	stat.value = dsl_dir_phys(
	    zv_objset->os_dsl_dataset->ds_dir)->dd_used_bytes;

	bzero(&hdr, sizeof (hdr));
	hdr.version = REPLICA_VERSION;
	hdr.opcode = hdrp->opcode;
	hdr.io_seq = hdrp->io_seq;
	hdr.len = sizeof (zvol_op_stat_t);
	hdr.status = ZVOL_OP_STATUS_OK;

	return (reply_data(conn, &hdr, &stat, sizeof (stat)));
}

static void
uzfs_append_snapshot_properties(nvlist_t *nv, struct json_object *robj,
    char *prop_name)
{
	nvpair_t	*elem = NULL;
	nvlist_t	*nvlist_value;
	uint64_t value = 0;
	char *str_value;
	int len;

	if (nv == NULL) {
		return;
	}

	while ((elem = nvlist_next_nvpair(nv, elem)) != NULL) {
		switch (nvpair_type(elem)) {
		case DATA_TYPE_UINT64:
			nvpair_value_uint64(elem, &value);
			if (!prop_name) {
				if (strcmp(nvpair_name(elem), "source"))
					LOG_ERR("property name not set.. "
					    "elem:%s val:%lu",
					    nvpair_name(elem), value);
			} else {
				len = snprintf(NULL, 0, "%lu", value) + 1;
				str_value = kmem_zalloc(len, KM_SLEEP);
				snprintf(str_value, len, "%lu", value);
				json_object_object_add(robj, prop_name,
				    json_object_new_string(str_value));
				kmem_free(str_value, len);
			}
			break;

		case DATA_TYPE_STRING:
			nvpair_value_string(elem, &str_value);
			if (!prop_name) {
				if (strcmp(nvpair_name(elem), "source"))
					LOG_ERR("property name not set.. "
					    "elem:%s val:%lu",
					    nvpair_name(elem), value);
			} else
				json_object_object_add(robj, prop_name,
				    json_object_new_string(str_value));
			break;

		case DATA_TYPE_NVLIST:
			(void) nvpair_value_nvlist(elem, &nvlist_value);
			uzfs_append_snapshot_properties(nvlist_value, robj,
			    nvpair_name(elem));
			break;

		default:
			LOG_ERR("nvpair type : %d name:%s\n",
			    nvpair_type(elem), nvpair_name(elem));
		}
		prop_name = NULL;
	}
}

/* Returns TRUE if given is name of internally created snapshot */
static boolean_t
internal_snapshot(char *snap)
{
	if ((strcmp(snap, REBUILD_SNAPSHOT_SNAPNAME) == 0) ||
	    (strncmp(snap, IO_DIFF_SNAPNAME, sizeof (IO_DIFF_SNAPNAME) - 1)
	    == 0))
		return (B_TRUE);
	return (B_FALSE);
}

static int
uzfs_zvol_fetch_snapshot_list(zvol_info_t *zinfo, void **buf,
    size_t *buflen)
{
	char *snapname;
	boolean_t case_conflict, prop_error;
	uint64_t id, pos = 0;
	int error = 0;
	zvol_state_t *zv = (zvol_state_t *)zinfo->main_zv;
	objset_t *os = zv->zv_objset;
	struct zvol_snapshot_list *snap_list;
	dsl_dataset_t *ds;
	dsl_pool_t *dp = os->os_dsl_dataset->ds_dir->dd_pool;
	objset_t *snap_os;
	nvlist_t *nv;
	struct json_object *jobj, *jarray, *jprop;
	const char *json_string;
	uint64_t total_len;
	char err_msg[128];

	snapname = kmem_alloc(ZFS_MAX_DATASET_NAME_LEN, KM_SLEEP);
	jarray = json_object_new_array();

	while (error == 0) {
		prop_error = TRUE;
		dsl_pool_config_enter(dmu_objset_pool(os), FTAG);
		error = dmu_snapshot_list_next(os,
		    ZFS_MAX_DATASET_NAME_LEN, snapname, &id, &pos,
		    &case_conflict);
		if (error) {
			dsl_pool_config_exit(dmu_objset_pool(os), FTAG);
			goto out;
		}

		if (internal_snapshot(snapname)) {
			dsl_pool_config_exit(dmu_objset_pool(os), FTAG);
			continue;
		}

		error = dsl_dataset_hold_obj(dp, id, FTAG, &ds);
		if (error == 0) {
			error = dmu_objset_from_ds(ds, &snap_os);
			if (error == 0 &&
			    !dsl_prop_get_all(snap_os, &nv)) {
				dmu_objset_stats(snap_os, nv);
				if (zvol_get_stats(snap_os, nv))
					LOG_ERR("Failed to get zvol "
					    "stats");
				prop_error = FALSE;
			} else
				prop_error = TRUE;
			dsl_dataset_rele(ds, FTAG);
		}
		dsl_pool_config_exit(dmu_objset_pool(os), FTAG);

		jobj = json_object_new_object();
		json_object_object_add(jobj, "name",
		    json_object_new_string(snapname));

		jprop = json_object_new_object();
		if (error == 0 && !prop_error) {
			uzfs_append_snapshot_properties(nv, jprop, NULL);
			nvlist_free(nv);
		} else {
			snprintf(err_msg, sizeof (err_msg),
			    "Failed to fetch snapshot details.. err(%d)",
			    error);
			json_object_object_add(jprop, "error",
			    json_object_new_string(err_msg));
		}
		json_object_object_add(jobj, "properties", jprop);
		json_object_array_add(jarray, jobj);
	}

out:
	jobj = json_object_new_object();
	json_object_object_add(jobj, "snapshot", jarray);

	kmem_free(snapname, ZFS_MAX_DATASET_NAME_LEN);

	json_string = json_object_to_json_string_ext(jobj,
	    JSON_C_TO_STRING_PLAIN);
	total_len = strlen(json_string);
	snap_list = malloc(total_len + sizeof (*snap_list));
	memset(snap_list, 0, total_len + sizeof (*snap_list));
	snap_list->zvol_guid = zinfo->zvol_guid;
	snap_list->error = (error == ENOENT) ? 0 : error;
	snap_list->data_len = total_len;
	strncpy(snap_list->data, json_string, total_len);
	json_object_put(jobj);

	*buf = snap_list;
	*buflen = total_len + sizeof (*snap_list);

	return (0);
}

static void
free_async_task(async_task_t *async_task)
{
	ASSERT(MUTEX_HELD(&async_tasks_mtx));
	uzfs_zinfo_drop_refcnt(async_task->zinfo);
	if (async_task->payload)
		kmem_free(async_task->payload, async_task->payload_length);
	if (async_task->response)
		kmem_free(async_task->response, async_task->response_length);
	kmem_free(async_task, sizeof (*async_task));
}

/*
 * Iterate through all finished async tasks and send replies to clients.
 */
int
finish_async_tasks(void)
{
	async_task_t *async_task, *async_task_tmp;
	int rc = 0;

	mutex_enter(&async_tasks_mtx);
	for (async_task = SLIST_FIRST(&async_tasks);
	    async_task != NULL;
	    async_task = async_task_tmp) {
		async_task_tmp = SLIST_NEXT(async_task, task_next);
		if (!async_task->finished)
			continue;
		/* connection could have been closed in the meantime */
		if (!async_task->conn_closed) {
			if (async_task->response) {
				async_task->hdr.status = async_task->status;
				async_task->hdr.len =
				    async_task->response_length;
				rc = reply_data(async_task->conn,
				    &async_task->hdr, async_task->response,
				    async_task->response_length);
			} else
				rc = reply_nodata(async_task->conn,
				    async_task->status, async_task->hdr.opcode,
				    async_task->hdr.io_seq);
		}
		SLIST_REMOVE(&async_tasks, async_task, async_task, task_next);
		free_async_task(async_task);
		if (rc != 0) {
			LOG_ERR("replying to client returned error(%d)",
			    async_task->conn->conn_fd);
			break;
		}
	}
	mutex_exit(&async_tasks_mtx);
	return (rc);
}

/*
 * Checks that running io_num is not greater than snapshot_io_num
 * Update snapshot IO to ZAP and take snapshot.
 */
int
uzfs_zvol_create_snapshot_update_zap(zvol_info_t *zinfo,
    char *snapname, uint64_t snapshot_io_num)
{
	int ret = 0;

	if ((uzfs_zvol_get_status(zinfo->main_zv) == ZVOL_STATUS_HEALTHY) &&
	    (zinfo->running_ionum > snapshot_io_num -1)) {
		LOG_ERR("Failed to create snapshot as running_ionum %lu"
		    " is greater than snapshot_io_num %lu",
		    zinfo->running_ionum, snapshot_io_num);
		return (ret = -1);
	}

	uzfs_zinfo_store_last_committed_healthy_io_no(zinfo,
	    snapshot_io_num - 1);

	ret = dmu_objset_snapshot_one(zinfo->name, snapname);
	return (ret);
}

/*
 * Returns zv of snap that is just higher than given ionum
 * If no such snap exists, it returns NULL
 * Note: caller should do uzfs_close_dataset of zv, and,
 * caller need to take care of any ongoing snap requests
 */
int
uzfs_get_snap_zv_ionum(zvol_info_t *zinfo, uint64_t ionum,
    zvol_state_t **psnapzv)
{
	if ((zinfo == NULL) || (zinfo->main_zv == NULL) ||
	    (zinfo->main_zv->zv_objset == NULL))
		return (-1);

	uint64_t obj = 0, cookie = 0;
	zvol_state_t *zv = zinfo->main_zv;
	zvol_state_t *snap_zv = NULL;
	zvol_state_t *smallest_higher_snapzv = NULL;
	objset_t *os = zv->zv_objset;
	char snapname[MAXNAMELEN];
	uint64_t healthy_ionum, smallest_higher_ionum = 0;
	int error;

	while (1) {
		dsl_pool_config_enter(spa_get_dsl(zv->zv_spa), FTAG);
		error = dmu_snapshot_list_next(os, sizeof (snapname) - 1,
		    snapname, &obj, &cookie, NULL);
		dsl_pool_config_exit(spa_get_dsl(zv->zv_spa), FTAG);

		if (error) {
			if (error == ENOENT)
				error = 0;
			break;
		}
		if (internal_snapshot(snapname))
			continue;
		error = get_snapshot_zv(zv, snapname, &snap_zv, B_FALSE,
		    B_TRUE);
		if (error) {
			LOG_ERR("err %d in getting snap %s", error, snapname);
			break;
		}
		error = uzfs_zvol_get_last_committed_io_no(snap_zv,
		    HEALTHY_IO_SEQNUM, &healthy_ionum);
		if (error) {
			LOG_ERR("err %d in getting last commited for snap %s",
			    error, snap_zv->zv_name);
			uzfs_close_dataset(snap_zv);
			snap_zv = NULL;
			break;
		}
		if ((healthy_ionum > ionum) &&
		    ((smallest_higher_snapzv == NULL) ||
		    (smallest_higher_ionum > healthy_ionum))) {
			smallest_higher_ionum = healthy_ionum;
			if (smallest_higher_snapzv != NULL)
				uzfs_close_dataset(smallest_higher_snapzv);
			smallest_higher_snapzv = snap_zv;
		} else
			uzfs_close_dataset(snap_zv);
	}
	if (error) {
		if (smallest_higher_snapzv != NULL) {
			uzfs_close_dataset(smallest_higher_snapzv);
			smallest_higher_snapzv = NULL;
		}
	} else if (psnapzv != NULL)
		*psnapzv = smallest_higher_snapzv;

	return (error);
}

/*
 * For a given snap name, get snap dataset and IO number stored in ZAP
 * Input: zinfo, snap
 * Output: snapshot_io_num, snap_zv
 */
int
uzfs_zvol_get_snap_dataset_with_io(zvol_info_t *zinfo,
    char *snapname, uint64_t *snapshot_io_num, zvol_state_t **snap_zv)
{
	int ret = 0;

	char *longsnap = kmem_asprintf("%s@%s",
	    strchr(zinfo->name, '/') + 1, snapname);
	ret = uzfs_open_dataset(zinfo->main_zv->zv_spa, longsnap, snap_zv);
	if (ret != 0) {
		LOG_ERR("Failed to get info about %s", longsnap);
		strfree(longsnap);
		return (ret);
	}

	strfree(longsnap);
	ret = uzfs_hold_dataset(*snap_zv);
	if (ret != 0) {
		LOG_ERR("Failed to hold snapshot: %d", ret);
		uzfs_close_dataset(*snap_zv);
		*snap_zv = NULL;
		return (ret);
	}

	ret = uzfs_zvol_get_last_committed_io_no(*snap_zv,
	    HEALTHY_IO_SEQNUM, snapshot_io_num);
	return (ret);
}

/*
 * Perform the command (in async context).
 *
 * Currently we have only snapshot commands which are async. We might need to
 * make the code & structures more generic if we add more commands.
 */
static void
uzfs_zvol_execute_async_command(void *arg)
{
	async_task_t *async_task = arg;
	zvol_info_t *zinfo = async_task->zinfo;
	char *dataset;
	char *snap;
	uint64_t volsize;
	int rc;

	switch (async_task->hdr.opcode) {
	case ZVOL_OPCODE_SNAP_CREATE:
		snap = async_task->payload;
		rc = uzfs_zvol_create_snapshot_update_zap(zinfo, snap,
		    async_task->hdr.io_seq);
		if (rc != 0) {
			/*
			 * snap create command failed, close the io
			 * connection so that it can start the rebuilding
			 */
			if (zinfo->io_fd >= 0)
				VERIFY0(shutdown(zinfo->io_fd, SHUT_RDWR));
			LOG_ERR("Failed to create %s@%s: %d",
			    zinfo->name, snap, rc);
			async_task->status = ZVOL_OP_STATUS_FAILED;
		} else {
			async_task->status = ZVOL_OP_STATUS_OK;
		}
		break;
	case ZVOL_OPCODE_SNAP_DESTROY:
		snap = async_task->payload;
		dataset = kmem_asprintf("%s@%s", zinfo->name, snap);
		rc = dsl_destroy_snapshot(dataset, B_FALSE);
		strfree(dataset);
		if (rc != 0) {
			LOG_ERR("Failed to destroy %s@%s: %d",
			    zinfo->name, snap, rc);
			async_task->status = ZVOL_OP_STATUS_FAILED;
		} else {
			async_task->status = ZVOL_OP_STATUS_OK;
		}
		break;
	case ZVOL_OPCODE_RESIZE:
		volsize = *(uint64_t *)async_task->payload;
		rc = zvol_check_volsize(volsize,
		    zinfo->main_zv->zv_volblocksize);
		if (rc == 0) {
			rc = zvol_update_volsize(volsize,
			    zinfo->main_zv->zv_objset);
			if (rc == 0)
				zvol_size_changed(zinfo->main_zv, volsize);
		}
		if (rc != 0) {
			LOG_ERR("Failed to resize zvol %s", zinfo->name);
			async_task->status = ZVOL_OP_STATUS_FAILED;
		} else {
			async_task->status = ZVOL_OP_STATUS_OK;
		}
		break;
	case ZVOL_OPCODE_SNAP_LIST:
		rc = uzfs_zvol_fetch_snapshot_list(zinfo, &async_task->response,
		    (size_t *)&async_task->response_length);
		if (rc != 0) {
			LOG_ERR("Failed to fetch snapshot list for zvol %s\n",
			    zinfo->name);
			async_task->status = ZVOL_OP_STATUS_FAILED;
		} else {
			async_task->status = ZVOL_OP_STATUS_OK;
		}
		break;
	default:
		ASSERT(0);
	}

	/*
	 * Drop the async cmd if event loop thread has terminated or
	 * corresponding connection has been closed
	 */
	mutex_enter(&async_tasks_mtx);
	if (mgmt_eventfd < 0 || async_task->conn_closed) {
		free_async_task(async_task);
	} else {
		uint64_t val = 1;

		async_task->finished = B_TRUE;
		rc = write(mgmt_eventfd, &val, sizeof (val));
		ASSERT3S(rc, ==, sizeof (val));
	}
	mutex_exit(&async_tasks_mtx);
}

/*
 * Dispatch command which should be executed asynchronously to a taskq.
 */
static int
uzfs_zvol_dispatch_command(uzfs_mgmt_conn_t *conn, zvol_io_hdr_t *hdrp,
    void *payload, int length, zvol_info_t *zinfo)
{
	struct epoll_event ev;
	async_task_t *arg;

	arg = kmem_zalloc(sizeof (*arg), KM_SLEEP);
	arg->conn = conn;
	arg->zinfo = zinfo;
	arg->hdr = *hdrp;
	if (length) {
		arg->payload_length = length;
		arg->payload = kmem_zalloc(arg->payload_length, KM_SLEEP);
		memcpy(arg->payload, payload, arg->payload_length);
	}

	mutex_enter(&async_tasks_mtx);
	SLIST_INSERT_HEAD(&async_tasks, arg, task_next);
	mutex_exit(&async_tasks_mtx);

	taskq_dispatch(zinfo->uzfs_zvol_taskq, uzfs_zvol_execute_async_command,
	    arg, TQ_SLEEP);
	/* Until we have the result, don't poll read/write events on FD */
	ev.events = 0;	/* ERR and HUP are implicitly set */
	ev.data.ptr = conn;
	return (epoll_ctl(epollfd, EPOLL_CTL_MOD, conn->conn_fd, &ev));
}

/*
 * Sanitizes the START_REBUILD request payload.
 * Starts rebuild thread to every helping replica
 */
static int
uzfs_zinfo_rebuild_start_threads(mgmt_ack_t *mack, zvol_info_t *zinfo,
    int rebuild_op_cnt)
{
	int 			io_sfd = -1;
	rebuild_thread_arg_t	*thrd_arg;
	kthread_t		*thrd_info;
	for (; rebuild_op_cnt > 0; rebuild_op_cnt--, mack++) {
		LOG_INFO("zvol %s at %s:%u helping in rebuild",
		    mack->volname, mack->ip, mack->port);
		if (uzfs_zvol_name_compare(zinfo, mack->dw_volname) != 0) {
			LOG_ERR("zvol %s not matching with zinfo %s",
			    mack->dw_volname, zinfo->name);
ret_error:
			mutex_enter(&zinfo->main_zv->rebuild_mtx);

			/* Error happened, so set to REBUILD_ERRORED state */
			uzfs_zvol_set_rebuild_status(zinfo->main_zv,
			    ZVOL_REBUILDING_ERRORED);

			(zinfo->main_zv->rebuild_info.rebuild_failed_cnt) +=
			    rebuild_op_cnt;
			(zinfo->main_zv->rebuild_info.rebuild_done_cnt) +=
			    rebuild_op_cnt;

			/*
			 * If all the triggered rebuilds are done,
			 * mark state as REBUILD_FAILED
			 */
			if (zinfo->main_zv->rebuild_info.rebuild_cnt ==
			    zinfo->main_zv->rebuild_info.rebuild_done_cnt)
				uzfs_zvol_set_rebuild_status(zinfo->main_zv,
				    ZVOL_REBUILDING_FAILED);

			mutex_exit(&zinfo->main_zv->rebuild_mtx);
			return (-1);
		}

		io_sfd = create_and_bind("", B_FALSE, B_FALSE);
		if (io_sfd < 0) {
			/* Fail this rebuild process entirely */
			LOG_ERR("Rebuild IO socket create and bind"
			    " failed on zvol: %s", zinfo->name);
			goto ret_error;
		}

		uzfs_zinfo_take_refcnt(zinfo);

		thrd_arg = kmem_alloc(sizeof (rebuild_thread_arg_t), KM_SLEEP);
		thrd_arg->zinfo = zinfo;
		thrd_arg->fd = io_sfd;
		thrd_arg->port = mack->port;
		strlcpy(thrd_arg->ip, mack->ip, MAX_IP_LEN);
		strlcpy(thrd_arg->zvol_name, mack->volname, MAXNAMELEN);
		thrd_info = zk_thread_create(NULL, 0,
		    dw_replica_fn, thrd_arg, 0, NULL, TS_RUN, 0,
		    PTHREAD_CREATE_DETACHED);
		VERIFY3P(thrd_info, !=, NULL);
	}

	return (0);
}

/*
 * Calls API to start rebuild threads
 */
static int
uzfs_zvol_rebuild_dw_replica_start(uzfs_mgmt_conn_t *conn, zvol_io_hdr_t *hdrp,
    mgmt_ack_t *mack, zvol_info_t *zinfo, int rebuild_op_cnt)
{
	int rc;
	rc = uzfs_zinfo_rebuild_start_threads(mack, zinfo, rebuild_op_cnt);
	if (rc != 0)
		return (reply_nodata(conn, ZVOL_OP_STATUS_FAILED, hdrp->opcode,
		    hdrp->io_seq));
	return (reply_nodata(conn, ZVOL_OP_STATUS_OK, hdrp->opcode,
	    hdrp->io_seq));
}

/*
 * This API starts thread to rebuild data from its clone to main vol.
 * As rebuild_cnt is incremented in this fn, this need to be called from
 * rebuilding thread of downgraded replica to make sure that done_cnt hadn't
 * reached rebuild_cnt yet.
 */
int
uzfs_zinfo_rebuild_from_clone(zvol_info_t *zinfo)
{
	mgmt_ack_t mack;
	zvol_io_hdr_t in_hdr, out_hdr;
	int rc;
	in_hdr.opcode = ZVOL_OPCODE_PREPARE_FOR_REBUILD;
	in_hdr.io_seq = 0;

	rc = uzfs_zvol_mgmt_get_handshake_info(&in_hdr, zinfo->name, zinfo,
	    &out_hdr, &mack);
	if (rc != 0)
		return (rc);
	strcpy(mack.dw_volname, mack.volname);

	mutex_enter(&zinfo->main_zv->rebuild_mtx);
	zinfo->main_zv->rebuild_info.rebuild_cnt++;
	mutex_exit(&zinfo->main_zv->rebuild_mtx);

	return (uzfs_zinfo_rebuild_start_threads(&mack, zinfo, 1));
}

/*
 * Sanitizes START_REBUILD request, its header.
 * Handles rebuild for single replica case.
 * Calls API to start threads with every helping replica to rebuild
 */
int
handle_start_rebuild_req(uzfs_mgmt_conn_t *conn, zvol_io_hdr_t *hdrp,
    void *payload, size_t payload_size)
{
	int rc = 0;
	zvol_info_t *zinfo;

	/* Invalid payload size */
	if ((payload_size == 0) || (payload_size % sizeof (mgmt_ack_t)) != 0) {
		LOG_ERR("rebuilding failed.. response is invalid");
		rc = reply_nodata(conn, ZVOL_OP_STATUS_FAILED,
		    hdrp->opcode, hdrp->io_seq);
		goto end;
	}

	/* Find matching zinfo for given downgraded replica */
	mgmt_ack_t *mack = (mgmt_ack_t *)payload;
	zinfo = uzfs_zinfo_lookup(mack->dw_volname);
	if ((zinfo == NULL) || (zinfo->mgmt_conn != conn) ||
	    (zinfo->main_zv == NULL)) {
		if (zinfo != NULL) {
			LOG_ERR("rebuilding failed for %s..", zinfo->name);
			uzfs_zinfo_drop_refcnt(zinfo);
		}
		else
			LOG_ERR("rebuilding failed..");
		rc = reply_nodata(conn, ZVOL_OP_STATUS_FAILED,
		    hdrp->opcode, hdrp->io_seq);
		goto end;
	}

	mutex_enter(&zinfo->main_zv->rebuild_mtx);
	/* Check rebuild status of downgraded zinfo */
	if (uzfs_zvol_get_rebuild_status(zinfo->main_zv) !=
	    ZVOL_REBUILDING_INIT) {
		mutex_exit(&zinfo->main_zv->rebuild_mtx);
		LOG_ERR("rebuilding failed for %s due to improper rebuild "
		    "status", zinfo->name);
		uzfs_zinfo_drop_refcnt(zinfo);
		rc = reply_nodata(conn, ZVOL_OP_STATUS_FAILED,
		    hdrp->opcode, hdrp->io_seq);
		goto end;
	}

	/*
	 * Case where just one replica is being used by customer
	 */
	if ((strcmp(mack->volname, "")) == 0) {
		memset(&zinfo->main_zv->rebuild_info, 0,
		    sizeof (zvol_rebuild_info_t));
		/* Mark replica healthy now */
		uzfs_zvol_set_rebuild_status(zinfo->main_zv,
		    ZVOL_REBUILDING_AFS);
		/*
		 * Lets ask io_receiver thread to flush
		 * all outstanding IOs in taskq
		 */
		zinfo->quiesce_done = 0;
		zinfo->quiesce_requested = 1;
		mutex_exit(&zinfo->main_zv->rebuild_mtx);

		quiesce_wait(zinfo);
		rc = uzfs_zinfo_rebuild_from_clone(zinfo);
		if (rc != 0) {
			LOG_ERR("Rebuild from clone for vol %s "
			    "failed", zinfo->name);
			rc = reply_nodata(conn, ZVOL_OP_STATUS_FAILED,
			    hdrp->opcode, hdrp->io_seq);
		} else {
			LOG_INFO("Rebuild started from clone for vol "
			    "%s", zinfo->name);
			rc = reply_nodata(conn, ZVOL_OP_STATUS_OK,
			    hdrp->opcode, hdrp->io_seq);
		}
		uzfs_zinfo_drop_refcnt(zinfo);
		goto end;
	}

	int rebuild_op_cnt = (payload_size / sizeof (mgmt_ack_t));
	int loop_cnt;
	uint64_t max_ioseq;
	for (loop_cnt = 0, max_ioseq = 0, mack = payload;
	    loop_cnt < rebuild_op_cnt; loop_cnt++, mack++)
		if (max_ioseq < mack->checkpointed_io_seq)
			max_ioseq = mack->checkpointed_io_seq;

	if ((zinfo->checkpointed_ionum < max_ioseq) &&
	    (rebuild_op_cnt != 1)) {
		mutex_exit(&zinfo->main_zv->rebuild_mtx);
		LOG_ERR("rebuilding failed for %s due to rebuild_op_cnt"
		    "(%d) is not one when checkpointed num (%lu) is "
		    "less than max_ioseq(%lu)", zinfo->name,
		    rebuild_op_cnt, zinfo->checkpointed_ionum,
		    max_ioseq);
		uzfs_zinfo_drop_refcnt(zinfo);
		rc = reply_nodata(conn, ZVOL_OP_STATUS_FAILED,
		    hdrp->opcode, hdrp->io_seq);
		goto end;
	}

	memset(&zinfo->main_zv->rebuild_info, 0,
	    sizeof (zvol_rebuild_info_t));
	zinfo->quiesce_requested = zinfo->quiesce_done = 0;
	uzfs_zvol_set_rebuild_status(zinfo->main_zv,
	    ZVOL_REBUILDING_SNAP);

	/* Track # of rebuilds we are initializing on replica */
	zinfo->main_zv->rebuild_info.rebuild_cnt = rebuild_op_cnt;

	mutex_exit(&zinfo->main_zv->rebuild_mtx);

	DBGCONN(conn, "Rebuild start command");
	/* Call API to start threads with every helping replica */
	rc = uzfs_zvol_rebuild_dw_replica_start(conn, hdrp, payload,
	    zinfo, rebuild_op_cnt);

	/* dropping refcount for uzfs_zinfo_lookup */
	uzfs_zinfo_drop_refcnt(zinfo);
end:
	return (rc);
}

/*
 * Process the whole message consisting of message header and optional payload.
 */
static int
process_message(uzfs_mgmt_conn_t *conn)
{
	char zvol_name[MAX_NAME_LEN + 1];
	zvol_io_hdr_t *hdrp = conn->conn_hdr;
	void *payload = conn->conn_buf;
	size_t payload_size = conn->conn_bufsiz;
	zvol_op_resize_data_t *resize_data;
	zvol_info_t *zinfo;
	char *snap = NULL;
	int rc = 0;

	conn->conn_hdr = NULL;
	conn->conn_buf = NULL;
	conn->conn_bufsiz = 0;
	conn->conn_procn = 0;

	switch (hdrp->opcode) {
	case ZVOL_OPCODE_HANDSHAKE:
	case ZVOL_OPCODE_PREPARE_FOR_REBUILD:
	case ZVOL_OPCODE_REPLICA_STATUS:
	case ZVOL_OPCODE_STATS:
		if (payload_size == 0 || payload_size >= MAX_NAME_LEN) {
			rc = reply_nodata(conn, ZVOL_OP_STATUS_FAILED,
			    hdrp->opcode, hdrp->io_seq);
			break;
		}
		strlcpy(zvol_name, payload, payload_size);
		zvol_name[payload_size] = '\0';

		if ((zinfo = uzfs_zinfo_lookup(zvol_name)) == NULL) {
			LOGERRCONN(conn, "Unknown zvol: %s", zvol_name);
			rc = reply_nodata(conn, ZVOL_OP_STATUS_FAILED,
			    hdrp->opcode, hdrp->io_seq);
			break;
		}
		/*
		 * Can happen if target asks for a zvol which exists but is
		 * presumably served by a different mgmt connection. Recovery
		 * from that case would not be trivial so we pretend a miss.
		 */
		if (zinfo->mgmt_conn != conn) {
			uzfs_zinfo_drop_refcnt(zinfo);
			LOGERRCONN(conn, "Target used invalid connection for "
			    "zvol %s", zvol_name);
			rc = reply_nodata(conn, ZVOL_OP_STATUS_FAILED,
			    hdrp->opcode, hdrp->io_seq);
			break;
		}

		if (hdrp->opcode == ZVOL_OPCODE_HANDSHAKE) {
			LOGCONN(conn, "Handshake command for zvol %s",
			    zvol_name);
			rc = uzfs_zvol_mgmt_do_handshake(conn, hdrp, zvol_name,
			    zinfo);
		} else if (hdrp->opcode == ZVOL_OPCODE_PREPARE_FOR_REBUILD) {
			LOGCONN(conn, "Prepare for rebuild command for zvol %s",
			    zvol_name);
			rc = uzfs_zvol_mgmt_do_handshake(conn, hdrp, zvol_name,
			    zinfo);
		} else if (hdrp->opcode == ZVOL_OPCODE_REPLICA_STATUS) {
			LOGCONN(conn, "Replica status command for zvol %s",
			    zvol_name);
			rc = uzfs_zvol_rebuild_status(conn, hdrp, zvol_name,
			    zinfo);
		} else if (hdrp->opcode == ZVOL_OPCODE_STATS) {
			DBGCONN(conn, "Stats command for zvol %s", zvol_name);
			rc = uzfs_zvol_stats(conn, hdrp, zinfo);
		} else {
			ASSERT(0);
		}
		uzfs_zinfo_drop_refcnt(zinfo);
		break;

	case ZVOL_OPCODE_SNAP_CREATE:
	case ZVOL_OPCODE_SNAP_DESTROY:
	case ZVOL_OPCODE_SNAP_LIST:
		if (payload_size == 0 || payload_size >= MAX_NAME_LEN) {
			rc = reply_nodata(conn, ZVOL_OP_STATUS_FAILED,
			    hdrp->opcode, hdrp->io_seq);
			break;
		}
		strlcpy(zvol_name, payload, payload_size);
		zvol_name[payload_size] = '\0';
		if (hdrp->opcode != ZVOL_OPCODE_SNAP_LIST) {
			snap = strchr(zvol_name, '@');
			if (snap == NULL) {
				LOG_ERR("Invalid snapshot name: %s",
				    zvol_name);
				rc = reply_nodata(conn, ZVOL_OP_STATUS_FAILED,
				    hdrp->opcode, hdrp->io_seq);
				break;
			}
			*snap++ = '\0';
		}
		/* ref will be released when async command has finished */
		if ((zinfo = uzfs_zinfo_lookup(zvol_name)) == NULL) {
			LOGERRCONN(conn, "Unknown zvol: %s", zvol_name);
			rc = reply_nodata(conn, ZVOL_OP_STATUS_FAILED,
			    hdrp->opcode, hdrp->io_seq);
			break;
		}
		if (zinfo->mgmt_conn != conn) {
			uzfs_zinfo_drop_refcnt(zinfo);
			LOGERRCONN(conn, "Target used invalid connection for "
			    "zvol %s to take %s snapshot", zvol_name, snap);
			rc = reply_nodata(conn, ZVOL_OP_STATUS_FAILED,
			    hdrp->opcode, hdrp->io_seq);
			break;
		}
		if (hdrp->opcode == ZVOL_OPCODE_SNAP_LIST) {
			LOGCONN(conn, "Snaplist command for %s", zinfo->name);
			rc = uzfs_zvol_dispatch_command(conn, hdrp, NULL, 0,
			    zinfo);
			break;
		}
		if (uzfs_zvol_get_status(zinfo->main_zv) !=
		    ZVOL_STATUS_HEALTHY) {
			if (hdrp->opcode == ZVOL_OPCODE_SNAP_CREATE &&
			    ZVOL_IS_REBUILDING_AFS(zinfo->main_zv)) {
				LOG_INFO("zvol %s is not healthy and rebuild"
				"is going on, can't take the %s snapshot,"
				"erroring out the rebuild", zvol_name, snap);
				mutex_enter(&zinfo->main_zv->rebuild_mtx);
				uzfs_zvol_set_rebuild_status(zinfo->main_zv,
				    ZVOL_REBUILDING_ERRORED);
				mutex_exit(&zinfo->main_zv->rebuild_mtx);
			}
			uzfs_zinfo_drop_refcnt(zinfo);
			LOG_ERR("zvol %s is not healthy to take %s snapshot",
			    zvol_name, snap);
			rc = reply_nodata(conn, ZVOL_OP_STATUS_FAILED,
			    hdrp->opcode, hdrp->io_seq);
			break;
		}
		if (hdrp->opcode == ZVOL_OPCODE_SNAP_CREATE) {
			LOGCONN(conn, "Create snapshot command for %s@%s",
			    zinfo->name, snap);
		} else {
			LOGCONN(conn, "Destroy snapshot command for %s@%s",
			    zinfo->name, snap);
		}
		rc = uzfs_zvol_dispatch_command(conn, hdrp, snap,
		    strlen(snap) + 1, zinfo);
		break;

	case ZVOL_OPCODE_RESIZE:
		if (payload_size != sizeof (*resize_data)) {
			rc = reply_nodata(conn, ZVOL_OP_STATUS_FAILED,
			    hdrp->opcode, hdrp->io_seq);
			break;
		}
		resize_data = payload;

		/* ref will be released when async command has finished */
		if ((zinfo = uzfs_zinfo_lookup(resize_data->volname)) == NULL) {
			LOGERRCONN(conn, "Unknown zvol: %s",
			    resize_data->volname);
			rc = reply_nodata(conn, ZVOL_OP_STATUS_FAILED,
			    hdrp->opcode, hdrp->io_seq);
			break;
		}
		if (zinfo->mgmt_conn != conn) {
			uzfs_zinfo_drop_refcnt(zinfo);
			LOGERRCONN(conn, "Target used invalid connection for "
			    "zvol %s", resize_data->volname);
			rc = reply_nodata(conn, ZVOL_OP_STATUS_FAILED,
			    hdrp->opcode, hdrp->io_seq);
			break;
		}
		LOGCONN(conn, "Resize zvol %s to %lu bytes", zinfo->name,
		    resize_data->size);
		rc = uzfs_zvol_dispatch_command(conn, hdrp, &resize_data->size,
		    sizeof (uint64_t), zinfo);
		break;

	case ZVOL_OPCODE_START_REBUILD:
		/* iSCSI controller will send this msg to downgraded replica */
		rc = handle_start_rebuild_req(conn, hdrp, payload,
		    payload_size);
		break;

	default:
		LOGERRCONN(conn, "Message with unknown OP code %d",
		    hdrp->opcode);
		rc = reply_nodata(conn, ZVOL_OP_STATUS_FAILED, hdrp->opcode,
		    hdrp->io_seq);
		break;
	}
	kmem_free(hdrp, sizeof (*hdrp));
	if (payload != NULL)
		kmem_free(payload, payload_size);

	return (rc);
}

/*
 * Transition to the next state. This is called only if IO buffer was fully
 * read or written.
 */
static int
move_to_next_state(uzfs_mgmt_conn_t *conn)
{
	struct epoll_event ev;
	zvol_io_hdr_t *hdrp;
	uint16_t vers;
	int rc = 0;

	ASSERT3U(conn->conn_bufsiz, ==, conn->conn_procn);

	switch (conn->conn_state) {
	case CS_CONNECT:
		LOGCONN(conn, "Connected");
		rc = set_socket_keepalive(conn->conn_fd);
		if (rc != 0)
			LOGERRCONN(conn, "Failed to set keepalive");
		rc = 0;
		/* Fall-through */
	case CS_INIT:
		DBGCONN(conn, "Reading version..");
		if (conn->conn_buf != NULL)
			kmem_free(conn->conn_buf, conn->conn_bufsiz);
		conn->conn_buf = kmem_alloc(sizeof (uint16_t), KM_SLEEP);
		conn->conn_bufsiz = sizeof (uint16_t);
		conn->conn_procn = 0;
		ev.events = EPOLLIN;
		ev.data.ptr = conn;
		rc = epoll_ctl(epollfd, EPOLL_CTL_MOD, conn->conn_fd, &ev);
		conn->conn_state = CS_READ_VERSION;
		break;
	case CS_READ_VERSION:
		vers = *((uint16_t *)conn->conn_buf);
		kmem_free(conn->conn_buf, sizeof (uint16_t));
		conn->conn_buf = NULL;
		if (vers != REPLICA_VERSION) {
			LOGERRCONN(conn, "Invalid replica protocol version %d",
			    vers);
			rc = reply_nodata(conn, ZVOL_OP_STATUS_VERSION_MISMATCH,
			    0, 0);
			/* override the default next state from reply_nodata */
			conn->conn_state = CS_CLOSE;
		} else {
			DBGCONN(conn, "Reading header..");
			hdrp = kmem_zalloc(sizeof (*hdrp), KM_SLEEP);
			hdrp->version = vers;
			conn->conn_buf = hdrp;
			conn->conn_bufsiz = sizeof (*hdrp);
			conn->conn_procn = sizeof (uint16_t); // skip version
			conn->conn_state = CS_READ_HEADER;
		}
		break;
	case CS_READ_HEADER:
		hdrp = conn->conn_buf;
		conn->conn_hdr = hdrp;
		if (hdrp->len > 0) {
			DBGCONN(conn, "Reading payload (%lu bytes)..",
			    hdrp->len);
			conn->conn_buf = kmem_zalloc(hdrp->len, KM_SLEEP);
			conn->conn_bufsiz = hdrp->len;
			conn->conn_procn = 0;
			conn->conn_state = CS_READ_PAYLOAD;
		} else {
			conn->conn_buf = NULL;
			conn->conn_bufsiz = 0;
			rc = process_message(conn);
		}
		break;
	case CS_READ_PAYLOAD:
		rc = process_message(conn);
		break;
	default:
		ASSERT(0);
		/* Fall-through */
	case CS_CLOSE:
		rc = close_conn(conn);
		break;
	}

	return (rc);
}

/*
 * One thread to serve all management connections operating in non-blocking
 * event driven style.
 *
 * Error handling: the thread may terminate the whole process and it is
 * appropriate response to unrecoverable error.
 */
void
uzfs_zvol_mgmt_thread(void *arg)
{
	char			*buf;
	uzfs_mgmt_conn_t	*conn;
	struct epoll_event	ev, events[MAX_EVENTS];
	int			nfds, i, rc;
	boolean_t		do_scan;
	async_task_t		*async_task;
	struct timespec diff_time, now, last_time;

	mgmt_eventfd = eventfd(0, EFD_NONBLOCK);
	if (mgmt_eventfd < 0) {
		perror("eventfd");
		goto exit;
	}
	epollfd = epoll_create1(0);
	if (epollfd < 0) {
		perror("epoll_create1");
		goto exit;
	}
	ev.events = EPOLLIN;
	ev.data.ptr = NULL;
	if (epoll_ctl(epollfd, EPOLL_CTL_ADD, mgmt_eventfd, &ev) == -1) {
		perror("epoll_ctl");
		goto exit;
	}

	prctl(PR_SET_NAME, "mgmt_conn", 0, 0, 0);
	clock_gettime(CLOCK_MONOTONIC, &last_time);

	/*
	 * The only reason to break from this loop is a failure to update FDs
	 * in poll set. In that case we cannot guarantee consistent state.
	 * Any other failure should be handled gracefully.
	 */
	while (1) {
		do_scan = B_FALSE;
		nfds = epoll_wait(epollfd, events, MAX_EVENTS,
		    1000 * RECONNECT_DELAY / 2);
		if (nfds == -1) {
			if (errno == EINTR)
				continue;
			perror("epoll_wait");
			goto exit;
		}

		for (i = 0; i < nfds; i++) {
			conn = events[i].data.ptr;

			/*
			 * data.ptr is null only for eventfd. In that case:
			 *  A) zinfo was created or deleted -> scan the list or
			 *  B) async task has finished -> send reply
			 */
			if (conn == NULL) {
				uint64_t value;

				do_scan = B_TRUE;
				/* consume the event */
				rc = read(mgmt_eventfd, &value, sizeof (value));
				ASSERT3S(rc, ==, sizeof (value));
				if (finish_async_tasks() != 0) {
					goto exit;
				}
				continue;
			}

			if (events[i].events & EPOLLERR) {
				if (conn->conn_state == CS_CONNECT) {
					LOG_ERR("Failed to connect to %s:%d "
					    "fd(%d)", conn->conn_host,
					    conn->conn_port, conn->conn_fd);
				} else {
					LOGERRCONN(conn, "Error on connection "
					    "for sock(%d)", conn->conn_fd);
				}
				if (close_conn(conn) != 0) {
					goto exit;
				}
			/* tcp connected event */
			} else if ((events[i].events & EPOLLOUT) &&
			    conn->conn_state == CS_CONNECT) {
				move_to_next_state(conn);
			/* data IO */
			} else if ((events[i].events & EPOLLIN) ||
			    (events[i].events & EPOLLOUT)) {
				ssize_t cnt;
				int nbytes;

				/* restore reading/writing state */
				buf = (char *)conn->conn_buf + conn->conn_procn;
				nbytes = conn->conn_bufsiz - conn->conn_procn;

				if (events[i].events & EPOLLIN) {
					cnt = read(conn->conn_fd, buf, nbytes);
					DBGCONN(conn, "Read %ld bytes", cnt);
				} else {
					cnt = write(conn->conn_fd, buf, nbytes);
					DBGCONN(conn, "Written %ld bytes", cnt);
				}

				if (cnt == 0) {
					/* the other peer closed the conn */
					if (events[i].events & EPOLLIN) {
						LOG_ERR("connection closed for "
						    "fd(%d)", conn->conn_fd);
						if (close_conn(conn) != 0) {
							goto exit;
						}
					}
				} else if (cnt < 0) {
					if (errno == EAGAIN ||
					    errno == EWOULDBLOCK ||
					    errno == EINTR) {
						continue;
					}
					LOG_ERR("Read/Write error(%d) on "
					    "fd(%d)", errno, conn->conn_fd);
					if (close_conn(conn) != 0) {
						goto exit;
					}
				} else if (cnt <= nbytes) {
					conn->conn_procn += cnt;
					/*
					 * If we read/write the full buffer,
					 * move to the next state.
					 */
					if (cnt == nbytes &&
					    move_to_next_state(conn) != 0) {
						goto exit;
					}
				}
			}
		}
		/*
		 * Scan the list either if signalled or timed out waiting
		 * for event
		 */
		if (nfds != 0 && !do_scan) {
			timesdiff(CLOCK_MONOTONIC, last_time, now, diff_time);
			if (diff_time.tv_sec >= (RECONNECT_DELAY / 2))
				do_scan = 1;
		}

		if (nfds == 0 || do_scan) {
			if (scan_conn_list() != 0) {
				goto exit;
			}
			clock_gettime(CLOCK_MONOTONIC, &last_time);
		}
	}

exit:
	/*
	 * If we get here it means we encountered encoverable error and
	 * the whole process needs to terminate now. We try to be nice
	 * and release all held resources before exiting.
	 */
	if (epollfd >= 0) {
		(void) close(epollfd);
		epollfd = -1;
	}
	mutex_enter(&conn_list_mtx);
	SLIST_FOREACH(conn, &uzfs_mgmt_conns, conn_next) {
		if (conn->conn_fd >= 0)
			close_conn(conn);
	}
	mutex_exit(&conn_list_mtx);

	mutex_enter(&async_tasks_mtx);
	if (mgmt_eventfd >= 0) {
		(void) close(mgmt_eventfd);
		mgmt_eventfd = -1;
	}
	while ((async_task = SLIST_FIRST(&async_tasks)) != NULL) {
		SLIST_REMOVE_HEAD(&async_tasks, task_next);
		/*
		 * We can't free the task if async thread is still referencing
		 * it. It will be freed by async thread when it is done.
		 */
		if (async_task->finished)
			free_async_task(async_task);
	}
	mutex_exit(&async_tasks_mtx);
	/*
	 * We don't destroy the mutexes as other threads might be still using
	 * them, although that our care here is a bit pointless because
	 * we are going to exit from process in a moment.
	 *
	 *	mutex_destroy(&conn_list_mtx);
	 *	mutex_destroy(&async_tasks_mtx);
	 */
	exit(2);
}
