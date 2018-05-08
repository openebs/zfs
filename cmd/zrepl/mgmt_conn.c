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

#include <sys/dsl_dataset.h>
#include <sys/dsl_prop.h>
#include <sys/dmu_objset.h>
#include <zrepl_prot.h>

#include "mgmt_conn.h"
#include "data_conn.h"

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

/* To print verbose debug messages uncomment the following line */
#define	MGMT_CONN_DEBUG	1

#ifdef MGMT_CONN_DEBUG
static const char *
gettimestamp(void)
{
	struct timeval tv;
	static char buf[20];
	struct tm *timeinfo;
	unsigned int ms;

	gettimeofday(&tv, NULL);
	timeinfo = localtime(&tv.tv_sec);
	ms = tv.tv_usec / 1000;

	strftime(buf, sizeof (buf), "%H:%M:%S.", timeinfo);
	snprintf(buf + 9, sizeof (buf) - 9, "%u", ms);

	return (buf);
}
#define	DBGCONN(c, fmt, ...)	fprintf(stderr, "%s [tgt %s:%u]: " fmt "\n", \
				gettimestamp(), \
				(c)->conn_host, (c)->conn_port, ##__VA_ARGS__)
#else
#define	DBGCONN(c, fmt, ...)
#endif

/* Max # of events from epoll processed at once */
#define	MAX_EVENTS	10
#define	MGMT_PORT	"12000"
#define	RECONNECT_DELAY	4	// 4 seconds

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

/* conn list can be traversed or changed only when holding the mutex */
kmutex_t	conn_list_mtx;
SLIST_HEAD(, uzfs_mgmt_conn) uzfs_mgmt_conns;

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

	conn->conn_last_connect = time(NULL);

	bzero((char *)&istgt_addr, sizeof (istgt_addr));
	istgt_addr.sin_family = AF_INET;
	istgt_addr.sin_addr.s_addr = inet_addr(conn->conn_host);
	istgt_addr.sin_port = htons(conn->conn_port);

	sfd = create_and_bind(MGMT_PORT, B_FALSE, B_TRUE);
	if (sfd < 0)
		return (-1);

	rc = connect(sfd, (struct sockaddr *)&istgt_addr, sizeof (istgt_addr));
	/* EINPROGRESS means that EPOLLOUT will tell us when connect is done */
	if (rc != 0 && errno != EINPROGRESS) {
		close(sfd);
		DBGCONN(conn, "Failed to connect");
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
	uzfs_mgmt_conn_t *conn;
	struct epoll_event ev;
	int rc = 0;

	mutex_enter(&conn_list_mtx);
	SLIST_FOREACH(conn, &uzfs_mgmt_conns, conn_next) {
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
		} else if (conn->conn_refcount == 0 && conn->conn_fd >= 0) {
			DBGCONN(conn, "Closing the connection");
			if (close_conn(conn) != 0) {
				rc = -1;
				break;
			}
		}
	}
	mutex_exit(&conn_list_mtx);

	return (rc);
}

/*
 * Try to obtain controller address from zfs property.
 */
static int
get_controller_ip(objset_t *os, char *buf, int len)
{
	nvlist_t *props, *propval;
	char *ip;
	int error;
	dsl_pool_t *dp = spa_get_dsl(os->os_spa);

	dsl_pool_config_enter(dp, FTAG);
	error = dsl_prop_get_all(os, &props);
	dsl_pool_config_exit(dp, FTAG);
	if (error != 0)
		return (error);
	if (nvlist_lookup_nvlist(props, ZFS_PROP_TARGET_IP, &propval) != 0)
		return (ENOENT);
	if (nvlist_lookup_string(propval, ZPROP_VALUE, &ip) != 0)
		return (EINVAL);

	strncpy(buf, ip, len);
	nvlist_free(props);
	return (0);
}

/*
 * This gets called whenever a new zinfo is created. We might need to create
 * a new mgmt connection to iscsi target in response to this event.
 */
void
zinfo_create_cb(zvol_info_t *zinfo, nvlist_t *create_props)
{
	char target_host[256];
	uint16_t target_port;
	uzfs_mgmt_conn_t *mgmt_conn, *new_mgmt_conn;
	zvol_state_t *zv = zinfo->zv;
	char *delim, *ip;
	uint64_t val = 1;
	int rc;

	/* if zvol is being created the zvol property does not exist yet */
	if (create_props != NULL &&
	    nvlist_lookup_string(create_props, ZFS_PROP_TARGET_IP, &ip) == 0) {
		strncpy(target_host, ip, sizeof (target_host));
	} else {
		/* get it from zvol properties */
		if (get_controller_ip(zv->zv_objset, target_host,
		    sizeof (target_host)) != 0) {
			/* in case of missing property take the default IP */
			strncpy(target_host, target_addr, sizeof (target_host));
			target_port = TARGET_PORT;
		}
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
	SLIST_FOREACH(mgmt_conn, &uzfs_mgmt_conns, conn_next) {
		if (strcmp(mgmt_conn->conn_host, target_host) == 0 &&
		    mgmt_conn->conn_port == target_port) {
			/* we already have conn for this target */
			mgmt_conn->conn_refcount++;
			zinfo->mgmt_conn = mgmt_conn;
			mutex_exit(&conn_list_mtx);
			kmem_free(new_mgmt_conn, sizeof (*new_mgmt_conn));
			return;
		}
	}

	new_mgmt_conn->conn_fd = -1;
	new_mgmt_conn->conn_refcount = 1;
	new_mgmt_conn->conn_port = target_port;
	strncpy(new_mgmt_conn->conn_host, target_host,
	    sizeof (new_mgmt_conn->conn_host));

	zinfo->mgmt_conn = new_mgmt_conn;
	SLIST_INSERT_HEAD(&uzfs_mgmt_conns, new_mgmt_conn, conn_next);
	/* signal the event loop thread */
	if (mgmt_eventfd >= 0) {
		rc = write(mgmt_eventfd, &val, sizeof (val));
		ASSERT3P(rc, ==, sizeof (val));
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
		/* signal the event loop thread to close FD */
		if (conn->conn_fd >= 0) {
			ASSERT3P(mgmt_eventfd, >=, 0);
			rc = write(mgmt_eventfd, &val, sizeof (val));
			ASSERT3P(rc, ==, sizeof (val));
			mutex_exit(&conn_list_mtx);
			/* wait for event loop thread to close the FD */
			/* TODO: too rough algorithm with sleep */
			while (1) {
				usleep(1000);
				mutex_enter(&conn_list_mtx);
				if (conn->conn_refcount > 0 ||
				    conn->conn_fd < 0)
					break;
				mutex_exit(&conn_list_mtx);
			}
			/* someone else reused the conn while waiting - ok */
			if (conn->conn_refcount > 0) {
				mutex_exit(&conn_list_mtx);
				return;
			}
		}
		SLIST_REMOVE(&uzfs_mgmt_conns, conn, uzfs_mgmt_conn,
		    conn_next);
		kmem_free(conn, sizeof (*conn));
	}
	mutex_exit(&conn_list_mtx);
}

/*
 * Send handshake reply with error status to the client.
 */
static int
reply_error(uzfs_mgmt_conn_t *conn, zvol_op_status_t status,
    int opcode, uint64_t io_seq, enum conn_state next_state)
{
	zvol_io_hdr_t *hdrp;
	struct epoll_event ev;

	DBGCONN(conn, "Error reply with status %d for OP %d",
	    status, opcode);

	hdrp = kmem_zalloc(sizeof (*hdrp), KM_SLEEP);
	hdrp->version = REPLICA_VERSION;
	hdrp->opcode = opcode;
	hdrp->io_seq = io_seq;
	hdrp->status = status;
	conn->conn_buf = hdrp;
	conn->conn_bufsiz = sizeof (*hdrp);
	conn->conn_procn = 0;
	conn->conn_state = next_state;

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

	conn->conn_bufsiz = sizeof (*hdrp) + size;
	conn->conn_procn = 0;
	conn->conn_state = CS_INIT;
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
static int
uzfs_zvol_get_ip(char *host)
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
			    host, NI_MAXHOST,
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
	zvol_state_t	*zv = zinfo->zv;
	mgmt_ack_t 	mgmt_ack;
	zvol_io_hdr_t	hdr;

	printf("Volume %s sent for enq\n", name);

	bzero(&mgmt_ack, sizeof (mgmt_ack));
	if (uzfs_zvol_get_ip(mgmt_ack.ip) == -1) {
		fprintf(stderr, "Unable to get IP with err: %d\n", errno);
		return (reply_error(conn, ZVOL_OP_STATUS_FAILED, hdrp->opcode,
		    hdrp->io_seq, CS_INIT));
	}

	strncpy(mgmt_ack.volname, name, sizeof (mgmt_ack.volname));
	mgmt_ack.port = atoi((hdrp->opcode == ZVOL_OPCODE_PREPARE_FOR_REBUILD) ?
	    REBUILD_IO_SERVER_PORT : IO_SERVER_PORT);
	mgmt_ack.pool_guid = spa_guid(zv->zv_spa);
	/*
	 * We don't use fsid_guid because that one is not guaranteed
	 * to stay the same (it is changed in case of conflicts).
	 */
	mgmt_ack.zvol_guid = dsl_dataset_phys(
	    zv->zv_objset->os_dsl_dataset)->ds_guid;

	bzero(&hdr, sizeof (hdr));
	hdr.version = REPLICA_VERSION;
	hdr.opcode = hdrp->opcode; // HANDSHAKE or PREPARE_FOR_REBUILD
	hdr.io_seq = hdrp->io_seq;
	hdr.len = sizeof (mgmt_ack);
	hdr.status = ZVOL_OP_STATUS_OK;
	uzfs_zvol_get_last_committed_io_no(zv, &hdr.checkpointed_io_seq);

	return (reply_data(conn, &hdr, &mgmt_ack, sizeof (mgmt_ack)));
}

static int
uzfs_zvol_rebuild_status(uzfs_mgmt_conn_t *conn, zvol_io_hdr_t *hdrp,
    const char *name, zvol_info_t *zinfo)
{
	zrepl_status_ack_t	status_ack;
	zvol_io_hdr_t		hdr;

	status_ack.state = uzfs_zvol_get_status(zinfo->zv);
	status_ack.rebuild_status = uzfs_zvol_get_rebuild_status(zinfo->zv);

	bzero(&hdr, sizeof (hdr));
	hdr.version = REPLICA_VERSION;
	hdr.opcode = hdrp->opcode;
	hdr.io_seq = hdrp->io_seq;
	hdr.len = sizeof (status_ack);
	hdr.status = ZVOL_OP_STATUS_OK;

	return (reply_data(conn, &hdr, &status_ack, sizeof (status_ack)));
}

static int
uzfs_zvol_rebuild_dw_replica_start(uzfs_mgmt_conn_t *conn, zvol_io_hdr_t *hdrp,
    mgmt_ack_t *mack, int rebuild_op_cnt)
{
	int 			io_sfd = -1;
	rebuild_thread_arg_t	*thrd_arg;
	kthread_t		*thrd_info;
	zvol_info_t		*zinfo = NULL;

	for (; rebuild_op_cnt > 0; rebuild_op_cnt--, mack++) {
		printf("Replica %s at %s:%u helping in rebuild\n",
		    mack->volname, mack->ip, mack->port);
		if (zinfo == NULL) {
			zinfo = uzfs_zinfo_lookup(mack->dw_volname);
			if (zinfo == NULL) {
				printf("Replica %s not found\n",
				    mack->dw_volname);
				return (reply_error(conn, ZVOL_OP_STATUS_FAILED,
				    hdrp->opcode, hdrp->io_seq, CS_INIT));
			}
			/* Track # of rebuilds we are initializing on replica */
			zinfo->zv->rebuild_info.rebuild_cnt = rebuild_op_cnt;

			/*
			 * Case where just one replica is being used by customer
			 */
			if ((strcmp(mack->volname, "")) == 0) {
				zinfo->zv->rebuild_info.rebuild_cnt = 0;
				zinfo->zv->rebuild_info.rebuild_done_cnt = 0;
				/* Mark replica healthy now */
				uzfs_zvol_set_rebuild_status(zinfo->zv,
				    ZVOL_REBUILDING_DONE);
				uzfs_zvol_set_status(zinfo->zv,
				    ZVOL_STATUS_HEALTHY);
				printf("Rebuild of replica %s completed\n",
				    zinfo->name);
				uzfs_zinfo_drop_refcnt(zinfo, B_FALSE);
				break;
			}
			uzfs_zvol_set_rebuild_status(zinfo->zv,
			    ZVOL_REBUILDING_IN_PROGRESS);
		} else {
			uzfs_zinfo_take_refcnt(zinfo, B_FALSE);
		}

		io_sfd = create_and_bind("", B_FALSE, B_FALSE);
		if (io_sfd < 0) {
			/* Fail this rebuild process entirely */
			fprintf(stderr, "Rebuild IO socket create and bind"
			    " failed on volume: %s\n", zinfo->name);
			uzfs_zvol_set_rebuild_status(zinfo->zv,
			    ZVOL_REBUILDING_FAILED);
			uzfs_zinfo_drop_refcnt(zinfo, B_FALSE);
			break;
		}

		thrd_arg = kmem_alloc(sizeof (rebuild_thread_arg_t), KM_SLEEP);
		thrd_arg->zinfo = zinfo;
		thrd_arg->fd = io_sfd;
		thrd_arg->port = mack->port;
		strlcpy(thrd_arg->ip, mack->ip, MAX_IP_LEN);
		strlcpy(thrd_arg->zvol_name, mack->volname, MAXNAMELEN);
		thrd_info = zk_thread_create(NULL, 0,
		    uzfs_zvol_rebuild_dw_replica, thrd_arg, 0, NULL, TS_RUN, 0,
		    PTHREAD_CREATE_DETACHED);
		VERIFY3P(thrd_info, !=, NULL);
	}

	conn->conn_state = CS_INIT;
	return (move_to_next_state(conn));
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
	zvol_info_t *zinfo;
	int rc = 0;

	conn->conn_hdr = NULL;
	conn->conn_buf = NULL;
	conn->conn_bufsiz = 0;
	conn->conn_procn = 0;

	switch (hdrp->opcode) {
	case ZVOL_OPCODE_HANDSHAKE:
	case ZVOL_OPCODE_PREPARE_FOR_REBUILD:
	case ZVOL_OPCODE_REPLICA_STATUS:
		if (payload_size == 0 || payload_size > MAX_NAME_LEN) {
			rc = reply_error(conn, ZVOL_OP_STATUS_FAILED,
			    hdrp->opcode, hdrp->io_seq, CS_INIT);
			break;
		}
		strncpy(zvol_name, payload, payload_size);
		zvol_name[payload_size] = '\0';

		if ((zinfo = uzfs_zinfo_lookup(zvol_name)) == NULL) {
			fprintf(stderr, "Unknown zvol: %s\n", zvol_name);
			rc = reply_error(conn, ZVOL_OP_STATUS_FAILED,
			    hdrp->opcode, hdrp->io_seq, CS_INIT);
			break;
		}

		if (hdrp->opcode == ZVOL_OPCODE_HANDSHAKE) {
			DBGCONN(conn, "Handshake command for zvol %s",
			    zvol_name);
			rc = uzfs_zvol_mgmt_do_handshake(conn, hdrp, zvol_name,
			    zinfo);
		} else if (hdrp->opcode == ZVOL_OPCODE_PREPARE_FOR_REBUILD) {
			DBGCONN(conn, "Prepare for rebuild command for zvol %s",
			    zvol_name);
			rc = uzfs_zvol_mgmt_do_handshake(conn, hdrp, zvol_name,
			    zinfo);
		} else if (hdrp->opcode == ZVOL_OPCODE_REPLICA_STATUS) {
			DBGCONN(conn, "Replica status command for zvol %s",
			    zvol_name);
			rc = uzfs_zvol_rebuild_status(conn, hdrp, zvol_name,
			    zinfo);
		} else {
			ASSERT(0);
		}
		uzfs_zinfo_drop_refcnt(zinfo, B_FALSE);
		break;


	case ZVOL_OPCODE_START_REBUILD:
		/* iSCSI controller will send this msg to downgraded replica */
		if (payload_size < sizeof (mgmt_ack_t)) {
			rc = reply_error(conn, ZVOL_OP_STATUS_FAILED,
			    hdrp->opcode, hdrp->io_seq, CS_INIT);
			break;
		}
		DBGCONN(conn, "Rebuild start command");
		rc = uzfs_zvol_rebuild_dw_replica_start(conn, hdrp, payload,
		    payload_size / sizeof (mgmt_ack_t));
		break;

	default:
		DBGCONN(conn, "Message with unknown OP code %d", hdrp->opcode);
		rc = reply_error(conn, ZVOL_OP_STATUS_FAILED, hdrp->opcode,
		    hdrp->io_seq, CS_INIT);
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

	ASSERT3P(conn->conn_bufsiz, ==, conn->conn_procn);

	switch (conn->conn_state) {
	case CS_CONNECT:
		DBGCONN(conn, "Connected");
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
		if (vers != REPLICA_VERSION) {
			fprintf(stderr, "invalid replica protocol version %d\n",
			    vers);
			rc = reply_error(conn, ZVOL_OP_STATUS_VERSION_MISMATCH,
			    0, 0, CS_CLOSE);
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
 */
void
uzfs_zvol_mgmt_thread(void *arg)
{
	char			*buf;
	uzfs_mgmt_conn_t	*conn;
	struct epoll_event	ev, events[MAX_EVENTS];
	int			nfds, i, rc;
	boolean_t		do_scan;

	mutex_init(&conn_list_mtx, NULL, MUTEX_DEFAULT, NULL);

	mgmt_eventfd = eventfd(0, EFD_NONBLOCK);
	if (mgmt_eventfd < 0) {
		perror("eventfd");
		zk_thread_exit();
		return;
	}
	epollfd = epoll_create1(0);
	if (epollfd < 0) {
		perror("epoll_create1");
		zk_thread_exit();
		return;
	}
	ev.events = EPOLLIN;
	ev.data.ptr = NULL;
	if (epoll_ctl(epollfd, EPOLL_CTL_ADD, mgmt_eventfd, &ev) == -1) {
		perror("epoll_ctl");
		zk_thread_exit();
	}

	prctl(PR_SET_NAME, "mgmt_conn", 0, 0, 0);

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
			 * data.ptr is null only for eventfd. In that case
			 * zinfo was created or deleted -> scan the list.
			 */
			if (conn == NULL) {
				uint64_t value;

				do_scan = B_TRUE;
				/* consume the event */
				rc = read(mgmt_eventfd, &value, sizeof (value));
				ASSERT3P(rc, ==, sizeof (value));
				continue;
			}

			if (events[i].events & EPOLLERR) {
				if (conn->conn_state == CS_CONNECT) {
					DBGCONN(conn, "Failed to connect");
				} else {
					fprintf(stderr, "Error on connection "
					    "to %s:%d\n",
					    conn->conn_host, conn->conn_port);
				}
				if (close_conn(conn) != 0)
					goto exit;
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
						if (close_conn(conn) != 0)
							goto exit;
					}
				} else if (cnt < 0) {
					if (errno == EAGAIN ||
					    errno == EWOULDBLOCK ||
					    errno == EINTR) {
						continue;
					}
					perror("read/write");
					if (close_conn(conn) != 0)
						goto exit;
				} else if (cnt <= nbytes) {
					conn->conn_procn += cnt;
					/*
					 * If we read/write the full buffer,
					 * move to the next state.
					 */
					if (cnt == nbytes &&
					    move_to_next_state(conn) != 0)
						goto exit;
				}
			}
		}
		/*
		 * Scan the list either if signalled or timed out waiting
		 * for event
		 */
		if (nfds == 0 || do_scan) {
			if (scan_conn_list() != 0)
				goto exit;
		}
	}

exit:
	(void) close(epollfd);
	epollfd = -1;
	(void) close(mgmt_eventfd);
	mgmt_eventfd = -1;
	mutex_enter(&conn_list_mtx);
	SLIST_FOREACH(conn, &uzfs_mgmt_conns, conn_next) {
		close_conn(conn);
	}
	mutex_exit(&conn_list_mtx);
	mutex_destroy(&conn_list_mtx);
	fprintf(stderr, "uzfs_zvol_mgmt_thread thread exiting\n");
	zk_thread_exit();
}
