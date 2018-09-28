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

#include <sys/epoll.h>
#include <sys/prctl.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <uzfs_io.h>
#include <uzfs_rebuilding.h>
#include <zrepl_mgmt.h>
#include <uzfs_mgmt.h>
#include "mgmt_conn.h"
#include "data_conn.h"

#define	MAXEVENTS 64

#define	ZVOL_REBUILD_STEP_SIZE  (10 * 1024ULL * 1024ULL * 1024ULL) // 10GB
uint64_t zvol_rebuild_step_size = ZVOL_REBUILD_STEP_SIZE;

#define	REBUILD_CMD_QUEUE_MAX_LIMIT (100)
uint64_t zvol_rebuild_cmd_queue_limit = REBUILD_CMD_QUEUE_MAX_LIMIT;

#define	IS_REBUILD_HIT_MAX_CMD_LIMIT(zinfo)	\
	((zinfo->rebuild_cmd_queued_cnt -	\
	    zinfo->rebuild_cmd_acked_cnt) >	\
	    zvol_rebuild_cmd_queue_limit)

uint16_t io_server_port = IO_SERVER_PORT;
uint16_t rebuild_io_server_port = REBUILD_IO_SERVER_PORT;

kcondvar_t timer_cv;
kmutex_t timer_mtx;

typedef struct singly_node_list_s {
	void *node;
	SLIST_ENTRY(singly_node_list_s) node_next;
} singly_node_list_t;

SLIST_HEAD(singly_node_list, singly_node_list_s);

/*
 * Allocate zio command along with
 * buffer needed for IO completion.
 */
zvol_io_cmd_t *
zio_cmd_alloc(zvol_io_hdr_t *hdr, int fd)
{
	zvol_io_cmd_t *zio_cmd = kmem_zalloc(
	    sizeof (zvol_io_cmd_t), KM_SLEEP);

	bcopy(hdr, &zio_cmd->hdr, sizeof (zio_cmd->hdr));
	if ((hdr->opcode == ZVOL_OPCODE_READ) ||
	    (hdr->opcode == ZVOL_OPCODE_WRITE) ||
	    (hdr->opcode == ZVOL_OPCODE_OPEN)) {
		zio_cmd->buf = kmem_zalloc(sizeof (char) * hdr->len, KM_SLEEP);
		zio_cmd->buf_len = hdr->len;
	}

	zio_cmd->conn = fd;
	return (zio_cmd);
}

/*
 * Free zio command along with buffer.
 */
void
zio_cmd_free(zvol_io_cmd_t **cmd)
{
	zvol_io_cmd_t *zio_cmd = *cmd;
	zvol_op_code_t opcode = zio_cmd->hdr.opcode;
	switch (opcode) {
		case ZVOL_OPCODE_READ:
		case ZVOL_OPCODE_WRITE:
		case ZVOL_OPCODE_OPEN:
			if (zio_cmd->buf != NULL) {
				kmem_free(zio_cmd->buf, zio_cmd->buf_len);
			}
			break;

		case ZVOL_OPCODE_SYNC:
		case ZVOL_OPCODE_REBUILD_STEP_DONE:
		case ZVOL_OPCODE_UNMAP:
			/* Nothing to do */
			break;

		default:
			VERIFY(!"Should be a valid opcode");
			break;
	}

	kmem_free(zio_cmd, sizeof (zvol_io_cmd_t));
	*cmd = NULL;
}

/*
 * This API is to read data from "blocking" sockets
 * Returns 0 on success, -1 on error
 */
int
uzfs_zvol_socket_read(int fd, char *buf, uint64_t nbytes)
{
	ssize_t count = 0;
	char *p = buf;
	while (nbytes) {
		count = read(fd, (void *)p, nbytes);
		if (count < 0) {
			if (errno == EINTR)
				continue;
			LOG_ERRNO("Socket read error");
			return (-1);
		} else if (count == 0) {
			LOG_INFO("Connection closed by the peer");
			return (-1);
		}
		p += count;
		nbytes -= count;
	}
	return (0);
}

/*
 * Read header message from socket in safe manner, which is: first we read a
 * version number and if valid then we read the rest of the message.
 *
 * Return value < 0 => error
 *              > 0 => invalid version
 *              = 0 => ok
 */
int
uzfs_zvol_read_header(int fd, zvol_io_hdr_t *hdr)
{
	int rc;

	rc = uzfs_zvol_socket_read(fd, (char *)hdr,
	    sizeof (hdr->version));
	if (rc != 0)
		return (-1);

	if (hdr->version != REPLICA_VERSION) {
		LOG_ERR("invalid replica protocol version %d",
		    hdr->version);
		return (1);
	}
	rc = uzfs_zvol_socket_read(fd,
	    ((char *)hdr) + sizeof (hdr->version),
	    sizeof (*hdr) - sizeof (hdr->version));
	if (rc != 0)
		return (-1);

	return (0);
}

/*
 * This API is to write data from "blocking" sockets
 * Returns 0 on success, -1 on error
 */
int
uzfs_zvol_socket_write(int fd, char *buf, uint64_t nbytes)
{
	ssize_t count = 0;
	char *p = buf;
	while (nbytes) {
		count = write(fd, (void *)p, nbytes);
		if (count < 0) {
			if (errno == EINTR)
				continue;
			LOG_ERRNO("Socket write error");
			return (-1);
		}
		p += count;
		nbytes -= count;
	}
	return (0);
}

/*
 * We expect only one chunk of data with meta header in write request.
 * Nevertheless the code is general to handle even more of them.
 */
static int
uzfs_submit_writes(zvol_info_t *zinfo, zvol_io_cmd_t *zio_cmd)
{
	blk_metadata_t	metadata;
	boolean_t	is_rebuild = B_FALSE;
	zvol_io_hdr_t 	*hdr = &zio_cmd->hdr;
	struct zvol_io_rw_hdr *write_hdr;
	char	*datap = (char *)zio_cmd->buf;
	size_t	data_offset = hdr->offset;
	size_t	remain = hdr->len;
	int	rc = 0;
	uint64_t running_ionum;
	is_rebuild = hdr->flags & ZVOL_OP_FLAG_REBUILD;

	while (remain > 0) {
		if (remain < sizeof (*write_hdr))
			return (-1);

		write_hdr = (struct zvol_io_rw_hdr *)datap;
		metadata.io_num = write_hdr->io_num;

		datap += sizeof (*write_hdr);
		remain -= sizeof (*write_hdr);
		if (remain < write_hdr->len)
			return (-1);

		rc = uzfs_write_data(zinfo->main_zv, datap, data_offset,
		    write_hdr->len, &metadata, is_rebuild);
		if (rc != 0)
			break;

		/* IO to clone should be sent only when it is from app */
		if (!is_rebuild && (zinfo->clone_zv != NULL)) {
			rc = uzfs_write_data(zinfo->clone_zv, datap,
			    data_offset, write_hdr->len, &metadata,
			    is_rebuild);
			if (rc != 0)
				break;
		}
		/* Update the highest ionum used for checkpointing */
		running_ionum = zinfo->running_ionum;
		while (running_ionum < write_hdr->io_num) {
			atomic_cas_64(&zinfo->running_ionum, running_ionum,
			    write_hdr->io_num);
			running_ionum = zinfo->running_ionum;
		}

		datap += write_hdr->len;
		remain -= write_hdr->len;
		data_offset += write_hdr->len;
	}

	return (rc);
}

/*
 * zvol worker is responsible for actual work.
 * It execute read/write/sync command to uzfs.
 * It enqueue command to completion queue and
 * send signal to ack-sender thread.
 *
 * Write commands that are for rebuild will not
 * be enqueued. Also, commands memory is
 * maintained by its caller.
 */
void
uzfs_zvol_worker(void *arg)
{
	zvol_io_cmd_t	*zio_cmd;
	zvol_info_t	*zinfo;
	zvol_state_t	*zvol_state, *read_zv;
	zvol_io_hdr_t 	*hdr;
	metadata_desc_t	**metadata_desc;
	int		rc = 0;
	boolean_t	rebuild_cmd_req;
	boolean_t	read_metadata;

	zio_cmd = (zvol_io_cmd_t *)arg;
	hdr = &zio_cmd->hdr;
	zinfo = zio_cmd->zinfo;
	zvol_state = zinfo->main_zv;
	rebuild_cmd_req = hdr->flags & ZVOL_OP_FLAG_REBUILD;
	read_metadata = hdr->flags & ZVOL_OP_FLAG_READ_METADATA;

	if (zinfo->is_io_ack_sender_created == B_FALSE) {
		if (!(rebuild_cmd_req && (hdr->opcode == ZVOL_OPCODE_WRITE)))
			zio_cmd_free(&zio_cmd);
		if (hdr->opcode == ZVOL_OPCODE_WRITE)
			atomic_inc_64(&zinfo->write_req_received_cnt);
		goto drop_refcount;
	}

	/*
	 * For rebuild case, do not free zio_cmd
	 */
	if (zinfo->state == ZVOL_INFO_STATE_OFFLINE) {
		hdr->status = ZVOL_OP_STATUS_FAILED;
		hdr->len = 0;
		if (!(rebuild_cmd_req && (hdr->opcode == ZVOL_OPCODE_WRITE)))
			zio_cmd_free(&zio_cmd);
		goto drop_refcount;
	}

	/*
	 * If zvol hasn't passed rebuild phase or if read
	 * is meant for rebuild or if target has asked for metadata
	 * then we need the metadata
	 */
	if ((!rebuild_cmd_req && ZVOL_IS_REBUILDED(zvol_state)) &&
	    !read_metadata) {
		metadata_desc = NULL;
		zio_cmd->metadata_desc = NULL;
	} else {
		metadata_desc = &zio_cmd->metadata_desc;
	}
	switch (hdr->opcode) {
		case ZVOL_OPCODE_READ:
			read_zv = zinfo->main_zv;
			if (rebuild_cmd_req) {
				/*
				 * if we are rebuilding, we have
				 * to read the data from the snapshot
				 */
				if (zinfo->rebuild_zv) {
					read_zv = zinfo->rebuild_zv;
				} else {
					rc = -1;
					break;
				}
			}

			rc = uzfs_read_data(read_zv,
			    (char *)zio_cmd->buf,
			    hdr->offset, hdr->len,
			    metadata_desc);
			atomic_inc_64(&zinfo->read_req_received_cnt);
			break;

		case ZVOL_OPCODE_WRITE:
			rc = uzfs_submit_writes(zinfo, zio_cmd);
			atomic_inc_64(&zinfo->write_req_received_cnt);
			break;

		case ZVOL_OPCODE_SYNC:
			uzfs_flush_data(zinfo->main_zv);
			atomic_inc_64(&zinfo->sync_req_received_cnt);
			break;

		case ZVOL_OPCODE_UNMAP:
			if ((rebuild_cmd_req &&
			    ZVOL_IS_REBUILDING(zinfo->main_zv)) ||
			    !CHECK_UNMAP_IOSEQ(hdr->io_seq)) {
				rc = uzfs_unmap_data(zinfo->main_zv,
				    hdr->offset, hdr->len,
				    (blk_metadata_t *)&hdr->io_seq,
				    rebuild_cmd_req);
				hdr->len = 0;
				atomic_inc_64(&zinfo->unmap_req_received_cnt);
			}
			break;

		case ZVOL_OPCODE_REBUILD_STEP_DONE:
			break;
		default:
			VERIFY(!"Should be a valid opcode");
			break;
	}

	if (rc != 0) {
		LOG_ERR("OP code %d failed: %d", hdr->opcode, rc);
		hdr->status = ZVOL_OP_STATUS_FAILED;
		hdr->len = 0;
	} else {
		hdr->status = ZVOL_OP_STATUS_OK;
	}

	/*
	 * We are not sending ACK for writes/unmap meant for rebuild
	 */
	if (rebuild_cmd_req && ((hdr->opcode == ZVOL_OPCODE_WRITE) ||
	    ((hdr->opcode == ZVOL_OPCODE_UNMAP) &&
	    ZVOL_IS_REBUILDING(zinfo->main_zv)))) {
		goto drop_refcount;
	}

	(void) pthread_mutex_lock(&zinfo->zinfo_mutex);
	if (!zinfo->is_io_ack_sender_created) {
		(void) pthread_mutex_unlock(&zinfo->zinfo_mutex);
		zio_cmd_free(&zio_cmd);
		goto drop_refcount;
	}
	STAILQ_INSERT_TAIL(&zinfo->complete_queue, zio_cmd, cmd_link);

	if (zinfo->io_ack_waiting) {
		rc = pthread_cond_signal(&zinfo->io_ack_cond);
	}
	(void) pthread_mutex_unlock(&zinfo->zinfo_mutex);

drop_refcount:
	uzfs_zinfo_drop_refcnt(zinfo);
}

static void
uzfs_zvol_append_to_fd_list(zvol_info_t *zinfo, int fd)
{
	zinfo_fd_t *new_zinfo_fd = kmem_alloc(sizeof (zinfo_fd_t), KM_SLEEP);
	new_zinfo_fd->fd = fd;

	(void) pthread_mutex_lock(&zinfo->zinfo_mutex);
#ifdef DEBUG
	zinfo_fd_t *zinfo_fd = NULL;
	STAILQ_FOREACH(zinfo_fd, &zinfo->fd_list, fd_link) {
		if (zinfo_fd->fd == fd) {
			ASSERT(1 == 0);
		}
	}
#endif
	STAILQ_INSERT_TAIL(&zinfo->fd_list, new_zinfo_fd, fd_link);
	LOG_DEBUG("Appending fd %d for zvol %s", fd, zinfo->name);
	(void) pthread_mutex_unlock(&zinfo->zinfo_mutex);
}

static void
uzfs_zvol_remove_from_fd_list(zvol_info_t *zinfo, int fd)
{
	zinfo_fd_t *zinfo_fd = NULL;

	(void) pthread_mutex_lock(&zinfo->zinfo_mutex);
#ifdef DEBUG
	int count = 0;
	STAILQ_FOREACH(zinfo_fd, &zinfo->fd_list, fd_link) {
		if (zinfo_fd->fd == fd)
			count++;
	}
	ASSERT(count == 1);
#endif
	zinfo_fd = STAILQ_FIRST(&zinfo->fd_list);
	while (zinfo_fd != NULL) {
		if (zinfo_fd->fd == fd) {
			STAILQ_REMOVE(&zinfo->fd_list, zinfo_fd,
			    zinfo_fd_s, fd_link);
			kmem_free(zinfo_fd, sizeof (zinfo_fd_t));
			break;
		}
		zinfo_fd = STAILQ_NEXT(zinfo_fd, fd_link);
	}
	(void) pthread_mutex_unlock(&zinfo->zinfo_mutex);
}

static int
uzfs_zvol_handle_rebuild_snap_done(zvol_io_hdr_t *hdrp,
    int sfd, zvol_info_t *zinfo)
{
	int rc = 0;
	char *snap;
	char zvol_name[MAX_NAME_LEN + 1];

	if (hdrp->len == 0 || hdrp->len > MAX_NAME_LEN) {
		LOG_ERR("Unexpected hdr.len:%ld on volume: %s",
		    hdrp->len, zinfo->name);
		return (rc = -1);
	}

	if ((rc = uzfs_zvol_socket_read(sfd, zvol_name, hdrp->len)) != 0)
		return (rc);

	zvol_name[hdrp->len] = '\0';
	snap = strchr(zvol_name, '@');
	if (snap == NULL) {
		LOG_ERR("Invalid snapshot name: %s", zvol_name);
		return (rc = -1);
	}

	*snap++ = '\0';

	if (strcmp(zinfo->name, zvol_name) != 0) {
		LOG_ERR("Wrong volume, Received name: %s, Expected:%s",
		    zvol_name, zinfo->name);
		return (rc = -1);
	}

	rc = uzfs_zvol_create_snapshot_update_zap(zinfo, snap, hdrp->io_seq);
	if (rc != 0) {
		LOG_ERR("Failed to create %s@%s: %d", zinfo->name, snap, rc);
	}
	return (rc);
}

void
uzfs_zvol_rebuild_dw_replica(void *arg)
{
	rebuild_thread_arg_t *rebuild_args = arg;
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

	sfd = rebuild_args->fd;
	zinfo = rebuild_args->zinfo;

	uzfs_zvol_append_to_fd_list(zinfo, sfd);

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

	rc = set_socket_keepalive(sfd);
	if (rc != 0)
		LOG_ERR("keepalive errored on connected rebuild fd %d", sfd);
	rc = 0;

	/* Set state in-progess state now */
	checkpointed_ionum = uzfs_zvol_get_last_committed_io_no(
	    zinfo->main_zv, HEALTHY_IO_SEQNUM);
	zvol_state = zinfo->main_zv;
	bzero(&hdr, sizeof (hdr));
	hdr.status = ZVOL_OP_STATUS_OK;
	hdr.version = REPLICA_VERSION;
	hdr.opcode = ZVOL_OPCODE_HANDSHAKE;
	hdr.len = strlen(rebuild_args->zvol_name) + 1;

	rc = uzfs_zvol_socket_write(sfd, (char *)&hdr, sizeof (hdr));
	if (rc != 0) {
		LOG_ERR("Socket hdr write failed");
		goto exit;
	}

	rc = uzfs_zvol_socket_write(sfd, (void *)rebuild_args->zvol_name,
	    hdr.len);
	if (rc != 0) {
		LOG_ERR("Socket handshake write failed");
		goto exit;
	}

next_step:

	if (ZVOL_IS_REBUILDING_ERRORED(zinfo->main_zv)) {
		LOG_ERR("rebuilding errored.. for %s..", zinfo->name);
		rc = -1;
		goto exit;
	}

	if (offset >= ZVOL_VOLUME_SIZE(zvol_state)) {
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
	} else {
		bzero(&hdr, sizeof (hdr));
		hdr.status = ZVOL_OP_STATUS_OK;
		hdr.version = REPLICA_VERSION;
		hdr.opcode = ZVOL_OPCODE_REBUILD_STEP;
		hdr.checkpointed_io_seq = checkpointed_ionum;
		hdr.offset = offset;
		if ((offset + zvol_rebuild_step_size) >
		    ZVOL_VOLUME_SIZE(zvol_state))
			hdr.len = ZVOL_VOLUME_SIZE(zvol_state) - offset;
		else
			hdr.len = zvol_rebuild_step_size;
		rc = uzfs_zvol_socket_write(sfd, (char *)&hdr, sizeof (hdr));
		if (rc != 0) {
			LOG_ERR("Socket rebuild_step write failed");
			goto exit;
		}
	}

	while (1) {

		if (ZVOL_IS_REBUILDING_ERRORED(zinfo->main_zv)) {
			LOG_ERR("rebuilding already errored.. for %s..",
			    zinfo->name);
			rc = -1;
			goto exit;
		}

		rc = uzfs_zvol_socket_read(sfd, (char *)&hdr, sizeof (hdr));
		if (rc != 0)
			goto exit;

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

		/* One more snapshot has been transferred */
		if (hdr.opcode == ZVOL_OPCODE_REBUILD_SNAP_DONE) {
			rc = uzfs_zvol_handle_rebuild_snap_done(&hdr,
			    sfd, zinfo);
			if (rc != 0) {
				LOG_ERR("Rebuild snap_done failed.. for %s",
				    zinfo->name);
				goto exit;
			}
			offset = 0;
			checkpointed_ionum = uzfs_zvol_get_last_committed_io_no(
			    zinfo->main_zv, HEALTHY_IO_SEQNUM);
			goto next_step;
		}

		/* All snapshots has been transferred */
		if (hdr.opcode == ZVOL_OPCODE_REBUILD_ALL_SNAP_DONE) {
			/*
			 * Change rebuild state to mark that all
			 * snapshots has been transferred now
			 */
			uzfs_zvol_set_rebuild_status(zinfo->main_zv,
			    ZVOL_REBUILDING_AFS);
			offset = 0;
			checkpointed_ionum = uzfs_zvol_get_last_committed_io_no(
			    zinfo->main_zv, HEALTHY_IO_SEQNUM);
			goto next_step;
		}
		ASSERT((hdr.opcode == ZVOL_OPCODE_READ ||
		    hdr.opcode == ZVOL_OPCODE_UNMAP) &&
		    (hdr.flags & ZVOL_OP_FLAG_REBUILD));

		if (hdr.opcode == ZVOL_OPCODE_READ)
			hdr.opcode = ZVOL_OPCODE_WRITE;

		zio_cmd = zio_cmd_alloc(&hdr, sfd);
		if (hdr.opcode == ZVOL_OPCODE_WRITE) {
			rc = uzfs_zvol_socket_read(sfd, zio_cmd->buf, hdr.len);
			if (rc != 0) {
				LOG_ERR("read failed %d %lu %lu..",
				    hdr.opcode, hdr.offset, hdr.len);
				goto exit;
			}
		}

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
	}

exit:
	uzfs_zvol_remove_from_fd_list(zinfo, sfd);

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
			uzfs_zvol_set_status(zinfo->main_zv,
			    ZVOL_STATUS_HEALTHY);
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

	zk_thread_exit();
}

#define	STORE_LAST_COMMITTED_HEALTHY_IO_NO	\
    uzfs_zvol_store_last_committed_healthy_io_no

#define	STORE_LAST_COMMITTED_DEGRADED_IO_NO	\
    uzfs_zvol_store_last_committed_degraded_io_no

void
uzfs_zvol_timer_thread(void)
{
	zvol_info_t *zinfo;
	time_t min_interval;
	time_t now, next_check;
	struct singly_node_list zvol_node_list, free_node_list;
	singly_node_list_t *n_zinfo, *t_zinfo;

	init_zrepl();
	prctl(PR_SET_NAME, "zvol_timer", 0, 0, 0);
	SLIST_INIT(&zvol_node_list);
	SLIST_INIT(&free_node_list);

	mutex_enter(&timer_mtx);
	while (1) {
		min_interval = 5;  // we check intervals at least every 5 sec

		mutex_enter(&zvol_list_mutex);
		SLIST_FOREACH(zinfo, &zvol_list, zinfo_next) {
			if (!SLIST_EMPTY(&free_node_list)) {
				n_zinfo = SLIST_FIRST(&free_node_list);
				SLIST_REMOVE_HEAD(&free_node_list, node_next);
			} else {
				n_zinfo = kmem_alloc(sizeof (*n_zinfo),
				    KM_SLEEP);
			}
			uzfs_zinfo_take_refcnt(zinfo);
			n_zinfo->node = (void *) zinfo;
			SLIST_INSERT_HEAD(&zvol_node_list, n_zinfo, node_next);
		}
		mutex_exit(&zvol_list_mutex);

		next_check = now = time(NULL);
		SLIST_FOREACH(n_zinfo, &zvol_node_list, node_next) {
			zinfo = (zvol_info_t *)n_zinfo->node;
			if (uzfs_zvol_get_status(zinfo->main_zv) ==
			    ZVOL_STATUS_HEALTHY &&
			    zinfo->main_zv->zv_objset) {
				next_check = zinfo->checkpointed_time +
				    zinfo->update_ionum_interval;
				if (next_check <= now) {
					LOG_DEBUG("Checkpointing ionum "
					    "%lu on %s",
					    zinfo->checkpointed_ionum,
					    zinfo->name);
					STORE_LAST_COMMITTED_HEALTHY_IO_NO(
					    zinfo, zinfo->checkpointed_ionum);
					zinfo->checkpointed_ionum =
					    zinfo->running_ionum;
					zinfo->checkpointed_time = now;
					next_check = now +
					    zinfo->update_ionum_interval;
				}
			} else if (uzfs_zvol_get_status(zinfo->main_zv) ==
			    ZVOL_STATUS_DEGRADED &&
			    zinfo->main_zv->zv_objset) {
				next_check = zinfo->degraded_checkpointed_time
				    + DEGRADED_IO_UPDATE_INTERVAL;
				if (next_check <= now &&
				    zinfo->degraded_checkpointed_ionum <
				    zinfo->running_ionum) {
					zinfo->degraded_checkpointed_ionum =
					    zinfo->running_ionum;
					LOG_DEBUG("Checkpointing ionum "
					    "%lu on %s for degraded mode",
					    zinfo->degraded_checkpointed_ionum,
					    zinfo->name);
					STORE_LAST_COMMITTED_DEGRADED_IO_NO(
					    zinfo,
					    zinfo->degraded_checkpointed_ionum);
					zinfo->degraded_checkpointed_time =
					    now;
					next_check = now +
					    DEGRADED_IO_UPDATE_INTERVAL;
				}
			}

			if (next_check > now &&
			    (min_interval > next_check - now))
				min_interval = next_check - now;
		}

		(void) cv_timedwait(&timer_cv, &timer_mtx, ddi_get_lbolt() +
		    SEC_TO_TICK(min_interval));

		SLIST_FOREACH_SAFE(n_zinfo, &zvol_node_list,
		    node_next, t_zinfo) {
			SLIST_REMOVE(&zvol_node_list, n_zinfo,
			    singly_node_list_s, node_next);
			zinfo = (zvol_info_t *)n_zinfo->node;
			uzfs_zinfo_drop_refcnt(zinfo);
			SLIST_INSERT_HEAD(&free_node_list, n_zinfo, node_next);
		}
	}

	mutex_exit(&timer_mtx);
	mutex_destroy(&timer_mtx);
	cv_destroy(&timer_cv);

	SLIST_FOREACH_SAFE(n_zinfo, &free_node_list, node_next, t_zinfo) {
		SLIST_REMOVE(&free_node_list, n_zinfo, singly_node_list_s,
		    node_next);
		kmem_free(n_zinfo, sizeof (*n_zinfo));
	}
}

/*
 * Update interval and wake up timer thread so that it can adjust to the new
 * value. If timeout is zero, then we just wake up the timer thread (used in
 * case when zvol state is changed to make timer thread aware of it).
 */
void
uzfs_update_ionum_interval(zvol_info_t *zinfo, uint32_t timeout)
{
	mutex_enter(&timer_mtx);
	if (zinfo->update_ionum_interval == timeout) {
		mutex_exit(&timer_mtx);
		return;
	}
	if (timeout != 0)
		zinfo->update_ionum_interval = timeout;
	cv_signal(&timer_cv);
	mutex_exit(&timer_mtx);
}

/*
 * This function finds cmds that need to be acked to its sender on a given fd,
 * and removes those commands from that list.
 */
void
remove_pending_cmds_to_ack(int fd, zvol_info_t *zinfo)
{
	zvol_io_cmd_t *zio_cmd, *zio_cmd_next;
	(void) pthread_mutex_lock(&zinfo->zinfo_mutex);
	zio_cmd = STAILQ_FIRST(&zinfo->complete_queue);
	while (zio_cmd != NULL) {
		zio_cmd_next = STAILQ_NEXT(zio_cmd, cmd_link);
		if (zio_cmd->conn == fd) {
			STAILQ_REMOVE(&zinfo->complete_queue, zio_cmd,
			    zvol_io_cmd_s, cmd_link);
			zio_cmd_free(&zio_cmd);
		}
		zio_cmd = zio_cmd_next;
	}
	while ((zinfo->zio_cmd_in_ack != NULL) &&
	    (((zvol_io_cmd_t *)(zinfo->zio_cmd_in_ack))->conn == fd)) {
		(void) pthread_mutex_unlock(&zinfo->zinfo_mutex);
		LOG_INFO("Waiting for IO to send off on vol %s", zinfo->name);
		sleep(1);
		(void) pthread_mutex_lock(&zinfo->zinfo_mutex);
	}
	(void) pthread_mutex_unlock(&zinfo->zinfo_mutex);
}

/*
 * One thread per replica. Responsible for accepting
 * IO connections. This thread will accept a connection
 * and spawn a new thread for each new connection req.
 *
 * This accepts connections for rebuild operation from
 * another replica to help it in rebuilding missing data.
 *
 * Exits if any error in bind/listen/epoll_* APIs
 */
void
uzfs_zvol_io_conn_acceptor(void *arg)
{
	int			io_sfd, efd;
	intptr_t		new_fd;
	int			rebuild_fd;
	int			rc, i, n;
	uint32_t		flags;
#ifdef DEBUG
	char			*hbuf;
	char			*sbuf;
#endif
	kthread_t		*thrd_info;
	socklen_t		in_len;
	struct sockaddr		in_addr;
	struct epoll_event	event;
	struct epoll_event	*events = NULL;
	char port[10];
	conn_acceptors_t	*ca = (conn_acceptors_t *)arg;

	io_sfd = rebuild_fd = efd = -1;
	flags = EPOLLIN | EPOLLERR | EPOLLHUP | EPOLLRDHUP;

	/* Create IO connection acceptor fd in non-blocking mode */
	snprintf(port, 8, "%d", io_server_port);
	io_sfd = create_and_bind(port, B_TRUE, B_FALSE);
	if (io_sfd == -1) {
		LOG_ERRNO("unable to bind to port %s", port);
		goto exit;
	}

	rc = listen(io_sfd, SOMAXCONN);
	if (rc == -1) {
		LOG_ERRNO("listen on IO FD in acceptor failed");
		goto exit;
	}
	LOG_DEBUG("listening on port %s for IO", port);

	snprintf(port, 8, "%d", rebuild_io_server_port);
	rebuild_fd = create_and_bind(port, B_TRUE, B_FALSE);
	if (rebuild_fd == -1) {
		LOG_ERRNO("unable to bind to port %s", port);
		goto exit;
	}

	rc = listen(rebuild_fd, SOMAXCONN);
	if (rc == -1) {
		LOG_ERRNO("listen on rebuild FD in acceptor failed");
		goto exit;
	}
	LOG_DEBUG("listening on port %s for rebuild IO", port);

	efd = epoll_create1(0);
	if (efd == -1) {
		LOG_ERRNO("epoll_create1 failed");
		goto exit;
	}

	event.data.fd = io_sfd;
	event.events = flags;
	rc = epoll_ctl(efd, EPOLL_CTL_ADD, io_sfd, &event);
	if (rc == -1) {
		LOG_ERRNO("epoll_ctl on IO FD failed");
		goto exit;
	}

	event.data.fd = rebuild_fd;
	event.events = flags;
	rc = epoll_ctl(efd, EPOLL_CTL_ADD, rebuild_fd, &event);
	if (rc == -1) {
		LOG_ERRNO("epoll_ctl on rebuild FD failed");
		goto exit;
	}

	/* Buffer where events are returned */
	events = calloc(MAXEVENTS, sizeof (event));

	prctl(PR_SET_NAME, "acceptor", 0, 0, 0);

	if (ca != NULL) {
		ca->io_fd = io_sfd;
		ca->rebuild_fd = rebuild_fd;
	}

	/* The event loop */
	while (1) {
		n = epoll_wait(efd, events, MAXEVENTS, -1);
		/*
		 * EINTR err can come when signal handler
		 * interrupt epoll_wait system call. It
		 * should be okay to continue in that case.
		 */
		if ((n < 0) && (errno == EINTR)) {
			continue;
		} else if (n < 0) {
			goto exit;
		}

		for (i = 0; i < n; i++) {
			/*
			 * An error has occured on this fd, or
			 * the socket is not ready for reading
			 * (why were we notified then?)
			 */
			if ((events[i].events & (~EPOLLIN)) != 0) {
				LOG_ERRNO("epoll failed");
				if (events[i].data.fd == io_sfd) {
					io_sfd = -1;
				} else {
					rebuild_fd = -1;
				}
				close(events[i].data.fd);
				/*
				 * TODO:We have choosen to exit
				 * instead of continuing here.
				 */
				goto exit;
			}
			/*
			 * We have a notification on the listening
			 * socket, which means one or more incoming
			 * connections.
			 */
			in_len = sizeof (in_addr);
			new_fd = accept(events[i].data.fd, &in_addr, &in_len);
			if (new_fd == -1) {
				LOG_ERRNO("accept failed");
				continue;
			}
#ifdef DEBUG
			hbuf = kmem_alloc(NI_MAXHOST, KM_SLEEP);
			sbuf = kmem_alloc(NI_MAXSERV, KM_SLEEP);
			rc = getnameinfo(&in_addr, in_len, hbuf,
			    NI_MAXHOST, sbuf, NI_MAXSERV,
			    NI_NUMERICHOST | NI_NUMERICSERV);
			if (rc == 0) {
				LOG_DEBUG("Accepted connection from %s:%s",
				    hbuf, sbuf);
			}

			kmem_free(hbuf, NI_MAXHOST);
			kmem_free(sbuf, NI_MAXSERV);
#endif

			rc = set_socket_keepalive(new_fd);
			if (rc != 0)
				LOG_ERR("Failed to set keepalive on "
				    "accepted fd %d", new_fd);
			rc = 0;

			if (events[i].data.fd == io_sfd) {
				LOG_INFO("New data connection");
				thrd_info = zk_thread_create(NULL, 0,
				    (thread_func_t)io_receiver,
				    (void *)new_fd, 0, NULL, TS_RUN, 0,
				    PTHREAD_CREATE_DETACHED);
			} else {
				LOG_INFO("New rebuild connection");
				thrd_info = zk_thread_create(NULL, 0,
				    (thread_func_t)rebuild_scanner,
				    (void *)new_fd, 0, NULL, TS_RUN, 0,
				    PTHREAD_CREATE_DETACHED);
			}
			VERIFY3P(thrd_info, !=, NULL);
		}
	}
exit:
	if (events != NULL)
		free(events);

	if (io_sfd != -1) {
		LOG_DEBUG("closing iofd %d", io_sfd);
		close(io_sfd);
	}

	if (rebuild_fd != -1) {
		LOG_DEBUG("closing rebuildfd %d", rebuild_fd);
		close(rebuild_fd);
	}

	if (efd != -1)
		close(efd);

	LOG_DEBUG("uzfs_zvol_io_conn_acceptor thread exiting");

	exit(1);
}

void
init_zrepl(void)
{
	mutex_init(&timer_mtx, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&timer_cv, NULL, CV_DEFAULT, NULL);
}

static int
uzfs_zvol_rebuild_scanner_callback(off_t offset, size_t len,
    blk_metadata_t *metadata, zvol_state_t *zv, void *args)
{
	zvol_io_hdr_t	hdr;
	zvol_io_cmd_t	*zio_cmd;
	zvol_rebuild_t  *warg;
	zvol_info_t	*zinfo;

	warg = (zvol_rebuild_t *)args;
	zinfo = warg->zinfo;

	hdr.version = REPLICA_VERSION;

	if (CHECK_UNMAP_IOSEQ(metadata->io_num))
		hdr.opcode = ZVOL_OPCODE_UNMAP;
	else
		hdr.opcode = ZVOL_OPCODE_READ;

	hdr.io_seq = metadata->io_num;
	hdr.offset = offset;
	hdr.len = len;
	hdr.flags = ZVOL_OP_FLAG_REBUILD;
	hdr.status = ZVOL_OP_STATUS_OK;

	while (1) {
		if ((zinfo->state == ZVOL_INFO_STATE_OFFLINE) ||
		    (zinfo->is_io_ack_sender_created == B_FALSE))
			return (-1);
		if (IS_REBUILD_HIT_MAX_CMD_LIMIT(zinfo))
			usleep(100);
		else
			break;
	}

	zinfo->rebuild_cmd_queued_cnt++;
	LOG_DEBUG("IO number for rebuild %ld", metadata->io_num);
	zio_cmd = zio_cmd_alloc(&hdr, warg->fd);
	/* Take refcount for uzfs_zvol_worker to work on it */
	uzfs_zinfo_take_refcnt(zinfo);
	zio_cmd->zinfo = zinfo;
	zinfo->rebuild_zv = zv;

	/*
	 * Any error in uzfs_zvol_worker will send FAILURE status to degraded
	 * replica. Degraded replica will take care of breaking the connection
	 */
	uzfs_zvol_worker(zio_cmd);
	return (0);
}

/*
 * Rebuild scanner function which after receiving
 * vol_name and IO number, will scan metadata and
 * read data and send across.
 */
void
uzfs_zvol_rebuild_scanner(void *arg)
{
	int		fd = (uintptr_t)arg;
	zvol_info_t	*zinfo = NULL;
	zvol_io_hdr_t	hdr;
	int 		rc = 0;
	zvol_rebuild_t	warg;
	char 		*name;
	blk_metadata_t	metadata;
	uint64_t	rebuild_req_offset;
	uint64_t	rebuild_req_len;
	zvol_io_cmd_t	*zio_cmd;
	struct linger	lo = { 1, 0 };

	if ((rc = setsockopt(fd, SOL_SOCKET, SO_LINGER, &lo, sizeof (lo)))
	    != 0) {
		LOG_ERRNO("setsockopt failed");
		goto exit;
	}
read_socket:
	if ((zinfo != NULL) &&
	    ((zinfo->state == ZVOL_INFO_STATE_OFFLINE) ||
	    (zinfo->is_io_ack_sender_created == B_FALSE)))
		goto exit;

	rc = uzfs_zvol_read_header(fd, &hdr);
	if ((rc != 0) ||
	    ((zinfo != NULL) &&
	    ((zinfo->state == ZVOL_INFO_STATE_OFFLINE) ||
	    (zinfo->is_io_ack_sender_created == B_FALSE))))
		goto exit;

	LOG_DEBUG("op_code=%d io_seq=%ld", hdr.opcode, hdr.io_seq);

	/* Handshake yet to happen */
	if ((hdr.opcode != ZVOL_OPCODE_HANDSHAKE) && (zinfo == NULL)) {
		LOG_DEBUG("Wrong opcode:%d, expecting handshake", hdr.opcode);
		rc = -1;
		goto exit;
	}
	switch (hdr.opcode) {
		case ZVOL_OPCODE_HANDSHAKE:
			name = kmem_alloc(hdr.len, KM_SLEEP);
			rc = uzfs_zvol_socket_read(fd, name, hdr.len);
			if (rc != 0) {
				LOG_ERR("Error reading zvol name");
				kmem_free(name, hdr.len);
				goto exit;
			}

			/* Handshake already happened */
			if (zinfo != NULL) {
				LOG_ERR("Second handshake on %s connection for "
				    "zvol %s",
				    zinfo->name, name);
				kmem_free(name, hdr.len);
				rc = -1;
				goto exit;
			}

			zinfo = uzfs_zinfo_lookup(name);
			if (zinfo == NULL) {
				LOG_ERR("zvol %s not found", name);
				kmem_free(name, hdr.len);
				rc = -1;
				goto exit;
			}

			LOG_INFO("Rebuild scanner started on zvol %s", name);

			uzfs_zvol_append_to_fd_list(zinfo, fd);
			zinfo->rebuild_cmd_queued_cnt =
			    zinfo->rebuild_cmd_acked_cnt = 0;

			kmem_free(name, hdr.len);
			warg.zinfo = zinfo;
			warg.fd = fd;
			goto read_socket;

		case ZVOL_OPCODE_REBUILD_STEP:

			metadata.io_num = hdr.checkpointed_io_seq;
			rebuild_req_offset = hdr.offset;
			rebuild_req_len = hdr.len;

			LOG_INFO("Checkpointed IO_seq: %ld, "
			    "Rebuild Req offset: %ld, Rebuild Req length: %ld",
			    metadata.io_num, rebuild_req_offset,
			    rebuild_req_len);
#if DEBUG
			if (inject_error.delay.helping_replica_rebuild_step
			    == 1)
				sleep(5);
#endif
			rc = uzfs_get_io_diff(zinfo->main_zv, &metadata,
			    uzfs_zvol_rebuild_scanner_callback,
			    rebuild_req_offset, rebuild_req_len, &warg);
			if (rc != 0) {
				LOG_ERR("Rebuild scanning failed on zvol %s "
				    "err(%d)", zinfo->name, rc);
				goto exit;
			}
			bzero(&hdr, sizeof (hdr));
			hdr.status = ZVOL_OP_STATUS_OK;
			hdr.version = REPLICA_VERSION;
			hdr.opcode = ZVOL_OPCODE_REBUILD_STEP_DONE;
			zio_cmd = zio_cmd_alloc(&hdr, fd);
			/* Take refcount for uzfs_zvol_worker to work on it */
			uzfs_zinfo_take_refcnt(zinfo);
			zio_cmd->zinfo = zinfo;
			uzfs_zvol_worker(zio_cmd);
			zio_cmd = NULL;
			goto read_socket;

		case ZVOL_OPCODE_REBUILD_COMPLETE:
			LOG_INFO("Rebuild process is over on zvol %s",
			    zinfo->name);
			goto exit;

		default:
			LOG_ERR("Wrong opcode: %d", hdr.opcode);
			goto exit;
	}

exit:
	if (zinfo != NULL) {
		LOG_INFO("Closing rebuild connection for zvol %s", zinfo->name);
		remove_pending_cmds_to_ack(fd, zinfo);
		uzfs_zvol_remove_from_fd_list(zinfo, fd);

		uzfs_zinfo_drop_refcnt(zinfo);
	} else {
		LOG_INFO("Closing rebuild connection");
	}

	shutdown(fd, SHUT_RDWR);
	close(fd);
	zk_thread_exit();
}

/*
 * (Re)Initializes zv's state variables.
 * This fn need to be called to use zv across network disconnections.
 * Lock protection and life of zv need to be managed by caller
 */
static void
reinitialize_zv_state(zvol_state_t *zv)
{
	if (zv == NULL)
		return;

	uzfs_zvol_set_status(zv, ZVOL_STATUS_DEGRADED);
	uzfs_zvol_set_rebuild_status(zv, ZVOL_REBUILDING_INIT);
}

/*
 * This func takes care of sending potentially multiple read blocks each
 * prefixed by metainfo.
 */
static int
uzfs_send_reads(int fd, zvol_io_cmd_t *zio_cmd)
{
	zvol_io_hdr_t 	*hdr = &zio_cmd->hdr;
	struct zvol_io_rw_hdr read_hdr;
	metadata_desc_t	*md;
	size_t	rel_offset = 0;
	int	rc = 0;

	/* special case for missing metadata */
	if (zio_cmd->metadata_desc == NULL) {
		read_hdr.io_num = 0;
		/*
		 * read_hdr.len should be adjusted back
		 * to actual read request size now
		 */
		read_hdr.len = hdr->len -
		    sizeof (struct zvol_io_rw_hdr);
		rc = uzfs_zvol_socket_write(fd, (char *)&read_hdr,
		    sizeof (read_hdr));
		if (rc != 0)
			return (rc);
		/* Data that need to be sent is equal to read_hdr.len */
		rc = uzfs_zvol_socket_write(fd, zio_cmd->buf, read_hdr.len);
		return (rc);
	}

	/*
	 * TODO: Optimize performance by combining multiple writes to a single
	 * system call either by copying all data to larger buffer or using
	 * vector write.
	 */
	for (md = zio_cmd->metadata_desc; md != NULL; md = md->next) {
		read_hdr.io_num = DECODE_IF_UNMAP_IOSEQ(md->metadata.io_num);
		read_hdr.len = md->len;
		rc = uzfs_zvol_socket_write(fd, (char *)&read_hdr,
		    sizeof (read_hdr));
		if (rc != 0)
			goto end;

		rc = uzfs_zvol_socket_write(fd,
		    (char *)zio_cmd->buf + rel_offset, md->len);
		if (rc != 0)
			goto end;
		rel_offset += md->len;
	}

end:
	FREE_METADATA_LIST(zio_cmd->metadata_desc);
	zio_cmd->metadata_desc = NULL;

	return (rc);
}

/*
 * One thread per LUN/vol. This thread works
 * on queue and it sends ack back to client on
 * a given fd.
 * There are two types of clients - one is iscsi target, and,
 * other is a replica which undergoes rebuild.
 * Need to exit from thread when there are network errors
 * on fd related to iscsi target.
 */
static void
uzfs_zvol_io_ack_sender(void *arg)
{
	int fd;
	int md_len;
	zvol_info_t		*zinfo;
	thread_args_t 		*thrd_arg;
	zvol_io_cmd_t 		*zio_cmd = NULL;

	thrd_arg = (thread_args_t *)arg;
	fd = thrd_arg->fd;
	zinfo = thrd_arg->zinfo;
	kmem_free(arg, sizeof (thread_args_t));

	prctl(PR_SET_NAME, "ack_sender", 0, 0, 0);

	LOG_INFO("Started ack sender for zvol %s fd: %d", zinfo->name, fd);

	while (1) {
		int rc = 0;
		(void) pthread_mutex_lock(&zinfo->zinfo_mutex);
		zinfo->zio_cmd_in_ack = NULL;
		while (1) {
			if ((zinfo->state == ZVOL_INFO_STATE_OFFLINE) ||
			    (zinfo->conn_closed == B_TRUE)) {
				(void) pthread_mutex_unlock(
				    &zinfo->zinfo_mutex);
				goto exit;
			}
			if (STAILQ_EMPTY(&zinfo->complete_queue)) {
				zinfo->io_ack_waiting = 1;
				pthread_cond_wait(&zinfo->io_ack_cond,
				    &zinfo->zinfo_mutex);
				zinfo->io_ack_waiting = 0;
			}
			else
				break;
		}

		zio_cmd = STAILQ_FIRST(&zinfo->complete_queue);
		STAILQ_REMOVE_HEAD(&zinfo->complete_queue, cmd_link);
		zinfo->zio_cmd_in_ack = zio_cmd;
		if (zio_cmd->hdr.flags & ZVOL_OP_FLAG_REBUILD)
			zinfo->rebuild_cmd_acked_cnt++;
		(void) pthread_mutex_unlock(&zinfo->zinfo_mutex);

		LOG_DEBUG("ACK for op: %d, seq-id: %ld",
		    zio_cmd->hdr.opcode, zio_cmd->hdr.io_seq);

		/* account for space taken by metadata headers */
		if (zio_cmd->hdr.status == ZVOL_OP_STATUS_OK &&
		    zio_cmd->hdr.opcode == ZVOL_OPCODE_READ) {
			md_len = 0;
			for (metadata_desc_t *md = zio_cmd->metadata_desc;
			    md != NULL;
			    md = md->next) {
				md_len++;
			}
			/* we need at least one header even if no metadata */
			if (md_len == 0)
				md_len++;
			zio_cmd->hdr.len += (md_len *
			    sizeof (struct zvol_io_rw_hdr));
		}

		rc = uzfs_zvol_socket_write(zio_cmd->conn,
		    (char *)&zio_cmd->hdr, sizeof (zio_cmd->hdr));
		if (rc == -1) {
			LOG_ERRNO("socket write err");
			zinfo->zio_cmd_in_ack = NULL;
			/*
			 * exit due to network errors on fd related
			 * to iscsi target
			 */
			if (zio_cmd->conn == fd) {
				zio_cmd_free(&zio_cmd);
				goto exit;
			}
			zio_cmd_free(&zio_cmd);
			continue;
		}

		switch (zio_cmd->hdr.opcode) {
			case ZVOL_OPCODE_WRITE:
				atomic_inc_64(&zinfo->write_req_ack_cnt);
				break;
			case ZVOL_OPCODE_SYNC:
				atomic_inc_64(&zinfo->sync_req_ack_cnt);
				break;
			case ZVOL_OPCODE_UNMAP:
				atomic_inc_64(&zinfo->unmap_req_ack_cnt);
				break;
			case ZVOL_OPCODE_READ:
				if (zio_cmd->hdr.status == ZVOL_OP_STATUS_OK) {
					/* Send data read from disk */
					rc = uzfs_send_reads(zio_cmd->conn,
					    zio_cmd);
					if (rc == -1) {
						zinfo->zio_cmd_in_ack = NULL;
						LOG_ERRNO("socket write err");
						if (zio_cmd->conn == fd) {
							zio_cmd_free(&zio_cmd);
							goto exit;
						}
					}
				}
				atomic_inc_64(&zinfo->read_req_ack_cnt);
				break;
			default:
				break;
		}
		zinfo->zio_cmd_in_ack = NULL;
		zio_cmd_free(&zio_cmd);
	}
exit:
	zinfo->zio_cmd_in_ack = NULL;
	shutdown(fd, SHUT_RDWR);
	LOG_INFO("Data connection for zvol %s closed on fd: %d",
	    zinfo->name, fd);

	(void) pthread_mutex_lock(&zinfo->zinfo_mutex);
	zinfo->is_io_ack_sender_created = B_FALSE;
	(void) pthread_mutex_unlock(&zinfo->zinfo_mutex);

	remove_pending_cmds_to_ack(fd, zinfo);

	(void) pthread_mutex_lock(&zinfo->zinfo_mutex);
	zinfo->conn_closed = B_FALSE;
	(void) pthread_mutex_unlock(&zinfo->zinfo_mutex);

	uzfs_zinfo_drop_refcnt(zinfo);

	zk_thread_exit();
}
/*
 * Process open request on data connection, the first message.
 *
 * Return status meaning:
 *   != 0: OPEN failed, stop reading data from connection.
 *   == 0 && zinfopp == NULL: OPEN failed, recoverable error
 *   == 0 && zinfopp != NULL: OPEN succeeded, proceed with other commands
 */
static int
open_zvol(int fd, zvol_info_t **zinfopp)
{
	int		rc;
	zvol_io_hdr_t	hdr;
	zvol_op_open_data_t open_data;
	zvol_info_t	*zinfo = NULL;
	zvol_state_t	*zv = NULL;
	kthread_t	*thrd_info;
	thread_args_t 	*thrd_arg;
	int		rele_dataset_on_error = 0;

	/*
	 * If we don't know the version yet, be more careful when
	 * reading header
	 */
	if (uzfs_zvol_read_header(fd, &hdr) != 0) {
		LOG_ERR("error reading open header");
		return (-1);
	}
	if (hdr.opcode != ZVOL_OPCODE_OPEN) {
		LOG_ERR("zvol must be opened first");
		return (-1);
	}
	if (hdr.len != sizeof (open_data)) {
		LOG_ERR("Invalid payload length for open");
		return (-1);
	}
	rc = uzfs_zvol_socket_read(fd, (char *)&open_data, sizeof (open_data));
	if (rc != 0) {
		LOG_ERR("Payload read failed");
		return (-1);
	}

	open_data.volname[MAX_NAME_LEN - 1] = '\0';
	zinfo = uzfs_zinfo_lookup(open_data.volname);
	if (zinfo == NULL) {
		LOG_ERR("zvol %s not found", open_data.volname);
		hdr.status = ZVOL_OP_STATUS_FAILED;
		goto open_reply;
	}
	(void) pthread_mutex_lock(&zinfo->zinfo_mutex);
	if (zinfo->state != ZVOL_INFO_STATE_ONLINE) {
		LOG_ERR("zvol %s is not online", open_data.volname);
		hdr.status = ZVOL_OP_STATUS_FAILED;
		(void) pthread_mutex_unlock(&zinfo->zinfo_mutex);
		goto open_reply;
	}
	if (zinfo->is_io_ack_sender_created != B_FALSE) {
		LOG_ERR("zvol %s ack sender already present",
		    open_data.volname);
		hdr.status = ZVOL_OP_STATUS_FAILED;
		(void) pthread_mutex_unlock(&zinfo->zinfo_mutex);
		goto open_reply;
	}
	if (zinfo->is_io_receiver_created != B_FALSE) {
		LOG_ERR("zvol %s io receiver already present",
		    open_data.volname);
		hdr.status = ZVOL_OP_STATUS_FAILED;
		(void) pthread_mutex_unlock(&zinfo->zinfo_mutex);
		goto open_reply;
	}

	zv = zinfo->main_zv;
	ASSERT3P(zv, !=, NULL);

	ASSERT3P(zv->zv_status, ==, ZVOL_STATUS_DEGRADED);
	ASSERT3P(zv->rebuild_info.zv_rebuild_status, ==, ZVOL_REBUILDING_INIT);

	if ((zv->zv_status != ZVOL_STATUS_DEGRADED) ||
	    ((zv->rebuild_info.zv_rebuild_status != ZVOL_REBUILDING_INIT) &&
	    (zv->rebuild_info.zv_rebuild_status != ZVOL_REBUILDING_FAILED))) {
		LOG_ERR("as status for %s is %d or rebuild status is %d",
		    open_data.volname, zv->zv_status,
		    zv->rebuild_info.zv_rebuild_status);
		hdr.status = ZVOL_OP_STATUS_FAILED;
		(void) pthread_mutex_unlock(&zinfo->zinfo_mutex);
		goto open_reply;
	}
	// validate block size (only one bit is set in the number)
	if (open_data.tgt_block_size == 0 ||
	    (open_data.tgt_block_size & (open_data.tgt_block_size - 1)) != 0) {
		LOG_ERR("Invalid block size");
		hdr.status = ZVOL_OP_STATUS_FAILED;
		(void) pthread_mutex_unlock(&zinfo->zinfo_mutex);
		goto open_reply;
	}

	/*
	 * Hold objset if this is the first query for the zvol. This can happen
	 * in case that the target creates data connection directly without
	 * getting the endpoint through mgmt connection first.
	 */
	rele_dataset_on_error = 0;
	if (zv->zv_objset == NULL) {
		if (uzfs_hold_dataset(zv) != 0) {
			(void) pthread_mutex_unlock(&zinfo->zinfo_mutex);
			LOG_ERR("Failed to hold zvol during open");
			hdr.status = ZVOL_OP_STATUS_FAILED;
			goto open_reply;
		}
		rele_dataset_on_error = 1;
	}
	if (uzfs_update_metadata_granularity(zv,
	    open_data.tgt_block_size) != 0) {
		if (rele_dataset_on_error == 1)
			uzfs_rele_dataset(zv);
		LOG_ERR("Failed to set granularity of metadata");
		hdr.status = ZVOL_OP_STATUS_FAILED;
		(void) pthread_mutex_unlock(&zinfo->zinfo_mutex);
		goto open_reply;
	}

	if (zinfo->snap_zv == NULL) {
		ASSERT3P(zinfo->clone_zv, ==, NULL);
		/* Create clone for rebuild */
		if (uzfs_zvol_get_or_create_internal_clone(zinfo->main_zv,
		    &zinfo->snap_zv, &zinfo->clone_zv, NULL) != 0) {
			if (rele_dataset_on_error == 1)
				uzfs_rele_dataset(zv);
			LOG_ERR("Failed to create clone for rebuild");
			hdr.status = ZVOL_OP_STATUS_FAILED;
			(void) pthread_mutex_unlock(&zinfo->zinfo_mutex);
			goto open_reply;
		}
	}
	ASSERT3P(zinfo->clone_zv, !=, NULL);
	/*
	 * TODO: Once we support multiple concurrent data connections for a
	 * single zvol, we should probably check that the timeout is the same
	 * for all data connections.
	 */
	uzfs_update_ionum_interval(zinfo, open_data.timeout);
	zinfo->timeout = open_data.timeout;
	*zinfopp = zinfo;

	zinfo->conn_closed = B_FALSE;
	zinfo->is_io_ack_sender_created = B_TRUE;
	zinfo->is_io_receiver_created = B_TRUE;
	(void) pthread_mutex_unlock(&zinfo->zinfo_mutex);
	thrd_arg = kmem_alloc(sizeof (thread_args_t), KM_SLEEP);
	thrd_arg->fd = fd;
	thrd_arg->zinfo = zinfo;
	uzfs_zinfo_take_refcnt(zinfo);
	thrd_info = zk_thread_create(NULL, 0,
	    (thread_func_t)uzfs_zvol_io_ack_sender, (void *)thrd_arg, 0, NULL,
	    TS_RUN, 0, PTHREAD_CREATE_DETACHED);
	VERIFY3P(thrd_info, !=, NULL);

	hdr.status = ZVOL_OP_STATUS_OK;

open_reply:
	hdr.len = 0;
	rc = uzfs_zvol_socket_write(fd, (char *)&hdr, sizeof (hdr));

	/*
	 * Reinitializing zv states during this error is taken care
	 * in open_zvol caller
	 */
	if (rc == -1)
		LOG_ERR("Failed to send reply for open request");
	if (hdr.status != ZVOL_OP_STATUS_OK) {
		ASSERT3P(*zinfopp, ==, NULL);
		if (zinfo != NULL)
			uzfs_zinfo_drop_refcnt(zinfo);
		return (-1);
	}
	return (rc);
}

/*
 * IO-Receiver would be per ZVOL, it would be
 * responsible for receiving IOs on given socket.
 */
void
uzfs_zvol_io_receiver(void *arg)
{
	int		rc;
	int		fd = (uintptr_t)arg;
	zvol_info_t	*zinfo = NULL;
	zvol_io_cmd_t	*zio_cmd;
	zvol_io_hdr_t	hdr;

	prctl(PR_SET_NAME, "io_receiver", 0, 0, 0);

	/* First command should be OPEN */
	while (zinfo == NULL) {
		if (open_zvol(fd, &zinfo) != 0) {
			if ((zinfo != NULL) &&
			    (zinfo->is_io_ack_sender_created))
				goto exit;
			shutdown(fd, SHUT_RDWR);
			goto thread_exit;
		}
	}

	LOG_INFO("Data connection associated with zvol %s fd: %d",
	    zinfo->name, fd);

	while ((rc = uzfs_zvol_socket_read(fd, (char *)&hdr, sizeof (hdr))) ==
	    0) {
		if ((zinfo->state == ZVOL_INFO_STATE_OFFLINE))
			break;

		if (hdr.opcode != ZVOL_OPCODE_WRITE &&
		    hdr.opcode != ZVOL_OPCODE_READ &&
		    hdr.opcode != ZVOL_OPCODE_UNMAP &&
		    hdr.opcode != ZVOL_OPCODE_SYNC) {
			LOG_ERR("Unexpected opcode %d", hdr.opcode);
			break;
		}

		if (((hdr.opcode == ZVOL_OPCODE_WRITE) ||
		    (hdr.opcode == ZVOL_OPCODE_READ)) && !hdr.len) {
			LOG_ERR("Zero Payload size for opcode %d", hdr.opcode);
			break;
		} else if ((hdr.opcode == ZVOL_OPCODE_SYNC) && hdr.len > 0) {
			LOG_ERR("Unexpected payload for opcode %d", hdr.opcode);
			break;
		}

		zio_cmd = zio_cmd_alloc(&hdr, fd);
		/* Read payload for commands which have it */
		if (hdr.opcode == ZVOL_OPCODE_WRITE) {
			rc = uzfs_zvol_socket_read(fd, zio_cmd->buf, hdr.len);
			if (rc != 0) {
				zio_cmd_free(&zio_cmd);
				break;
			}
		}

		if (zinfo->state == ZVOL_INFO_STATE_OFFLINE) {
			zio_cmd_free(&zio_cmd);
			break;
		}
		/* Take refcount for uzfs_zvol_worker to work on it */
		uzfs_zinfo_take_refcnt(zinfo);
		zio_cmd->zinfo = zinfo;
		taskq_dispatch(zinfo->uzfs_zvol_taskq, uzfs_zvol_worker,
		    zio_cmd, TQ_SLEEP);
	}
exit:
	(void) pthread_mutex_lock(&zinfo->zinfo_mutex);
	zinfo->conn_closed = B_TRUE;
	/*
	 * Send signal to ack sender so that it can free
	 * zio_cmd, close fd and exit.
	 */
	if (zinfo->io_ack_waiting) {
		rc = pthread_cond_signal(&zinfo->io_ack_cond);
	}
	/*
	 * wait for ack thread to exit to avoid races with new
	 * connections for the same zinfo
	 */
	while (zinfo->conn_closed || zinfo->is_io_ack_sender_created) {
		(void) pthread_mutex_unlock(&zinfo->zinfo_mutex);
		usleep(1000);
		(void) pthread_mutex_lock(&zinfo->zinfo_mutex);
	}
	(void) pthread_mutex_unlock(&zinfo->zinfo_mutex);

	shutdown_fds_related_to_zinfo(zinfo);

	zinfo->io_ack_waiting = 0;

	taskq_wait(zinfo->uzfs_zvol_taskq);
	reinitialize_zv_state(zinfo->main_zv);
	zinfo->is_io_receiver_created = B_FALSE;
	(void) uzfs_zvol_release_internal_clone(zinfo->main_zv,
	    &zinfo->snap_zv, &zinfo->clone_zv);
	uzfs_zinfo_drop_refcnt(zinfo);
thread_exit:
	close(fd);
	LOG_INFO("Data connection closed on fd: %d", fd);
	zk_thread_exit();
}
