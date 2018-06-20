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

#include <sys/prctl.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <uzfs_io.h>
#include <uzfs_rebuilding.h>
#include <zrepl_mgmt.h>
#include "mgmt_conn.h"
#include "data_conn.h"

#define	ZVOL_REBUILD_STEP_SIZE  (10 * 1024ULL * 1024ULL * 1024ULL) // 10GB

uint64_t zvol_rebuild_step_size = ZVOL_REBUILD_STEP_SIZE;

kcondvar_t timer_cv;
kmutex_t timer_mtx;

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
				kmem_free(zio_cmd->buf, zio_cmd->hdr.len);
			}
			break;

		case ZVOL_OPCODE_SYNC:
		case ZVOL_OPCODE_REBUILD_STEP_DONE:
			/* Nothing to do */
			break;

		default:
			VERIFY(!"Should be a valid opcode");
			break;
	}

	kmem_free(zio_cmd, sizeof (zvol_io_cmd_t));
	*cmd = NULL;
}

int
uzfs_zvol_socket_read(int fd, char *buf, uint64_t nbytes)
{
	ssize_t count = 0;
	char *p = buf;
	while (nbytes) {
		count = read(fd, (void *)p, nbytes);
		if (count <= 0) {
			if (count == 0) {
				LOG_INFO("Connection closed");
			} else {
				LOG_ERRNO("Socket read error");
			}
			return (-1);
		}
		p += count;
		nbytes -= count;
	}
	return (0);
}

int
uzfs_zvol_socket_write(int fd, char *buf, uint64_t nbytes)
{
	ssize_t count = 0;
	char *p = buf;
	while (nbytes) {
		count = write(fd, (void *)p, nbytes);
		if (count < 0) {
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

		rc = uzfs_write_data(zinfo->zv, datap, data_offset,
		    write_hdr->len, &metadata, is_rebuild);
		if (rc != 0)
			break;
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
	zvol_state_t	*zvol_state;
	zvol_io_hdr_t 	*hdr;
	metadata_desc_t	**metadata_desc;
	int		rc = 0;
	boolean_t	rebuild_cmd_req;
	boolean_t	read_metadata;

	zio_cmd = (zvol_io_cmd_t *)arg;
	hdr = &zio_cmd->hdr;
	zinfo = zio_cmd->zv;
	zvol_state = zinfo->zv;
	rebuild_cmd_req = hdr->flags & ZVOL_OP_FLAG_REBUILD;
	read_metadata = hdr->flags & ZVOL_OP_FLAG_READ_METADATA;

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
			rc = uzfs_read_data(zinfo->zv,
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
			uzfs_flush_data(zinfo->zv);
			atomic_inc_64(&zinfo->sync_req_received_cnt);
			break;

		case ZVOL_OPCODE_REBUILD_STEP_DONE:
			break;
		default:
			VERIFY(!"Should be a valid opcode");
			break;
	}

	if (rc != 0) {
		LOG_ERR("OP code %d failed", hdr->opcode);
		hdr->status = ZVOL_OP_STATUS_FAILED;
		hdr->len = 0;
	} else {
		hdr->status = ZVOL_OP_STATUS_OK;
	}

	/*
	 * We are not sending ACK for writes meant for rebuild
	 */
	if (rebuild_cmd_req && (hdr->opcode == ZVOL_OPCODE_WRITE)) {
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
	uzfs_zinfo_drop_refcnt(zinfo, B_FALSE);
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

	sfd = rebuild_args->fd;
	zinfo = rebuild_args->zinfo;

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

	/* Set state in-progess state now */
	checkpointed_ionum = uzfs_zvol_get_last_committed_io_no(zinfo->zv);
	zvol_state = zinfo->zv;
	bzero(&hdr, sizeof (hdr));
	hdr.status = ZVOL_OP_STATUS_OK;
	hdr.version = REPLICA_VERSION;
	hdr.opcode = ZVOL_OPCODE_HANDSHAKE;
	hdr.len = strlen(rebuild_args->zvol_name) + 1;

	rc = uzfs_zvol_socket_write(sfd, (char *)&hdr, sizeof (hdr));
	if (rc != 0) {
		LOG_ERRNO("Socket hdr write failed");
		goto exit;
	}

	rc = uzfs_zvol_socket_write(sfd, (void *)rebuild_args->zvol_name,
	    hdr.len);
	if (rc != 0) {
		LOG_ERRNO("Socket write failed");
		goto exit;
	}

next_step:

	if (ZVOL_IS_REBUILDING_ERRORED(zinfo->zv)) {
		LOG_ERR("rebuilding errored.. for %s..", zinfo->name);
		rc = -1;
		goto exit;
	}

	if (offset >= ZVOL_VOLUME_SIZE(zvol_state)) {
		hdr.opcode = ZVOL_OPCODE_REBUILD_COMPLETE;
		rc = uzfs_zvol_socket_write(sfd, (char *)&hdr, sizeof (hdr));
		if (rc != 0) {
			LOG_ERRNO("Socket write failed");
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
		if ((offset + ZVOL_REBUILD_STEP_SIZE) >
		    ZVOL_VOLUME_SIZE(zvol_state))
			hdr.len = ZVOL_VOLUME_SIZE(zvol_state) - offset;
		else
			hdr.len = ZVOL_REBUILD_STEP_SIZE;
		rc = uzfs_zvol_socket_write(sfd, (char *)&hdr, sizeof (hdr));
		if (rc != 0) {
			LOG_ERRNO("Socket write failed");
			goto exit;
		}
	}

	while (1) {

		if (ZVOL_IS_REBUILDING_ERRORED(zinfo->zv)) {
			LOG_ERR("rebuilding already errored.. for %s..",
			    zinfo->name);
			rc = -1;
			goto exit;
		}

		rc = uzfs_zvol_socket_read(sfd, (char *)&hdr, sizeof (hdr));
		if (rc != 0) {
			LOG_ERRNO("Socket read failed");
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

		ASSERT((hdr.opcode == ZVOL_OPCODE_READ) &&
		    (hdr.flags & ZVOL_OP_FLAG_REBUILD));
		hdr.opcode = ZVOL_OPCODE_WRITE;

		zio_cmd = zio_cmd_alloc(&hdr, sfd);
		rc = uzfs_zvol_socket_read(sfd, zio_cmd->buf, hdr.len);
		if (rc != 0) {
			LOG_ERRNO("Socket read failed");
			goto exit;
		}

		/*
		 * Take refcount for uzfs_zvol_worker to work on it.
		 * Will dropped by uzfs_zvol_worker once cmd is executed.
		 */
		uzfs_zinfo_take_refcnt(zinfo, B_FALSE);
		zio_cmd->zv = zinfo;
		uzfs_zvol_worker(zio_cmd);
		if (zio_cmd->hdr.status != ZVOL_OP_STATUS_OK) {
			LOG_ERR("rebuild IO failed.. for %s..", zinfo->name);
			rc = -1;
			goto exit;
		}
		zio_cmd_free(&zio_cmd);
	}

exit:
	mutex_enter(&zinfo->zv->rebuild_mtx);
	if (rc != 0) {
		uzfs_zvol_set_rebuild_status(zinfo->zv,
		    ZVOL_REBUILDING_ERRORED);
		(zinfo->zv->rebuild_info.rebuild_failed_cnt) += 1;
		LOG_ERR("uzfs_zvol_rebuild_dw_replica thread exiting, "
		    "rebuilding failed zvol: %s", zinfo->name);
	}
	(zinfo->zv->rebuild_info.rebuild_done_cnt) += 1;
	if (zinfo->zv->rebuild_info.rebuild_cnt ==
	    zinfo->zv->rebuild_info.rebuild_done_cnt) {
		if (zinfo->zv->rebuild_info.rebuild_failed_cnt != 0)
			uzfs_zvol_set_rebuild_status(zinfo->zv,
			    ZVOL_REBUILDING_FAILED);
		else {
			/* Mark replica healthy now */
			uzfs_zvol_set_rebuild_status(zinfo->zv,
			    ZVOL_REBUILDING_DONE);
			uzfs_zvol_set_status(zinfo->zv, ZVOL_STATUS_HEALTHY);
			uzfs_update_ionum_interval(zinfo, 0);
		}
	}
	mutex_exit(&zinfo->zv->rebuild_mtx);

	kmem_free(arg, sizeof (rebuild_thread_arg_t));
	if (zio_cmd != NULL)
		zio_cmd_free(&zio_cmd);
	if (sfd != -1) {
		shutdown(sfd, SHUT_RDWR);
		close(sfd);
	}
	/* Parent thread have taken refcount, drop it now */
	uzfs_zinfo_drop_refcnt(zinfo, B_FALSE);

	zk_thread_exit();
}

void
uzfs_zvol_timer_thread(void)
{
	zvol_info_t *zinfo;
	time_t min_interval;
	time_t now, next_check;

	init_zrepl();
	prctl(PR_SET_NAME, "zvol_timer", 0, 0, 0);

	mutex_enter(&timer_mtx);
	while (1) {
		min_interval = 600;  // we check intervals at least every 10mins
		mutex_enter(&zvol_list_mutex);
		now = time(NULL);
		SLIST_FOREACH(zinfo, &zvol_list, zinfo_next) {
			if (uzfs_zvol_get_status(zinfo->zv) ==
			    ZVOL_STATUS_HEALTHY) {
				next_check = zinfo->checkpointed_time +
				    zinfo->update_ionum_interval;
				if (next_check <= now) {
					LOG_DEBUG("Checkpointing ionum "
					    "%lu on %s",
					    zinfo->checkpointed_ionum,
					    zinfo->name);
					uzfs_zvol_store_last_committed_io_no(
					    zinfo->zv,
					    zinfo->checkpointed_ionum);
					zinfo->checkpointed_ionum =
					    zinfo->running_ionum;
					zinfo->checkpointed_time = now;
					next_check = now +
					    zinfo->update_ionum_interval;
				}
				if (min_interval > next_check - now)
					min_interval = next_check - now;
			}
		}
		mutex_exit(&zvol_list_mutex);

		(void) cv_timedwait(&timer_cv, &timer_mtx, ddi_get_lbolt() +
		    SEC_TO_TICK(min_interval));
	}
	mutex_exit(&timer_mtx);
	mutex_destroy(&timer_mtx);
	cv_destroy(&timer_cv);
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
		sleep(1);
		(void) pthread_mutex_lock(&zinfo->zinfo_mutex);
	}
	(void) pthread_mutex_unlock(&zinfo->zinfo_mutex);
}

void
init_zrepl(void)
{
	mutex_init(&timer_mtx, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&timer_cv, NULL, CV_DEFAULT, NULL);
}
