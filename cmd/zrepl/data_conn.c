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

#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <uzfs_io.h>
#include <uzfs_rebuilding.h>
#include <zrepl_mgmt.h>
#include "data_conn.h"

#define	ZVOL_REBUILD_STEP_SIZE  (128 * 1024 * 1024) // 128MB

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
	    (hdr->opcode == ZVOL_OPCODE_HANDSHAKE)) {
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
		case ZVOL_OPCODE_HANDSHAKE:
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
			ZREPL_ERRLOG("Read error:%d\n", errno);
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
		if (count <= 0) {
			ZREPL_ERRLOG("Write error:%d\n", errno);
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
	int 		write = 0;
	boolean_t	rebuild_cmd_req;

	zio_cmd = (zvol_io_cmd_t *)arg;
	hdr = &zio_cmd->hdr;
	zinfo = zio_cmd->zv;
	zvol_state = zinfo->zv;
	rebuild_cmd_req = hdr->flags & ZVOL_OP_FLAG_REBUILD;

	/*
	 * If zvol hasn't passed rebuild phase or if read
	 * is meant for rebuild then we need the metadata
	 */
	if (!rebuild_cmd_req && ZVOL_IS_REBUILDED(zvol_state)) {
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
			break;

		case ZVOL_OPCODE_WRITE:
			write = 1;
			rc = uzfs_submit_writes(zinfo, zio_cmd);
			break;

		case ZVOL_OPCODE_SYNC:
			uzfs_flush_data(zinfo->zv);
			break;
		case ZVOL_OPCODE_REBUILD_STEP_DONE:
			break;
		default:
			VERIFY(!"Should be a valid opcode");
			break;
	}

	if (rc != 0) {
		ZREPL_ERRLOG("Zvol op_code :%d failed with "
		    "error: %d\n", hdr->opcode, errno);
		hdr->status = ZVOL_OP_STATUS_FAILED;
		hdr->len = 0;
	} else {
		hdr->status = ZVOL_OP_STATUS_OK;
	}

	/*
	 * We are not sending ACK for writes meant for rebuild
	 */
	if (rebuild_cmd_req && (hdr->opcode == ZVOL_OPCODE_WRITE)) {
		zio_cmd_free(&zio_cmd);
		goto drop_refcount;
	}

	(void) pthread_mutex_lock(&zinfo->complete_queue_mutex);
	STAILQ_INSERT_TAIL(&zinfo->complete_queue, zio_cmd, cmd_link);
	if (write) {
		zinfo->write_req_received_cnt++;
	} else {
		zinfo->read_req_received_cnt++;
	}

	if (zinfo->io_ack_waiting) {
		rc = pthread_cond_signal(&zinfo->io_ack_cond);
	}

	(void) pthread_mutex_unlock(&zinfo->complete_queue_mutex);

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
	uint64_t	checkpointed_io_seq;
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
		perror("connect");
		goto exit;
	}

	/* Set state in-progess state now */
	uzfs_zvol_get_last_committed_io_no(zinfo->zv, &checkpointed_io_seq);
	zvol_state = zinfo->zv;
	bzero(&hdr, sizeof (hdr));
	hdr.status = ZVOL_OP_STATUS_OK;
	hdr.version = REPLICA_VERSION;
	hdr.opcode = ZVOL_OPCODE_HANDSHAKE;
	hdr.len = strlen(rebuild_args->zvol_name) + 1;

	rc = uzfs_zvol_socket_write(sfd, (char *)&hdr, sizeof (hdr));
	if (rc == -1) {
		ZREPL_ERRLOG("Socket write failed, err: %d\n", errno);
		goto exit;
	}

	rc = uzfs_zvol_socket_write(sfd, (void *)rebuild_args->zvol_name,
	    hdr.len);
	if (rc == -1) {
		ZREPL_ERRLOG("Socket write failed, err: %d\n", errno);
		goto exit;
	}

next_step:

	if (ZVOL_IS_REBUILDING_FAILED(zinfo->zv)) {
		goto exit;
	}

	if (offset >= ZVOL_VOLUME_SIZE(zvol_state)) {
		hdr.opcode = ZVOL_OPCODE_REBUILD_COMPLETE;
		rc = uzfs_zvol_socket_write(sfd, (char *)&hdr, sizeof (hdr));
		if (rc != 0) {
			ZREPL_ERRLOG("Socket write failed, err: %d\n", errno);
			goto exit;
		}

		atomic_inc_16(&zinfo->zv->rebuild_info.rebuild_done_cnt);
		if (zinfo->zv->rebuild_info.rebuild_cnt ==
		    zinfo->zv->rebuild_info.rebuild_done_cnt) {
			/* Mark replica healthy now */
			uzfs_zvol_set_rebuild_status(zinfo->zv,
			    ZVOL_REBUILDING_DONE);
			uzfs_zvol_set_status(zinfo->zv, ZVOL_STATUS_HEALTHY);
		}
		ZREPL_ERRLOG("Rebuilding on Replica:%s completed\n",
		    zinfo->name);
		goto exit;
	} else {
		bzero(&hdr, sizeof (hdr));
		hdr.status = ZVOL_OP_STATUS_OK;
		hdr.version = REPLICA_VERSION;
		hdr.opcode = ZVOL_OPCODE_REBUILD_STEP;
		hdr.checkpointed_io_seq = checkpointed_io_seq;
		hdr.offset = offset;
		hdr.len = ZVOL_REBUILD_STEP_SIZE;
		rc = uzfs_zvol_socket_write(sfd, (char *)&hdr, sizeof (hdr));
		if (rc != 0) {
			ZREPL_ERRLOG("Socket write failed, err: %d\n", errno);
			goto exit;
		}
	}

	while (1) {

		if (ZVOL_IS_REBUILDING_FAILED(zinfo->zv)) {
			goto exit;
		}

		rc = uzfs_zvol_socket_read(sfd, (char *)&hdr, sizeof (hdr));
		if (rc != 0) {
			ZREPL_ERRLOG("Socket read failed, err: %d\n", errno);
			goto exit;
		}

		if (hdr.opcode == ZVOL_OPCODE_REBUILD_STEP_DONE) {
			offset += ZVOL_REBUILD_STEP_SIZE;
			printf("ZVOL_OPCODE_REBUILD_STEP_DONE received\n");
			goto next_step;
		}

		ASSERT((hdr.opcode == ZVOL_OPCODE_READ) &&
		    (hdr.flags & ZVOL_OP_FLAG_REBUILD));
		hdr.opcode = ZVOL_OPCODE_WRITE;

		zio_cmd = zio_cmd_alloc(&hdr, sfd);
		rc = uzfs_zvol_socket_read(sfd, zio_cmd->buf, hdr.len);
		if (rc != 0) {
			ZREPL_ERRLOG("Socket read failed with "
			    "error: %d\n", errno);
			goto exit;
		}

		/*
		 * Take refcount for uzfs_zvol_worker to work on it.
		 * Will dropped by uzfs_zvol_worker once cmd is executed.
		 */
		uzfs_zinfo_take_refcnt(zinfo, B_FALSE);
		zio_cmd->zv = zinfo;
		uzfs_zvol_worker(zio_cmd);
		zio_cmd = NULL;
	}

exit:
	kmem_free(arg, sizeof (rebuild_thread_arg_t));
	if (zio_cmd != NULL)
		zio_cmd_free(&zio_cmd);
	if (sfd != -1)
		close(sfd);

	if (rc == -1)
		uzfs_zvol_set_rebuild_status(zinfo->zv, ZVOL_REBUILDING_FAILED);

	ZREPL_LOG("uzfs_zvol_rebuild_dw_replica thread exiting, volume:%s\n",
	    zinfo->name);
	/* Parent thread have taken refcount, drop it now */
	uzfs_zinfo_drop_refcnt(zinfo, B_FALSE);

	zk_thread_exit();
}
