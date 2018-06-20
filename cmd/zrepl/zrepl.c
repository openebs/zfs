#include <arpa/inet.h>
#include <netdb.h>
#include <execinfo.h>

#include <libuzfs.h>
#include <libzfs.h>
#include <sys/prctl.h>
#include <sys/queue.h>
#include <uzfs_mgmt.h>
#include <zrepl_mgmt.h>
#include <uzfs_io.h>
#include <sys/epoll.h>
#include <sys/types.h>
#include <uzfs_rebuilding.h>
#include <atomic.h>
#include <uzfs_zap.h>

#include "mgmt_conn.h"
#include "data_conn.h"

#define	MAXEVENTS 64
#define	ZAP_UPDATE_TIME_INTERVAL 2

__thread char tinfo[50] = {0};
extern unsigned long zfs_arc_max;
extern unsigned long zfs_arc_min;
extern int zfs_autoimport_disable;

static void uzfs_zvol_io_ack_sender(void *arg);

kthread_t	*conn_accpt_thread;
kthread_t	*uzfs_timer_thread;
kthread_t	*mgmt_conn_thread;

/*
 * Read header message from socket in safe manner, which is: first we read a
 * version number and if valid then we read the rest of the message.
 *
 * Return value < 0 => error
 *              > 0 => invalid version
 *              = 0 => ok
 */
static int
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
	zvol_state_t	*zv;
	kthread_t	*thrd_info;
	thread_args_t 	*thrd_arg;

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
	zv = zinfo->zv;
	ASSERT3P(zv, !=, NULL);
	if (zv->zv_metavolblocksize != 0 &&
	    zv->zv_metavolblocksize != open_data.tgt_block_size) {
		LOG_ERR("Conflicting block size");
		hdr.status = ZVOL_OP_STATUS_FAILED;
		goto open_reply;
	}
	// validate block size (only one bit is set in the number)
	if (open_data.tgt_block_size == 0 ||
	    (open_data.tgt_block_size & (open_data.tgt_block_size - 1)) != 0) {
		LOG_ERR("Invalid block size");
		hdr.status = ZVOL_OP_STATUS_FAILED;
		goto open_reply;
	}

	(void) pthread_mutex_lock(&zinfo->zinfo_mutex);
	/*
	 * Hold objset if this is the first query for the zvol. This can happen
	 * in case that the target creates data connection directly without
	 * getting the endpoint through mgmt connection first.
	 */
	if (zv->zv_objset == NULL && uzfs_hold_dataset(zv) != 0) {
		(void) pthread_mutex_unlock(&zinfo->zinfo_mutex);
		LOG_ERR("Failed to hold zvol during open");
		hdr.status = ZVOL_OP_STATUS_FAILED;
		goto open_reply;
	}
	if (uzfs_update_metadata_granularity(zv,
	    open_data.tgt_block_size) != 0) {
		(void) pthread_mutex_unlock(&zinfo->zinfo_mutex);
		uzfs_rele_dataset(zv);
		LOG_ERR("Failed to set granularity of metadata");
		hdr.status = ZVOL_OP_STATUS_FAILED;
		goto open_reply;
	}
	/*
	 * TODO: Once we support multiple concurrent data connections for a
	 * single zvol, we should probably check that the timeout is the same
	 * for all data connections.
	 */
	uzfs_update_ionum_interval(zinfo, open_data.timeout);
	zinfo->timeout = open_data.timeout;
	*zinfopp = zinfo;

	if (!zinfo->is_io_ack_sender_created) {
		zinfo->conn_closed = B_FALSE;
		zinfo->is_io_ack_sender_created = B_TRUE;
		(void) pthread_mutex_unlock(&zinfo->zinfo_mutex);
		thrd_arg = kmem_alloc(sizeof (thread_args_t), KM_SLEEP);
		thrd_arg->fd = fd;
		thrd_arg->zinfo = zinfo;
		uzfs_zinfo_take_refcnt(zinfo, B_FALSE);
		thrd_info = zk_thread_create(NULL, 0,
		    (thread_func_t)uzfs_zvol_io_ack_sender,
		    (void *)thrd_arg, 0, NULL, TS_RUN, 0,
		    PTHREAD_CREATE_DETACHED);
		VERIFY3P(thrd_info, !=, NULL);
	} else {
		(void) pthread_mutex_unlock(&zinfo->zinfo_mutex);
	}

	hdr.status = ZVOL_OP_STATUS_OK;

open_reply:
	hdr.len = 0;
	rc = uzfs_zvol_socket_write(fd, (char *)&hdr, sizeof (hdr));
	if (rc == -1)
		LOG_ERR("Failed to send reply for open request");
	if (hdr.status != ZVOL_OP_STATUS_OK) {
		if (zinfo != NULL)
			uzfs_zinfo_drop_refcnt(zinfo, B_FALSE);
		return (-1);
	}
	return (rc);
}

/*
 * IO-Receiver would be per ZVOL, it would be
 * responsible for receiving IOs on given socket.
 */
static void
uzfs_zvol_io_receiver(void *arg)
{
	int		rc;
	int		fd = (uintptr_t)arg;
	zvol_info_t	*zinfo = NULL;
	zvol_io_cmd_t	*zio_cmd;
	zvol_io_hdr_t	hdr;

	/* First command should be OPEN */
	while (zinfo == NULL) {
		if (open_zvol(fd, &zinfo) != 0)
			goto exit;
		snprintf(tinfo, 50, "io_receiver_%lu", zinfo->zvol_guid);
		prctl(PR_SET_NAME, tinfo, 0, 0, 0);
	}

	while (1) {
		rc = uzfs_zvol_socket_read(fd, (char *)&hdr,
		    sizeof (hdr));
		if (rc != 0)
			goto exit;

		if (hdr.opcode != ZVOL_OPCODE_WRITE &&
		    hdr.opcode != ZVOL_OPCODE_READ &&
		    hdr.opcode != ZVOL_OPCODE_SYNC) {
			LOG_ERR("Unexpected opcode %d", hdr.opcode);
			goto exit;
		}

		if (((hdr.opcode == ZVOL_OPCODE_WRITE) ||
		    (hdr.opcode == ZVOL_OPCODE_READ)) && !hdr.len) {
			LOG_ERR("Zero Payload size for opcode %d", hdr.opcode);
			goto exit;
		} else if ((hdr.opcode == ZVOL_OPCODE_SYNC) && hdr.len > 0) {
			LOG_ERR("Unexpected payload for opcode %d", hdr.opcode);
			goto exit;
		}

		zio_cmd = zio_cmd_alloc(&hdr, fd);
		/* Read payload for commands which have it */
		if (hdr.opcode == ZVOL_OPCODE_WRITE) {
			rc = uzfs_zvol_socket_read(fd, zio_cmd->buf, hdr.len);
			if (rc != 0) {
				zio_cmd_free(&zio_cmd);
				goto exit;
			}
		}

		/* Take refcount for uzfs_zvol_worker to work on it */
		uzfs_zinfo_take_refcnt(zinfo, B_FALSE);
		zio_cmd->zv = zinfo;
		taskq_dispatch(zinfo->uzfs_zvol_taskq, uzfs_zvol_worker,
		    zio_cmd, TQ_SLEEP);
	}
exit:
	if (zinfo != NULL) {
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
		while (zinfo->conn_closed && zinfo->is_io_ack_sender_created) {
			(void) pthread_mutex_unlock(&zinfo->zinfo_mutex);
			usleep(1000);
			(void) pthread_mutex_lock(&zinfo->zinfo_mutex);
		}
		(void) pthread_mutex_unlock(&zinfo->zinfo_mutex);
		uzfs_zinfo_drop_refcnt(zinfo, B_FALSE);
	}
	LOG_DEBUG("%s thread exiting", tinfo);
	zk_thread_exit();
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
	hdr.opcode = ZVOL_OPCODE_READ;
	hdr.io_seq = metadata->io_num;
	hdr.offset = offset;
	hdr.len = len;
	hdr.flags = ZVOL_OP_FLAG_REBUILD;
	hdr.status = ZVOL_OP_STATUS_OK;
	LOG_INFO("IO number for rebuild %ld", metadata->io_num);
	zio_cmd = zio_cmd_alloc(&hdr, warg->fd);
	/* Take refcount for uzfs_zvol_worker to work on it */
	uzfs_zinfo_take_refcnt(zinfo, B_FALSE);
	zio_cmd->zv = zinfo;

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
static void
uzfs_zvol_rebuild_scanner(void *arg)
{
	int		fd = (uintptr_t)arg;
	zvol_info_t	*zinfo = NULL;
	zvol_io_hdr_t	hdr;
	int 		rc = 0;
	zvol_rebuild_t  warg;
	char 		*name;
	blk_metadata_t	metadata;
	uint64_t	rebuild_req_offset;
	uint64_t	rebuild_req_len;
	zvol_io_cmd_t	*zio_cmd;

read_socket:
	rc = uzfs_zvol_read_header(fd, &hdr);
	if (rc != 0) {
		goto exit;
	}

	LOG_DEBUG("op_code=%d io_seq=%ld", hdr.opcode, hdr.io_seq);

	/* Handshake yet to happen */
	if ((hdr.opcode != ZVOL_OPCODE_HANDSHAKE) && (zinfo == NULL)) {
		rc = -1;
		goto exit;
	}
	switch (hdr.opcode) {
		case ZVOL_OPCODE_HANDSHAKE:
			name = kmem_alloc(hdr.len, KM_SLEEP);
			rc = uzfs_zvol_socket_read(fd, name, hdr.len);
			if (rc != 0) {
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

			rc = uzfs_get_io_diff(zinfo->zv, &metadata,
			    uzfs_zvol_rebuild_scanner_callback,
			    rebuild_req_offset, rebuild_req_len, &warg);
			if (rc != 0) {
				LOG_ERR("Rebuild scanning failed on zvol %s ",
				    "err(%d)", zinfo->name, rc);
				goto exit;
			}
			bzero(&hdr, sizeof (hdr));
			hdr.status = ZVOL_OP_STATUS_OK;
			hdr.version = REPLICA_VERSION;
			hdr.opcode = ZVOL_OPCODE_REBUILD_STEP_DONE;
			zio_cmd = zio_cmd_alloc(&hdr, fd);
			/* Take refcount for uzfs_zvol_worker to work on it */
			uzfs_zinfo_take_refcnt(zinfo, B_FALSE);
			zio_cmd->zv = zinfo;
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
		LOG_DEBUG("uzfs_zvol_rebuild_scanner thread for zvol %s "
		    "exiting", zinfo->name);
		remove_pending_cmds_to_ack(fd, zinfo);
		uzfs_zinfo_drop_refcnt(zinfo, B_FALSE);
	} else {
		LOG_DEBUG("uzfs_zvol_rebuild_scanner thread exiting");
	}

	shutdown(fd, SHUT_RDWR);
	close(fd);
	zk_thread_exit();
}

/*
 * One thread per replica. Responsible for accepting
 * IO connections. This thread will accept a connection
 * and spawn a new thread for each new connection req.
 */
static void
uzfs_zvol_io_conn_acceptor(void)
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

	io_sfd = rebuild_fd = efd = -1;
	flags = EPOLLIN | EPOLLET | EPOLLERR | EPOLLHUP | EPOLLRDHUP;
	/* Create IO connection acceptor fd first */
	io_sfd = create_and_bind(IO_SERVER_PORT, B_TRUE, B_TRUE);
	if (io_sfd == -1) {
		goto exit;
	}

	rc = listen(io_sfd, SOMAXCONN);
	if (rc == -1) {
		LOG_ERRNO("listen on IO FD in acceptor failed");
		goto exit;
	}

	rebuild_fd = create_and_bind(REBUILD_IO_SERVER_PORT, B_TRUE, B_TRUE);
	if (rebuild_fd == -1) {
		goto exit;
	}

	rc = listen(rebuild_fd, SOMAXCONN);
	if (rc == -1) {
		LOG_ERRNO("listen on rebuild FD in acceptor failed");
		goto exit;
	}

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
			if (!(events[i].events & EPOLLIN)) {
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
				goto exit;
			}
#ifdef DEBUG
			hbuf = kmem_alloc(sizeof (NI_MAXHOST), KM_SLEEP);
			sbuf = kmem_alloc(sizeof (NI_MAXSERV), KM_SLEEP);
			rc = getnameinfo(&in_addr, in_len, hbuf, sizeof (hbuf),
			    sbuf, sizeof (sbuf), NI_NUMERICHOST |
			    NI_NUMERICSERV);
			if (rc == 0) {
				LOG_DEBUG("Accepted connection from %s:%s",
				    hbuf, sbuf);
			}

			kmem_free(hbuf, sizeof (NI_MAXHOST));
			kmem_free(sbuf, sizeof (NI_MAXSERV));
#endif
			if (events[i].data.fd == io_sfd) {
				thrd_info = zk_thread_create(NULL, 0,
				    (thread_func_t)uzfs_zvol_io_receiver,
				    (void *)new_fd, 0, NULL, TS_RUN, 0,
				    PTHREAD_CREATE_DETACHED);
			} else {
				LOG_INFO("Connection req for rebuild");
				thrd_info = zk_thread_create(NULL, 0,
				    uzfs_zvol_rebuild_scanner,
				    (void *)new_fd, 0, NULL, TS_RUN, 0,
				    PTHREAD_CREATE_DETACHED);
			}
			VERIFY3P(thrd_info, !=, NULL);
		}
	}
exit:
	if (events != NULL)
		free(events);

	if (io_sfd != -1)
		close(io_sfd);

	if (rebuild_fd != -1)
		close(rebuild_fd);

	if (efd != -1)
		close(efd);

	LOG_DEBUG("uzfs_zvol_io_conn_acceptor thread exiting");
	zk_thread_exit();
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
		read_hdr.io_num = md->metadata.io_num;
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

	snprintf(tinfo, 50, "ack_sender_%lu", zinfo->zvol_guid);
	prctl(PR_SET_NAME, tinfo, 0, 0, 0);

	while (1) {
		int rc = 0;
		(void) pthread_mutex_lock(&zinfo->zinfo_mutex);
		zinfo->zio_cmd_in_ack = NULL;
		while (1) {
			if ((zinfo->state == ZVOL_INFO_STATE_OFFLINE) ||
			    (zinfo->conn_closed == B_TRUE)) {
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
				(void) pthread_mutex_lock(&zinfo->zinfo_mutex);
				goto exit;
			}
			zio_cmd_free(&zio_cmd);
			continue;
		}

		if (zio_cmd->hdr.opcode == ZVOL_OPCODE_READ) {
			if (zio_cmd->hdr.status == ZVOL_OP_STATUS_OK) {
				/* Send data read from disk */
				rc = uzfs_send_reads(zio_cmd->conn, zio_cmd);
				if (rc == -1) {
					zinfo->zio_cmd_in_ack = NULL;
					LOG_ERRNO("socket write err");
					if (zio_cmd->conn == fd) {
						zio_cmd_free(&zio_cmd);
						(void) pthread_mutex_lock(
						    &zinfo->zinfo_mutex);
						goto exit;
					}
				}
			}
			atomic_inc_64(&zinfo->read_req_ack_cnt);
		} else {
			if (zio_cmd->hdr.opcode == ZVOL_OPCODE_WRITE)
				atomic_inc_64(&zinfo->write_req_ack_cnt);
			else if (zio_cmd->hdr.opcode == ZVOL_OPCODE_SYNC)
				atomic_inc_64(&zinfo->sync_req_ack_cnt);
		}
		zinfo->zio_cmd_in_ack = NULL;
		zio_cmd_free(&zio_cmd);
	}
exit:
	zinfo->zio_cmd_in_ack = NULL;
	shutdown(fd, SHUT_RDWR);
	close(fd);
	while (!STAILQ_EMPTY(&zinfo->complete_queue)) {
		zio_cmd = STAILQ_FIRST(&zinfo->complete_queue);
		STAILQ_REMOVE_HEAD(&zinfo->complete_queue, cmd_link);
		zio_cmd_free(&zio_cmd);
	}
	zinfo->is_io_ack_sender_created = B_FALSE;
	(void) pthread_mutex_unlock(&zinfo->zinfo_mutex);
	uzfs_zinfo_drop_refcnt(zinfo, B_FALSE);

	LOG_DEBUG("%s thread exiting", tinfo);
	zk_thread_exit();
}

void
zrepl_svc_run(void)
{
	mgmt_conn_thread = zk_thread_create(NULL, 0,
	    (thread_func_t)uzfs_zvol_mgmt_thread, NULL, 0, NULL,
	    TS_RUN, 0, PTHREAD_CREATE_DETACHED);
	VERIFY3P(mgmt_conn_thread, !=, NULL);

	conn_accpt_thread = zk_thread_create(NULL, 0,
	    (thread_func_t)uzfs_zvol_io_conn_acceptor, NULL, 0, NULL, TS_RUN,
	    0, PTHREAD_CREATE_DETACHED);
	VERIFY3P(conn_accpt_thread, !=, NULL);

	uzfs_timer_thread = zk_thread_create(NULL, 0,
	    (thread_func_t)uzfs_zvol_timer_thread, NULL, 0, NULL, TS_RUN,
	    0, PTHREAD_CREATE_DETACHED);
	VERIFY3P(uzfs_timer_thread, !=, NULL);
}

/*
 * Print a stack trace before program exits.
 */
void
fatal_handler(int sig)
{
	void *array[20];
	size_t size;

	fprintf(stderr, "Fatal signal received: %d\n", sig);
	fprintf(stderr, "Stack trace:\n");

	size = backtrace(array, 20);
	backtrace_symbols_fd(array, size, STDERR_FILENO);

	/*
	 * Hand over the sig for default processing to system to generate
	 * a coredump
	 */
	signal(sig, SIG_DFL);
	kill(getpid(), sig);
}

/*
 * We would like to do a graceful shutdown here to avoid recovery actions
 * when pool is imported next time. However we don't want to call export
 * which does a bunch of other things which are not necessary (freeing
 * memory resources etc.), since we run in userspace.
 *
 * mutex_enter(&spa_namespace_lock);
 * while ((spa = spa_next(NULL)) != NULL) {
 *	strlcpy(spaname, spa_name(spa), sizeof (spaname));
 *	mutex_exit(&spa_namespace_lock);
 *	LOG_INFO("Exporting pool %s", spaname);
 *	spa_export(spaname, NULL, B_TRUE, B_FALSE);
 *	mutex_enter(&spa_namespace_lock);
 * }
 * mutex_exit(&spa_namespace_lock);
 *
 * For now we keep it simple and just exit.
 */
void
exit_handler(int sig)
{
	LOG_INFO("Caught SIGTERM. Exiting...");
	exit(0);
}

/*
 * Main function for replica.
 */
int
main(int argc, char **argv)
{
	int	rc;

	/* Use opt parsing lib if we have more options */
	zrepl_log_level = LOG_LEVEL_INFO;
	if (argc == 3 && strcmp(argv[1], "-l") == 0) {
		if (strcmp(argv[2], "debug") == 0)
			zrepl_log_level = LOG_LEVEL_DEBUG;
		else if (strcmp(argv[2], "info") == 0)
			zrepl_log_level = LOG_LEVEL_INFO;
		else if (strcmp(argv[2], "error") == 0)
			zrepl_log_level = LOG_LEVEL_ERR;
		else {
			fprintf(stderr, "Log level should be one of "
			    "\"debug\", \"info\" or \"error\"\n");
			return (-1);
		}
	}

	if (getenv("CONFIG_LOAD_DISABLE") != NULL) {
		LOG_INFO("disabled auto import (reading of zpool.cache)");
		zfs_autoimport_disable = 1;
	} else {
		LOG_INFO("auto importing pools by reading zpool.cache files");
		zfs_autoimport_disable = 0;
	}

	zinfo_create_hook = &zinfo_create_cb;
	zinfo_destroy_hook = &zinfo_destroy_cb;
	rc = uzfs_init();
	if (rc != 0) {
		LOG_ERR("initialization errored: %d", rc);
		return (-1);
	}

	/* Ignore SIGPIPE signal */
	signal(SIGPIPE, SIG_IGN);
	signal(SIGTERM, exit_handler);
	signal(SIGSEGV, fatal_handler);
	signal(SIGBUS, fatal_handler);
	signal(SIGILL, fatal_handler);

	if (libuzfs_ioctl_init() < 0) {
		LOG_ERR("Failed to initialize libuzfs ioctl");
		goto initialize_error;
	}

	zrepl_svc_run();
	while (1) {
		sleep(5);
	}

initialize_error:
	uzfs_fini();
	return (-1);
}
