#include <arpa/inet.h>
#include <netdb.h>

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
	if (rc != 0) {
		ZREPL_ERRLOG("error reading from socket: %d\n", errno);
		return (-1);
	}
	if (hdr->version != REPLICA_VERSION) {
		ZREPL_ERRLOG("invalid replica protocol version %d\n",
		    hdr->version);
		return (1);
	}
	rc = uzfs_zvol_socket_read(fd,
	    ((char *)hdr) + sizeof (hdr->version),
	    sizeof (*hdr) - sizeof (hdr->version));
	if (rc != 0) {
		ZREPL_ERRLOG("error reading from socket: %d\n", errno);
		return (-1);
	}

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
	open_payload_t	open_pd;
	zvol_info_t	*zinfo = NULL;
	zvol_state_t	*zv;
	kthread_t	*thrd_info;
	thread_args_t 	*thrd_arg;

	/*
	 * If we don't know the version yet, be more careful when
	 * reading header
	 */
	if (uzfs_zvol_read_header(fd, &hdr) != 0) {
		ZREPL_ERRLOG("error reading open header\n");
		return (-1);
	}
	if (hdr.opcode != ZVOL_OPCODE_OPEN) {
		ZREPL_ERRLOG("Zvol must be opened first\n");
		return (-1);
	}
	if (hdr.len != sizeof (open_payload_t)) {
		ZREPL_ERRLOG("Invalid payload length for open\n");
		return (-1);
	}
	rc = uzfs_zvol_socket_read(fd, (char *)&open_pd, sizeof (open_pd));
	if (rc != 0) {
		ZREPL_ERRLOG("Payload read failed: %d\n", errno);
		return (-1);
	}

	open_pd.volname[MAX_NAME_LEN - 1] = '\0';
	zinfo = uzfs_zinfo_lookup(open_pd.volname);
	if (zinfo == NULL) {
		ZREPL_ERRLOG("zvol %s not found", open_pd.volname);
		hdr.status = ZVOL_OP_STATUS_FAILED;
		goto open_reply;
	}
	zv = zinfo->zv;
	ASSERT3P(zv, !=, NULL);
	if (zv->zv_metavolblocksize != 0 &&
	    zv->zv_metavolblocksize != open_pd.block_size) {
		ZREPL_ERRLOG("Conflicting block size");
		hdr.status = ZVOL_OP_STATUS_FAILED;
		goto open_reply;
	}
	// validate block size (only one bit is set in the number)
	if (open_pd.block_size == 0 ||
	    (open_pd.block_size & (open_pd.block_size - 1)) != 0) {
		ZREPL_ERRLOG("Invalid block size");
		hdr.status = ZVOL_OP_STATUS_FAILED;
		goto open_reply;
	}
	if (zinfo->timeout != 0 && zinfo->timeout != open_pd.timeout) {
		ZREPL_ERRLOG("Conflicting timeout value");
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
		ZREPL_ERRLOG("Failed to hold zvol during open\n");
		hdr.status = ZVOL_OP_STATUS_FAILED;
		goto open_reply;
	}
	if (uzfs_update_metadata_granularity(zv, open_pd.block_size) != 0) {
		(void) pthread_mutex_unlock(&zinfo->zinfo_mutex);
		ZREPL_ERRLOG("Failed to set granularity of metadata\n");
		hdr.status = ZVOL_OP_STATUS_FAILED;
		goto open_reply;
	}
	uzfs_update_ionum_interval(zinfo, open_pd.timeout);
	zinfo->timeout = open_pd.timeout;
	*zinfopp = zinfo;

	if (!zinfo->is_io_ack_sender_created) {
		thrd_arg = kmem_alloc(sizeof (thread_args_t), KM_SLEEP);
		thrd_arg->fd = fd;
		thrd_arg->zinfo = zinfo;
		uzfs_zinfo_take_refcnt(zinfo, B_FALSE);
		zinfo->conn_closed = B_FALSE;
		zinfo->is_io_ack_sender_created = B_TRUE;
		thrd_info = zk_thread_create(NULL, 0,
		    (thread_func_t)uzfs_zvol_io_ack_sender,
		    (void *)thrd_arg, 0, NULL, TS_RUN, 0,
		    PTHREAD_CREATE_DETACHED);
		VERIFY3P(thrd_info, !=, NULL);
	}
	(void) pthread_mutex_unlock(&zinfo->zinfo_mutex);

	hdr.status = ZVOL_OP_STATUS_OK;

open_reply:
	hdr.len = 0;
	rc = uzfs_zvol_socket_write(fd, (char *)&hdr, sizeof (hdr));
	if (rc == -1)
		ZREPL_ERRLOG("failed to send reply for open request\n");
	if (hdr.status != ZVOL_OP_STATUS_OK) {
		if (zinfo != NULL)
			uzfs_zinfo_drop_refcnt(zinfo, B_TRUE);
		return (-1);
	}
	return (0);
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

	prctl(PR_SET_NAME, "io_receiver", 0, 0, 0);

	/* First command should be OPEN */
	while (zinfo == NULL) {
		if (open_zvol(fd, &zinfo) != 0)
			goto exit;
	}

	while (1) {
		rc = uzfs_zvol_socket_read(fd, (char *)&hdr,
		    sizeof (hdr));
		if (rc != 0) {
			ZREPL_ERRLOG("error reading from socket: %d\n",
			    errno);
			goto exit;
		}
		if (hdr.opcode != ZVOL_OPCODE_WRITE &&
		    hdr.opcode != ZVOL_OPCODE_READ &&
		    hdr.opcode != ZVOL_OPCODE_SYNC) {
			ZREPL_ERRLOG("Unexpected opcode %d\n",
			    hdr.opcode);
			goto exit;
		}

		zio_cmd = zio_cmd_alloc(&hdr, fd);
		/* Read payload for commands which have it */
		if (hdr.opcode == ZVOL_OPCODE_WRITE) {
			rc = uzfs_zvol_socket_read(fd, zio_cmd->buf, hdr.len);
			if (rc != 0) {
				zio_cmd_free(&zio_cmd);
				ZREPL_ERRLOG("Socket read failed with "
				    "error: %d\n", errno);
				goto exit;
			}
		} else if (hdr.opcode != ZVOL_OPCODE_READ && hdr.len > 0) {
			ZREPL_ERRLOG("Unexpected payload for opcode %d\n",
			    hdr.opcode);
			zio_cmd_free(&zio_cmd);
			goto exit;
		}

		/* Take refcount for uzfs_zvol_worker to work on it */
		uzfs_zinfo_take_refcnt(zinfo, B_FALSE);
		zio_cmd->zv = zinfo;
		taskq_dispatch(zinfo->uzfs_zvol_taskq, uzfs_zvol_worker,
		    zio_cmd, TQ_SLEEP);
	}
exit:
	if (zinfo != NULL) {
		ZREPL_LOG("uzfs_zvol_io_receiver thread exiting, volume: %s\n",
		    zinfo->name);
		(void) pthread_mutex_lock(&zinfo->zinfo_mutex);
		zinfo->conn_closed = B_TRUE;
		/*
		 * Send signal to ack sender so that it can free
		 * zio_cmd, close fd and exit.
		 */
		if (zinfo->io_ack_waiting) {
			rc = pthread_cond_signal(&zinfo->io_ack_cond);
		}
		(void) pthread_mutex_unlock(&zinfo->zinfo_mutex);
		/*
		 * wait for ack thread to exit to avoid races with new
		 * connections for the same zinfo
		 */
		while (zinfo->is_io_ack_sender_created) {
			usleep(1000);
		}
		uzfs_zinfo_drop_refcnt(zinfo, B_FALSE);
	} else {
		ZREPL_LOG("uzfs_zvol_io_receiver thread exiting\n");
	}
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
	printf("IO number for rebuild %ld\n", metadata->io_num);
	zio_cmd = zio_cmd_alloc(&hdr, warg->fd);
	/* Take refcount for uzfs_zvol_worker to work on it */
	uzfs_zinfo_take_refcnt(zinfo, B_FALSE);
	zio_cmd->zv = zinfo;
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

	printf("op_code=%d io_seq=%ld\n", hdr.opcode, hdr.io_seq);

	/* Handshake yet to happen */
	if ((hdr.opcode != ZVOL_OPCODE_HANDSHAKE) && (zinfo == NULL)) {
		goto exit;
	}
	switch (hdr.opcode) {

		case ZVOL_OPCODE_HANDSHAKE:
			name = kmem_alloc(hdr.len, KM_SLEEP);
			rc = uzfs_zvol_socket_read(fd, name, hdr.len);
			if (rc != 0) {
				kmem_free(name, hdr.len);
				ZREPL_ERRLOG("Socket read error: %d\n", errno);
				goto exit;
			}

			/* Handshake already happened */
			if (zinfo != NULL) {
				ZREPL_ERRLOG("Again handshake request on "
				    "<fd:%d - volume:%s> for volume:%s \n",
				    fd, zinfo->name, name);
				kmem_free(name, hdr.len);
				goto exit;
			}

			zinfo = uzfs_zinfo_lookup(name);
			if (zinfo == NULL) {
				ZREPL_ERRLOG("Volume/LUN: %s not found", name);
				kmem_free(name, hdr.len);
				goto exit;
			}

			ZREPL_ERRLOG("Rebuild scanner started on volume:%s\n",
			    name);
			kmem_free(name, hdr.len);
			warg.zinfo = zinfo;
			warg.fd = fd;
			goto read_socket;
			break;

		case ZVOL_OPCODE_REBUILD_STEP:

			metadata.io_num = hdr.checkpointed_io_seq;
			rebuild_req_offset = hdr.offset;
			rebuild_req_len = hdr.len;

			ZREPL_LOG("Checkpointed IO_seq: %ld, "
			    "Rebuild Req offset:%ld, Rebuild Req length:%ld\n",
			    metadata.io_num, rebuild_req_offset,
			    rebuild_req_len);

			rc = uzfs_get_io_diff(zinfo->zv, &metadata,
			    uzfs_zvol_rebuild_scanner_callback,
			    rebuild_req_offset, rebuild_req_len, &warg);
			if (rc != 0) {
				ZREPL_ERRLOG("Rebuild scanning failed on "
				    "Volume:%s\n", zinfo->name);
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
			goto read_socket;
			break;

		case ZVOL_OPCODE_REBUILD_COMPLETE:
			ZREPL_LOG("Rebuild process is over on Replica:%s\n",
			    zinfo->name);
			goto exit;
			break;

		default:
			ZREPL_LOG("Wrong opcode:%d\n", hdr.opcode);
			goto exit;
			break;
	}

exit:
	if (zinfo != NULL) {
		ZREPL_LOG("uzfs_zvol_rebuild_scanner thread exiting,"
		    " volume:%s\n", zinfo->name);
		uzfs_zinfo_drop_refcnt(zinfo, B_FALSE);
	} else {
		printf("uzfs_zvol_rebuild_scanner thread exiting\n");
	}

	if (fd != -1)
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
		ZREPL_ERRLOG("listen() on IO_SFD failed with errno:%d\n",
		    errno);
		goto exit;
	}

	rebuild_fd = create_and_bind(REBUILD_IO_SERVER_PORT, B_TRUE, B_TRUE);
	if (rebuild_fd == -1) {
		goto exit;
	}

	rc = listen(rebuild_fd, SOMAXCONN);
	if (rc == -1) {
		ZREPL_ERRLOG("listen() on REBUILD_FD failed with errno:%d\n",
		    errno);
		goto exit;
	}

	efd = epoll_create1(0);
	if (efd == -1) {
		ZREPL_ERRLOG("epoll_create() failed with errno:%d\n", errno);
		goto exit;
	}

	event.data.fd = io_sfd;
	event.events = flags;
	rc = epoll_ctl(efd, EPOLL_CTL_ADD, io_sfd, &event);
	if (rc == -1) {
		ZREPL_ERRLOG("epoll_ctl() for IO_SFD failed with errno:%d\n",
		    errno);
		goto exit;
	}

	event.data.fd = rebuild_fd;
	event.events = flags;
	rc = epoll_ctl(efd, EPOLL_CTL_ADD, rebuild_fd, &event);
	if (rc == -1) {
		ZREPL_ERRLOG("epoll_ctl() for REBUILD_FD failed with "
		    "errno:%d\n", errno);
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
				ZREPL_ERRLOG("epoll err() :%d\n", errno);
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
				ZREPL_ERRLOG("accept err() :%d\n", errno);
				goto exit;
			}
#ifdef DEBUG
			hbuf = kmem_alloc(sizeof (NI_MAXHOST), KM_SLEEP);
			sbuf = kmem_alloc(sizeof (NI_MAXSERV), KM_SLEEP);
			rc = getnameinfo(&in_addr, in_len, hbuf, sizeof (hbuf),
			    sbuf, sizeof (sbuf), NI_NUMERICHOST |
			    NI_NUMERICSERV);
			if (rc == 0) {
				ZREPL_LOG("Accepted connection on fd %ld "
				"(host=%s, port=%s)\n", new_fd, hbuf, sbuf);
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
				ZREPL_ERRLOG("Connection req for rebuild\n");
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

	ZREPL_ERRLOG("uzfs_zvol_io_conn_acceptor thread exiting\n");
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

	while (1) {
		int rc = 0;
		(void) pthread_mutex_lock(&zinfo->zinfo_mutex);
		while (STAILQ_EMPTY(&zinfo->complete_queue)) {

			if ((zinfo->state == ZVOL_INFO_STATE_OFFLINE) ||
			    (zinfo->conn_closed == B_TRUE)) {
				goto exit;
			}
			zinfo->io_ack_waiting = 1;
			pthread_cond_wait(&zinfo->io_ack_cond,
			    &zinfo->zinfo_mutex);
			zinfo->io_ack_waiting = 0;
		}

		zio_cmd = STAILQ_FIRST(&zinfo->complete_queue);
		STAILQ_REMOVE_HEAD(&zinfo->complete_queue, cmd_link);
		(void) pthread_mutex_unlock(&zinfo->zinfo_mutex);

		ZREPL_LOG("ACK for op:%d with seq-id %ld\n",
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
			ZREPL_ERRLOG("socket write err :%d\n", errno);
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
					ZREPL_ERRLOG("socket write err :%d\n",
					    errno);
					if (zio_cmd->conn == fd) {
						(void) pthread_mutex_lock(
						    &zinfo->zinfo_mutex);
						goto exit;
					}
				}
			}
			zinfo->read_req_ack_cnt++;
		} else {
			zinfo->write_req_ack_cnt++;
		}
		zio_cmd_free(&zio_cmd);
	}
exit:
	ZREPL_LOG("uzfs_zvol_io_ack_sender thread exiting, volume:%s\n",
	    zinfo->name);

	close(fd);
	while (!STAILQ_EMPTY(&zinfo->complete_queue)) {
		zio_cmd = STAILQ_FIRST(&zinfo->complete_queue);
		STAILQ_REMOVE_HEAD(&zinfo->complete_queue, cmd_link);
		zio_cmd_free(&zio_cmd);
	}
	zinfo->is_io_ack_sender_created = B_FALSE;
	(void) pthread_mutex_unlock(&zinfo->zinfo_mutex);
	uzfs_zinfo_drop_refcnt(zinfo, B_FALSE);

	zk_thread_exit();
}

static void
uzfs_zrepl_open_log(void)
{
	openlog("zrepl", LOG_PID, LOG_LOCAL7);
}

static void
uzfs_zrepl_close_log(void)
{
	closelog();
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
 * Main function for replica.
 */
int
main(int argc, char **argv)
{

	int	rc;

	if (getenv("CONFIG_LOAD_DISABLE") != NULL) {
		printf("disabled auto import (reading of zpool.cache)\n");
		zfs_autoimport_disable = 1;
	} else {
		printf("auto importing pools by reading zpool.cache files\n");
		zfs_autoimport_disable = 0;
	}

	zinfo_create_hook = &zinfo_create_cb;
	zinfo_destroy_hook = &zinfo_destroy_cb;
	rc = uzfs_init();
	uzfs_zrepl_open_log();
	if (rc != 0) {
		ZREPL_ERRLOG("initialization errored.. %d\n", rc);
		return (-1);
	}

	/* Ignore SIGPIPE signal */
	signal(SIGPIPE, SIG_IGN);
	if (libuzfs_ioctl_init() < 0) {
		ZREPL_ERRLOG("Failed to initialize libuzfs ioctl\n");
		goto initialize_error;
	}

	zrepl_svc_run();
	while (1) {
		sleep(5);
	}

initialize_error:
	uzfs_zrepl_close_log();
	uzfs_fini();
	return (-1);
}
