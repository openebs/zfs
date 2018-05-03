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
char 		*pool_name = NULL;
struct 		in_addr addr = {0};
int zrepl_import(int argc, char **argv);
int zrepl_start(int argc, char **argv);

typedef struct zrepl_command {
	const char *cmd_name;
	int (*func)(int, char **);
} zrepl_cmd_t;

static zrepl_cmd_t cmd_table[] = {
	{"import",	zrepl_import},
	{"start",	zrepl_start},
	{NULL},
};

#define	NCMDS   (sizeof (cmd_table) / sizeof (zrepl_cmd_t))

int
find_command(const char *cmd_name, int *index)
{
	for (int i = 0; i < NCMDS; i++) {
		if (cmd_table[i].cmd_name == NULL)
			continue;
		if (strcmp(cmd_name, cmd_table[i].cmd_name) == 0) {
			*index = i;
			return (0);
		}
	}
	return (1);
}

void
help(void)
{
	/*
	 * XXX need to do better here
	 */

	printf("zrepl command args ... \nwhere 'command' is one of:\n\n");
	printf("\t import <pool_name> [-t ip address)]\n");
	printf("\t start [-t ip address)]\n");
}

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
 * IO-Receiver would be per ZVOL, it would be
 * responsible for receiving IOs on given socket.
 */
static void
uzfs_zvol_io_receiver(void *arg)
{
	int		rc, fd;
	zvol_info_t	*zinfo = NULL;
	zvol_io_hdr_t	hdr;
	thread_args_t	*thrd_arg;
	zvol_io_cmd_t	*zio_cmd;
	kthread_t	*thrd_info;
	fd = *(int *)arg;
	kmem_free(arg, sizeof (int));

	prctl(PR_SET_NAME, "io_receiver", 0, 0, 0);

	while (1) {
		/*
		 * if we don't know the version yet, be more careful when
		 * reading header
		 */
		if (zinfo == NULL) {
			if (uzfs_zvol_read_header(fd, &hdr) != 0) {
				ZREPL_ERRLOG("error reading header"
				    " from socket\n");
				goto exit;
			}
			if (hdr.opcode != ZVOL_OPCODE_HANDSHAKE) {
				ZREPL_ERRLOG("Handshake yet to happen\n");
				goto exit;
			}
		} else {
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
		}

		ASSERT((hdr.opcode == ZVOL_OPCODE_WRITE) ||
		    (hdr.opcode == ZVOL_OPCODE_READ) ||
		    (hdr.opcode == ZVOL_OPCODE_HANDSHAKE) ||
		    (hdr.opcode == ZVOL_OPCODE_SYNC));
		if ((hdr.opcode != ZVOL_OPCODE_HANDSHAKE) &&
		    (zinfo == NULL)) {
			/*
			 * TODO: Stats need to be maintained for any
			 * such IO which came before handshake ?
			 */
			ZREPL_ERRLOG("Handshake yet to happen\n");
			continue;
		}

		zio_cmd = zio_cmd_alloc(&hdr, fd);
		if ((hdr.opcode == ZVOL_OPCODE_WRITE) ||
		    (hdr.opcode == ZVOL_OPCODE_HANDSHAKE)) {
			rc = uzfs_zvol_socket_read(fd, zio_cmd->buf, hdr.len);
			if (rc != 0) {
				zio_cmd_free(&zio_cmd);
				ZREPL_ERRLOG("Socket read failed with "
				    "error: %d\n", errno);
				goto exit;
			}
		}

		if (hdr.opcode == ZVOL_OPCODE_HANDSHAKE) {
			zinfo = uzfs_zinfo_lookup(zio_cmd->buf);
			if (zinfo == NULL) {
				ZREPL_ERRLOG("Volume/LUN: %s not found",
				    (char *)zio_cmd->buf);
				zio_cmd_free(&zio_cmd);
				goto exit;
			}

			zio_cmd_free(&zio_cmd);
			(void) pthread_mutex_lock(&zinfo->zinfo_mutex);
			if (zinfo->is_io_ack_sender_created) {
				ZREPL_ERRLOG("Multiple handshake on IO port "
				    "for volume: %s\n", zinfo->name);
				(void) pthread_mutex_unlock(
				    &zinfo->zinfo_mutex);
				uzfs_zinfo_drop_refcnt(zinfo, B_FALSE);
				close(fd);
				zinfo = NULL;
				goto exit;
			}

			thrd_arg = kmem_alloc(sizeof (thread_args_t), KM_SLEEP);
			thrd_arg->fd = fd;
			strlcpy(thrd_arg->zvol_name, zinfo->name, MAXNAMELEN);
			zinfo->conn_closed = B_FALSE;
			zinfo->is_io_ack_sender_created = B_TRUE;
			thrd_info = zk_thread_create(NULL, 0,
			    (thread_func_t)uzfs_zvol_io_ack_sender,
			    (void *)thrd_arg, 0, NULL, TS_RUN, 0,
			    PTHREAD_CREATE_DETACHED);
			VERIFY3P(thrd_info, !=, NULL);
			(void) pthread_mutex_unlock(&zinfo->zinfo_mutex);
			continue;
		}

		if (zio_cmd->hdr.opcode == ZVOL_OPCODE_WRITE) {
			(void) pthread_mutex_lock(&zinfo->zinfo_mutex);
			zinfo->running_io_seq = zio_cmd->hdr.io_seq;
			(void) pthread_mutex_unlock(&zinfo->zinfo_mutex);
		}

		/* Take refcount for uzfs_zvol_worker to work on it */
		uzfs_zinfo_take_refcnt(zinfo, B_FALSE);
		zio_cmd->zv = zinfo;
		taskq_dispatch(zinfo->uzfs_zvol_taskq, uzfs_zvol_worker,
		    zio_cmd, TQ_SLEEP);
	}
exit:
	if (zinfo != NULL) {
		ZREPL_LOG("uzfs_zvol_io_receiver thread exiting, volume:%s\n",
		    zinfo->name);
		(void) pthread_mutex_lock(&zinfo->zinfo_mutex);
		zinfo->conn_closed = B_TRUE;
		/*
		 * Send signal to ack sender so that it can free
		 * zio_cmd, close fd and exit.
		 */
		(void) pthread_mutex_lock(&zinfo->complete_queue_mutex);
		if (zinfo->io_ack_waiting) {
			rc = pthread_cond_signal(&zinfo->io_ack_cond);
		}
		(void) pthread_mutex_unlock(&zinfo->complete_queue_mutex);
		/*
		 * wait for ack thread to exit to avoid races with new
		 * connections for the same zinfo
		 */
		while (zinfo->is_io_ack_sender_created) {
			usleep(1000);
		}
		(void) pthread_mutex_unlock(&zinfo->zinfo_mutex);
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
	int		fd = -1;
	zvol_info_t	*zinfo = NULL;
	zvol_io_hdr_t	hdr;
	int 		rc = 0;
	zvol_rebuild_t  warg;
	char 		*name;
	blk_metadata_t	metadata;
	uint64_t	rebuild_req_offset;
	uint64_t	rebuild_req_len;
	zvol_io_cmd_t	*zio_cmd;

	fd = *(int *)arg;
	kmem_free(arg, sizeof (int));

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
				printf("Rebuild scanning failed\n");
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
	int			new_fd, rebuild_fd;
	int			rc, i, n;
	int			*thread_fd;
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
				ZREPL_LOG("Accepted connection on fd %d "
				"(host=%s, port=%s)\n", new_fd, hbuf, sbuf);
			}

			kmem_free(hbuf, sizeof (NI_MAXHOST));
			kmem_free(sbuf, sizeof (NI_MAXSERV));
#endif
			thread_fd = kmem_alloc(sizeof (int), KM_SLEEP);
			*thread_fd = new_fd;
			if (events[i].data.fd == io_sfd) {
				thrd_info = zk_thread_create(NULL, 0,
				    (thread_func_t)uzfs_zvol_io_receiver,
				    (void *)thread_fd, 0, NULL, TS_RUN, 0,
				    PTHREAD_CREATE_DETACHED);
			} else {
				ZREPL_ERRLOG("Connection req for rebuild\n");
				thrd_info = zk_thread_create(NULL, 0,
				    uzfs_zvol_rebuild_scanner,
				    (void *)thread_fd, 0, NULL, TS_RUN, 0,
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

static void
uzfs_zvol_timer_thread(void)
{
	prctl(PR_SET_NAME, "zvol_timer", 0, 0, 0);

	while (1) {
		sleep(ZAP_UPDATE_TIME_INTERVAL);
		uzfs_zinfo_update_io_seq_for_all_volumes();
	}
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
	zinfo = uzfs_zinfo_lookup(thrd_arg->zvol_name);
	kmem_free(arg, sizeof (thread_args_t));

	prctl(PR_SET_NAME, "ack_sender", 0, 0, 0);

	while (1) {
		int rc = 0;
		(void) pthread_mutex_lock(&zinfo->complete_queue_mutex);
		do {
			if (STAILQ_EMPTY(&zinfo->complete_queue)) {
				if ((zinfo->state == ZVOL_INFO_STATE_OFFLINE) ||
				    (zinfo->conn_closed == B_TRUE)) {
					(void) pthread_mutex_unlock(
					    &zinfo->complete_queue_mutex);
					goto exit;
				}
				zinfo->io_ack_waiting = 1;
				pthread_cond_wait(&zinfo->io_ack_cond,
				    &zinfo->complete_queue_mutex);
				zinfo->io_ack_waiting = 0;
			}
		} while (STAILQ_EMPTY(&zinfo->complete_queue));

		zio_cmd = STAILQ_FIRST(&zinfo->complete_queue);
		STAILQ_REMOVE_HEAD(&zinfo->complete_queue, cmd_link);
		(void) pthread_mutex_unlock(&zinfo->complete_queue_mutex);

		ZREPL_LOG("ACK for op:%d with seq-id %ld\n",
		    zio_cmd->hdr.opcode, zio_cmd->hdr.io_seq);

		/* account for space taken by metadata headers */
		if (zio_cmd->hdr.opcode == ZVOL_OPCODE_READ) {
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
			zio_cmd_free(&zio_cmd);
			goto exit;
		}

		switch (zio_cmd->hdr.opcode) {
			case ZVOL_OPCODE_HANDSHAKE:
			case ZVOL_OPCODE_WRITE:
			case ZVOL_OPCODE_SYNC:
			case ZVOL_OPCODE_REBUILD_STEP_DONE:
				zinfo->write_req_ack_cnt++;
				/* Send handsake ack */
				break;
			case ZVOL_OPCODE_READ:
				/* Send data read from disk */
				rc = uzfs_send_reads(zio_cmd->conn, zio_cmd);
				if (rc == -1) {
					ZREPL_ERRLOG("socket write err :%d\n",
					    errno);
					goto exit;
				}
				zinfo->read_req_ack_cnt++;
				break;

			default:
				VERIFY(!"Should be a valid opcode");
				break;
		}
		zio_cmd_free(&zio_cmd);
	}
exit:
	close(fd);
	while (!STAILQ_EMPTY(&zinfo->complete_queue)) {
		zio_cmd = STAILQ_FIRST(&zinfo->complete_queue);
		STAILQ_REMOVE_HEAD(&zinfo->complete_queue, cmd_link);
		zio_cmd_free(&zio_cmd);
	}
	zinfo->is_io_ack_sender_created = B_FALSE;
	ZREPL_LOG("uzfs_zvol_io_ack_sender thread exiting, volume:%s\n",
	    zinfo->name);
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

int
zrepl_import(int argc, char **argv)
{
	int c;
	nvlist_t	*config = NULL;
	importargs_t	importargs = {0};
	int		error;
	spa_t		*spa;
	nvlist_t	*props = NULL;

	argc -= optind;
	argv += optind;

	if (argc < 1) {
		help();
		return (1);
	}

	pool_name = argv[1];

	while ((c = getopt(argc, argv, "t:")) != -1) {
		switch (c) {
		case 't':
			if (inet_aton(optarg, &addr) == 0) {
				fprintf(stderr,
				    "Invalid target address\n");
				help();
				return (1);
			}
			target_addr = optarg;
			break;
		default:
			help();
			return (1);
		}
	}

	if (target_addr == NULL) {
		help();
		return (1);
	}

	fprintf(stdout, "import pool %s default target addr %s\n", pool_name,
	    target_addr);
	libzfs_handle_t *hdl = libzfs_init();

	importargs.scan = B_TRUE;
	importargs.cachefile = NULL;

	if ((error = zpool_tryimport(hdl, pool_name, &config, &importargs))
	    != 0) {
		fprintf(stderr, "cannot import pool:%s, %s\n", pool_name,
		    libzfs_error_description(hdl));
		libzfs_fini(hdl);
		return (1);
	}

	if ((error = spa_import(pool_name, config, props, ZFS_IMPORT_NORMAL))
	    != 0) {
		fprintf(stderr, "failed import %s\n", strerror(error));
		return (1);
	}

	libzfs_fini(hdl);

	if ((error = uzfs_open_pool(pool_name, &spa)) != 0) {
		fprintf(stderr, "spa open failed %s\n ", strerror(error));
		return (1);
	}

	return (0);
}

int
zrepl_start(int argc, char **argv)
{

	int c;

	while ((c = getopt(argc, argv, "t:")) != -1) {
		switch (c) {
		case 't':
			if (inet_aton(optarg, &addr) == 0) {
				fprintf(stderr, "Invalid target address\n");
				help();
				return (1);
			}
			target_addr = optarg;
			break;
		default:
			help();
			return (1);
		}
	}

	if (target_addr == NULL) {
		help();
		return (1);
	}

	return (0);
}

void
zrepl_svc_run(void)
{
	mgmt_conn_thread = zk_thread_create(NULL, 0,
	    (thread_func_t)uzfs_zvol_mgmt_thread, target_addr, 0, NULL,
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
	int	i = 0;
	const char *cmd_name = NULL;

	if (argc < 2) {
		help();
		return (1);
	}

	cmd_name = argv[1];

	if ((rc = find_command(cmd_name, &i)) != 0) {
		help();
		return (1);
	}

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

	if ((rc = cmd_table[i].func(argc, argv)) != 0)
		goto initialize_error;
	zrepl_svc_run();
	while (1) {
		sleep(5);
	}

initialize_error:
	uzfs_zrepl_close_log();
	uzfs_fini();
	return (-1);
}
