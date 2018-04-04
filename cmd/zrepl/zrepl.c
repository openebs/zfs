#include <arpa/inet.h>
#include <netdb.h>

#include <syslog.h>
#include <libuzfs.h>
#include <libzfs.h>
#include <uzfs_mgmt.h>
#include <zrepl_mgmt.h>
#include <uzfs_io.h>
#include <sys/epoll.h>
#include <sys/types.h>
#include <ifaddrs.h>

#define	MAXEVENTS 64
#define	ZAP_UPDATE_TIME_INTERVAL 600

char *accpt_port = "3232";
char *mgmt_port = "12000";

extern unsigned long zfs_arc_max;
extern unsigned long zfs_arc_min;
extern int zfs_autoimport_disable;
__thread char  tinfo[20] =  {0};

static void uzfs_zvol_io_ack_sender(void *arg);
static int get_controller_ip_address(char *buf, int len);

kthread_t	*conn_accpt_thrd;
kthread_t	*uzfs_mgmt_thread;
kthread_t *uzfs_timer_thread;
char		*target_addr = NULL;
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


static int
make_socket_non_blocking(int sfd)
{
	int flags, s;

	flags = fcntl(sfd, F_GETFL, 0);
	if (flags == -1) {
		ZREPL_ERRLOG("fcntl() failed errno:%d\n", errno);
		return (-1);
	}

	flags |= O_NONBLOCK;
	s = fcntl(sfd, F_SETFL, flags);
	if (s == -1) {
		ZREPL_ERRLOG("fcntl() failed errno:%d\n", errno);
		return (-1);
	}
	return (0);
}

static int
uzfs_zvol_get_ip(char *host)
{
	struct ifaddrs *ifaddr, *ifa;
	int family, s, n;

	if (getifaddrs(&ifaddr) == -1) {
		ZREPL_ERRLOG("getifaddrs() failed errno:%d\n", errno);
		return (-1);
	}

	/*
	 * Walk through linked list, maintaining head
	 * pointer so we can free list later
	 */

	for (ifa = ifaddr, n = 0; ifa != NULL; ifa = ifa->ifa_next, n++) {
		if (ifa->ifa_addr == NULL) {
			continue;
		}

		family = ifa->ifa_addr->sa_family;

		if (family == AF_INET || family == AF_INET6) {
			s = getnameinfo(ifa->ifa_addr, (family == AF_INET) ?
			    sizeof (struct sockaddr_in) :
			    sizeof (struct sockaddr_in6),
			    host, NI_MAXHOST,
			    NULL, 0, NI_NUMERICHOST);
			if (s != 0) {
				ZREPL_ERRLOG("getnameinfo() failed: %d\n",
				    errno);
				s = -1;
				goto exit;
			}

			if (family == AF_INET) {
				if (strcmp(host, "127.0.0.1") == 0) {
					continue;
				}
				ZREPL_LOG("IP address: %s\n", host);
				break;
			}
		}
	}
exit:
	freeifaddrs(ifaddr);
	return (s);
}
/*
 * Allocate zio command along with
 * buffer needed for IO completion.
 */
static zvol_io_cmd_t *
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
static void
zio_cmd_free(zvol_io_cmd_t **cmd)
{
	zvol_io_cmd_t *zio_cmd = *cmd;
	zvol_op_code_t opcode = zio_cmd->hdr.opcode;
	switch (opcode) {
		case ZVOL_OPCODE_READ:
		case ZVOL_OPCODE_WRITE:
		case ZVOL_OPCODE_HANDSHAKE:
			if (zio_cmd->buf != NULL) {
				free(zio_cmd->buf);
			}
			break;
		default:
			VERIFY(!"Should be a valid opcode");
			break;
	}

	free(zio_cmd);
	*cmd = NULL;
}


static int
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


static inline int
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
	zvol_io_hdr_t 	*hdr = &zio_cmd->hdr;
	struct zvol_io_rw_hdr *write_hdr;
	char	*datap = (char *)zio_cmd->buf;
	size_t	data_offset = hdr->offset;
	size_t	remain = hdr->len;
	int	rc = 0;

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
		    write_hdr->len, &metadata, B_FALSE);
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
static void
uzfs_zvol_worker(void *arg)
{
	zvol_io_cmd_t	*zio_cmd;
	zvol_info_t	*zinfo;
	zvol_state_t	*zvol_state;
	zvol_io_hdr_t 	*hdr;
	metadata_desc_t	**metadata_desc;
	int		rc = 0;
	int 		write = 0;

	zio_cmd = (zvol_io_cmd_t *)arg;
	hdr = &zio_cmd->hdr;
	zinfo = zio_cmd->zv;
	zvol_state = zinfo->zv;
	/* If zvol hasn't passed rebuild phase we need the metadata */
	if (ZVOL_IS_REBUILDED(zvol_state)) {
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
			zinfo->checkpointed_io_seq =
			    zio_cmd->hdr.checkpointed_io_seq;
			break;

		case ZVOL_OPCODE_SYNC:
			break;

		default:
			VERIFY(!"Should be a valid opcode");
			break;
	}

	if (rc < 0) {
		ZREPL_ERRLOG("Zvol op_code :%d failed with "
		    "error: %d\n", hdr->opcode, errno);
		hdr->status = ZVOL_OP_STATUS_FAILED;
	} else {
		hdr->status = ZVOL_OP_STATUS_OK;
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
	uzfs_zinfo_drop_refcnt(zinfo, B_FALSE);
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
	free(arg);

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
			rc = uzfs_zvol_socket_read(fd, zio_cmd->buf,
			    (sizeof (char) * hdr.len));
			if (rc != 0) {
				zio_cmd_free(&zio_cmd);
				ZREPL_ERRLOG("Socket read failed with "
				    "error: %d\n", errno);
				goto exit;
			}
		}

		if (hdr.opcode == ZVOL_OPCODE_HANDSHAKE) {
			zinfo = uzfs_zinfo_lookup(zio_cmd->buf);
			zio_cmd_free(&zio_cmd);
			if (zinfo == NULL) {
				ZREPL_ERRLOG("Volume/LUN: %s not found",
				    zinfo->name);
				goto exit;
			}

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
	}

	ZREPL_LOG("uzfs_zvol_io_receiver thread exiting\n");
	zk_thread_exit();
}

/*
 * This function suppose to lookup into zvol list
 * to find if LUN presented for identification is
 * available/online or not. This function also need
 * to return IP address of replica along with port
 * so that ISTGT controller can open a connection
 * for IOs.
 */
static int
uzfs_zvol_mgmt_do_handshake(zvol_io_hdr_t *hdr, int sfd, char *name)
{
	int 		rc;
	zvol_info_t 	*zinfo = NULL;
	mgmt_ack_t 	mgmt_ack;

	printf("Volume: %s sent for enq\n", name);

	hdr->len = 0;
	hdr->version = REPLICA_VERSION;
	hdr->opcode = ZVOL_OPCODE_HANDSHAKE;

	bzero(&mgmt_ack, sizeof (mgmt_ack));
	strncpy(mgmt_ack.volname, name, sizeof (mgmt_ack.volname));
	mgmt_ack.port = atoi(accpt_port);
	rc = uzfs_zvol_get_ip(mgmt_ack.ip);

	if (rc == -1) {
		ZREPL_ERRLOG("Unable to get IP with err: %d\n", errno);
		hdr->status = ZVOL_OP_STATUS_FAILED;
	} else if ((zinfo = uzfs_zinfo_lookup(name)) == NULL) {
		ZREPL_ERRLOG("Unknown zvol: %s\n", name);
		hdr->status = ZVOL_OP_STATUS_FAILED;
	} else {
		hdr->status = ZVOL_OP_STATUS_OK;
		hdr->len = sizeof (mgmt_ack_t);
	}

	if (zinfo != NULL) {
		zvol_state_t *zv = zinfo->zv;
		uzfs_zvol_get_last_committed_io_no(zv,
		    &hdr->checkpointed_io_seq);
		mgmt_ack.pool_guid = spa_guid(zv->zv_spa);
		mgmt_ack.zvol_guid = dmu_objset_fsid_guid(zv->zv_objset);
		uzfs_zinfo_drop_refcnt(zinfo, B_FALSE);
	}

	rc = uzfs_zvol_socket_write(sfd, (char *)hdr, sizeof (*hdr));
	if (rc != 0) {
		ZREPL_ERRLOG("Write to socket failed with err: %d\n", errno);
		return (-1);
	}
	if (hdr->status != ZVOL_OP_STATUS_OK) {
		return (-1);
	}

	rc = uzfs_zvol_socket_write(sfd, (char *)&mgmt_ack, sizeof (mgmt_ack));
	if (rc != 0) {
		ZREPL_ERRLOG("Write to socket failed with err: %d\n", errno);
		rc = -1;
	}
	return (rc);
}

static int
uzfs_zvol_connect_to_tgt_controller(void *arg)
{
	char ip_buf[256];
	int sfd, rc;
	struct sockaddr_in istgt_addr;
	const char *target_addr = arg;

	if (target_addr == NULL) {
		if (get_controller_ip_address(ip_buf, sizeof (ip_buf)) != 0) {
			ZREPL_ERRLOG("parsing IP address did not work\n");
			return (-1);
		}
		target_addr = ip_buf;
	}

	ZREPL_LOG("iSCSI controller IP address is: %s\n", target_addr);
	bzero((char *)&istgt_addr, sizeof (istgt_addr));
	istgt_addr.sin_family = AF_INET;
	istgt_addr.sin_addr.s_addr = inet_addr(target_addr);
	istgt_addr.sin_port = htons(TARGET_PORT);
retry:
	sfd = create_and_bind(mgmt_port, B_FALSE);
	if (sfd == -1) {
		return (-1);
	}

	rc = connect(sfd, (struct sockaddr *)&istgt_addr, sizeof (istgt_addr));
	if (rc == -1) {
		close(sfd);
		sleep(2);
		printf("Retrying ....\n");
		goto retry;
	} else {
		ZREPL_LOG("Connection to iSCSI controller is successful\n");
	}
	return (sfd);
}

/*
 * TODO: This is throw away API. Side Car has to find
 * a better way to pass iSCSI Controller IP address.
 */
static int
get_controller_ip_address(char *buf, int len)
{
	size_t nbytes;

	FILE *fp = fopen("/var/openebs/controllers.conf", "r");
	if (fp == NULL) {
		printf("Error opening file\n");
		return (-1);
	}

	nbytes = fread(buf, sizeof (char), len, fp);

	if (nbytes <= 0) {
		printf("Read error\n");
		return (-1);
	}
	return (0);
}

/*
 * One thread per replica, which will be
 * responsible for initial handshake and
 * exchanging info like IP add, port etc.
 */
static void
uzfs_zvol_mgmt_thread(void *arg)
{
	int			rc;
	char			*buf;
	int			sfd = -1;
	zvol_io_hdr_t		hdr = {0, };

	sfd = uzfs_zvol_connect_to_tgt_controller(arg);
	if (sfd == -1) {
		goto exit;
	}

	while (1) {
		rc = uzfs_zvol_read_header(sfd, &hdr);
		if (rc < 0) {
			ZREPL_ERRLOG("Management connection "
			    "disconnected\n");
			/*
			 * Error has occurred on this socket
			 * close it and open a new socket after
			 * 5 sec of sleep.
			 */
close_conn:
			close(sfd);
			sfd = uzfs_zvol_connect_to_tgt_controller(arg);
			if (sfd == -1) {
				goto exit;
			}
			continue;
		} else if (rc > 0) {
			/* Send to target the correct version */
			hdr.version = REPLICA_VERSION;
			hdr.status = ZVOL_OP_STATUS_VERSION_MISMATCH;
			hdr.opcode = ZVOL_OPCODE_HANDSHAKE;
			hdr.len = 0;
			(void) uzfs_zvol_socket_write(sfd,
			    (char *)&hdr, sizeof (hdr));
			goto close_conn;
		}

		buf = kmem_alloc(hdr.len * sizeof (char), KM_SLEEP);
		rc = uzfs_zvol_socket_read(sfd, buf, hdr.len);
		if (rc != 0) {
			free(buf);
			goto close_conn;
		}

		switch (hdr.opcode) {
		case ZVOL_OPCODE_HANDSHAKE:
			rc = uzfs_zvol_mgmt_do_handshake(&hdr, sfd, buf);
			if (rc != 0) {
				ZREPL_ERRLOG("Handshake failed\n");
			}
			break;
		/* More management commands will come here in future */
		default:
			/* Command yet to be implemented */
			hdr.status = ZVOL_OP_STATUS_FAILED;
			hdr.len = 0;
			(void) uzfs_zvol_socket_write(sfd,
			    (char *)&hdr, sizeof (hdr));
			free(buf);
			goto close_conn;
			break; /* Should not be reached */
		}
		free(buf);
	}
exit:
	if (sfd < 0)
		close(sfd);
	ZREPL_LOG("uzfs_zvol_mgmt_thread thread exiting\n");
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
	int			sfd, efd;
	int			new_fd;
	int			rc, i, n;
	int			*thread_fd;
#ifdef DEBUG
	char			*hbuf;
	char			*sbuf;
#endif
	socklen_t		in_len;
	struct sockaddr		in_addr;
	struct epoll_event	event;
	struct epoll_event	*events = NULL;

	sfd = efd = -1;
	sfd = create_and_bind(accpt_port, B_TRUE);
	if (sfd == -1) {
		goto exit;
	}

	rc = make_socket_non_blocking(sfd);
	if (rc == -1) {
		goto exit;
	}

	rc = listen(sfd, SOMAXCONN);
	if (rc == -1) {
		ZREPL_ERRLOG("listen() failed with errno:%d\n", errno);
		goto exit;
	}

	efd = epoll_create1(0);
	if (efd == -1) {
		ZREPL_ERRLOG("epoll_create() failed with errno:%d\n", errno);
		goto exit;
	}

	event.data.fd = sfd;
	event.events = EPOLLIN | EPOLLET | EPOLLERR | EPOLLHUP | EPOLLRDHUP;
	rc = epoll_ctl(efd, EPOLL_CTL_ADD, sfd, &event);
	if (rc == -1) {
		ZREPL_ERRLOG("epoll_ctl() failed with errno:%d\n", errno);
		goto exit;
	}

	/* Buffer where events are returned */
	events = calloc(MAXEVENTS, sizeof (event));

	/* The event loop */
	while (1) {
		kthread_t *thrd_info;
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

			free(hbuf);
			free(sbuf);
#endif
			thread_fd = kmem_alloc(sizeof (int), KM_SLEEP);
			*thread_fd = new_fd;
			thrd_info = zk_thread_create(NULL, 0,
			    (thread_func_t)uzfs_zvol_io_receiver,
			    (void *)thread_fd, 0, NULL, TS_RUN, 0,
			    PTHREAD_CREATE_DETACHED);
			VERIFY3P(thrd_info, !=, NULL);
		}
	}
exit:
	if (events != NULL) {
		free(events);
	}

	if (sfd != -1) {
		close(sfd);
	}

	if (efd != -1) {
		close(efd);
	}

	ZREPL_ERRLOG("uzfs_zvol_io_conn_acceptor thread exiting\n");
	zk_thread_exit();
}

static void
uzfs_zvol_timer_thread(void)
{
	while (1) {
		sleep(ZAP_UPDATE_TIME_INTERVAL);
		printf("Event triggered by timer\n");
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
		rc = uzfs_zvol_socket_write(fd, zio_cmd->buf, hdr->len);
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
	md = zio_cmd->metadata_desc;
	while (md != NULL) {
		metadata_desc_t *md_tmp = md->next;
		kmem_free(md, sizeof (*md));
		md = md_tmp;
	}
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
	free(arg);
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

		ASSERT3P(zio_cmd->conn, ==, fd);
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
	uzfs_zinfo_drop_refcnt(zinfo, B_FALSE);

	ZREPL_LOG("uzfs_zvol_io_ack_sender thread exiting\n");
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

	fprintf(stdout, "import pool %s target addr %s\n", pool_name,
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

	conn_accpt_thrd = zk_thread_create(NULL, 0,
	    (thread_func_t)uzfs_zvol_io_conn_acceptor, NULL, 0, NULL, TS_RUN,
	    0, PTHREAD_CREATE_DETACHED);
	VERIFY3P(conn_accpt_thrd, !=, NULL);

	uzfs_mgmt_thread = zk_thread_create(NULL, 0,
	    (thread_func_t)uzfs_zvol_mgmt_thread, target_addr, 0, NULL,
	    TS_RUN, 0, PTHREAD_CREATE_DETACHED);
	VERIFY3P(uzfs_mgmt_thread, !=, NULL);

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
	const char	*cmd_name = NULL;

	if (argc < 2) {
		help();
		return (1);
	}

	cmd_name = argv[1];

	if ((rc = find_command(cmd_name, &i)) != 0) {
		help();
		return (1);
	}

	pthread_t slf = pthread_self();
	snprintf(tinfo, sizeof (tinfo), "m#%d.%d",
	    (int)(((uint64_t *)slf)[0]), getpid());

	if (getenv("CONFIG_LOAD_DISABLE") != NULL) {
		printf("disabled auto import (reading of zpool.cache)\n");
		zfs_autoimport_disable = 1;
	} else {
		printf("auto importing pools by reading zpool.cache files\n");
		zfs_autoimport_disable = 0;
	}

	rc = uzfs_init();
	uzfs_zrepl_open_log();
	if (rc != 0) {
		ZREPL_ERRLOG("initialization errored.. %d\n", rc);
		return (-1);
	}

	rc = pthread_mutex_init(&zvol_list_mutex, NULL);
	if (rc != 0) {
		ZREPL_ERRLOG("zvol_global mutex_init() failed\n");
		goto initialize_error;
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
