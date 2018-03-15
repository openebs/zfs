
#include <arpa/inet.h>
#include <netdb.h>

#include <syslog.h>
#include <libuzfs.h>
#include <uzfs_mgmt.h>
#include <zrepl_mgmt.h>
#include <uzfs_io.h>
#include <sys/epoll.h>
#include <sys/types.h>
#include <ifaddrs.h>


#define	true 1
#define	false 0
#define	MAXEVENTS 64

char *accpt_port = "3232";
char *mgmt_port = "12000";

extern unsigned long zfs_arc_max;
extern unsigned long zfs_arc_min;

__thread char  tinfo[20] =  {0};

static void uzfs_zvol_io_ack_sender(void *arg);

static int
create_and_bind(const char *port, int bind_needed)
{
	int s, sfd;
	struct addrinfo hints = {0, };
	struct addrinfo *rp, *result = NULL;

	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;

	s = getaddrinfo(NULL, port, &hints, &result);
	if (s != 0) {
		ZREPL_ERRLOG("getaddrinfo failed with error: %d\n", errno);
		return (-1);
	}

	for (rp = result; rp != NULL; rp = rp->ai_next) {
		sfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if (sfd == -1) {
			continue;
		} else if (bind_needed == 0) {
			break;
		}

		s = bind(sfd, rp->ai_addr, rp->ai_addrlen);
		if (s == 0) {
			/* We managed to bind successfully! */
			ZREPL_LOG("bind is successful\n");
			break;
		}
		close(sfd);
	}

	freeaddrinfo(result);
	if (rp == NULL) {
		ZREPL_ERRLOG("bind failed with err:%d\n", errno);
		return (-1);
	}

	return (sfd);
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
				printf("IP address: %s\n", host);
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
			ASSERT(!"Wrong Op code");
			break;
	}

	free(zio_cmd);
	*cmd = NULL;
}


static int
uzfs_zvol_socket_read(int fd, char *buf, uint64_t nbytes)
{
	uint64_t count = 0;
	char *p = buf;
	ZREPL_ERRLOG("Trying to read nbytes: %lu\n", nbytes);
	while (nbytes) {
		count = read(fd, (void *)p, nbytes);
		if ((count <= 0) && (errno == EAGAIN)) {
			continue;
		} else if (count <= 0) {
			printf("Read error\n");
			return (-1);
		}

		ZREPL_ERRLOG("In read count:%lu nbytes: %lu\n", count, nbytes);
		p += count;
		nbytes -= count;
	}
	ZREPL_LOG("Successful read count:%lu nbytes: %lu\n", count, nbytes);
	return (1);
}


static inline int
uzfs_zvol_socket_write(int fd, char *buf, int nbytes)
{
	int count = 0;
	char *p = buf;
	while (nbytes) {
		count = write(fd, (void *)p, nbytes);
		if (count <= 0) {
			printf("Write error\n");
			return (-1);
		}
		p += count;
		nbytes -= count;
	}
	return (0);
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
	zvol_io_hdr_t 	*hdr;
	int		rc = 0;
	int 		write = 0;


	zio_cmd = (zvol_io_cmd_t *)arg;
	hdr = &zio_cmd->hdr;
	zinfo = zio_cmd->zv;
	ASSERT(zinfo);
	switch (hdr->opcode) {
		case ZVOL_OPCODE_READ:
			rc = uzfs_read_data(zinfo->zv,
			    (char *)zio_cmd->buf,
			    hdr->offset, hdr->len, NULL, NULL);
			break;

		case ZVOL_OPCODE_WRITE:
			write = 1;
			rc = uzfs_write_data(zinfo->zv,
			    (char *)zio_cmd->buf,
			    hdr->offset, hdr->len, NULL);
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
		ZREPL_LOG("Zvol io_seq:%ld op_code :%d passed\n",
		    hdr->io_seq, hdr->opcode);
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
	uzfs_zinfo_drop_refcnt(zinfo, false);
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
	int 		count = 0;
	kthread_t	*thrd_info;
	fd = *(int *)arg;
	free(arg);

	while (1) {
		count = uzfs_zvol_socket_read(fd, (char *)&hdr, sizeof (hdr));
		if (count <= 0) {
			printf("error has come on socket"
			    " with error %d\n", errno);
			goto exit;
		}

		printf("op_code=%d io_seq=%ld offset=%ld len=%ld\n", hdr.opcode,
		    hdr.io_seq, hdr.offset, hdr.len);

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
			count = uzfs_zvol_socket_read(fd, zio_cmd->buf,
			    (sizeof (char) * hdr.len));
			if (count <= 0) {
				zio_cmd_free(&zio_cmd);
				ZREPL_ERRLOG("Socket read failed with "
				    "error: %d\n", errno);
				goto exit;
			}
		}

		ZREPL_LOG("Count:%d Size: %ld\n", count, hdr.len);
		if (hdr.opcode == ZVOL_OPCODE_HANDSHAKE) {
			zinfo = uzfs_zinfo_lookup(zio_cmd->buf);
			zio_cmd_free(&zio_cmd);
			if (zinfo == NULL) {
				ZREPL_ERRLOG("Volume/LUN: %s not found",
				    zinfo->name);
				printf("Error in getting zinfo\n");
				goto exit;
			}

			ASSERT(!zinfo->is_io_ack_sender_created);
			if (zinfo->is_io_ack_sender_created) {
				ZREPL_ERRLOG("Multiple handshake on IO port "
				    "for volume: %s\n", zinfo->name);
				uzfs_zinfo_drop_refcnt(zinfo, false);
				continue;
			}

			(void) pthread_mutex_lock(&zinfo->zinfo_mutex);
			if (!zinfo->is_io_ack_sender_created) {
				thrd_arg = kmem_alloc(
				    sizeof (thread_args_t), KM_SLEEP);
				thrd_arg->fd = fd;
				strlcpy(thrd_arg->zvol_name, zinfo->name,
				    MAXNAMELEN);
				thrd_info = zk_thread_create(NULL, 0,
				    (thread_func_t)uzfs_zvol_io_ack_sender,
				    (void *)thrd_arg, 0, NULL, TS_RUN, 0,
				    PTHREAD_CREATE_DETACHED);
				VERIFY3P(thrd_info, !=, NULL);
				zinfo->is_io_ack_sender_created = 1;
				zinfo->conn_closed = false;
			}
			(void) pthread_mutex_unlock(&zinfo->zinfo_mutex);
			continue;
		}
		// printf("Enqueuing op_code=%d io_seq=%ld offset=%ld\n",
		//    hdr.opcode, hdr.io_seq, hdr.offset);

		/* Take refcount for uzfs_zvol_worker to work on it */
		uzfs_zinfo_take_refcnt(zinfo, false);
		zio_cmd->zv = zinfo;
		taskq_dispatch(zinfo->uzfs_zvol_taskq, uzfs_zvol_worker,
		    zio_cmd, TQ_SLEEP);
	}
exit:
	if (zinfo != NULL) {

		(void) pthread_mutex_lock(&zinfo->zinfo_mutex);
		zinfo->conn_closed = true;
		zinfo->is_io_ack_sender_created = 0;
		(void) pthread_mutex_unlock(&zinfo->zinfo_mutex);
		/*
		 * Send signal to ack sender so that it can free
		 * zio_cmd, close fd and exit.
		 */
		(void) pthread_mutex_lock(&zinfo->complete_queue_mutex);
		if (zinfo->io_ack_waiting) {
			rc = pthread_cond_signal(&zinfo->io_ack_cond);
		}
		(void) pthread_mutex_unlock(&zinfo->complete_queue_mutex);
		uzfs_zinfo_drop_refcnt(zinfo, false);
	}

	printf("uzfs_zvol_io_receiver thread exiting\n");
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
	int 		count, rc = 0;
	zvol_info_t 	*zinfo;
	mgmt_ack_t 	mgmt_ack;
	char 		*packet = NULL;
	char 		*p = NULL;

	printf("Volume: %s sent for enq\n", name);
	zinfo = uzfs_zinfo_lookup(name);
	/*
	 * XXX if anything in this function fails we should not send any
	 * payload at all - just a header with failed status.
	 */
	if (zinfo == NULL) {
		hdr->status = ZVOL_OP_STATUS_FAILED;
	} else {
		hdr->status = ZVOL_OP_STATUS_OK;
	}
	hdr->len = sizeof (mgmt_ack_t);

	bzero(&mgmt_ack, sizeof (mgmt_ack));
	strncpy(mgmt_ack.volname, name, strlen(name));
	mgmt_ack.port = atoi(accpt_port);
	rc = uzfs_zvol_get_ip(mgmt_ack.ip);
	if (rc == -1) {
		hdr->status = ZVOL_OP_STATUS_FAILED;
		ZREPL_ERRLOG("Unable to get IP"
		    " with err:%d\n", errno);
	}

	packet = kmem_alloc((sizeof (mgmt_ack_t) + sizeof (*hdr)) *
	    sizeof (char), KM_SLEEP);
	bcopy(hdr, packet, sizeof (*hdr));
	p = packet + sizeof (*hdr);
	bcopy(&mgmt_ack, p, sizeof (mgmt_ack));
	count = write(sfd, packet, (sizeof (*hdr) + sizeof (mgmt_ack_t)));
	if (count == -1) {
		ZREPL_ERRLOG("Write to socket failed"
		    " with err:%d\n", errno);
		rc = -1;
	}
	if (packet != NULL)
		free(packet);
	if (zinfo != NULL)
		uzfs_zinfo_drop_refcnt(zinfo, false);
	return (rc);
}

/*
 * TODO: IMHO, this should be a through away API.
 * Side Car has to find a more smart way to pass
 * ISCSI Controller IP address.
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
	const char *target_addr = arg;
	char buf[256];
	int sfd, rc, count;
	struct sockaddr_in istgt_addr;
	zvol_io_hdr_t hdr = {0, };
	char *name = NULL;


	sfd = create_and_bind(mgmt_port, false);
	if (sfd == -1) {
		goto exit;
	}

	if (target_addr == NULL) {
		if (get_controller_ip_address(buf, sizeof (buf)) != 0) {
			printf("parsing IP address did not work\n");
			goto exit;
		}
		target_addr = buf;
	}

	printf("Controller IP address is: %s\n", target_addr);
	bzero((char *)&istgt_addr, sizeof (istgt_addr));
	istgt_addr.sin_family = AF_INET;
	istgt_addr.sin_addr.s_addr = inet_addr(target_addr);
	istgt_addr.sin_port = htons(TARGET_PORT);
retry:
	rc = connect(sfd, (struct sockaddr *)&istgt_addr, sizeof (istgt_addr));
	if ((rc == -1) && ((errno == EINTR) || (errno == ECONNREFUSED) ||
	    (errno == ETIMEDOUT) || (errno == EINPROGRESS))) {
		ZREPL_ERRLOG("Failed to connect to istgt_controller"
		    " with err:%d\n", errno);
		sleep(2);
		printf("Retrying ....\n");
		goto retry;
	} else {
		printf("Connection to TGT controller successful\n");
		ZREPL_LOG("Connection to TGT controller iss successful\n");
	}

	while (1) {
		bzero(&hdr, sizeof (hdr));
		count = read(sfd, (char *)&hdr, sizeof (hdr));
		if (count <= 0) {
			ZREPL_ERRLOG("Replica-iSCSI Tgt connection got "
			    "disconnected with err:%d\n", errno);
			/*
			 * Error has occurred on this socket
			 * close it and open a new socket after
			 * 5 sec of sleep.
			 */
			close(sfd);
			printf("Retrying ....\n");
			sleep(5);
			sfd = create_and_bind(mgmt_port, false);
			if (sfd == -1) {
				goto exit;
			}

retry1:
			rc = connect(sfd, (struct sockaddr *)&istgt_addr,
			    sizeof (istgt_addr));
			if ((rc == -1) && ((errno == EINTR) ||
			    (errno == ECONNREFUSED) || (errno == ETIMEDOUT))) {
				ZREPL_ERRLOG("Failed to connect to"
				    " istgt_controller with err:%d\n",
				    errno);
				sleep(2);
				goto retry1;
			} else {
				printf("Connection to TGT controller "
				    "successful\n");
				ZREPL_LOG("Connection to TGT controller"
				    "is successful\n");
			}
			continue;
		}

		if (hdr.opcode == ZVOL_OPCODE_HANDSHAKE) {
			name = kmem_alloc(
			    hdr.len * sizeof (char), KM_SLEEP);
			count = read(sfd, name, sizeof (char) * hdr.len);
			if (count == -1) {
				ZREPL_ERRLOG("Read from socket failed"
				    " with err:%d\n", errno);
				goto exit;
			}

			rc = uzfs_zvol_mgmt_do_handshake(&hdr, sfd, name);
			free(name);
			if (rc == -1) {
				ZREPL_ERRLOG("handshake failed with"
				    " errno:%d\n", errno);
				goto exit;
			}
		}
	}
exit:
	printf("uzfs_zvol_mgmt_thread thread exiting\n");
	zk_thread_exit();
}
#if 0
/*
 * One thread per replica, which will be
 * responsible for initial handshake and
 * exchanging info like IP add, port etc.
 */
static void
uzfs_zvol_mgmt_thread(void *arg)
{

	int sfd, efd, rc, count;
	struct epoll_event event;
	struct sockaddr_in istgt_addr;
	zvol_io_hdr_t hdr = {0, };
	struct epoll_event *events = NULL;
	char *name = NULL;
	char *buf = NULL;


	sfd = create_and_bind(mgmt_port, false);
	if (sfd == -1) {
		goto exit;
	}

	rc = make_socket_non_blocking(sfd);
	if (rc == -1) {
		goto exit;
	}

	buf = get_controller_ip_address();
	if (buf == NULL) {
		printf("parsing IP address did not work\n");
		goto exit;
	}
	printf("Controller IP address is: %s", buf);
	bzero((char *)&istgt_addr, sizeof (istgt_addr));
	istgt_addr.sin_family = AF_INET;
	istgt_addr.sin_addr.s_addr = inet_addr(buf);
	istgt_addr.sin_port = htons(6060);
	free(buf);
retry:
	rc = connect(sfd, (struct sockaddr *)&istgt_addr, sizeof (istgt_addr));
	if ((rc == -1) && (errno == EINTR)) {
		ZREPL_ERRLOG("Failed to connect to istgt_controller"
		    " with err:%d\n", errno);
		sleep(10);
		goto retry;
	} else {
		printf("Connection to TGT controller successful\n");
		ZREPL_LOG("Connection to TGT controller iss successful\n");
	}

	efd = epoll_create1(0);
	if (efd == -1) {
		ZREPL_ERRLOG("epoll_create() failed with errno:%d\n", errno);
		goto exit;
	}

	event.data.fd = sfd;
	event.events = EPOLLIN | EPOLLET | EPOLLERR |
	    EPOLLHUP | EPOLLRDHUP;
	rc = epoll_ctl(efd, EPOLL_CTL_ADD, sfd, &event);
	if (rc == -1) {
		ZREPL_ERRLOG("epoll_ctl() failed with errno:%d\n", errno);
		goto exit;
	}

	/* Buffer where events are returned */
	events = calloc(MAXEVENTS, sizeof (event));

	/* The event loop */
	while (1) {
		int n, i;
		n = epoll_wait(efd, events, MAXEVENTS, -1);
		for (i = 0; i < n; i++) {
			if ((events[i].events & EPOLLERR) ||
			    (events[i].events & EPOLLHUP) ||
			    (events[i].events & EPOLLRDHUP)) {
				/*
				 * Error has occurred on this socket
				 * close it and open a new socket after
				 * 5 sec of sleep.
				 */
				ZREPL_ERRLOG("epoll err() :%d\n", errno);
				close(events[i].data.fd);
				printf("Retrying ....\n");
				sleep(5);
				sfd = create_and_bind(mgmt_port, false);
				if (sfd == -1) {
					goto exit;
				}

				rc = make_socket_non_blocking(sfd);
				if (rc == -1) {
					goto exit;
				}
retry1:
				rc = connect(sfd,
				    (struct sockaddr *)&istgt_addr,
				    sizeof (istgt_addr));
				if ((rc == -1) && (errno == EINTR)) {
					ZREPL_ERRLOG("Failed to connect to"
					    " istgt_controller with err:%d\n",
					    errno);
					sleep(2);
					goto retry1;
				}

				event.data.fd = sfd;
				event.events = EPOLLIN | EPOLLET |
				    EPOLLERR | EPOLLHUP | EPOLLRDHUP;
				rc = epoll_ctl(efd, EPOLL_CTL_ADD, sfd, &event);
				if (rc == -1) {
					ZREPL_ERRLOG("epoll_ctl() failed with"
					    " errno:%d\n", errno);
					goto exit;
				}
				continue;
			}

			bzero(&hdr, sizeof (hdr));
			count = read(events[i].data.fd, (char *)&hdr,
			    sizeof (hdr));
			if (count == -1) {
				ZREPL_ERRLOG("Read from socket failed"
				    " with err:%d\n", errno);
				goto exit;
			}

			if (hdr.opcode == ZVOL_OPCODE_HANDSHAKE) {
				name = kmem_alloc(
				    hdr.len * sizeof (char), KM_SLEEP);
				count = read(events[i].data.fd, name,
				    sizeof (char) * hdr.len);
				if (count == -1) {
					ZREPL_ERRLOG("Read from socket failed"
					    " with err:%d\n", errno);
					goto exit;
				}

				rc = uzfs_zvol_mgmt_do_handshake(&hdr,
				    events[i].data.fd, name);
				free(name);
				if (rc == -1) {
					ZREPL_ERRLOG("handshake failed with"
					    " errno:%d\n", errno);
					goto exit;
				}
			}
		}
	}
exit:
	if (events != NULL) {
		free(events);
	}
	printf("uzfs_zvol_mgmt_thread thread exiting\n");
	zk_thread_exit();
}
#endif
/*
 * One thread per replica. Responsible for accepting
 * IO connections. This thread will accept a connection
 * and spawn a new thread for each new connection req.
 */
static void
uzfs_zvol_io_conn_acceptor(void)
{
	int rc, sfd, efd;
#ifdef DEBUG
	char *hbuf;
	char *sbuf;
#endif
	int new_fd;
	socklen_t in_len;
	struct sockaddr in_addr;
	struct epoll_event event;
	struct epoll_event *events = NULL;

	sfd = efd = -1;
	sfd = create_and_bind(accpt_port, true);
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
		int i, n = 0;
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
#if 0
			while (1) {
#endif
				in_len = sizeof (in_addr);
				new_fd = accept(events[i].data.fd,
				    &in_addr, &in_len);
#if 0
				if ((errno == EAGAIN) ||
				    (errno == EWOULDBLOCK)) {
					break;
				}
#endif
				if (new_fd == -1) {
					ZREPL_ERRLOG("accept err() :%d\n",
					    errno);
					goto exit;
				}
#ifdef DEBUG
				hbuf = kmem_alloc(
				    sizeof (NI_MAXHOST), KM_SLEEP);
				sbuf = kmem_alloc(
				    sizeof (NI_MAXSERV), KM_SLEEP);
				rc = getnameinfo(&in_addr, in_len, hbuf,
				    sizeof (hbuf), sbuf, sizeof (sbuf),
				    NI_NUMERICHOST | NI_NUMERICSERV);
				if (rc == 0) {
					ZREPL_LOG("Accepted connection on "
					    "descriptor %d "
					    "(host=%s, port=%s)\n",
					    new_fd, hbuf, sbuf);
					printf("Accepted IO conn on "
					    "descriptor %d "
					    "(host=%s, port=%s)\n",
					    new_fd, hbuf, sbuf);
				}

				free(hbuf);
				free(sbuf);
#endif
				int *thread_fd = kmem_alloc(
				    sizeof (int), KM_SLEEP);
				*thread_fd = new_fd;
				thrd_info = zk_thread_create(NULL, 0,
				    (thread_func_t)uzfs_zvol_io_receiver,
				    (void *)thread_fd, 0, NULL, TS_RUN, 0,
				    PTHREAD_CREATE_DETACHED);
				VERIFY3P(thrd_info, !=, NULL);
#if 0
			}
#endif
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

	printf("uzfs_zvol_io_conn_acceptor thread exiting\n");
	ZREPL_ERRLOG("uzfs_zvol_io_conn_acceptor thread exiting\n");
	zk_thread_exit();
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
				zinfo->io_ack_waiting = 1;
				pthread_cond_wait(&zinfo->io_ack_cond,
				    &zinfo->complete_queue_mutex);

				zinfo->io_ack_waiting = 0;
				if ((zinfo->state == ZVOL_INFO_STATE_OFFLINE) ||
				    (zinfo->conn_closed == true)) {
					(void) pthread_mutex_unlock(
					    &zinfo->complete_queue_mutex);
					goto exit;
				}
			}
		} while (STAILQ_EMPTY(&zinfo->complete_queue));

		zio_cmd = STAILQ_FIRST(&zinfo->complete_queue);
		STAILQ_REMOVE_HEAD(&zinfo->complete_queue, cmd_link);
		(void) pthread_mutex_unlock(&zinfo->complete_queue_mutex);

		ASSERT(zio_cmd->conn == fd);
		ZREPL_LOG("ACK for op:%d with seq-id %ld\n",
		    zio_cmd->hdr.opcode, zio_cmd->hdr.io_seq);

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
				printf("ACK for op:%d with seq-id %ld\n",
				    zio_cmd->hdr.opcode, zio_cmd->hdr.io_seq);
				/* Send data read from disk */
				rc = uzfs_zvol_socket_write(zio_cmd->conn,
				    zio_cmd->buf,
				    (sizeof (char) * zio_cmd->hdr.len));
				if (rc == -1) {
					ZREPL_ERRLOG("socket write err :%d\n",
					    errno);
					ASSERT(0);
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
	uzfs_zinfo_drop_refcnt(zinfo, false);

	printf("uzfs_zvol_io_ack_sender thread exiting\n");
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

static void
uzfs_zrepl_walk_pool_directory(void)
{
	spa_t	*spa = NULL;
	spa_t	*sp = NULL;
	int	rc = 0;

	mutex_enter(&spa_namespace_lock);
	while ((spa = spa_next(spa)) != NULL) {
		(void) printf(">>>>>>>\t%s\n", spa_name(spa));
		rc = spa_open(spa_name(spa), &sp, spa);
		if (rc == 0) {
			spa_close(spa, spa);
		}
	}
	mutex_exit(&spa_namespace_lock);
}

/*
 * Main function for replica.
 */
int
main(int argc, char **argv)
{
	int 		rc;
	kthread_t	*conn_accpt_thrd;
	kthread_t	*uzfs_mgmt_thread;
	char		*target_addr = NULL;

	pthread_t slf = pthread_self();
	snprintf(tinfo, sizeof (tinfo), "m#%d.%d",
	    (int)(((uint64_t *)slf)[0]), getpid());

	rc = uzfs_init();
	uzfs_zrepl_open_log();
	if (rc != 0) {
		printf("initialization errored.. %d\n", rc);
		return (-1);
	}

	rc = pthread_mutex_init(&zvol_list_mutex, NULL);
	if (rc != 0) {
		ZREPL_ERRLOG("zvol_global mutex_init() failed\n");
		return (-1);
	}

	uzfs_zrepl_walk_pool_directory();
	sleep(5);

	/* Ignore SIGPIPE signal */
	signal(SIGPIPE, SIG_IGN);
	if (libuzfs_ioctl_init() < 0) {
		ZREPL_ERRLOG("Failed to initialize libuzfs ioctl\n");
		(void) fprintf(stderr, "%s",
		    "failed to initialize libuzfs ioctl\n");
		goto initialize_error;
	}

	if (argc > 1)
		target_addr = argv[1];

	conn_accpt_thrd = zk_thread_create(NULL, 0,
	    (thread_func_t)uzfs_zvol_io_conn_acceptor,
	    NULL, 0, NULL, TS_RUN, 0,
	    PTHREAD_CREATE_DETACHED);
	VERIFY3P(conn_accpt_thrd, !=, NULL);

	uzfs_mgmt_thread = zk_thread_create(NULL, 0,
	    (thread_func_t)uzfs_zvol_mgmt_thread,
	    target_addr, 0, NULL, TS_RUN, 0,
	    PTHREAD_CREATE_DETACHED);
	VERIFY3P(uzfs_mgmt_thread, !=, NULL);

	while (1) {
		sleep(5);
	}

initialize_error:
	uzfs_zrepl_close_log();
	uzfs_fini();
	return (-1);
}
