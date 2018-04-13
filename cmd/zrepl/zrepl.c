#include <arpa/inet.h>
#include <netdb.h>

#include <syslog.h>
#include <libuzfs.h>
#include <libzfs.h>
#include <sys/dsl_dataset.h>
#include <sys/dmu_objset.h>
#include <uzfs_mgmt.h>
#include <zrepl_mgmt.h>
#include <uzfs_io.h>
#include <sys/epoll.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include <uzfs_rebuilding.h>
#include <atomic.h>

#define	MAXEVENTS 64
#define	ZAP_UPDATE_TIME_INTERVAL 2
#define	ZVOL_REBUILD_STEP_SIZE  (128 * 1024 * 1024) // 128MB

char *io_server_port = "3232";
char *rebuild_io_server_port = "3233";
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

		case ZVOL_OPCODE_SYNC:
		case ZVOL_OPCODE_REBUILD_STEP_DONE:
			/* Nothing to do */
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
	boolean_t	rebuild;

	zio_cmd = (zvol_io_cmd_t *)arg;
	hdr = &zio_cmd->hdr;
	zinfo = zio_cmd->zv;
	zvol_state = zinfo->zv;
	rebuild = hdr->flags & ZVOL_OP_FLAG_REBUILD;
	/*
	 * Read metadata/IO# too in following cases:
	 * 1. When Replica is helping other replica to rebuild
	 * 2. When Replica is not healthy, need to return metadata too
	 */
	if (rebuild || ZVOL_IS_REBUILDED(zvol_state)) {
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
			uzfs_flush_data(zinfo->zv);
			break;
		case ZVOL_OPCODE_REBUILD_STEP_DONE:
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

	/*
	 * We are not sending ACK for writes meant for rebuild
	 */
	if (rebuild && (hdr->opcode == ZVOL_OPCODE_WRITE)) {
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

static int
uzfs_zvol_rebuild_status(zvol_io_hdr_t *hdr, int sfd, char *name)
{
	int 			rc = 0;
	zvol_info_t 		*zinfo = NULL;
	zrepl_status_ack_t	status_ack;

	if ((zinfo = uzfs_zinfo_lookup(name)) == NULL) {
		ZREPL_ERRLOG("Unknown zvol: %s\n", name);
		hdr->status = ZVOL_OP_STATUS_FAILED;
	} else {
		hdr->status = ZVOL_OP_STATUS_OK;
		hdr->len = sizeof (zrepl_status_ack_t);
	}

	if (zinfo != NULL) {
		status_ack.state = uzfs_zvol_get_status(zinfo->zv);
		status_ack.rebuild_status =
		    uzfs_zvol_get_rebuild_status(zinfo->zv);
		uzfs_zinfo_drop_refcnt(zinfo, B_FALSE);
	}

	rc = uzfs_zvol_socket_write(sfd, (char *)hdr, sizeof (*hdr));
	if (rc != 0) {
		ZREPL_ERRLOG("Write to socket failed with err: %d\n", errno);
		return (-1);
	}

	if (hdr->status != ZVOL_OP_STATUS_OK) {
		return (0);
	}

	rc = uzfs_zvol_socket_write(sfd, (char *)&status_ack, hdr->len);
	if (rc != 0) {
		ZREPL_ERRLOG("Write to socket failed with err: %d\n", errno);
		rc = -1;
	}
	return (rc);
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

	bzero(&mgmt_ack, sizeof (mgmt_ack));
	strncpy(mgmt_ack.volname, name, sizeof (mgmt_ack.volname));
	if (hdr->opcode == ZVOL_OPCODE_PREPARE_FOR_REBUILD) {
		/*
		 * Send rebuild socket IP and port
		 */
		mgmt_ack.port = atoi(rebuild_io_server_port);
	} else {
		/*
		 * Send normal IO socket IP and port
		 */
		mgmt_ack.port = atoi(io_server_port);
	}
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

	/*
	 * Retrieve checkpointed io_seq from ZAP
	 * and share it with iSCSI controller.
	 */
	if (zinfo != NULL) {
		zvol_state_t *zv = zinfo->zv;
		uzfs_zvol_get_last_committed_io_no(zv,
		    &hdr->checkpointed_io_seq);
		mgmt_ack.pool_guid = spa_guid(zv->zv_spa);
		/*
		 * We don't use fsid_guid because that one is not guaranteed
		 * to stay the same (it is changed in case of conflicts).
		 */
		mgmt_ack.zvol_guid = dsl_dataset_phys(
		    zv->zv_objset->os_dsl_dataset)->ds_guid;
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

	rc = uzfs_zvol_socket_write(sfd, (char *)&mgmt_ack, hdr->len);
	if (rc != 0) {
		ZREPL_ERRLOG("Write to socket failed with err: %d\n", errno);
		rc = -1;
	}
	return (rc);
}

static int
uzfs_zvol_mgmt_sync(zvol_io_hdr_t *hdr, int sfd, char *name)
{
	int		rc = 0;
	zvol_io_cmd_t	*zio_cmd = NULL;
	zvol_info_t	*zinfo = NULL;

	ZREPL_LOG("Sync cmd received for Volume: %s\n", name);
	zinfo = uzfs_zinfo_lookup(name);
	if ((zinfo = uzfs_zinfo_lookup(name)) == NULL) {
		ZREPL_ERRLOG("Unknown zvol: %s\n", name);
		hdr->status = ZVOL_OP_STATUS_FAILED;
		return (-1);
	}
	zio_cmd = zio_cmd_alloc(hdr, sfd);
	zio_cmd->zv = zinfo;
	taskq_dispatch(zinfo->uzfs_zvol_taskq, uzfs_zvol_worker,
	    zio_cmd, TQ_SLEEP);
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

static void
uzfs_zvol_rebuild_dw_replica(void *arg)
{
	int		rc, sfd = -1;
	uint64_t	offset = 0;
	uint64_t	checkpointed_io_seq;
	thread_args_t	*thrd_arg;
	zvol_info_t	*zinfo = NULL;
	zvol_state_t	*zvol_state;
	zvol_io_cmd_t	*zio_cmd = NULL;
	zvol_io_hdr_t 	hdr;

	thrd_arg = (thread_args_t *)arg;
	sfd = thrd_arg->fd;
	zinfo = uzfs_zinfo_lookup(thrd_arg->dw_zvol_name);

	if (zinfo == NULL) {
		ZREPL_ERRLOG("Rebuild volume %s not found\n",
		    thrd_arg->dw_zvol_name);
		goto exit;
	}
	/* Count how many rebuilds we are initializing on this replica */
	atomic_inc_16(&zinfo->rebuild_cnt);
	uzfs_zvol_get_last_committed_io_no(zinfo->zv, &checkpointed_io_seq);
	zvol_state = zinfo->zv;
	bzero(&hdr, sizeof (hdr));
	hdr.status = ZVOL_OP_STATUS_OK;
	hdr.version = REPLICA_VERSION;
	hdr.opcode = ZVOL_OPCODE_HANDSHAKE;
	hdr.len = strlen(thrd_arg->zvol_name) + 1;

	rc = uzfs_zvol_socket_write(sfd, (char *)&hdr, sizeof (hdr));
	if (rc == -1) {
		ZREPL_ERRLOG("Socket write failed, err: %d\n", errno);
		goto exit;
	}

	rc = uzfs_zvol_socket_write(sfd, (void *)thrd_arg->zvol_name, hdr.len);
	if (rc == -1) {
		ZREPL_ERRLOG("Socket write failed, err: %d\n", errno);
		goto exit;
	}

next_step:
	if (offset >= ZVOL_VOLUME_SIZE(zvol_state)) {
		hdr.opcode = ZVOL_OPCODE_REBUILD_COMPLETE;
		rc = uzfs_zvol_socket_write(sfd, (char *)&hdr, sizeof (hdr));
		if (rc != 0) {
			ZREPL_ERRLOG("Socket write failed, err: %d\n", errno);
			goto exit;
		}
		atomic_dec_16(&zinfo->rebuild_cnt);
		if (!zinfo->rebuild_cnt) {
			/* Mark replica healthy now */
			uzfs_zvol_set_rebuild_status(zinfo->zv,
			    ZVOL_REBUILDING_DONE);
			uzfs_zvol_set_status(zinfo->zv, ZVOL_STATUS_HEALTHY);
		}
		ZREPL_ERRLOG("Rebuild on LUN:%s completed\n", zinfo->name);
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
			zio_cmd_free(&zio_cmd);
			ZREPL_ERRLOG("Socket read failed with "
			    "error: %d\n", errno);
			goto exit;
		}
		/* Take refcount for uzfs_zvol_worker to work on it */
		uzfs_zinfo_take_refcnt(zinfo, B_FALSE);
		zio_cmd->zv = zinfo;
		taskq_dispatch(zinfo->uzfs_zvol_taskq, uzfs_zvol_worker,
		    zio_cmd, TQ_SLEEP);
		zio_cmd = NULL;
	}

exit:
	kmem_free(thrd_arg, sizeof (thread_args_t));
	if (zio_cmd != NULL)
		zio_cmd_free(&zio_cmd);
	if (zinfo != NULL)
		uzfs_zinfo_drop_refcnt(zinfo, B_FALSE);
	if (sfd != -1)
		close(sfd);

	printf("uzfs_zvol_rebuild_dw_replica thread exiting\n");
	zk_thread_exit();
}

static int
uzfs_zvol_rebuild_dw_replica_start(zvol_io_hdr_t *hdr, int fd, char *buf)
{
	int			rc, io_sfd;
	int			rebuild_op_cnt;
	thread_args_t		*thrd_arg;
	mgmt_ack_t		*mgmt_ack;
	kthread_t		*thrd_info;
	struct sockaddr_in	replica_ip;

	rebuild_op_cnt = hdr->len / sizeof (mgmt_ack_t);
	ZREPL_LOG("Number of rebuild op triggered %d\n", rebuild_op_cnt);
	while (rebuild_op_cnt) {
		mgmt_ack = (mgmt_ack_t *)buf;
		printf("Replica to be rebuilt: %s\n", mgmt_ack->volname);
		printf("Replica's IP address: %s\n", mgmt_ack->ip);
		printf("Replica's Port: %d\n", mgmt_ack->port);

		bzero((char *)&replica_ip, sizeof (replica_ip));
		replica_ip.sin_family = AF_INET;
		replica_ip.sin_addr.s_addr = inet_addr(mgmt_ack->ip);
		replica_ip.sin_port = htons(mgmt_ack->port);
		io_sfd = create_and_bind("", B_FALSE);
		if (io_sfd == -1) {
			ZREPL_ERRLOG("Rebuild IO socket create "
			    "and bind failed\n");
			return (-1);
		}

		rc = connect(io_sfd, (struct sockaddr *)&replica_ip,
		    sizeof (replica_ip));
		if (rc == -1) {
			printf("Failed to connect to bad replica IO port\n");
			return (-1);
		}

		thrd_arg = kmem_alloc(sizeof (thread_args_t), KM_SLEEP);
		thrd_arg->fd = io_sfd;
		strlcpy(thrd_arg->dw_zvol_name, mgmt_ack->dw_volname,
		    MAXNAMELEN);
		strlcpy(thrd_arg->zvol_name, mgmt_ack->volname, MAXNAMELEN);
		thrd_info = zk_thread_create(NULL, 0,
		    (thread_func_t)uzfs_zvol_rebuild_dw_replica,
		    (void *)thrd_arg, 0, NULL, TS_RUN, 0,
		    PTHREAD_CREATE_DETACHED);
		VERIFY3P(thrd_info, !=, NULL);
		rebuild_op_cnt--;
		mgmt_ack++;
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
		case ZVOL_OPCODE_PREPARE_FOR_REBUILD:
			rc = uzfs_zvol_mgmt_do_handshake(&hdr, sfd, buf);
			if (rc != 0) {
				ZREPL_ERRLOG("Handshake failed\n");
			}
			break;

		case ZVOL_OPCODE_START_REBUILD:
			/*
			 * iSCSI controller will send this
			 * message to a downgraded replica
			 */
			rc = uzfs_zvol_rebuild_dw_replica_start(&hdr, sfd, buf);
			if (rc == -1) {
				ZREPL_ERRLOG("Rebuild start failed errno:%d\n",
				    errno);
			}
			break;

		case ZVOL_OPCODE_REPLICA_STATUS:
			rc = uzfs_zvol_rebuild_status(&hdr, sfd, buf);
			if (rc != 0) {
				ZREPL_ERRLOG("Rebuild status enq failed\n");
			}
			break;

		case ZVOL_OPCODE_SYNC:
			uzfs_zvol_mgmt_sync(&hdr, sfd, buf);
			if (rc == -1) {
				ZREPL_ERRLOG("Sync failed errno:%d\n",
				    errno);
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
	int		fd;
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
	free(arg);

read_socket:
	rc = uzfs_zvol_read_header(fd, &hdr);
	if (rc != 0) {
		close(fd);
		goto exit;
	}

	printf("op_code=%d io_seq=%ld\n", hdr.opcode, hdr.io_seq);
	switch (hdr.opcode) {

		case ZVOL_OPCODE_HANDSHAKE:
			name = kmem_alloc(hdr.len, KM_SLEEP);
			rc = uzfs_zvol_socket_read(fd, name, hdr.len);
			if (rc != 0) {
				free(name);
				ZREPL_ERRLOG("Socket read error: %d\n", errno);
				goto exit;
			}

			zinfo = uzfs_zinfo_lookup(name);
			if (zinfo == NULL) {
				ZREPL_ERRLOG("Volume/LUN: %s not found", name);
				free(name);
				goto exit;
			}
			free(name);
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
			ZREPL_LOG("Rebuild on LUN:%s completed\n", zinfo->name);
			goto exit;
			break;

		default:
			ASSERT(0);
			break;
	}

exit:
	if (zinfo != NULL) {
		uzfs_zinfo_drop_refcnt(zinfo, B_FALSE);
	}

	printf("uzfs_zvol_rebuild_scanner thread exiting\n");
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
	io_sfd = create_and_bind(io_server_port, B_TRUE);
	if (io_sfd == -1) {
		goto exit;
	}

	rc = make_socket_non_blocking(io_sfd);
	if (rc == -1) {
		goto exit;
	}

	rc = listen(io_sfd, SOMAXCONN);
	if (rc == -1) {
		ZREPL_ERRLOG("listen() on IO_SFD failed with errno:%d\n",
		    errno);
		goto exit;
	}

	rebuild_fd = create_and_bind(rebuild_io_server_port, B_TRUE);
	if (rebuild_fd == -1) {
		goto exit;
	}

	rc = make_socket_non_blocking(rebuild_fd);
	if (rc == -1) {
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

			free(hbuf);
			free(sbuf);
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

		// ASSERT3P(zio_cmd->conn, ==, fd);
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
