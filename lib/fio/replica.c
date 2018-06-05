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
 * Copyright (c) 2018 CloudByte, Inc. All rights reserved.
 */

/*
 * cstor replica engine
 *
 * IO engine that reads/writes to/from cstor replica.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <assert.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/poll.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <fio.h>
#include <optgroup.h>

#include <zrepl_prot.h>

/*
 * List of IOs in progress.
 */
struct io_list_entry;
typedef struct io_list_entry {
	uint64_t io_num;
	struct io_u *io_u;
	struct io_list_entry *io_next;
} io_list_entry_t;

/*
 * Engine per thread data
 */
struct netio_data {
	io_list_entry_t *io_inprog;
	struct io_u **io_completed;
};

// global because mgmt conn must be shared by all data connections
int mgmt_conn = -1;
pthread_mutex_t mgmt_mtx = PTHREAD_MUTEX_INITIALIZER;

struct repl_options {
	struct thread_data *td;
	unsigned int port;
	unsigned int nodelay;
	unsigned int window_size;
	unsigned int mss;
	unsigned int metadata_bs;
	const char *address;
};

static struct fio_option options[] = {
	{
		.name	= "address",
		.lname	= "replica IP address",
		.type	= FIO_OPT_STR_STORE,
		.off1	= offsetof(struct repl_options, address),
		.help	= "IP address of replica",
		.category = FIO_OPT_C_ENGINE,
		.group	= FIO_OPT_G_NETIO,
	},
	{
		.name	= "port",
		.lname	= "replica port number",
		.type	= FIO_OPT_INT,
		.off1	= offsetof(struct repl_options, port),
		.minval	= 1,
		.maxval	= 65535,
		.help	= "Port to use for TCP net connections",
		.category = FIO_OPT_C_ENGINE,
		.group	= FIO_OPT_G_NETIO,
	},
	{
		.name	= "nodelay",
		.lname	= "No Delay",
		.type	= FIO_OPT_BOOL,
		.off1	= offsetof(struct repl_options, nodelay),
		.help	= "Use TCP_NODELAY on TCP connections",
		.category = FIO_OPT_C_ENGINE,
		.group	= FIO_OPT_G_NETIO,
	},
	{
		.name	= "window_size",
		.lname	= "Window Size",
		.type	= FIO_OPT_INT,
		.off1	= offsetof(struct repl_options, window_size),
		.minval	= 0,
		.help	= "Set socket buffer window size",
		.category = FIO_OPT_C_ENGINE,
		.group	= FIO_OPT_G_NETIO,
	},
	{
		.name	= "mss",
		.lname	= "Maximum segment size",
		.type	= FIO_OPT_INT,
		.off1	= offsetof(struct repl_options, mss),
		.minval	= 0,
		.help	= "Set TCP maximum segment size",
		.category = FIO_OPT_C_ENGINE,
		.group	= FIO_OPT_G_NETIO,
	},
	{
		.name	= "metadata_block_size",
		.lname	= "Metadata granularity",
		.type	= FIO_OPT_INT,
		.off1	= offsetof(struct repl_options, metadata_bs),
		.minval	= 512,
		.help	= "Set granularity of metadata book keeping records",
		.category = FIO_OPT_C_ENGINE,
		.group	= FIO_OPT_G_NETIO,
	},
	{
		.name	= NULL,
	},
};

static int set_window_size(struct thread_data *td, int fd)
{
	struct repl_options *o = td->eo;
	unsigned int wss;
	int snd, rcv, ret;

	if (!o->window_size)
		return (0);

	rcv = 0;
	snd = 1;
	wss = o->window_size;
	ret = 0;

	if (rcv) {
		ret = setsockopt(fd, SOL_SOCKET, SO_RCVBUF, (void *) &wss,
		    sizeof (wss));
		if (ret < 0)
			td_verror(td, errno, "rcvbuf window size");
	}
	if (snd && !ret) {
		ret = setsockopt(fd, SOL_SOCKET, SO_SNDBUF, (void *) &wss,
		    sizeof (wss));
		if (ret < 0)
			td_verror(td, errno, "sndbuf window size");
	}

	return (ret);
}

static int set_mss(struct thread_data *td, int fd)
{
	struct repl_options *o = td->eo;
	unsigned int mss;
	int ret;

	if (!o->mss)
		return (0);

	mss = o->mss;
	ret = setsockopt(fd, IPPROTO_TCP, TCP_MAXSEG, (void *) &mss,
	    sizeof (mss));
	if (ret < 0)
		td_verror(td, errno, "setsockopt TCP_MAXSEG");

	return (ret);
}


/*
 * Return -1 for error and 'nr events' for a positive number
 * of events
 */
static int poll_wait(struct thread_data *td, int fd, short events)
{
	struct pollfd pfd;
	int ret;

	while (!td->terminate) {
		pfd.fd = fd;
		pfd.events = events;
		ret = poll(&pfd, 1, -1);
		if (ret < 0) {
			if (errno == EINTR)
				break;

			td_verror(td, errno, "poll");
			return (-1);
		} else if (!ret)
			continue;

		break;
	}

	if (pfd.revents & events)
		return (1);

	return (-1);
}

static int read_from_socket(int fd, void *buf, size_t nbytes)
{
	int rc, n = 0;

	while (n < nbytes) {
		rc = recv(fd, ((char *)buf) + n, nbytes - n, 0);
		if (rc < 0)
			return (errno);
		if (rc == 0)
			return (ESRCH);
		n += rc;
	}
	return (0);
}

static int write_to_socket(int fd, const void *buf, size_t nbytes, int more)
{
	int rc, n = 0;
	int flags = (more) ? MSG_MORE : 0;

	while (n < nbytes) {
		rc = send(fd, ((const char *) buf) + n, nbytes - n, flags);
		if (rc < 0)
			return (errno);
		n += rc;
	}
	return (0);
}

static int do_handshake(struct thread_data *td, const char *volname,
    mgmt_ack_t *mgmt_ack)
{
	ssize_t rc;
	zvol_io_hdr_t hdr;
	uint16_t vers;
	int volname_size = strlen(volname) + 1;

	hdr.version = REPLICA_VERSION;
	hdr.opcode = ZVOL_OPCODE_HANDSHAKE;
	hdr.status = 0;
	hdr.io_seq = 0;
	hdr.offset = 0;
	hdr.len = volname_size;

	rc = write_to_socket(mgmt_conn, &hdr, sizeof (hdr), 1);
	if (rc != 0) {
		td_verror(td, rc, "write");
		return (-1);
	}
	rc = write_to_socket(mgmt_conn, volname, volname_size, 0);
	if (rc != 0) {
		td_verror(td, rc, "write");
		return (-1);
	}

	rc = read_from_socket(mgmt_conn, &hdr, sizeof (vers));
	if (hdr.version != REPLICA_VERSION) {
		log_err("repl: Incompatible replica version %d\n", hdr.version);
		return (-1);
	}
	rc = read_from_socket(mgmt_conn, ((char *)&hdr) + sizeof (vers),
	    sizeof (hdr) - sizeof (vers));
	if (rc != 0) {
		td_verror(td, rc, "read");
		return (-1);
	}

	if (hdr.opcode != ZVOL_OPCODE_HANDSHAKE) {
		log_err("repl: Unexpected replica op code %d\n", hdr.opcode);
		return (-1);
	}
	if (hdr.status != ZVOL_OP_STATUS_OK) {
		log_err("repl: Handshake failed (does zvol %s exist?)\n",
		    volname);
		return (-1);
	}
	if (hdr.len != sizeof (mgmt_ack_t)) {
		log_err("repl: Handshake payload has %lu bytes. "
		    "Should be %lu bytes\n", hdr.len, sizeof (mgmt_ack_t));
		return (-1);
	}

	rc = read_from_socket(mgmt_conn, mgmt_ack, hdr.len);
	if (rc != 0) {
		td_verror(td, rc, "read");
		return (-1);
	}

	return (0);
}

static int open_zvol(struct thread_data *td, int fd, const char *volname)
{
	struct repl_options *o = td->eo;
	ssize_t rc;
	zvol_io_hdr_t hdr;
	zvol_op_open_data_t open_data;
	int volname_size = strlen(volname) + 1;

	hdr.version = REPLICA_VERSION;
	hdr.opcode = ZVOL_OPCODE_OPEN;
	hdr.status = 0;
	hdr.io_seq = 0;
	hdr.offset = 0;
	hdr.len = sizeof (open_data);

	// we use the smallest possible bs for metadata granularity, this still
	// allows us to use arbitrary larger bs for IO
	open_data.tgt_block_size = (o->metadata_bs) ? o->metadata_bs : 512;
	open_data.timeout = 120;
	strncpy(open_data.volname, volname, sizeof (open_data.volname));

	rc = write_to_socket(fd, &hdr, sizeof (hdr), 1);
	if (rc != 0) {
		td_verror(td, rc, "write");
		return (-1);
	}
	rc = write_to_socket(fd, &open_data, hdr.len, 0);
	if (rc != 0) {
		td_verror(td, rc, "write");
		return (-1);
	}

	rc = read_from_socket(fd, &hdr, sizeof (hdr));
	if (hdr.version != REPLICA_VERSION) {
		log_err("repl: Incompatible replica version %d\n", hdr.version);
		return (-1);
	}
	if (hdr.opcode != ZVOL_OPCODE_OPEN) {
		log_err("repl: Unexpected replica op code %d\n", hdr.opcode);
		return (-1);
	}
	if (hdr.status != ZVOL_OP_STATUS_OK) {
		log_err("repl: Open of zvol %s failed\n", volname);
		return (-1);
	}
	if (hdr.len != 0) {
		log_err("repl: Unexpected open zvol payload");
		return (-1);
	}

	return (0);
}

/*
 * Creates mgmt connection used for retrieval of data endpoint info later on.
 */
static int create_mgmt_conn(struct thread_data *td)
{
	socklen_t socklen;
	struct sockaddr *saddr;
	struct sockaddr_in addr;
	int listenfd;
	int fd;
	int opt = 1;

	listenfd = socket(AF_INET, SOCK_STREAM, 0);
	if (listenfd < 0) {
		td_verror(td, errno, "socket");
		return (-1);
	}
	if (setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, (void *) &opt,
	    sizeof (opt)) < 0) {
		td_verror(td, errno, "setsockopt");
		close(listenfd);
		return (-1);
	}

	socklen = sizeof (addr);
	memset(&addr, 0, socklen);
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_ANY);
	addr.sin_port = htons(TARGET_PORT);
	saddr = (struct sockaddr *)&addr;

	if (bind(listenfd, saddr, socklen) < 0) {
		td_verror(td, errno, "bind");
		close(listenfd);
		return (-1);
	}
	if (listen(listenfd, 5) < 0) {
		td_verror(td, errno, "listen");
		close(listenfd);
		return (-1);
	}

	log_info("repl: waiting for connection from replica\n");

	if (poll_wait(td, listenfd, POLLIN) < 0) {
		close(listenfd);
		return (-1);
	}

	fd = accept(listenfd, (struct sockaddr *)&addr, &socklen);
	if (fd < 0) {
		td_verror(td, errno, "accept");
		close(listenfd);
		return (-1);
	}

	log_info("repl: replica connected\n");
	return (fd);
}

/*
 * Return host:port for given zvol name.
 */
static int get_data_endpoint(struct thread_data *td, const char *volname,
	short *port, char *host)
{
	mgmt_ack_t mgmt_ack;

	pthread_mutex_lock(&mgmt_mtx);

	// send volume name we want to open to replica
	if (do_handshake(td, volname, &mgmt_ack) != 0) {
		pthread_mutex_unlock(&mgmt_mtx);
		return (1);
	}
	log_info("repl: replica server: %s:%d, volume name %s, "
	    "pool GUID: %lx, zvol GUID: %lx\n",
	    mgmt_ack.ip, mgmt_ack.port, mgmt_ack.volname,
	    mgmt_ack.pool_guid, mgmt_ack.zvol_guid);

	*port = mgmt_ack.port;
	strncpy(host, mgmt_ack.ip, 256);

	pthread_mutex_unlock(&mgmt_mtx);
	return (0);
}

/*
 * Opens and initializes data connection for zvol.
 */
static int fio_repl_open_file(struct thread_data *td, struct fio_file *f)
{
	struct repl_options *o = td->eo;
	struct sockaddr_in addr;
	short port;
	char host[256] = "127.0.0.1";

	port = o->port;
	if (port && o->address)
		strcpy(host, o->address);

	// use mgmt connection to get host:port if not explicitly specified
	if (!port) {
		if (get_data_endpoint(td, f->file_name, &port, host) != 0)
			return (1);
	}

	f->fd = socket(AF_INET, SOCK_STREAM, 0);
	if (f->fd < 0) {
		td_verror(td, errno, "socket");
		return (1);
	}

	if (o->nodelay) {
		int optval = 1;

		if (setsockopt(f->fd, IPPROTO_TCP, TCP_NODELAY,
		    (void *) &optval, sizeof (int)) < 0) {
			log_err("repl: cannot set TCP_NODELAY option on "
			    "socket (%s), disable with 'nodelay=0'\n",
			    strerror(errno));
			return (1);
		}
	}

	if (set_window_size(td, f->fd)) {
		close(f->fd);
		return (1);
	}
	if (set_mss(td, f->fd)) {
		close(f->fd);
		return (1);
	}

	memset(&addr, 0, sizeof (addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_ANY);
	addr.sin_port = htons(port);
	if (inet_pton(AF_INET, host, &addr.sin_addr) <= 0) {
		td_verror(td, errno, "inet_pton");
		close(f->fd);
		return (1);
	}
	log_info("repl: opening zvol %s on data connection\n",
	    f->file_name);
	if (connect(f->fd, (struct sockaddr *)&addr, sizeof (addr)) < 0) {
		td_verror(td, errno, "connect");
		close(f->fd);
		return (1);
	}

	// send volume name we want to open to replica
	if (open_zvol(td, f->fd, f->file_name) != 0) {
		close(f->fd);
		return (1);
	}

	return (0);
}

/*
 * Close data connection.
 */
static int fio_repl_close_file(struct thread_data *td, struct fio_file *f)
{
	int rc;

	rc = close(f->fd);
	f->fd = -1;
	return (rc);
}

static void fio_repl_terminate(struct thread_data *td)
{
	kill(td->pid, SIGTERM);
}

/*
 * This is called before opening files and normally is used to retrieve file
 * sizes. We use it for engine structure initialization and mgmt connection
 * creation.
 *
 * Note that we don't need to lock mgmt connection structures because setup
 * hooks for fio threads are executed sequentially by fio.
 */
static int fio_repl_setup(struct thread_data *td)
{
	struct repl_options *o = td->eo;
	struct netio_data *nd;

	if (!td->o.use_thread) {
		log_err("repl: must set thread=1 when using repl plugin\n");
		return (1);
	}

	nd = malloc(sizeof (*nd));
	if (nd == NULL) {
		log_err("repl: memory allocation failed\n");
		return (1);
	}
	memset(nd, 0, sizeof (*nd));
	nd->io_inprog = NULL;
	nd->io_completed = calloc(td->o.iodepth, sizeof (struct io_u *));

	// only create mgmt conn if it is needed
	if (!o->port && mgmt_conn < 0) {
		mgmt_conn = create_mgmt_conn(td);
		if (mgmt_conn < 0)
			return (1);
	}
	td->io_ops_data = nd;

	return (0);
}

/*
 * Close mgmt connection and free engine data.
 */
static void fio_repl_cleanup(struct thread_data *td)
{
	struct netio_data *nd = td->io_ops_data;

	if (nd) {
		free(nd->io_completed);
		free(nd);
	}
	if (mgmt_conn >= 0) {
		close(mgmt_conn);
		mgmt_conn = -1;
	}
}

/*
 * Generate ID for IO message. Must be unique and monotonically increasing.
 */
static uint64_t gen_sequence_num(void)
{
	static uint64_t seq_num;

	return (__atomic_fetch_add(&seq_num, 1, __ATOMIC_SEQ_CST));
}

/*
 * Dispatch command to replica.
 */
static enum fio_q_status fio_repl_queue(struct thread_data *td,
    struct io_u *io_u)
{
	struct netio_data *nd = td->io_ops_data;
	zvol_io_hdr_t hdr;
	io_list_entry_t *io_ent;

	io_ent = malloc(sizeof (*io_ent));
	if (io_ent == NULL) {
		io_u->error = ENOMEM;
		goto end;
	}
	io_ent->io_num = gen_sequence_num();
	io_ent->io_u = io_u;
	io_ent->io_next = NULL;

	/*
	 * Send replica message header.
	 */
	hdr.io_seq = io_ent->io_num;
	hdr.offset = io_u->offset;
	hdr.len = io_u->xfer_buflen;
	hdr.status = 0;
	hdr.flags = 0;
	hdr.checkpointed_io_seq = 0;

	if (io_u->ddir == DDIR_WRITE) {
		hdr.opcode = ZVOL_OPCODE_WRITE;
		hdr.len += sizeof (struct zvol_io_rw_hdr);
	} else if (io_u->ddir == DDIR_READ) {
		hdr.opcode = ZVOL_OPCODE_READ;
	} else {
		hdr.opcode = ZVOL_OPCODE_SYNC;
		hdr.len = 0;
	}

	if (write_to_socket(io_u->file->fd, &hdr, sizeof (hdr), 0) != 0) {
		io_u->error = errno;
		goto end;
	}

	/*
	 * Send data in case of write.
	 */
	if (io_u->ddir == DDIR_WRITE) {
		struct zvol_io_rw_hdr write_hdr;

		write_hdr.io_num = hdr.io_seq;
		write_hdr.len = io_u->xfer_buflen;
		if (write_to_socket(io_u->file->fd, &write_hdr,
		    sizeof (write_hdr), 1) != 0) {
			io_u->error = errno;
			goto end;
		}
		if (write_to_socket(io_u->file->fd, io_u->xfer_buf,
		    io_u->xfer_buflen, 0) != 0) {
			io_u->error = errno;
			goto end;
		}
	}

end:
	if (io_u->error) {
		free(io_ent);
		td_verror(td, io_u->error, "xfer");
		return (FIO_Q_COMPLETED);
	}
	io_ent->io_next = nd->io_inprog;
	nd->io_inprog = io_ent;

	return (FIO_Q_QUEUED);
}

/*
 * Read IO acknowledgement.
 */
static io_list_entry_t *read_repl_reply(struct thread_data *td, int fd)
{
	struct netio_data *nd = td->io_ops_data;
	zvol_io_hdr_t hdr;
	io_list_entry_t *iter, *last;
	int ret;

	ret = read_from_socket(fd, &hdr, sizeof (hdr));
	if (ret != 0) {
		td_verror(td, ret, "read hdr");
		return (NULL);
	}

	iter = nd->io_inprog;
	last = NULL;
	while (iter != NULL) {
		if (iter->io_num == hdr.io_seq)
			break;
		last = iter;
		iter = iter->io_next;
	}
	if (iter == NULL) {
		td_verror(td, ENOENT, "unknown IO number");
		return (NULL);
	}
	if (last == NULL)
		nd->io_inprog = iter->io_next;
	else
		last->io_next = iter->io_next;
	iter->io_next = NULL;

	if (hdr.status != ZVOL_OP_STATUS_OK) {
		iter->io_u->error = EIO;
		return (iter);
	}

	// read command payload if any (each chunk is preceeded by meta data)
	if (hdr.opcode == ZVOL_OPCODE_READ) {
		size_t nread = 0;
		size_t data_offset = 0;
		struct zvol_io_rw_hdr read_hdr;

		while (nread < hdr.len) {
			// read metadata header
			if (hdr.len - nread < sizeof (read_hdr)) {
				iter->io_u->error = EIO;
				return (iter);
			}
			if (read_from_socket(fd, &read_hdr,
			    sizeof (read_hdr)) != 0) {
				iter->io_u->error = EIO;
				return (iter);
			}
			nread += sizeof (read_hdr);

			// read the data
			if (hdr.len - nread < read_hdr.len) {
				iter->io_u->error = EIO;
				return (iter);
			}
			if (iter->io_u->xfer_buflen < data_offset +
			    read_hdr.len) {
				iter->io_u->error = EIO;
				return (iter);
			}
			if (read_from_socket(fd,
			    (char *)iter->io_u->xfer_buf + data_offset,
			    read_hdr.len) != 0) {
				iter->io_u->error = EIO;
				return (iter);
			}
			nread += read_hdr.len;
			data_offset += read_hdr.len;
		}

		if (data_offset != iter->io_u->xfer_buflen) {
			log_err("repl: unexpected size of data in reply\n");
			iter->io_u->error = EIO;
			return (iter);
		}
	}

	return (iter);
}

static int fio_repl_getevents(struct thread_data *td, unsigned int min,
    unsigned int max, const struct timespec fio_unused *t)
{
	struct netio_data *nd = td->io_ops_data;
	int ret, read_error = 0, count = 0;
	unsigned int i;
	struct fio_file *f;
	int timeout = -1;
	struct pollfd *pfds;

	pfds = calloc(1, sizeof (struct pollfd) * td->o.nr_files);
	if (pfds == NULL)
		return (0);

	/*
	 * Fill in the file descriptors
	 */
	for_each_file(td, f, i) {
		/*
		 * don't block for min events == 0
		 */
		if (!min)
			timeout = 0;

		pfds[i].fd = f->fd;
		pfds[i].events = POLLIN;
	}

	while (!read_error && count < min) {
		assert(count < td->o.iodepth);
		ret = poll(pfds, td->o.nr_files, timeout);
		if (ret < 0) {
			td_verror(td, errno, "poll");
			goto end;
		} else if (ret == 0)
			goto end;

		for (i = 0; i < td->o.nr_files; i++) {
			if (pfds[i].revents & POLLIN) {
				io_list_entry_t *ent;

				ent = read_repl_reply(td, pfds[i].fd);
				if (ent == NULL) {
					read_error = 1;
				} else {
					assert(nd->io_completed[count] == NULL);
					nd->io_completed[count++] = ent->io_u;
					free(ent);
					if (count >= max)
						goto end;
				}
			}
		}
	}

end:
	free(pfds);
	return (count);
}

static struct io_u *fio_repl_event(struct thread_data *td, int event)
{
	struct netio_data *nd = td->io_ops_data;
	struct io_u *io_u = nd->io_completed[event];
	nd->io_completed[event] = NULL;
	return (io_u);
}

struct ioengine_ops ioengine = {
	.name			= "replica",
	.version		= FIO_IOOPS_VERSION,
	.queue			= fio_repl_queue,
	.getevents		= fio_repl_getevents,
	.event			= fio_repl_event,
	.setup			= fio_repl_setup,
	.cleanup		= fio_repl_cleanup,
	.open_file		= fio_repl_open_file,
	.close_file		= fio_repl_close_file,
	.terminate		= fio_repl_terminate,
	.options		= options,
	.option_struct_size	= sizeof (struct repl_options),
	.flags			=
	    FIO_NODISKUTIL |
	    FIO_RAWIO |
	    FIO_NOEXTEND |
	    FIO_DISKLESSIO
};

static void fio_init fio_repl_register(void)
{
	register_ioengine(&ioengine);
}

static void fio_exit fio_repl_unregister(void)
{
	unregister_ioengine(&ioengine);
}
