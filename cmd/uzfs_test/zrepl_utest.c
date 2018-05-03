#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <strings.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <pthread.h>
#include <string.h>
#include <zrepl_prot.h>
#include <sys/zfs_context.h>
#include <uzfs_test.h>
#include <uzfs_mgmt.h>
#include <zrepl_mgmt.h>

char *tgt_port = "6060";
char *ds1 = "ds1";
char *ds2 = "ds2";
char *ds3 = "ds3";
static uint64_t last_io_seq_sent;

struct data_io {
	zvol_io_hdr_t hdr;
	struct zvol_io_rw_hdr rw_hdr;
	char buf[0];
};

void
populate(char *p, int size)
{
	int i;

	for (i = 0; i < size; i++) {
		p[i] = 'C';
	}
}

int
zrepl_verify_data(char *p, int size)
{

	int i;

	for (i = 0; i < size; i++) {
		if (p[i] != 'C') {
			return (-1);
		}
	}
	return (0);
}

int
zrepl_compare_data(char *buf1, char *buf2, int size)
{

	int i;

	for (i = 0; i < size; i++) {
		if (buf1[i] != buf2[i]) {
			return (-1);
		}
	}
	return (0);
}

int
zrepl_utest_replica_handshake(char *volname, int fd,
    mgmt_ack_t *mgmt_ack)
{
	int count = 0;
	zvol_io_hdr_t hdr;
	bzero(&hdr, sizeof (hdr));

	hdr.version = REPLICA_VERSION;
	hdr.opcode = ZVOL_OPCODE_HANDSHAKE;
	hdr.len = strlen(volname) + 1;

	count = write(fd, (void *)&hdr, sizeof (zvol_io_hdr_t));
	if (count == -1) {
		printf("During handshake, Write error\n");
		return (count);
	}

	count = write(fd, volname, hdr.len);
	if (count == -1) {
		printf("During volname send, Write error\n");
		return (count);
	}

	count = read(fd, (void *)&hdr, sizeof (zvol_io_hdr_t));
	if (count == -1) {
		printf("During HDR read, Read error\n");
		return (count);
	}

	if (hdr.status == ZVOL_OP_STATUS_FAILED) {
		printf("Header status is failed\n");
		return (-1);
	}

	count = read(fd, (void *)mgmt_ack, hdr.len);
	if (count == -1) {
		printf("During mgmt Read error\n");
		return (count);
	}
	return (0);
}

int
zrepl_utest_get_replica_status(char *volname, int fd,
    zrepl_status_ack_t *status_ack)
{
	int count = 0;
	zvol_io_hdr_t hdr;

	bzero(&hdr, sizeof (hdr));
	hdr.version = REPLICA_VERSION;
	hdr.opcode = ZVOL_OPCODE_REPLICA_STATUS;
	hdr.len = strlen(volname) + 1;

	printf("Check health status of volume:%s\n", volname);
	count = write(fd, (void *)&hdr, sizeof (zvol_io_hdr_t));
	if (count == -1) {
		printf("Health status: sending hdr failed\n");
		return (-1);
	}

	count = write(fd, volname, hdr.len);
	if (count == -1) {
		printf("Health status: sending volname failed\n");
		return (-1);
	}

	count = read(fd, (void *)&hdr, sizeof (zvol_io_hdr_t));
	if (count == -1) {
		printf("Health status: error in hdr read\n");
		return (-1);
	}

	if (hdr.status != ZVOL_OP_STATUS_OK) {
		printf("Health status: response failed\n");
		return (-1);
	}

	count = read(fd, (void *)status_ack, sizeof (zrepl_status_ack_t));
	if (count == -1) {
		printf("Health status: error in statuc_ack read\n");
		return (-1);
	}
	return (0);
}

int
zrepl_utest_replica_rebuild_start(int fd, mgmt_ack_t *mgmt_ack,
    int size)
{
	int count = 0;
	zvol_io_hdr_t hdr;

	bzero(&hdr, sizeof (hdr));
	hdr.version = REPLICA_VERSION;
	hdr.opcode = ZVOL_OPCODE_START_REBUILD;
	hdr.len = size;
	count = write(fd, (void *)&hdr, sizeof (zvol_io_hdr_t));
	if (count == -1) {
		printf("Start_rebuild: sending hdr failed\n");
		return (count);
	}

	count = write(fd, (char *)mgmt_ack, hdr.len);
	if (count == -1) {
		printf("start_rebuild: sending volname failed\n");
		return (count);
	}
	return (0);
}

static void
reader_thread(void *arg)
{

	char *buf;
	int sfd, count;
	kmutex_t *mtx;
	kcondvar_t *cv;
	int *threads_done;
	int write_ack_cnt = 0;
	int read_ack_cnt = 0;
	int sync_ack_cnt = 0;
	zvol_io_hdr_t *hdr;
	struct zvol_io_rw_hdr read_hdr;
	worker_args_t *warg = (worker_args_t *)arg;

	mtx = warg->mtx;
	cv = warg->cv;
	threads_done = warg->threads_done;

	sfd = warg->sfd[0];
	hdr = kmem_alloc(sizeof (zvol_io_hdr_t), KM_SLEEP);
	buf = kmem_alloc(warg->io_block_size, KM_SLEEP);
	printf("Start reading ........\n");
	while (1) {
		if ((warg->max_iops == write_ack_cnt) &&
		    (warg->max_iops == read_ack_cnt) &&
		    sync_ack_cnt) {
			break;
		}
		count = read(sfd, (void *)hdr, sizeof (zvol_io_hdr_t));
		if (count == -1) {
			printf("Read error reader_thread\n");
			break;
		}

		if (hdr->opcode == ZVOL_OPCODE_SYNC) {
			sync_ack_cnt++;
			continue;
		}

		if (hdr->opcode == ZVOL_OPCODE_WRITE) {
			write_ack_cnt++;
			bzero(hdr, sizeof (zvol_io_hdr_t));
			continue;
		}

		if (hdr->opcode == ZVOL_OPCODE_READ) {
			int nbytes;
			char *p = buf;

			read_ack_cnt++;
			count = read(sfd, &read_hdr, sizeof (read_hdr));
			if (count != sizeof (read_hdr)) {
				printf("Meta data header read error\n");
				break;
			}
			nbytes = read_hdr.len;

			while (nbytes) {
				count = read(sfd, (void *)p, nbytes);
				if (count < 0) {
					printf("\n");
					printf("Read error in reader_thread "
					    "reading data\n");
				}
				p += count;
				nbytes -= count;
			}

			if (zrepl_verify_data(buf, warg->io_block_size) == -1) {
				printf("Read :%d bytes data\n", count);
				printf("Data mismatch\n");
			}
		}

		bzero(hdr, sizeof (zvol_io_hdr_t));
		bzero(buf, warg->io_block_size);
	}

	printf("Total iops requested:%d, total write acks%d,"
	    " total read acks: %d total sync acks:%d\n",
	    warg->max_iops, write_ack_cnt, read_ack_cnt, sync_ack_cnt);
	free(hdr);
	free(buf);
	mutex_enter(mtx);
	*threads_done = *threads_done + 1;
	cv_signal(cv);
	mutex_exit(mtx);
	zk_thread_exit();
}

static void
writer_thread(void *arg)
{

	int i = 0;
	int sfd, sfd1;
	int count = 0;
	int nbytes = 0;
	kmutex_t *mtx;
	kcondvar_t *cv;
	int *threads_done;
	struct data_io *io;
	worker_args_t *warg = (worker_args_t *)arg;

	sfd = warg->sfd[0];
	sfd1 = warg->sfd[1];
	mtx = warg->mtx;
	cv = warg->cv;
	threads_done = warg->threads_done;

	io = kmem_alloc((sizeof (struct data_io) +
	    warg->io_block_size), KM_SLEEP);
	printf("Dataset generation start........... \n");

	io->hdr.version = REPLICA_VERSION;
	io->hdr.opcode = ZVOL_OPCODE_HANDSHAKE;
	io->hdr.len    = strlen(ds) + 1;
	strncpy(io->buf, ds, io->hdr.len);

	count = write(sfd, (void *)&(io->hdr), sizeof (zvol_io_hdr_t));
	if (count == -1) {
		printf("Sending HDR failed\n");
		goto exit;
	}

	count = write(sfd, (void *)(io->buf), io->hdr.len);
	if (count == -1) {
		printf("Sending volname is failed\n");
		goto exit;
	}

	if (warg->rebuild_test == B_TRUE) {
		io->hdr.len = strlen(ds1) + 1;
		strncpy(io->buf, ds1, io->hdr.len);

		count = write(sfd1, (void *)&(io->hdr), sizeof (zvol_io_hdr_t));
		if (count == -1) {
			printf("Sending HDR failed\n");
			goto exit;
		}

		count = write(sfd1, (void *)(io->buf), io->hdr.len);
		if (count == -1) {
			printf("Sending volname is failed\n");
			goto exit;
		}
	}
	bzero(io, sizeof (struct data_io));
	populate(io->buf, warg->io_block_size);

	printf("Start writing ........\n");
	/* Write data */
	while (i < warg->max_iops) {
		io->hdr.version = REPLICA_VERSION;
		io->hdr.opcode = ZVOL_OPCODE_WRITE;
		io->hdr.checkpointed_io_seq = io->hdr.io_seq = i + 1;
		io->hdr.len = sizeof (struct zvol_io_rw_hdr) +
		    warg->io_block_size;
		io->hdr.status = 0;
		io->hdr.flags = 0;
		io->hdr.offset = nbytes;
		io->rw_hdr.len = warg->io_block_size;
		io->rw_hdr.io_num = i + 1;

		int bytes = sizeof (struct data_io) + warg->io_block_size;
		char *p = (char *)io;
		while (bytes) {
			count = write(sfd, (void *)p, bytes);
			if (count == -1) {
				printf("Write error\n");
				break;
			}
			bytes -= count;
			p += count;
		}

		if ((warg->rebuild_test == B_TRUE) &&
		    (i < (warg->max_iops / 2))) {
			bytes = sizeof (struct data_io) + warg->io_block_size;
			p = (char *)io;
			while (bytes) {
				count = write(sfd1, (void *)p, bytes);
				if (count == -1) {
					printf("Write error\n");
					break;
				}
				bytes -= count;
				p += count;
			}
		}
		nbytes += warg->io_block_size;
		i++;
		last_io_seq_sent = io->hdr.checkpointed_io_seq;
	}

	io->hdr.version = REPLICA_VERSION;
	io->hdr.opcode = ZVOL_OPCODE_SYNC;
	count = write(sfd, (void *)&io->hdr, sizeof (io->hdr));
	if (count == -1) {
		printf("Error sending sync on ds0\n");
		goto exit;
	}

	if (warg->rebuild_test == B_TRUE) {
		count = write(sfd1, (void *)&io->hdr, sizeof (io->hdr));
		if (count == -1) {
			printf("Error sending sync on ds1\n");
			goto exit;
		}
	}
	/* Read and validate data */
	i = 0;
	nbytes = 0;
	bzero(io, sizeof (struct data_io));
	while (i < warg->max_iops) {
		io->hdr.version = REPLICA_VERSION;
		io->hdr.opcode = ZVOL_OPCODE_READ;
		io->hdr.io_seq = i;
		io->hdr.len    = warg->io_block_size;
		io->hdr.status = 0;
		io->hdr.flags = 0;
		io->hdr.offset = nbytes;

		count = write(sfd, (void *)&io->hdr, sizeof (zvol_io_hdr_t));
		if (count == -1) {
			printf("Write error\n");
			break;
		}

		if ((warg->rebuild_test == B_TRUE) &&
		    (i < (warg->max_iops / 2))) {
			count = write(sfd1, (void *)&io->hdr,
			    sizeof (zvol_io_hdr_t));
			if (count == -1) {
				printf("Write error\n");
				break;
			}
		}
		nbytes += warg->io_block_size;
		i++;
	}
	printf("Dataset generation completed.....\n");
exit:
	free(io);
	mutex_enter(mtx);
	*threads_done = *threads_done + 1;
	cv_signal(cv);
	mutex_exit(mtx);
	zk_thread_exit();
}

static void
replica_data_verify_thread(void *arg)
{

	int i = 0;
	char *p;
	char *buf1;
	char *buf2;
	int sfd, sfd1;
	int count = 0;
	int nbytes = 0;
	int read_bytes = 0;
	kmutex_t *mtx;
	kcondvar_t *cv;
	zvol_io_hdr_t hdr;
	struct zvol_io_rw_hdr *read_hdr1;
	struct zvol_io_rw_hdr *read_hdr2;
	int *threads_done;
	worker_args_t *warg = (worker_args_t *)arg;

	sfd = warg->sfd[0];
	sfd1 = warg->sfd[1];
	mtx = warg->mtx;
	cv = warg->cv;
	threads_done = warg->threads_done;

	/* Read and validate data */
	i = 0;
	nbytes = 0;
	while (i < warg->max_iops) {
		bzero(&hdr, sizeof (zvol_io_hdr_t));

		/* Construct hdr for read request */
		hdr.version = REPLICA_VERSION;
		hdr.opcode = ZVOL_OPCODE_READ;
		hdr.io_seq = i;
		hdr.len    = warg->io_block_size;
		hdr.offset = nbytes;

		/* Read request to replica ds0 */
		count = write(sfd, (void *)&hdr, sizeof (zvol_io_hdr_t));
		if (count == -1) {
			printf("Write error\n");
			break;
		}

		/* Read request to replica ds1 */
		count = write(sfd1, (void *)&hdr, sizeof (zvol_io_hdr_t));
		if (count == -1) {
			printf("Write error\n");
			break;
		}

		nbytes += warg->io_block_size;
		i++;

		/* Read hdr from replica ds0(sfd) */
		count = read(sfd, &hdr, sizeof (zvol_io_hdr_t));
		if (count != sizeof (zvol_io_hdr_t)) {
			printf("Header read error\n");
			break;
		}

		read_bytes = hdr.len;
		buf1 = kmem_alloc(read_bytes, KM_SLEEP);
		p = buf1;

		/* Read data from replica ds0(sfd) */
		while (read_bytes) {
			count = read(sfd, (void *)p, nbytes);
			if (count < 0) {
				printf("\n");
				printf("Read error in reader_thread "
				    "reading data\n");
			}
			p += count;
			read_bytes -= count;
		}

		/* Read hdr from replica ds1(sfd1) */
		count = read(sfd1, &hdr, sizeof (zvol_io_hdr_t));
		if (count != sizeof (zvol_io_hdr_t)) {
			printf("Meta data header read error\n");
			break;
		}

		read_bytes = hdr.len;
		buf2 = kmem_alloc(read_bytes, KM_SLEEP);
		p = buf2;

		/* Read data from replica ds1(sfd1) */
		while (read_bytes) {
			count = read(sfd1, (void *)p, nbytes);
			if (count < 0) {
				printf("\n");
				printf("Read error in reader_thread "
				    "reading data\n");
			}
			p += count;
			read_bytes -= count;
		}

		read_hdr1 = (struct zvol_io_rw_hdr *)buf1;
		read_hdr2 = (struct zvol_io_rw_hdr *)buf2;
		/* Compare io_num, should be same */
		if (read_hdr1->io_num != read_hdr2->io_num) {
			ASSERT(!"IO Number mismatch\n");
		}

		/* Compare len, should be same */
		if (read_hdr1->len != read_hdr2->len) {
			ASSERT(!"IO length mismatch\n");
		}

		count = zrepl_compare_data(buf1 +
		    sizeof (struct zvol_io_rw_hdr),
		    buf2 + sizeof (struct zvol_io_rw_hdr), read_hdr1->len);
		if (count != 0) {
			ASSERT(!"Data mistmach mismatch\n");
		}

		kmem_free(buf1, hdr.len);
		kmem_free(buf2, hdr.len);
	}

	mutex_enter(mtx);
	*threads_done = *threads_done + 1;
	cv_signal(cv);
	mutex_exit(mtx);
	zk_thread_exit();
}

void
zrepl_utest(void *arg)
{
	kmutex_t mtx;
	kcondvar_t cv;
	int count, sfd, rc;
	int  io_sfd, new_fd;
	int threads_done = 0;
	int num_threads = 0;
	kthread_t *reader;
	kthread_t *writer;
	socklen_t in_len;
	mgmt_ack_t mgmt_ack;
	zrepl_status_ack_t status_ack;
	struct sockaddr in_addr;
	struct sockaddr_in replica_io_addr;
	worker_args_t writer_args, reader_args;

	io_block_size = 4096;
	active_size = 0;
	max_iops = 10000;
	pool = "testp";
	ds = "ds0";

	io_sfd = new_fd = sfd = -1;
	mutex_init(&mtx, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&cv, NULL, CV_DEFAULT, NULL);

	writer_args.threads_done = &threads_done;
	writer_args.mtx = &mtx;
	writer_args.cv = &cv;
	writer_args.io_block_size = io_block_size;
	writer_args.active_size = active_size;
	writer_args.max_iops = max_iops;
	writer_args.rebuild_test = B_FALSE;

	reader_args.threads_done = &threads_done;
	reader_args.mtx = &mtx;
	reader_args.cv = &cv;
	reader_args.io_block_size = io_block_size;
	reader_args.active_size = active_size;
	reader_args.max_iops = max_iops;
	reader_args.rebuild_test = B_FALSE;


	sfd = create_and_bind(tgt_port, B_TRUE, B_FALSE);
	if (sfd == -1) {
		return;
	}

	rc = listen(sfd, 10);
	if (rc == -1) {
		printf("listen() failed with errno:%d\n", rc);
		goto exit;
	}
	printf("Listen was successful\n");

start:
	in_len = sizeof (in_addr);
	new_fd = accept(sfd, &in_addr, &in_len);
	if (new_fd == -1) {
		printf("Unable to accept\n");
		goto exit;
	}

	printf("Connection accepted from replica successfully\n");
	count = zrepl_utest_replica_handshake(ds, new_fd, &mgmt_ack);
	if (count == -1) {
		goto exit;
	}

	printf("Vol name: %s\n", mgmt_ack.volname);
	printf("IP address: %s\n", mgmt_ack.ip);
	printf("Port: %d\n", mgmt_ack.port);

	bzero((char *)&replica_io_addr, sizeof (replica_io_addr));

	replica_io_addr.sin_family = AF_INET;
	replica_io_addr.sin_addr.s_addr = inet_addr(mgmt_ack.ip);
	replica_io_addr.sin_port = htons(mgmt_ack.port);
retry:
	io_sfd = create_and_bind("", B_FALSE, B_FALSE);
	if (io_sfd == -1) {
		printf("Socket creation failed with errno:%d\n", errno);
		goto start;
	}
	rc = connect(io_sfd, (struct sockaddr *)&replica_io_addr,
	    sizeof (replica_io_addr));
	if (rc == -1) {
		printf("Failed to connect to replica-IO port"
		    " with errno:%d\n", errno);
		close(io_sfd);
		sleep(1);
		goto retry;
	}
	printf("Connect to replica IO port is successfully\n");

	writer_args.sfd[0] = reader_args.sfd[0] = io_sfd;
	rc = zrepl_utest_get_replica_status(ds, new_fd, &status_ack);
	if (rc == -1) {
		goto exit;
	}

	if (status_ack.state != ZVOL_STATUS_HEALTHY) {
		printf("Volume:%s health status: NOT_HEALTHY\n", ds);
		strncpy(mgmt_ack.dw_volname, ds, sizeof (mgmt_ack.dw_volname));
		strncpy(mgmt_ack.volname, "", sizeof (mgmt_ack.volname));
		rc = zrepl_utest_replica_rebuild_start(new_fd, &mgmt_ack,
		    sizeof (mgmt_ack_t));
		if (rc == -1) {
			goto exit;
		}
	}

check_status:
	rc = zrepl_utest_get_replica_status(ds, new_fd, &status_ack);
	if (rc == -1) {
		goto exit;
	}

	if (status_ack.state != ZVOL_STATUS_HEALTHY) {
		sleep(1);
		goto check_status;
	}
	printf("Volume:%s health status: HEALTHY\n", ds);
	writer = zk_thread_create(NULL, 0,
	    (thread_func_t)writer_thread, &writer_args, 0, NULL,
	    TS_RUN, 0, PTHREAD_CREATE_DETACHED);
	num_threads++;
	reader = zk_thread_create(NULL, 0, (thread_func_t)reader_thread,
	    &reader_args, 0, NULL, TS_RUN, 0, PTHREAD_CREATE_DETACHED);
	num_threads++;
	printf("Write_func thread created successfully\n");
	mutex_enter(&mtx);
	while (threads_done != num_threads)
		cv_wait(&cv, &mtx);
	mutex_exit(&mtx);
	cv_destroy(&cv);
	mutex_destroy(&mtx);
exit:
	if (sfd != -1) {
		close(sfd);
	}

	if (new_fd != -1) {
		close(new_fd);
	}

	if (io_sfd != -1) {
		close(io_sfd);
	}
}

/*
 * Rebuilding downgraded replica test case. It covers following case:
 * =====Rebuild success case=====
 * Details:
 * - Two replicas, ds0 a healthy while ds1 will be downgrade replica
 * - Replica ds0 is marked as healthy replica in the beginning
 * - 10K IOs of size 4k pumped into ds0
 * - 5k IOs of size 4k (with same data) will be pumped into ds1
 * - Trigger rebuild workflow on ds1 using IP + Rebuild_port of ds0
 * - Wait for ds1 to be marked healthy
 * - Now read each block from ds0 and ds1, compare IO_seq and data.
 *
 * =====Multiple Rebuild success case=====
 * Details:
 * - Two replicas ds0 and ds1 are healthy
 * - ds2 downgrade replica
 * - Trigger rebuild workflow on ds2 using IP + Rebuild_port of ds0 & ds1
 * - Rebuild will be triggered successfully on ds0 & ds1
 * - Wait till ds2 become healthy
 *
 * =====Rebuild failure case=====
 * - Replicas ds0i, ds1 and ds2 are healthy
 * - ds3 downgrade replica
 * - Trigger rebuild workflow on ds3 using IP + Rebuild_port of ds0, ds1 and ds2
 * - Pass wrong IP address for ds2 so that connection got failed
 * - Rebuild will be triggered successfully on ds0 and ds1 but would fail on ds2
 * - Since rebuild would fail on ds2, all rebuild operation happening in
 *   parallel should be stopped and ds2 should be left in downgrade mode.
 */
void
zrepl_rebuild_test(void *arg)
{
	kmutex_t mtx;
	kcondvar_t cv;
	int i, count, sfd, rc;
	int  io_sfd, io_sfd1, new_fd;
	int threads_done = 0;
	int num_threads = 0;
	kthread_t *reader[2];
	kthread_t *writer;
	socklen_t in_len;
	zvol_io_hdr_t hdr;
	mgmt_ack_t *mgmt_ack = NULL;
	mgmt_ack_t *mgmt_ack_ds2 = NULL;
	mgmt_ack_t *mgmt_ack_ds3 = NULL;
	struct sockaddr in_addr;
	zrepl_status_ack_t status_ack;
	struct sockaddr_in replica_io_addr;
	worker_args_t writer_args, reader_args[2];

	io_block_size = 4096;
	active_size = 0;
	max_iops = 2000;
	pool = "testp";
	ds = "ds0";
	ds1 = "ds1";

	io_sfd = io_sfd1 = new_fd = sfd = -1;
	mutex_init(&mtx, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&cv, NULL, CV_DEFAULT, NULL);

	writer_args.threads_done = &threads_done;
	writer_args.mtx = &mtx;
	writer_args.cv = &cv;
	writer_args.io_block_size = io_block_size;
	writer_args.active_size = active_size;
	writer_args.max_iops = max_iops;
	writer_args.rebuild_test = B_TRUE;

	reader_args[0].threads_done = &threads_done;
	reader_args[0].mtx = &mtx;
	reader_args[0].cv = &cv;
	reader_args[0].io_block_size = io_block_size;
	reader_args[0].active_size = active_size;
	reader_args[0].max_iops = max_iops;
	reader_args[0].rebuild_test = B_FALSE;

	reader_args[1].threads_done = &threads_done;
	reader_args[1].mtx = &mtx;
	reader_args[1].cv = &cv;
	reader_args[1].io_block_size = io_block_size;
	reader_args[1].active_size = active_size;
	reader_args[1].max_iops = max_iops / 2;
	reader_args[1].rebuild_test = B_TRUE;

	sfd = create_and_bind(tgt_port, B_TRUE, B_FALSE);
	if (sfd == -1) {
		return;
	}

	rc = listen(sfd, 10);
	if (rc == -1) {
		printf("listen() failed with errno:%d\n", rc);
		goto exit;
	}
	printf("Listen was successful\n");

start:
	in_len = sizeof (in_addr);
	new_fd = accept(sfd, &in_addr, &in_len);
	if (new_fd == -1) {
		printf("Unable to accept\n");
		goto exit;
	}
	printf("Connection accepted from replica successfully\n");

	/* Handshake for replica ds0 */
	mgmt_ack = umem_alloc(sizeof (mgmt_ack_t), UMEM_NOFAIL);
	count = zrepl_utest_replica_handshake(ds, new_fd, mgmt_ack);
	if (count == -1) {
		goto exit;
	}

	printf("Vol name: %s\n", mgmt_ack->volname);
	printf("IP address: %s\n", mgmt_ack->ip);
	printf("Port: %d\n", mgmt_ack->port);

	bzero((char *)&replica_io_addr, sizeof (replica_io_addr));

	replica_io_addr.sin_family = AF_INET;
	replica_io_addr.sin_addr.s_addr = inet_addr(mgmt_ack->ip);
	replica_io_addr.sin_port = htons(mgmt_ack->port);
retry:
	/* Data connection for ds0 */
	io_sfd = create_and_bind("", B_FALSE, B_FALSE);
	if (io_sfd == -1) {
		printf("Socket creation failed with errno:%d\n", errno);
		goto start;
	}
	rc = connect(io_sfd, (struct sockaddr *)&replica_io_addr,
	    sizeof (replica_io_addr));
	if (rc == -1) {
		printf("Failed to connect to replica-IO port"
		    " with errno:%d\n", errno);
		close(io_sfd);
		sleep(1);
		goto retry;
	}
	printf("Connect to replica IO port is successfully\n");

	writer_args.sfd[0] = reader_args[0].sfd[0] = io_sfd;

	/* Data connection for ds1  */
	io_sfd1 = create_and_bind("", B_FALSE, B_FALSE);
	if (io_sfd1 == -1) {
		printf("Socket creation failed with errno:%d\n", errno);
		goto start;
	}
	rc = connect(io_sfd1, (struct sockaddr *)&replica_io_addr,
	    sizeof (replica_io_addr));
	if (rc == -1) {
		printf("Failed to connect to replica-IO port"
		    " with errno:%d\n", errno);
		sleep(1);
		close(io_sfd1);
		goto retry;
	}
	printf("Connect to replica IO port is successfully\n");

	/* Check status of replica ds0 */
	rc = zrepl_utest_get_replica_status(ds, new_fd, &status_ack);
	if (rc == -1) {
		goto exit;
	}

	/*
	 * If replica ds0 status is not healthy then trigger rebuild
	 * on ds0, without any target(healthy replica).
	 */
	if (status_ack.state != ZVOL_STATUS_HEALTHY) {
		printf("Volume:%s health status: NOT_HEALTHY\n", ds);
		strncpy(mgmt_ack->dw_volname, ds,
		    sizeof (mgmt_ack->dw_volname));
		strncpy(mgmt_ack->volname, "", sizeof (mgmt_ack->volname));
		rc = zrepl_utest_replica_rebuild_start(new_fd, mgmt_ack,
		    sizeof (mgmt_ack_t));
		if (rc == -1) {
			goto exit;
		}
	}

check_status:
	rc = zrepl_utest_get_replica_status(ds, new_fd, &status_ack);
	if (rc == -1) {
		goto exit;
	}

	if (status_ack.state != ZVOL_STATUS_HEALTHY) {
		sleep(1);
		goto check_status;
	}
	printf("Volume:%s health status: HEALTHY\n", ds);

	/* Start writing data to both replicas */
	writer_args.sfd[1] = reader_args[1].sfd[0] = io_sfd1;
	writer = zk_thread_create(NULL, 0,
	    (thread_func_t)writer_thread, &writer_args, 0, NULL,
	    TS_RUN, 0, PTHREAD_CREATE_DETACHED);
	num_threads++;
	printf("Write_func thread created successfully\n");

	reader[0] = zk_thread_create(NULL, 0, (thread_func_t)reader_thread,
	    &reader_args[0], 0, NULL, TS_RUN, 0, PTHREAD_CREATE_DETACHED);
	num_threads++;
	printf("Reader_func thread-0 created successfully\n");

	reader[1] = zk_thread_create(NULL, 0, (thread_func_t)reader_thread,
	    &reader_args[1], 0, NULL, TS_RUN, 0, PTHREAD_CREATE_DETACHED);
	num_threads++;
	printf("Reader_func thread-1 created successfully\n");
	mutex_enter(&mtx);
	while (threads_done != num_threads)
		cv_wait(&cv, &mtx);
	mutex_exit(&mtx);
	num_threads = threads_done = 0;
	/* Start rebuilding operation on ds1 from ds0 */

	/*
	 * Send ZVOL_OPCODE_PREPARE_FOR_REBUILD op_code
	 * to healthy replica ds0 and get rebuild_io port
	 * and ip from healthy replica ds0.
	 */
	hdr.version = REPLICA_VERSION;
	hdr.opcode = ZVOL_OPCODE_PREPARE_FOR_REBUILD;
	hdr.len = strlen(ds)+1;
	count = write(new_fd, (void *)&hdr, sizeof (zvol_io_hdr_t));
	if (count == -1) {
		printf("Prepare_for_rebuild: sending hdr failed\n");
		goto exit;
	}

	count = write(new_fd, ds, hdr.len);
	if (count == -1) {
		printf("Prepare_for_rebuild: sending volname failed\n");
		goto exit;
	}


	count = read(new_fd, (void *)&hdr, sizeof (zvol_io_hdr_t));
	if (count == -1) {
		printf("Prepare_for_rebuild: error in hdr read\n");
		goto exit;
	}

	count = read(new_fd, (void *)mgmt_ack, hdr.len);
	if (count == -1) {
		printf("Prepare_for_rebuild: error in mgmt_ack read\n");
		goto exit;
	}

	/* Copy downgraded replica (ds1) name in mgmt_ack */
	strncpy(mgmt_ack->dw_volname, ds1, sizeof (mgmt_ack->dw_volname));

	printf("Replica being rebuild is: %s\n", mgmt_ack->dw_volname);
	printf("Replica helping rebuild is: %s\n", mgmt_ack->volname);
	printf("Rebuilding IP address: %s\n", mgmt_ack->ip);
	printf("Rebuilding Port: %d\n", mgmt_ack->port);

	/*
	 * Start rebuild process on downgraded replica ds1
	 * by sharing IP and rebuild_Port info with ds1.
	 */
	rc = zrepl_utest_replica_rebuild_start(new_fd, mgmt_ack,
	    sizeof (mgmt_ack_t));
	if (rc == -1) {
		goto exit;
	}
	/*
	 * Check rebuild status of of downgrade replica ds1.
	 */
status_check:
	count = zrepl_utest_get_replica_status(ds1, new_fd, &status_ack);
	if (count == -1) {
		goto exit;
	}

	if (status_ack.state != ZVOL_STATUS_HEALTHY) {
		sleep(1);
		goto status_check;
	}
	printf("Replica:%s is healthy now\n", ds1);

	/* Verify if the data is same on both replica or not */
	writer = zk_thread_create(NULL, 0,
	    (thread_func_t)replica_data_verify_thread, &writer_args, 0, NULL,
	    TS_RUN, 0, PTHREAD_CREATE_DETACHED);
	num_threads++;
	mutex_enter(&mtx);
	while (threads_done != num_threads)
		cv_wait(&cv, &mtx);
	mutex_exit(&mtx);
	cv_destroy(&cv);
	mutex_destroy(&mtx);

	/* Start rebuilding operation on ds2 from ds0 and ds1 */

	/*
	 * mgmt_ack has IP + Rebuild_port for ds0, copy it
	 * to mgmt_ack_ds2, send ZVOL_OPCODE_PREPARE_FOR_REBUILD
	 * op_code to healthy replicas ds1, get rebuild_io port
	 * and ip. Copy it to mgmt_ack_ds2.
	 */
	mgmt_ack_ds2 = umem_alloc(sizeof (mgmt_ack_t) * 2, UMEM_NOFAIL);
	bcopy(mgmt_ack, mgmt_ack_ds2, sizeof (mgmt_ack_t));

	/* Modify dw_replica name to ds2 now */
	strncpy(mgmt_ack_ds2->dw_volname, ds2,
	    sizeof (mgmt_ack_ds2->dw_volname));

	hdr.version = REPLICA_VERSION;
	hdr.opcode = ZVOL_OPCODE_PREPARE_FOR_REBUILD;
	hdr.len = strlen(ds1)+1;
	count = write(new_fd, (void *)&hdr, sizeof (zvol_io_hdr_t));
	if (count == -1) {
		printf("Prepare_for_rebuild: sending hdr failed\n");
		goto exit;
	}

	count = write(new_fd, ds1, hdr.len);
	if (count == -1) {
		printf("Prepare_for_rebuild: sending volname failed\n");
		goto exit;
	}


	count = read(new_fd, (void *)&hdr, sizeof (zvol_io_hdr_t));
	if (count == -1) {
		printf("Prepare_for_rebuild: error in hdr read\n");
		goto exit;
	}

	count = read(new_fd, (void *)mgmt_ack, hdr.len);
	if (count == -1) {
		printf("Prepare_for_rebuild: error in mgmt_ack read\n");
		goto exit;
	}
	mgmt_ack_t *p = mgmt_ack_ds2;
	p++;
	bcopy(mgmt_ack, p, sizeof (mgmt_ack_t));
	/* Modify dw_replica name to ds2 now */
	strncpy(p->dw_volname, ds2, sizeof (p->dw_volname));

	p = mgmt_ack_ds2;
	for (i = 0; i < 2; i++) {
		printf("Replica being rebuild is: %s\n", p->dw_volname);
		printf("Replica helping rebuild is: %s\n", p->volname);
		printf("Rebuilding IP address: %s\n", p->ip);
		printf("Rebuilding Port: %d\n", p->port);
		p++;
	}

	/*
	 * Start rebuild process on downgraded replica ds2
	 * by sharing IP and rebuild_Port info with ds2.
	 */
	rc = zrepl_utest_replica_rebuild_start(new_fd, mgmt_ack_ds2,
	    sizeof (mgmt_ack_t) * 2);
	if (rc == -1) {
		goto exit;
	}
	/*
	 * Check rebuild status of ds2.
	 */
status_check1:
	count = zrepl_utest_get_replica_status(ds2, new_fd, &status_ack);
	if (count == -1) {
		goto exit;
	}

	if (status_ack.state != ZVOL_STATUS_HEALTHY) {
		sleep(1);
		goto status_check1;
	}
	printf("Replica:%s is healthy now\n", ds2);

	/* Start rebuilding operation on ds3 from ds0, ds1 and ds2 */

	/*
	 * Copy mgmt_ack_ds2 to mgmt_ack_ds3, mgmt_ack_ds2 has
	 * IP + rebuild_port info of ds0, ds1. Send
	 * ZVOL_OPCODE_PREPARE_FOR_REBUILD op_code ds2.
	 * Copy that too to mgmt_ack_ds3.
	 */
	mgmt_ack_ds3 = umem_alloc(sizeof (mgmt_ack_t) * 3, UMEM_NOFAIL);
	bcopy(mgmt_ack_ds2, mgmt_ack_ds3, sizeof (mgmt_ack_t) * 2);

	hdr.version = REPLICA_VERSION;
	hdr.opcode = ZVOL_OPCODE_PREPARE_FOR_REBUILD;
	hdr.len = strlen(ds2)+1;
	count = write(new_fd, (void *)&hdr, sizeof (zvol_io_hdr_t));
	if (count == -1) {
		printf("Prepare_for_rebuild: sending hdr failed\n");
		goto exit;
	}

	count = write(new_fd, ds2, hdr.len);
	if (count == -1) {
		printf("Prepare_for_rebuild: sending volname failed\n");
		goto exit;
	}


	count = read(new_fd, (void *)&hdr, sizeof (zvol_io_hdr_t));
	if (count == -1) {
		printf("Prepare_for_rebuild: error in hdr read\n");
		goto exit;
	}

	count = read(new_fd, (void *)mgmt_ack, hdr.len);
	if (count == -1) {
		printf("Prepare_for_rebuild: error in mgmt_ack read\n");
		goto exit;
	}

	p = mgmt_ack_ds3;
	p++; p++;
	bcopy(mgmt_ack, p, sizeof (mgmt_ack_t));

	p = mgmt_ack_ds3;
	for (i = 0; i < 3; i++) {
		/* Modify downgrade replica and set it to ds3 */
		strncpy(p->dw_volname, ds3, sizeof (p->dw_volname));
		printf("Replica being rebuild is: %s\n", p->dw_volname);
		printf("Replica helping rebuild is: %s\n", p->volname);
		printf("Rebuilding IP address: %s\n", p->ip);
		printf("Rebuilding Port: %d\n", p->port);
		if (i == 2) {
			/* For ds2, assign wrong port, so that rebuild fail */
			p->port = 9999;
		}
		p++;
	}

	/*
	 * Start rebuild process on downgraded replica ds3
	 * by sharing IP and rebuild_Port info with ds3.
	 */
	rc = zrepl_utest_replica_rebuild_start(new_fd, mgmt_ack_ds3,
	    sizeof (mgmt_ack_t) * 3);
	if (rc == -1) {
		goto exit;
	}
	/*
	 * Check rebuild status of ds3.
	 */
status_check2:
	count = zrepl_utest_get_replica_status(ds3, new_fd, &status_ack);
	if (count == -1) {
		goto exit;
	}

	if (status_ack.rebuild_status != ZVOL_REBUILDING_FAILED) {
		sleep(1);
		goto status_check2;
	}

	printf("Rebuilding failed on Replica:%s\n", ds3);
exit:
	if (sfd != -1)
		close(sfd);

	if (new_fd != -1)
		close(new_fd);

	if (io_sfd != -1)
		close(io_sfd);

	if (io_sfd1 != -1)
		close(io_sfd1);

	if (mgmt_ack != NULL)
		umem_free(mgmt_ack, sizeof (mgmt_ack_t));
	if (mgmt_ack_ds2 != NULL)
		umem_free(mgmt_ack_ds2, sizeof (mgmt_ack_t) * 2);
	if (mgmt_ack_ds3 != NULL)
		umem_free(mgmt_ack_ds3, sizeof (mgmt_ack_t) * 3);
}
