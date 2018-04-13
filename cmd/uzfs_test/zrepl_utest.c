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
		io->hdr.len    = strlen(ds1) + 1;
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

void
zrepl_utest(void *arg)
{
	kmutex_t mtx;
	kcondvar_t cv;
	int count, sfd, rc;
	int  io_sfd, new_fd;
	int threads_done = 0;
	int num_threads = 0;
	int wrong_message = 1;
	kthread_t *reader;
	kthread_t *writer;
	socklen_t in_len;
	zvol_io_hdr_t hdr;
	mgmt_ack_t mgmt_ack;
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


	sfd = create_and_bind(tgt_port, B_TRUE);
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
	printf("Connection accepted from replica successful\n");

	hdr.version = REPLICA_VERSION;
	if (wrong_message) {
		hdr.opcode = -1;
		wrong_message = 0;
	} else {
		hdr.opcode = ZVOL_OPCODE_HANDSHAKE;
	}
	hdr.len = strlen(ds)+1;
	printf("Op code sent %d with len:%ld\n", hdr.opcode, hdr.len);

	count = write(new_fd, (void *)&hdr, sizeof (zvol_io_hdr_t));
	if (count == -1) {
		printf("During hand shake Write error\n");
		goto exit;
	}
	printf("header has been sent with count %d\n", count);

	count = write(new_fd, ds, hdr.len);
	if (count == -1) {
		printf("During name send Write error\n");
		goto exit;
	}
	printf("Volname has been sent with count %d\n", count);

	count = read(new_fd, (void *)&hdr, sizeof (zvol_io_hdr_t));
	if (count == -1) {
		printf("During hdr Read error\n");
		goto exit;
	}
	printf("Header has read with count %d\n", count);

	if (hdr.status == ZVOL_OP_STATUS_FAILED) {
		close(new_fd);
		printf("Header status is failed\n");
		goto start;
	}

	count = read(new_fd, (void *)&mgmt_ack, sizeof (mgmt_ack));
	if (count == -1) {
		printf("During mgmt Read error\n");
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
	io_sfd = create_and_bind("", B_FALSE);
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
		goto retry;
	}
	printf("Connect to replica IO port is successfully\n");

	writer_args.sfd[0] = reader_args.sfd[0] = io_sfd;
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

void
zrepl_rebuild_test(void *arg)
{
	kmutex_t mtx;
	kcondvar_t cv;
	int count, sfd, rc;
	int  io_sfd, io_sfd1, new_fd;
	int threads_done = 0;
	int num_threads = 0;
	int wrong_message = 1;
	kthread_t *reader[2];
	kthread_t *writer;
	socklen_t in_len;
	zvol_io_hdr_t hdr;
	mgmt_ack_t *mgmt_ack = NULL;
	struct sockaddr in_addr;
	zrepl_status_ack_t status_ack;
	struct sockaddr_in replica_io_addr;
	worker_args_t writer_args, reader_args[2];

	io_block_size = 4096;
	active_size = 0;
	max_iops = 10000;
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
	reader_args[1].max_iops = max_iops/2;
	reader_args[1].rebuild_test = B_TRUE;

	sfd = create_and_bind(tgt_port, B_TRUE);
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
	printf("Connection accepted from replica successful\n");

	hdr.version = REPLICA_VERSION;
	if (wrong_message) {
		hdr.opcode = -1;
		wrong_message = 0;
	} else {
		hdr.opcode = ZVOL_OPCODE_HANDSHAKE;
	}
	hdr.len = strlen(ds)+1;
	printf("Op code sent %d with len:%ld\n", hdr.opcode, hdr.len);

	count = write(new_fd, (void *)&hdr, sizeof (zvol_io_hdr_t));
	if (count == -1) {
		printf("During hand shake Write error\n");
		goto exit;
	}
	printf("header has been sent with count %d\n", count);

	count = write(new_fd, ds, hdr.len);
	if (count == -1) {
		printf("During name send Write error\n");
		goto exit;
	}
	printf("Volname has been sent with count %d\n", count);

	count = read(new_fd, (void *)&hdr, sizeof (zvol_io_hdr_t));
	if (count == -1) {
		printf("During hdr Read error\n");
		goto exit;
	}
	printf("Header has read with count %d\n", count);

	if (hdr.status == ZVOL_OP_STATUS_FAILED) {
		close(new_fd);
		printf("Header status is failed\n");
		goto start;
	}

	mgmt_ack = umem_alloc(sizeof (mgmt_ack_t), UMEM_NOFAIL);

	count = read(new_fd, (void *)mgmt_ack, hdr.len);
	if (count == -1) {
		printf("During mgmt Read error\n");
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
	io_sfd = create_and_bind("", B_FALSE);
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
		goto retry;
	}
	printf("Connect to replica IO port is successfully\n");

	writer_args.sfd[0] = reader_args[0].sfd[0] = io_sfd;

	io_sfd1 = create_and_bind("", B_FALSE);
	if (io_sfd1 == -1) {
		printf("Socket creation failed with errno:%d\n", errno);
		goto start;
	}
	rc = connect(io_sfd1, (struct sockaddr *)&replica_io_addr,
	    sizeof (replica_io_addr));
	if (rc == -1) {
		printf("Failed to connect to replica-IO port"
		    " with errno:%d\n", errno);
		close(io_sfd1);
		goto retry;
	}
	printf("Connect to replica IO port is successfully\n");

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
	cv_destroy(&cv);
	mutex_destroy(&mtx);
	/* Start rebuilding operation */
	/*
	 * Step1: Send ZVOL_OPCODE_PREPARE_FOR_REBUILD message to
	 * healthy replica and get rebuild_io port and ip from healthy
	 * replica. ds0 is healthy replica in this case.
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

	strncpy(mgmt_ack->dw_volname, ds1, sizeof (mgmt_ack->dw_volname));
	printf("Healthy replica: %s\n", mgmt_ack->volname);
	printf("Rebuilding IP address: %s\n", mgmt_ack->ip);
	printf("Rebuilding Port: %d\n", mgmt_ack->port);
	printf("Downgraded replica: %s\n", mgmt_ack->dw_volname);
	/*
	 * Step2: Send Rebuild IP address and Port to downgrade
	 * replica. In this case ds1 is downgraded replica.
	 */
	hdr.version = REPLICA_VERSION;
	hdr.opcode = ZVOL_OPCODE_START_REBUILD;
	hdr.len = sizeof (mgmt_ack_t);
	count = write(new_fd, (void *)&hdr, sizeof (zvol_io_hdr_t));
	if (count == -1) {
		printf("Start_rebuild: sending hdr failed\n");
		goto exit;
	}

	count = write(new_fd, (char *)mgmt_ack, hdr.len);
	if (count == -1) {
		printf("start_rebuild: sending volname failed\n");
		goto exit;
	}
	printf("Rebuilding on volume:%s started ....\n", ds1);
	/*
	 * Step3: Check rebuild status of ds1.
	 */
status_check:
	printf("Lets wait for healthy status of volume:%s\n", ds1);
	hdr.version = REPLICA_VERSION;
	hdr.opcode = ZVOL_OPCODE_REPLICA_STATUS;
	hdr.len = strlen(ds1) + 1;
	count = write(new_fd, (void *)&hdr, sizeof (zvol_io_hdr_t));
	if (count == -1) {
		printf("Rebuild_status: sending hdr failed\n");
		goto exit;
	}

	count = write(new_fd, ds1, hdr.len);
	if (count == -1) {
		printf("Rebuild_status: sending volname failed\n");
		goto exit;
	}

	count = read(new_fd, (void *)&hdr, sizeof (zvol_io_hdr_t));
	if (count == -1) {
		printf("Rebuild_status: error in hdr read\n");
		goto exit;
	}

	if (hdr.status != ZVOL_OP_STATUS_OK) {
		printf("Rebuild_status: response failed\n");
		goto exit;
	}

	count = read(new_fd, (void *)&status_ack, hdr.len);
	if (count == -1) {
		printf("Rebuild_status: error in mgmt_ack read\n");
		goto exit;
	}

	if (status_ack.state != ZVOL_STATUS_HEALTHY) {
		sleep(1);
		goto status_check;
	}
exit:
	printf("Replica is healthy now\n");
	if (sfd != -1) {
		close(sfd);
	}

	if (new_fd != -1) {
		close(new_fd);
	}

	if (io_sfd != -1)
		close(io_sfd);

	if (io_sfd1 != -1)
		close(io_sfd1);

	if (mgmt_ack != NULL)
		umem_free(mgmt_ack, sizeof (mgmt_ack_t));
}
