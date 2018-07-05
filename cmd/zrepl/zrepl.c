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
#include <mgmt_conn.h>
#include <data_conn.h>

#include "zfs_events.h"

#define	ZAP_UPDATE_TIME_INTERVAL 2

extern unsigned long zfs_arc_max;
extern unsigned long zfs_arc_min;
extern int zfs_autoimport_disable;

static void uzfs_zvol_io_ack_sender(void *arg);

kthread_t	*conn_accpt_thread;
kthread_t	*uzfs_timer_thread;
kthread_t	*mgmt_conn_thread;
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

	prctl(PR_SET_NAME, "io_receiver", 0, 0, 0);

	/* First command should be OPEN */
	while (zinfo == NULL) {
		if (open_zvol(fd, &zinfo) != 0) {
			shutdown(fd, SHUT_RDWR);
			(void) close(fd);
			LOG_INFO("Data connection closed");
			zk_thread_exit();
			return;
		}
	}
	LOG_INFO("Data connection associated with zvol %s", zinfo->name);

	while ((rc = uzfs_zvol_socket_read(fd, (char *)&hdr, sizeof (hdr))) ==
	    0) {
		if ((zinfo->state == ZVOL_INFO_STATE_OFFLINE))
			break;

		if (hdr.opcode != ZVOL_OPCODE_WRITE &&
		    hdr.opcode != ZVOL_OPCODE_READ &&
		    hdr.opcode != ZVOL_OPCODE_SYNC) {
			LOG_ERR("Unexpected opcode %d", hdr.opcode);
			break;
		}

		if (((hdr.opcode == ZVOL_OPCODE_WRITE) ||
		    (hdr.opcode == ZVOL_OPCODE_READ)) && !hdr.len) {
			LOG_ERR("Zero Payload size for opcode %d", hdr.opcode);
			break;
		} else if ((hdr.opcode == ZVOL_OPCODE_SYNC) && hdr.len > 0) {
			LOG_ERR("Unexpected payload for opcode %d", hdr.opcode);
			break;
		}

		zio_cmd = zio_cmd_alloc(&hdr, fd);
		/* Read payload for commands which have it */
		if (hdr.opcode == ZVOL_OPCODE_WRITE) {
			rc = uzfs_zvol_socket_read(fd, zio_cmd->buf, hdr.len);
			if (rc != 0) {
				zio_cmd_free(&zio_cmd);
				break;
			}
		}

		if (zinfo->state == ZVOL_INFO_STATE_OFFLINE) {
			zio_cmd_free(&zio_cmd);
			goto exit;
		}
		/* Take refcount for uzfs_zvol_worker to work on it */
		uzfs_zinfo_take_refcnt(zinfo, B_FALSE);
		zio_cmd->zv = zinfo;
		taskq_dispatch(zinfo->uzfs_zvol_taskq, uzfs_zvol_worker,
		    zio_cmd, TQ_SLEEP);
	}

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

	prctl(PR_SET_NAME, "ack_sender", 0, 0, 0);

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
	LOG_INFO("Data connection for zvol %s closed", zinfo->name);
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
zrepl_svc_run(void)
{
	mgmt_conn_thread = zk_thread_create(NULL, 0,
	    uzfs_zvol_mgmt_thread, NULL, 0, NULL,
	    TS_RUN, 0, PTHREAD_CREATE_DETACHED);
	VERIFY3P(mgmt_conn_thread, !=, NULL);

	conn_accpt_thread = zk_thread_create(NULL, 0,
	    uzfs_zvol_io_conn_acceptor, NULL, 0, NULL, TS_RUN,
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
static void
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
static void
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

	io_server_port = IO_SERVER_PORT;
	rebuild_io_server_port = REBUILD_IO_SERVER_PORT;

	io_receiver = uzfs_zvol_io_receiver;
	rebuild_scanner = uzfs_zvol_rebuild_scanner;

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
	zrepl_monitor_errors();

initialize_error:
	uzfs_fini();
	return (-1);
}
