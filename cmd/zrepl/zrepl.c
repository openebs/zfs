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

#if DEBUG
inject_error_t	inject_error;
#endif

kthread_t	*conn_accpt_thread;
kthread_t	*uzfs_timer_thread;
kthread_t	*mgmt_conn_thread;

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

	if (getenv("CONFIG_LOAD_ENABLE") != NULL) {
		LOG_INFO("disabled auto import (reading of zpool.cache)");
		zfs_autoimport_disable = 0;
	} else {
		LOG_INFO("auto importing pools by reading zpool.cache files");
		zfs_autoimport_disable = 1;
	}

	SLIST_INIT(&uzfs_mgmt_conns);
	mutex_init(&conn_list_mtx, NULL, MUTEX_DEFAULT, NULL);
	mutex_init(&async_tasks_mtx, NULL, MUTEX_DEFAULT, NULL);

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
