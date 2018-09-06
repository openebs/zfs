#include <arpa/inet.h>
#include <netdb.h>
#include <sys/zil.h>
#include <sys/zfs_rlock.h>
#include <sys/uzfs_zvol.h>
#include <sys/dnode.h>
#include <zrepl_mgmt.h>
#include <uzfs_mgmt.h>
#include <mgmt_conn.h>
#include <uzfs_zap.h>
#include <uzfs_io.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#define	ZVOL_THREAD_STACKSIZE (2 * 1024 * 1024)

__thread char  tinfo[20] =  {0};
clockid_t clockid;
void (*zinfo_create_hook)(zvol_info_t *, nvlist_t *);
void (*zinfo_destroy_hook)(zvol_info_t *);

struct zvol_list zvol_list;

static int uzfs_zinfo_free(zvol_info_t *zinfo);

enum zrepl_log_level zrepl_log_level;

/*
 * Log message to stdout/stderr if log level allows it.
 */
void
zrepl_log(enum zrepl_log_level lvl, const char *fmt, ...)
{
	va_list args;
	struct timeval tv;
	struct tm *timeinfo;
	unsigned int ms;
	char line[512];
	int off = 0;

	if (lvl < zrepl_log_level)
		return;

	/* Create timestamp prefix */
	gettimeofday(&tv, NULL);
	timeinfo = localtime(&tv.tv_sec);
	ms = tv.tv_usec / 1000;
	strftime(line, sizeof (line), "%Y-%m-%d/%H:%M:%S.", timeinfo);
	off += 20;
	snprintf(line + off, sizeof (line) - off, "%03u ", ms);
	off += 4;

	if (lvl == LOG_LEVEL_ERR) {
		strncpy(line + off, "ERROR ", sizeof (line) - off);
		off += sizeof ("ERROR ") - 1;
	}

	va_start(args, fmt);
	vsnprintf(line + off, sizeof (line) - off, fmt, args);
	va_end(args);
	fprintf(stderr, "%s\n", line);
}

int
set_socket_keepalive(int sfd)
{
	int val = 1;
	int ret = 0;
	int max_idle_time = 5;
	int max_try = 5;
	int probe_interval = 5;

	if (sfd < 3) {
		LOG_ERR("can't set keepalive on fd(%d)\n", sfd);
		goto out;
	}

	if (setsockopt(sfd, SOL_SOCKET, SO_KEEPALIVE, &val, sizeof (val)) < 0) {
		LOG_ERR("Failed to set SO_KEEPALIVE for fd(%d) err(%d)\n",
		    sfd, errno);
		ret = errno;
		goto out;
	}

	if (setsockopt(sfd, SOL_TCP, TCP_KEEPCNT, &max_try, sizeof (max_try))) {
		LOG_ERR("Failed to set TCP_KEEPCNT for fd(%d) err(%d)\n",
		    sfd, errno);
		ret = errno;
		goto out;
	}

	if (setsockopt(sfd, SOL_TCP, TCP_KEEPIDLE, &max_idle_time,
	    sizeof (max_idle_time))) {
		LOG_ERR("Failed to set TCP_KEEPIDLE for fd(%d) err(%d)\n",
		    sfd, errno);
		ret = errno;
		goto out;
	}

	if (setsockopt(sfd, SOL_TCP, TCP_KEEPINTVL, &probe_interval,
	    sizeof (probe_interval))) {
		LOG_ERR("Failed to set TCP_KEEPINTVL for fd(%d) err(%d)\n",
		    sfd, errno);
		ret = errno;
	}

out:
	return (ret);
}

int
create_and_bind(const char *port, int bind_needed, boolean_t nonblock)
{
	int rc = 0;
	int sfd = -1;
	struct addrinfo hints = {0, };
	struct addrinfo *result = NULL;
	struct addrinfo *rp = NULL;

	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;

	rc = getaddrinfo(NULL, port, &hints, &result);
	if (rc != 0) {
		perror("getaddrinfo");
		return (-1);
	}

	for (rp = result; rp != NULL; rp = rp->ai_next) {
		int flags = rp->ai_socktype;
		int enable = 1;

		if (nonblock)
			flags |= SOCK_NONBLOCK;
		sfd = socket(rp->ai_family, flags, rp->ai_protocol);
		if (sfd == -1) {
			continue;
		}

		if (bind_needed == 0) {
			break;
		}

		if (setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &enable,
		    sizeof (int)) < 0) {
			perror("setsockopt(SO_REUSEADDR) failed");
		}

		rc = bind(sfd, rp->ai_addr, rp->ai_addrlen);
		if (rc == 0) {
			break;
		}

		close(sfd);
		sfd = -1;
	}

	if (result != NULL)
		freeaddrinfo(result);

	if (rp == NULL)
		return (-1);

	return (sfd);
}

static void
uzfs_insert_zinfo_list(zvol_info_t *zinfo)
{
	LOG_INFO("Instantiating zvol %s", zinfo->name);
	/* Base refcount is taken here */
	(void) mutex_enter(&zvol_list_mutex);
	uzfs_zinfo_take_refcnt(zinfo);
	SLIST_INSERT_HEAD(&zvol_list, zinfo, zinfo_next);
	(void) mutex_exit(&zvol_list_mutex);
}

void
shutdown_fds_related_to_zinfo(zvol_info_t *zinfo)
{
	zinfo_fd_t *zinfo_fd = NULL;

	(void) pthread_mutex_lock(&zinfo->zinfo_mutex);
	while (1) {
		STAILQ_FOREACH(zinfo_fd, &zinfo->fd_list, fd_link) {
			LOG_INFO("shutting down %d on %s", zinfo_fd->fd,
			    zinfo->name);
			shutdown(zinfo_fd->fd, SHUT_RDWR);
		}
		(void) pthread_mutex_unlock(&zinfo->zinfo_mutex);
		sleep(1);
		(void) pthread_mutex_lock(&zinfo->zinfo_mutex);
		if (STAILQ_EMPTY(&zinfo->fd_list))
			break;
	}
	(void) pthread_mutex_unlock(&zinfo->zinfo_mutex);
}

static void
uzfs_mark_offline_and_free_zinfo(zvol_info_t *zinfo)
{
	shutdown_fds_related_to_zinfo(zinfo);
	(void) pthread_mutex_lock(&zinfo->zinfo_mutex);
	zinfo->state = ZVOL_INFO_STATE_OFFLINE;
	/* Send signal to ack_sender thread about offline */
	if (zinfo->io_ack_waiting) {
		(void) pthread_cond_signal(&zinfo->io_ack_cond);
	}
	(void) pthread_mutex_unlock(&zinfo->zinfo_mutex);
	/* Base refcount is droped here */
	uzfs_zinfo_drop_refcnt(zinfo);

	/* Wait for refcounts to be drained */
	while (zinfo->refcnt > 0) {
		LOG_DEBUG("Waiting for refcount to go down to"
		    " zero on zvol:%s", zinfo->name);
		sleep(5);
	}

	LOG_INFO("Freeing zvol %s", zinfo->name);
	(void) uzfs_zinfo_free(zinfo);
}

int
uzfs_zvol_name_compare(zvol_info_t *zv, const char *name)
{

	char *p;
	int pathlen, namelen;

	if (name == NULL)
		return (-1);

	namelen = strlen(name);
	pathlen = strlen(zv->name);

	if (namelen > pathlen)
		return (-1);
	/*
	 * iSCSI controller send volume name without any prefix
	 * while zinfo store volume name with prefix of pool_name.
	 * So we need to extract volume name from zinfo->name
	 * and compare it with pass name.
	 */
	p = zv->name + (pathlen - namelen);

	/*
	 * Name can be in any of these formats
	 * "vol1" or "zpool/vol1"
	 */
	if ((strcmp(zv->name, name) == 0) ||
	    ((strcmp(p, name) == 0) && (*(--p) == '/'))) {
		return (0);
	}
	return (-1);
}

zvol_info_t *
uzfs_zinfo_lookup(const char *name)
{
	zvol_info_t *zv = NULL;

	if (name == NULL)
		return (NULL);

	(void) mutex_enter(&zvol_list_mutex);
	SLIST_FOREACH(zv, &zvol_list, zinfo_next) {
		if (uzfs_zvol_name_compare(zv, name) == 0)
			break;
	}
	if (zv != NULL) {
		/* Take refcount */
		uzfs_zinfo_take_refcnt(zv);
	}
	(void) mutex_exit(&zvol_list_mutex);

	return (zv);
}

static void
uzfs_zinfo_init_mutex(zvol_info_t *zinfo)
{

	(void) pthread_mutex_init(&zinfo->zinfo_mutex, NULL);
	(void) pthread_cond_init(&zinfo->io_ack_cond, NULL);
}

static void
uzfs_zinfo_destroy_mutex(zvol_info_t *zinfo)
{

	(void) pthread_mutex_destroy(&zinfo->zinfo_mutex);
	(void) pthread_cond_destroy(&zinfo->io_ack_cond);
}

int
uzfs_zinfo_destroy(const char *name, spa_t *spa)
{
	zvol_info_t	*zinfo = NULL;
	zvol_info_t    *zt = NULL;
	int namelen = ((name) ? strlen(name) : 0);
	zvol_state_t  *zv;

	mutex_enter(&zvol_list_mutex);

	/*  clear out all zvols for this spa_t */
	if (name == NULL) {
		SLIST_FOREACH_SAFE(zinfo, &zvol_list, zinfo_next, zt) {
			if (strncmp(spa_name(spa),
			    zinfo->name, strlen(spa_name(spa))) == 0) {
				SLIST_REMOVE(&zvol_list, zinfo, zvol_info_s,
				    zinfo_next);

				mutex_exit(&zvol_list_mutex);
				zv = zinfo->zv;
				uzfs_mark_offline_and_free_zinfo(zinfo);
				uzfs_close_dataset(zv);
				mutex_enter(&zvol_list_mutex);
			}
		}
	} else {
		SLIST_FOREACH_SAFE(zinfo, &zvol_list, zinfo_next, zt) {
			if (name == NULL || (strcmp(zinfo->name, name) == 0) ||
			    ((strncmp(zinfo->name, name, namelen) == 0) &&
			    zinfo->name[namelen] == '/' &&
			    zinfo->name[namelen + 1] == '\0')) {
				SLIST_REMOVE(&zvol_list, zinfo, zvol_info_s,
				    zinfo_next);

				mutex_exit(&zvol_list_mutex);
				zv = zinfo->zv;
				uzfs_mark_offline_and_free_zinfo(zinfo);
				uzfs_close_dataset(zv);
				mutex_enter(&zvol_list_mutex);
				break;
			}
		}
	}
	mutex_exit(&zvol_list_mutex);
	return (0);
}

int
uzfs_zinfo_init(void *zv, const char *ds_name, nvlist_t *create_props)
{
	zvol_info_t	*zinfo;

	zinfo =	kmem_zalloc(sizeof (zvol_info_t), KM_SLEEP);
	bzero(zinfo, sizeof (zvol_info_t));
	ASSERT(zinfo != NULL);

	zinfo->uzfs_zvol_taskq = taskq_create("replica", boot_ncpus,
	    defclsyspri, boot_ncpus, INT_MAX,
	    TASKQ_PREPOPULATE | TASKQ_DYNAMIC);

	STAILQ_INIT(&zinfo->complete_queue);
	STAILQ_INIT(&zinfo->fd_list);
	TAILQ_INIT(&zinfo->rebuild_stats);

	uzfs_zinfo_init_mutex(zinfo);

	strlcpy(zinfo->name, ds_name, MAXNAMELEN);
	zinfo->zv = zv;
	zinfo->state = ZVOL_INFO_STATE_ONLINE;
	/* iSCSI target will overwrite this value during handshake */
	zinfo->update_ionum_interval = 6000;
	/* Update zvol list */
	uzfs_insert_zinfo_list(zinfo);

	if (zinfo_create_hook)
		(*zinfo_create_hook)(zinfo, create_props);

	return (0);
}

static int
uzfs_zinfo_free(zvol_info_t *zinfo)
{
	if (zinfo_destroy_hook)
		(*zinfo_destroy_hook)(zinfo);

	taskq_destroy(zinfo->uzfs_zvol_taskq);
	(void) uzfs_zinfo_destroy_mutex(zinfo);
	ASSERT(STAILQ_EMPTY(&zinfo->complete_queue));

	free(zinfo);
	return (0);
}

uint64_t
uzfs_zvol_get_last_committed_io_no(zvol_state_t *zv, char *key)
{
	uzfs_zap_kv_t zap;
	zap.key = key;
	zap.value = 0;
	zap.size = sizeof (uint64_t);

	uzfs_read_zap_entry(zv, &zap);
	return (zap.value);
}

void
uzfs_zvol_store_last_committed_io_no(zvol_state_t *zv, char *key,
    uint64_t io_seq)
{
	uzfs_zap_kv_t *kv_array[0];
	uzfs_zap_kv_t zap;
	zap.key = key;
	zap.value = io_seq;
	zap.size = sizeof (io_seq);

	kv_array[0] = &zap;
	VERIFY0(uzfs_update_zap_entries(zv,
	    (const uzfs_zap_kv_t **) kv_array, 1));
}

void
uzfs_dump_zvol_stats(nvlist_t **stat)
{
	zvol_info_t *zinfo = NULL;
	nvlist_t *zstats, *nv, **nrebuild_stats;
	int i, rebuild_count = 0;
	rebuild_stats_t *r_stats;
	struct sockaddr_in sock_addr;
	socklen_t addrlen = sizeof (struct sockaddr);
	char tbuf[50];
	uzfs_mgmt_conn_t *conn;

	ASSERT(!*stat);

	if (nvlist_alloc(&zstats, NV_UNIQUE_NAME, 0)) {
		LOG_ERR("failed to alloc nvlist\n");
		return;
	}

	(void) mutex_enter(&zvol_list_mutex);
	SLIST_FOREACH(zinfo, &zvol_list, zinfo_next) {
		if (nvlist_alloc(&nv, NV_UNIQUE_NAME, 0)) {
			LOG_ERR("failed to alloc nvlist\n");
			return;
		}
		conn = zinfo->mgmt_conn;
		nvlist_add_uint64(nv, "guid", zinfo->zvol_guid);
		(void) getsockname(conn->conn_fd, (struct sockaddr *)&sock_addr,
		    &addrlen);
		nvlist_add_string(nv, "mgmt ip", inet_ntoa(sock_addr.sin_addr));
		nvlist_add_uint64(nv, "mgmt port", ntohs(sock_addr.sin_port));
		nvlist_add_uint64(nv, "refcnt", zinfo->refcnt);
		nvlist_add_uint64(nv, "timeout", zinfo->timeout);
		nvlist_add_uint64(nv, "running_ionum", zinfo->running_ionum);
		nvlist_add_uint64(nv, "checkpointed_ionum",
		    zinfo->checkpointed_ionum);
		nvlist_add_uint64(nv, "degraded_checkpointed_ionum",
		    zinfo->degraded_checkpointed_ionum);
		(void) ctime_r(&zinfo->checkpointed_time, tbuf);
		tbuf[strlen(tbuf) - 1] = '\0';
		nvlist_add_string(nv, "checkpointed_time", tbuf);
		nvlist_add_uint64(nv, "read_req_received_cnt",
		    zinfo->read_req_received_cnt);
		nvlist_add_uint64(nv, "write_req_received_cnt",
		    zinfo->write_req_received_cnt);
		nvlist_add_uint64(nv, "sync_req_received_cnt",
		    zinfo->sync_req_received_cnt);
		nvlist_add_uint64(nv, "read_req_ack_cnt",
		    zinfo->read_req_ack_cnt);
		nvlist_add_uint64(nv, "write_req_ack_cnt",
		    zinfo->write_req_ack_cnt);
		nvlist_add_uint64(nv, "sync_req_ack_cnt",
		    zinfo->sync_req_ack_cnt);
		nvlist_add_uint64(nv, "zio_cmd_inflight",
		    zinfo->zio_cmd_inflight);
		nvlist_add_uint64(nv, "zio_cmd_inflight",
		    zinfo->zio_cmd_inflight);
		nvlist_add_uint64(nv, "zio_cmd_inflight",
		    zinfo->zio_cmd_inflight);
		nvlist_add_uint64(nv, "zio_cmd_inflight",
		    zinfo->zio_cmd_inflight);
		nvlist_add_string(nv, "state",
		    (zinfo->state == ZVOL_INFO_STATE_ONLINE) ?
		    "online" : "offline");

		nvlist_add_string(nv, "zvol status",
		    (zinfo->zv->zv_status == ZVOL_STATUS_HEALTHY) ?
		    "healthy" : "degraded");
		nvlist_add_uint64(nv, "rebuild_bytes",
		    zinfo->zv->rebuild_info.rebuild_bytes);
		nvlist_add_uint64(nv, "rebuild count",
		    zinfo->zv->rebuild_info.rebuild_cnt);
		nvlist_add_uint64(nv, "rebuild done count",
		    zinfo->zv->rebuild_info.rebuild_done_cnt);
		nvlist_add_uint64(nv, "rebuild failed count",
		    zinfo->zv->rebuild_info.rebuild_failed_cnt);
		switch (zinfo->zv->rebuild_info.zv_rebuild_status) {
			case ZVOL_REBUILDING_INIT:
				nvlist_add_string(nv, "rebuild status",
				    "ZVOL_REBUILDING_INIT");
				break;

			case ZVOL_REBUILDING_IN_PROGRESS:
				nvlist_add_string(nv, "rebuild status",
				    "ZVOL_REBUILDING_IN_PROGRESS");
				break;

			case ZVOL_REBUILDING_DONE:
				nvlist_add_string(nv, "rebuild status",
				    "ZVOL_REBUILDING_DONE");
				break;

			case ZVOL_REBUILDING_ERRORED:
				nvlist_add_string(nv, "rebuild status",
				    "ZVOL_REBUILDING_ERRORED");
				break;

			case ZVOL_REBUILDING_FAILED:
				nvlist_add_string(nv, "rebuild status",
				    "ZVOL_REBUILDING_FAILED");
				break;
		}

		mutex_enter(&zinfo->zv->rebuild_mtx);
		TAILQ_FOREACH(r_stats, &zinfo->rebuild_stats, stat_next) {
			rebuild_count++;
		}

		nrebuild_stats = kmem_alloc(
		    rebuild_count * sizeof (nvlist_t *), KM_SLEEP);
		i = 0;
		TAILQ_FOREACH(r_stats, &zinfo->rebuild_stats, stat_next) {
			if (nvlist_alloc(&nrebuild_stats[i],
			    NV_UNIQUE_NAME, 0)) {
				LOG_ERR("failed to alloc nvlist for"
				    "rebuild stats\n");
				continue;
			}

			nvlist_add_uint64(nrebuild_stats[i], "offset",
			    r_stats->offset);
			nvlist_add_uint64(nrebuild_stats[i], "size",
			    r_stats->len);
			nvlist_add_uint64(nrebuild_stats[i], "io_sequence",
			    r_stats->io_seq);

			if (ntohs(r_stats->target.sin_port) !=
			    REBUILD_IO_SERVER_PORT) {
				nvlist_add_uint64(nrebuild_stats[i],
				    "completed",
				    r_stats->running_offset - r_stats->offset);
				nvlist_add_string(nrebuild_stats[i],
				    "target replica IP",
				    inet_ntoa(r_stats->target.sin_addr));
				nvlist_add_uint16(nrebuild_stats[i],
				    "target replica port",
				    ntohs(r_stats->target.sin_port));
			} else {
				nvlist_add_string(nrebuild_stats[i],
				    "helping replica IP",
				    inet_ntoa(r_stats->target.sin_addr));
				nvlist_add_uint16(nrebuild_stats[i],
				    "helping replica port",
				    ntohs(r_stats->target.sin_port));
			}
			i++;
		}
		mutex_exit(&zinfo->zv->rebuild_mtx);
		nvlist_add_nvlist_array(nv, "Rebuild stats", nrebuild_stats, i);
		while (i)
			nvlist_free(nrebuild_stats[--i]);

		kmem_free(nrebuild_stats, rebuild_count  * sizeof (nvlist_t *));

		nvlist_add_nvlist(zstats, zinfo->name, nv);
		nvlist_free(nv);
	}
	(void) mutex_exit(&zvol_list_mutex);
	*stat = zstats;
}
