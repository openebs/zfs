#include <arpa/inet.h>
#include <netdb.h>
#include <sys/zil.h>
#include <sys/zfs_rlock.h>
#include <sys/uzfs_zvol.h>
#include <sys/dnode.h>
#include <sys/dsl_destroy.h>
#include <sys/dsl_prop.h>
#include <sys/dsl_dir.h>
#include <zrepl_mgmt.h>
#include <uzfs_mgmt.h>
#include <uzfs_zap.h>
#include <uzfs_io.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <uzfs_rebuilding.h>

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
		int enable;

		if (nonblock)
			flags |= SOCK_NONBLOCK;
		sfd = socket(rp->ai_family, flags, rp->ai_protocol);
		if (sfd == -1) {
			continue;
		}

		enable = 1;
		if (setsockopt(sfd, IPPROTO_TCP, TCP_NODELAY, &enable,
		    sizeof (enable)) < 0) {
			perror("setsockopt(TCP_NODELAY) failed");
		}

		if (bind_needed == 0) {
			break;
		}

		enable = 1;
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
	zvol_state_t *snap_zv, *clone_zv;

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
		LOG_INFO("Waiting for refcount (%d) to go down to"
		    " zero on zvol:%s", zinfo->refcnt, zinfo->name);
		sleep(5);
	}

	(void) pthread_mutex_lock(&zinfo->zinfo_mutex);
	snap_zv = zinfo->snapshot_zv;
	clone_zv = zinfo->clone_zv;
	zinfo->snapshot_zv = NULL;
	zinfo->clone_zv = NULL;
	(void) pthread_mutex_unlock(&zinfo->zinfo_mutex);

	(void) uzfs_zvol_release_internal_clone(zinfo->main_zv, snap_zv,
	    clone_zv);

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
	(void) pthread_mutex_init(&zinfo->zinfo_ionum_mutex, NULL);
}

static void
uzfs_zinfo_destroy_mutex(zvol_info_t *zinfo)
{

	(void) pthread_mutex_destroy(&zinfo->zinfo_mutex);
	(void) pthread_cond_destroy(&zinfo->io_ack_cond);
	(void) pthread_mutex_destroy(&zinfo->zinfo_ionum_mutex);
}

int
uzfs_zinfo_destroy(const char *name, spa_t *spa)
{
	zvol_info_t	*zinfo = NULL;
	zvol_info_t    *zt = NULL;
	int namelen = ((name) ? strlen(name) : 0);
	zvol_state_t  *main_zv;
	int destroyed = 0;

	mutex_enter(&zvol_list_mutex);

	/*  clear out all zvols for this spa_t */
	if (name == NULL) {
		SLIST_FOREACH_SAFE(zinfo, &zvol_list, zinfo_next, zt) {
			if (strcmp(spa_name(spa),
			    spa_name(zinfo->main_zv->zv_spa)) == 0) {
				SLIST_REMOVE(&zvol_list, zinfo, zvol_info_s,
				    zinfo_next);

				mutex_exit(&zvol_list_mutex);
				main_zv = zinfo->main_zv;
				uzfs_mark_offline_and_free_zinfo(zinfo);
				uzfs_close_dataset(main_zv);
				destroyed++;
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
				main_zv = zinfo->main_zv;
				uzfs_mark_offline_and_free_zinfo(zinfo);
				uzfs_close_dataset(main_zv);
				destroyed++;
				goto end;
			}
		}
	}
	mutex_exit(&zvol_list_mutex);
end:
	LOG_INFO("Destroy for pool: %s vol: %s, destroyed: %d", (spa == NULL) ?
	    "null" : spa_name(spa), (name == NULL) ? "null" : name, destroyed);
	return (0);
}

int
uzfs_zinfo_init(void *zv, const char *ds_name, nvlist_t *create_props)
{
	zvol_info_t	*zinfo;

	zinfo =	kmem_zalloc(sizeof (zvol_info_t), KM_SLEEP);
	bzero(zinfo, sizeof (zvol_info_t));
	ASSERT(zinfo != NULL);
	ASSERT(zinfo->clone_zv == NULL);
	ASSERT(zinfo->snapshot_zv == NULL);

	char *env = getenv("UZFS_WORKER");
	int nthread = 1;
	if (env != NULL) {
		nthread = atoi(env);
		LOG_INFO("env UZFS_WORKER = %d", nthread);
	}

	int nworker = MAX(boot_ncpus, nthread);

	zinfo->uzfs_zvol_taskq = taskq_create("replica", nworker,
	    defclsyspri, nworker, INT_MAX,
	    TASKQ_PREPOPULATE | TASKQ_DYNAMIC);

	STAILQ_INIT(&zinfo->complete_queue);
	STAILQ_INIT(&zinfo->fd_list);
	uzfs_zinfo_init_mutex(zinfo);

	strlcpy(zinfo->name, ds_name, MAXNAMELEN);
	zinfo->main_zv = zv;
	zinfo->state = ZVOL_INFO_STATE_ONLINE;
	/* iSCSI target will overwrite this value (in sec) during handshake */
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

int
uzfs_zvol_get_kv_pair(zvol_state_t *zv, char *key, uint64_t *ionum)
{
	uzfs_zap_kv_t zap;
	int error;

	zap.key = key;
	zap.value = 0;
	zap.size = sizeof (uint64_t);

	error = uzfs_read_zap_entry(zv, &zap);
	if (ionum != NULL)
		*ionum = zap.value;

	return (error);
}

void
uzfs_zvol_store_kv_pair(zvol_state_t *zv, char *key,
    uint64_t io_seq)
{
	uzfs_zap_kv_t *kv_array[0];
	uzfs_zap_kv_t zap;

	if (io_seq == 0)
		return;

	zap.key = key;
	zap.value = io_seq;
	zap.size = sizeof (io_seq);

	kv_array[0] = &zap;
	VERIFY0(uzfs_update_zap_entries(zv,
	    (const uzfs_zap_kv_t **) kv_array, 1));
}

int
uzfs_zvol_get_last_committed_io_no(zvol_state_t *zv, char *key, uint64_t *ionum)
{
	return (uzfs_zvol_get_kv_pair(zv, key, ionum));
}

void
uzfs_zinfo_store_last_committed_degraded_io_no(zvol_info_t *zinfo,
    uint64_t io_seq)
{
	uzfs_zvol_store_kv_pair(zinfo->main_zv,
	    DEGRADED_IO_SEQNUM, io_seq);
}

uint8_t
uzfs_zinfo_get_quorum(zvol_info_t *zinfo)
{
	uint64_t quorum;
	VERIFY0(dsl_prop_get_integer(zinfo->main_zv->zv_name,
	    zfs_prop_to_name(ZFS_PROP_QUORUM), &quorum, NULL));
	return (!!quorum);
}

int
uzfs_zinfo_set_quorum(zvol_info_t *zinfo, uint64_t val)
{
	int err = dsl_dataset_set_quorum(zinfo->main_zv->zv_name,
	    ZPROP_SRC_LOCAL, 1);
	if (err)
		return (err);
	return (0);
}

/*
 * Stores given io_seq as healthy_io_seqnum if previously committed is
 * less than given io_seq.
 * Updates in-memory committed io_num.
 */
void
uzfs_zinfo_store_last_committed_healthy_io_no(zvol_info_t *zinfo,
    uint64_t io_seq)
{
	if (io_seq == 0)
		return;

	pthread_mutex_lock(&zinfo->zinfo_ionum_mutex);
	if (zinfo->stored_healthy_ionum > io_seq) {
		pthread_mutex_unlock(&zinfo->zinfo_ionum_mutex);
		return;
	}
	zinfo->stored_healthy_ionum = io_seq;
	uzfs_zvol_store_kv_pair(zinfo->main_zv,
	    HEALTHY_IO_SEQNUM, io_seq);
	pthread_mutex_unlock(&zinfo->zinfo_ionum_mutex);
}

void
uzfs_zinfo_set_status(zvol_info_t *zinfo, zvol_status_t status)
{
	uzfs_zvol_set_status(zinfo->main_zv, status);
}

zvol_status_t
uzfs_zinfo_get_status(zvol_info_t *zinfo)
{
	return (uzfs_zvol_get_status(zinfo->main_zv));
}

int
uzfs_zvol_destroy_snapshot_clone(zvol_state_t *zv, zvol_state_t *snap_zv,
    zvol_state_t *clone_zv)
{
	int ret = 0;
	int ret1 = 0;
	char *clonename;

	clonename = kmem_asprintf("%s/%s_%s", spa_name(zv->zv_spa),
	    strchr(zv->zv_name, '/') + 1,
	    REBUILD_SNAPSHOT_CLONENAME);

	LOG_INFO("Destroying %s and %s(%s) on:%s", snap_zv->zv_name,
	    clone_zv->zv_name, clonename, zv->zv_name);

	/* Destroy clone's snapshot */
	ret = uzfs_destroy_all_internal_snapshots(clone_zv);
	if (ret != 0) {
		LOG_ERR("Rebuild_clone snap destroy failed on:%s"
		    " with err:%d", zv->zv_name, ret);
	}

	uzfs_zvol_release_internal_clone(zv, snap_zv, clone_zv);

// try_clone_delete_again:
	/* Destroy clone */
	ret = dsl_destroy_head(clonename);
	if (ret != 0) {
		LOG_ERR("Rebuild_clone destroy failed on:%s"
		    " with err:%d", zv->zv_name, ret);
//		sleep(1);
//		goto try_clone_delete_again;
	}

// try_snap_delete_again:
	/* Destroy snapshot */
	ret1 = destroy_snapshot_zv(zv, REBUILD_SNAPSHOT_SNAPNAME);
	if (ret1 != 0) {
		LOG_ERR("Rebuild_snap destroy failed on:%s"
		    " with err:%d", zv->zv_name, ret1);
		ret = ret1;
//		sleep(1);
//		goto try_snap_delete_again;
	}

	strfree(clonename);

	return (ret);
}

/*
 * This API is used to delete internal
 * cloned volume and backing snapshot.
 */
int
uzfs_zinfo_destroy_internal_clone(zvol_info_t *zinfo)
{
	int ret = 0;
	zvol_state_t *snap_zv, *clone_zv;

	(void) pthread_mutex_lock(&zinfo->zinfo_mutex);
	snap_zv = zinfo->snapshot_zv;
	clone_zv = zinfo->clone_zv;

	if (snap_zv == NULL) {
		ASSERT(clone_zv == NULL);
		(void) pthread_mutex_unlock(&zinfo->zinfo_mutex);
		return (ret);
	}

	zinfo->snapshot_zv = NULL;
	zinfo->clone_zv = NULL;
	(void) pthread_mutex_unlock(&zinfo->zinfo_mutex);

	ret = uzfs_zvol_destroy_snapshot_clone(zinfo->main_zv, snap_zv,
	    clone_zv);
	return (ret);
}

/*
 * This API is used to delete stale
 * cloned volume and backing snapshot.
 */
int
uzfs_zinfo_destroy_stale_clone(zvol_info_t *zinfo)
{
	int ret = 0;
	char *clone_subname = NULL;
	zvol_state_t *l_snap_zv = NULL, *l_clone_zv = NULL;
	zvol_state_t *zv;

	if (!zinfo->main_zv)
		return (0);

	zv = zinfo->main_zv;

	ret = get_snapshot_zv(zv, REBUILD_SNAPSHOT_SNAPNAME,
	    &l_snap_zv, B_FALSE, B_TRUE);
	if (ret != 0) {
		LOG_ERR("Failed to get info about %s@%s",
		    zv->zv_name, REBUILD_SNAPSHOT_SNAPNAME);
		return (ret);
	}

	clone_subname = kmem_asprintf("%s_%s", strchr(zv->zv_name, '/') + 1,
	    REBUILD_SNAPSHOT_CLONENAME);

	ret = uzfs_open_dataset(zv->zv_spa, clone_subname, &l_clone_zv);
	if (ret == 0) {
		ret = uzfs_hold_dataset(l_clone_zv);
		if (ret != 0) {
			LOG_ERR("Failed to hold clone: %d", ret);
			uzfs_close_dataset(l_clone_zv);
			l_clone_zv = NULL;
		}
	}

	if (!uzfs_zvol_destroy_snapshot_clone(zv, l_snap_zv, l_clone_zv))
		zv->rebuild_info.stale_clone_exist = 0;

	strfree(clone_subname);

	return (ret);
}
