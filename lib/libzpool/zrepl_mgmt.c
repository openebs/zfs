#include <arpa/inet.h>
#include <netdb.h>
#include <sys/zil.h>
#include <sys/zfs_rlock.h>
#include <sys/uzfs_zvol.h>
#include <sys/dnode.h>
#include <zrepl_mgmt.h>
#include <uzfs_mgmt.h>
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

#define	SLIST_FOREACH_SAFE(var, head, field, tvar)			\
	for ((var) = SLIST_FIRST((head));				\
	    (var) && ((tvar) = SLIST_NEXT((var), field), 1);		\
	    (var) = (tvar))

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

static void
uzfs_mark_offline_and_free_zinfo(zvol_info_t *zinfo)
{
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
	uzfs_zinfo_init_mutex(zinfo);

	strlcpy(zinfo->name, ds_name, MAXNAMELEN);
	zinfo->zv = zv;
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
uzfs_zvol_get_last_committed_io_no(zvol_state_t *zv)
{
	uzfs_zap_kv_t zap;
	zap.key = "io_seq";
	zap.value = 0;
	zap.size = sizeof (uint64_t);

	uzfs_read_zap_entry(zv, &zap);
	return (zap.value);
}

void
uzfs_zvol_store_last_committed_io_no(zvol_state_t *zv, uint64_t io_seq)
{
	uzfs_zap_kv_t *kv_array[0];
	uzfs_zap_kv_t zap;
	zap.key = "io_seq";
	zap.value = io_seq;
	zap.size = sizeof (io_seq);

	kv_array[0] = &zap;
	VERIFY0(uzfs_update_zap_entries(zv,
	    (const uzfs_zap_kv_t **) kv_array, 1));
}
