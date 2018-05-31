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

#define	ZVOL_THREAD_STACKSIZE (2 * 1024 * 1024)

__thread char  tinfo[20] =  {0};
clockid_t clockid;
void (*zinfo_create_hook)(zvol_info_t *, nvlist_t *);
void (*zinfo_destroy_hook)(zvol_info_t *);

struct zvol_list zvol_list;
struct zvol_list stale_zv_list;

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
	FILE *outf;

	if (likely(lvl < zrepl_log_level))
		return;

	/* Create timestamp prefix */
	gettimeofday(&tv, NULL);
	timeinfo = localtime(&tv.tv_sec);
	ms = tv.tv_usec / 1000;
	strftime(line, sizeof (line), "%H:%M:%S.", timeinfo);
	snprintf(line + 9, sizeof (line) - 9, "%03u", ms);

	switch (lvl) {
	case LOG_LEVEL_DEBUG:
		outf = stdout;
		strncpy(line + 12, " DEBUG ", sizeof (line) - 12);
		break;
	case LOG_LEVEL_INFO:
		outf = stdout;
		strncpy(line + 12, " INFO  ", sizeof (line) - 12);
		break;
	case LOG_LEVEL_ERR:
		outf = stderr;
		strncpy(line + 12, " ERROR ", sizeof (line) - 12);
		break;
	default:
		ASSERT(0);
	}

	va_start(args, fmt);
	vsnprintf(line + 19, sizeof (line) - 19, fmt, args);
	va_end(args);
	fprintf(outf, "%s\n", line);
}

int
create_and_bind(const char *port, int bind_needed, boolean_t nonblock)
{
	int s, sfd;
	struct addrinfo hints = {0, };
	struct addrinfo *result, *rp;

	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;

	s = getaddrinfo(NULL, port, &hints, &result);
	if (s != 0) {
		perror("getaddrinfo");
		return (-1);
	}

	for (rp = result; rp != NULL; rp = rp->ai_next) {
		int flags = rp->ai_socktype;

		if (nonblock)
			flags |= SOCK_NONBLOCK;
		sfd = socket(rp->ai_family, flags, rp->ai_protocol);
		if (sfd == -1) {
			continue;
		}

		if (bind_needed == 0) {
			break;
		}
		s = bind(sfd, rp->ai_addr, rp->ai_addrlen);
		if (s == 0) {
			break;
		}

		close(sfd);
	}

	if (rp == NULL) {
		return (-1);
	}

	freeaddrinfo(result);
	return (sfd);
}

/*
 * API to drop refcnt on zinfo. If refcnt
 * dropped to zero then free zinfo.
 */
void
uzfs_zinfo_drop_refcnt(zvol_info_t *zinfo, int locked)
{
	if (!locked) {
		(void) mutex_enter(&zvol_list_mutex);
	}

	zinfo->refcnt--;
	if (zinfo->refcnt == 0) {
		(void) uzfs_zinfo_free(zinfo);
	}

	if (!locked) {
		(void) mutex_exit(&zvol_list_mutex);
	}
}

/*
 * API to take refcount on zinfo.
 */
void
uzfs_zinfo_take_refcnt(zvol_info_t *zinfo, int locked)
{
	if (!locked) {
		(void) mutex_enter(&zvol_list_mutex);
	}
	zinfo->refcnt++;
	if (!locked) {
		(void) mutex_exit(&zvol_list_mutex);
	}
}

static void
uzfs_insert_zinfo_list(zvol_info_t *zinfo)
{
	LOG_INFO("Instantiating zvol %s", zinfo->name);
	/* Base refcount is taken here */
	(void) mutex_enter(&zvol_list_mutex);
	uzfs_zinfo_take_refcnt(zinfo, B_TRUE);
	SLIST_INSERT_HEAD(&zvol_list, zinfo, zinfo_next);
	(void) mutex_exit(&zvol_list_mutex);
}

static void
uzfs_remove_zinfo_list(zvol_info_t *zinfo)
{
	LOG_INFO("Removing zvol %s", zinfo->name);
	SLIST_REMOVE(&zvol_list, zinfo, zvol_info_s, zinfo_next);
	(void) pthread_mutex_lock(&zinfo->zinfo_mutex);
	zinfo->state = ZVOL_INFO_STATE_OFFLINE;
	/* Send signal to ack_sender thread about offline */
	if (zinfo->io_ack_waiting) {
		(void) pthread_cond_signal(&zinfo->io_ack_cond);
	}
	(void) pthread_mutex_unlock(&zinfo->zinfo_mutex);
	/* Base refcount is droped here */
	uzfs_zinfo_drop_refcnt(zinfo, B_TRUE);
}

zvol_info_t *
uzfs_zinfo_lookup(const char *name)
{
	int pathlen;
	char *p;
	zvol_info_t *zv = NULL;
	int namelen = ((name) ? strlen(name) : 0);

	(void) mutex_enter(&zvol_list_mutex);
	SLIST_FOREACH(zv, &zvol_list, zinfo_next) {
		/*
		 * TODO: Come up with better approach.
		 * Since iSCSI tgt can send volname in desired format,
		 * we have added this hack where we do calculate length
		 * of name passed as arg, look for those many bytes in
		 * zv->name from tail/end.
		 */
		pathlen = strlen(zv->name);
		p = zv->name + (pathlen - namelen);

		/*
		 * Name can be in any of these formats
		 * "vol1" or "zpool/vol1"
		 */
		if (name == NULL || (strcmp(zv->name, name) == 0) ||
		    ((strcmp(p, name) == 0) && (*(--p) == '/'))) {
			break;
		}
	}
	if (zv != NULL) {
		/* Take refcount */
		uzfs_zinfo_take_refcnt(zv, B_TRUE);
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
				zv = zinfo->zv;
				uzfs_remove_zinfo_list(zinfo);
				uzfs_close_dataset(zv);
			}
		}
	} else {
		SLIST_FOREACH_SAFE(zinfo, &zvol_list, zinfo_next, zt) {
			if (name == NULL || (strcmp(zinfo->name, name) == 0) ||
			    ((strncmp(zinfo->name, name, namelen) == 0) &&
			    zinfo->name[namelen] == '/' &&
			    zinfo->name[namelen + 1] == '\0')) {
				zv = zinfo->zv;
				uzfs_remove_zinfo_list(zinfo);
				uzfs_close_dataset(zv);
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

	zvol_info_t 	*zinfo;

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
