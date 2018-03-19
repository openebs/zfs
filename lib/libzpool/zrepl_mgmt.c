#include <syslog.h>
#include <sys/zil.h>
#include <sys/zfs_rlock.h>
#include <sys/uzfs_zvol.h>
#include <sys/dnode.h>
#include <zrepl_mgmt.h>
#include <uzfs_mgmt.h>

#define	true 1
#define	false 0

#define	ZVOL_THREAD_STACKSIZE (2 * 1024 * 1024)

__thread char  tinfo[20] =  {0};
clockid_t clockid;

pthread_mutex_t zvol_list_mutex;
SLIST_HEAD(, zvol_info_s) zvol_list;
SLIST_HEAD(, zvol_info_s) stale_zv_list;

static int uzfs_zinfo_free(zvol_info_t *zinfo);

/*
 * API to drop refcnt on zinfo. If refcnt
 * dropped to zero then free zinfo.
 */
void
uzfs_zinfo_drop_refcnt(zvol_info_t *zinfo, int locked)
{
	if (!locked) {
		(void) pthread_mutex_lock(&zvol_list_mutex);
	}

	zinfo->refcnt--;
	if (zinfo->refcnt == 0) {
		(void) uzfs_zinfo_free(zinfo);
	}

	if (!locked) {
		(void) pthread_mutex_unlock(&zvol_list_mutex);
	}
}

/*
 * API to take refcount on zinfo.
 */
void
uzfs_zinfo_take_refcnt(zvol_info_t *zinfo, int locked)
{
	if (!locked) {
		(void) pthread_mutex_lock(&zvol_list_mutex);
	}
	zinfo->refcnt++;
	if (!locked) {
		(void) pthread_mutex_unlock(&zvol_list_mutex);
	}
}

static void
uzfs_insert_zinfo_list(zvol_info_t *zinfo)
{

	/* Base refcount is taken here */
	(void) pthread_mutex_lock(&zvol_list_mutex);
	uzfs_zinfo_take_refcnt(zinfo, true);
	SLIST_INSERT_HEAD(&zvol_list, zinfo, zinfo_next);
	(void) pthread_mutex_unlock(&zvol_list_mutex);
}

static void
uzfs_remove_zinfo_list(zvol_info_t *zinfo)
{

	SLIST_REMOVE(&zvol_list, zinfo, zvol_info_s, zinfo_next);
	zinfo->state = ZVOL_INFO_STATE_OFFLINE;
	/* Send signal to ack_sender thread about offline */
	(void) pthread_mutex_lock(&zinfo->complete_queue_mutex);
	if (zinfo->io_ack_waiting) {
		(void) pthread_cond_signal(&zinfo->io_ack_cond);
	}
	(void) pthread_mutex_unlock(&zinfo->complete_queue_mutex);
	/* Base refcount is droped here */
	uzfs_zinfo_drop_refcnt(zinfo, true);
}

zvol_info_t *
uzfs_zinfo_lookup(const char *name)
{
	int pathlen;
	char *p;
	zvol_info_t *zv = NULL;
	int namelen = ((name) ? strlen(name) : 0);

	(void) pthread_mutex_lock(&zvol_list_mutex);
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
		uzfs_zinfo_take_refcnt(zv, true);
	}
	(void) pthread_mutex_unlock(&zvol_list_mutex);

	return (zv);
}

static void
uzfs_zinfo_init_mutex(zvol_info_t *zinfo)
{

	(void) pthread_mutex_init(&zinfo->complete_queue_mutex, NULL);
	(void) pthread_mutex_init(&zinfo->zinfo_mutex, NULL);
	(void) pthread_cond_init(&zinfo->io_ack_cond, NULL);
}

static void
uzfs_zinfo_destroy_mutex(zvol_info_t *zinfo)
{

	(void) pthread_mutex_destroy(&zinfo->complete_queue_mutex);
	(void) pthread_mutex_destroy(&zinfo->zinfo_mutex);
	(void) pthread_cond_destroy(&zinfo->io_ack_cond);
}

int
uzfs_zinfo_destroy(const char *name)
{

	zvol_info_t	*zinfo = NULL;
	int namelen = ((name) ? strlen(name) : 0);
	zvol_state_t  *zv;

	(void) pthread_mutex_lock(&zvol_list_mutex);
	SLIST_FOREACH(zinfo, &zvol_list, zinfo_next) {
		if (name == NULL || strcmp(zinfo->name, name) == 0 ||
		    (strncmp(zinfo->name, name, namelen) == 0 &&
		    (zinfo->name[namelen] == '/' ||
		    zinfo->name[namelen] == '@'))) {
			zv = zinfo->zv;
			uzfs_remove_zinfo_list(zinfo);
			uzfs_close_dataset(zv);
			break;
		}
	}
	(void) pthread_mutex_unlock(&zvol_list_mutex);

	printf("uzfs_zinfo_destroy path\n");
	return (0);
}

int
uzfs_zinfo_init(void *zv, const char *ds_name)
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
	/* Update zvol list */
	uzfs_insert_zinfo_list(zinfo);

	printf("uzfs_zinfo_init in success path\n");
	return (0);
}

static int
uzfs_zinfo_free(zvol_info_t *zinfo)
{
	taskq_destroy(zinfo->uzfs_zvol_taskq);
	(void) uzfs_zinfo_destroy_mutex(zinfo);
	ASSERT(STAILQ_EMPTY(&zinfo->complete_queue));
	printf("Freeing volume =%s\n", zinfo->name);

	free(zinfo);
	return (0);
}
