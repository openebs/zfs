#ifndef _LIBUZFS_H_
#define	_LIBUZFS_H_

#include <sys/zfs_ioctl.h>
#include <libzfs.h>

#ifdef __cplusplus
extern "C" {
#endif

extern int kthread_nr;

#define	PEND_CONNECTIONS 10

#define	UZFS_SOCK "/tmp/uzfs.sock"

#define	SET_ERR(err) (errno = err, -1)

#define	S_ISSEEK(mode) ((!S_ISFIFO(mode)) && ((!S_ISSOCK(mode))))

typedef struct uzfs_ioctl {
	uint64_t packet_size;
	uint64_t ioc_num;
	uint64_t his_len;
	int ioc_ret;
} uzfs_ioctl_t;

typedef struct uzfs_info {
	uzfs_ioctl_t uzfs_cmd;
	int uzfs_recvfd;
} uzfs_info_t;

typedef struct uzfs_monitor {
	int mon_fd;
	int mon_reserved;
	pthread_t mon_tid;
	void (*mon_action)(int, void *);
	void *mon_arg;
} uzfs_mon_t;

/* _UZFS_IOC(ioctl_number, is_config_command, smush, description) */
#define	UZFS_IOCTL_LIST                                         \
    _UZFS_IOC(ZFS_IOC_OBJSET_STATS, 0, 0, "get the dataset stats")             \
    _UZFS_IOC(ZFS_IOC_POOL_CREATE, 1, 0, " create pool")                       \
    _UZFS_IOC(ZFS_IOC_POOL_IMPORT, 1, 0, "import pool")                        \
    _UZFS_IOC(ZFS_IOC_POOL_STATS, 0, 0, "get pool stats")                      \
    _UZFS_IOC(ZFS_IOC_POOL_TRYIMPORT, 0, 0, "do try import")                   \
    _UZFS_IOC(ZFS_IOC_CREATE, 1, 1, "dataset create")                          \
    _UZFS_IOC(ZFS_IOC_POOL_CONFIGS, 0, 0, "get pool config")                   \
    _UZFS_IOC(ZFS_IOC_DATASET_LIST_NEXT, 0, 0, "iterate dataset")              \
    _UZFS_IOC(ZFS_IOC_GET_BOOKMARKS, 0, 0, "get bookmark")                     \
    _UZFS_IOC(ZFS_IOC_POOL_GET_PROPS, 0, 0, "get pool properties")             \
    _UZFS_IOC(ZFS_IOC_POOL_EXPORT, 1, 0, "export the pool")                    \
    _UZFS_IOC(ZFS_IOC_POOL_GET_HISTORY, 0, 0, "get the pool history")          \
    _UZFS_IOC(ZFS_IOC_LOG_HISTORY, 0, 0, "log the history")                    \
    _UZFS_IOC(ZFS_IOC_SNAPSHOT, 1, 1, "create snapshot")                       \
    _UZFS_IOC(ZFS_IOC_SNAPSHOT_LIST_NEXT, 0, 0, "iterate snapshots")           \
    _UZFS_IOC(ZFS_IOC_POOL_DESTROY, 1, 0, "destroy pool")                      \
    _UZFS_IOC(ZFS_IOC_DESTROY_SNAPS, 1, 1, "destroy snapshot")                 \
    _UZFS_IOC(ZFS_IOC_DESTROY, 1, 0, "destroy dataset")                        \
    _UZFS_IOC(ZFS_IOC_POOL_SET_PROPS, 1, 0, "set pool property")               \
    _UZFS_IOC(ZFS_IOC_SET_PROP, 1, 0, "set dataset property")                  \
    _UZFS_IOC(ZFS_IOC_SEND, 0, 0, "send a snapshot")                           \
    _UZFS_IOC(ZFS_IOC_SEND_NEW, 0, 0, "resumable send")                        \
    _UZFS_IOC(ZFS_IOC_RECV, 1, 1, "receive a snapshot")                        \
    _UZFS_IOC(ZFS_IOC_RECV_NEW, 1, 1, "resumable receive")                     \
    _UZFS_IOC(ZFS_IOC_SEND_PROGRESS, 0, 0, "print zfs send stats")             \
    _UZFS_IOC(ZFS_IOC_VDEV_ADD, 1, 0, "add vdev to the pool")                  \
    _UZFS_IOC(ZFS_IOC_VDEV_REMOVE, 1, 0, "remove vdev from the pool")          \
    _UZFS_IOC(ZFS_IOC_ERROR_LOG, 0, 0, "get the error log")


#define	MAX_NVLIST_SRC_SIZE (128 * 1024 * 1024)

extern int uzfs_ioctl(int fd, unsigned long request, zfs_cmd_t *zc);
extern int uzfs_handle_ioctl(const char *pool, zfs_cmd_t *zc,
    uzfs_info_t *ucmd_info);
extern int uzfs_recv_ioctl(int fd, zfs_cmd_t *zc, uzfs_info_t *ucmd_info);
extern int uzfs_send_response(int fd, zfs_cmd_t *zc, uzfs_info_t *ucmd_info);
extern int uzfs_send_ioctl(int fd, unsigned long request, zfs_cmd_t *zc);
extern int libuzfs_ioctl_init(void);
extern int libuzfs_client_init(libzfs_handle_t *g_zfs);
extern int uzfs_recv_response(int fd, zfs_cmd_t *zc);
extern int uzfs_client_init(const char *sock_path);
extern int is_main_thread(void);

extern int do_sendfd(int sock, int fd);
extern int do_recvfd(int sock);

boolean_t zfs_is_bootfs(const char *name);
boolean_t zpl_earlier_version(const char *name, int version);
int zfs_set_prop_nvlist(const char *dsname, zprop_source_t source,
    nvlist_t *nvl, nvlist_t *errlist);

static inline int
is_config_command(unsigned long ioc_num)
{
	switch (ioc_num) {

#define	_UZFS_IOC(ioc, config, smush, desc) \
	case ioc:                           \
		return (config);            \
		break;

		UZFS_IOCTL_LIST

#undef _UZFS_IOC
	}
	return (0);
}

static inline int
should_smush_nvlist(unsigned long ioc_num)
{
	switch (ioc_num) {

#define	_UZFS_IOC(ioc, config, smush, desc) \
	case ioc:                           \
		return (smush);             \
		break;

		UZFS_IOCTL_LIST

#undef _UZFS_IOC
	}
	return (0);
}

#ifdef __cplusplus
}
#endif

#endif /* _LIBUZFS_H */
