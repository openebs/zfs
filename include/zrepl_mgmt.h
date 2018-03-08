
#ifndef	ZREPL_MGMT_H
#define	ZREPL_MGMT_H
#include <pthread.h>
#include <sys/queue.h>

#define	uZFS_ZVOL_WORKERS_MAX 128
#define	uZFS_ZVOL_WORKERS_DEFAULT 6
#define	MAX_IP_LEN 56

extern pthread_mutex_t zvol_list_mutex;
struct zvol_io_cmd_s;

typedef enum zvol_info_state_e {
	ZVOL_INFO_STATE_ONLINE,
	ZVOL_INFO_STATE_OFFLINE,
} zvol_info_state_t;

typedef struct thread_args_s {
	char zvol_name[MAXNAMELEN];
	int fd;
} thread_args_t;

typedef struct zvol_info_s {

	SLIST_ENTRY(zvol_info_s) zinfo_next;

	/* Logical Unit related fields */
	zvol_info_state_t	state;
	char 		name[MAXPATHLEN];
	void 		*zv;
	int 		refcnt;
	int		is_io_ack_sender_created;
	taskq_t		*uzfs_zvol_taskq;	/* Taskq for minor management */

	/* Thread sync related */

	/* For protection of complete_queue */
	pthread_mutex_t	zinfo_mutex;
	pthread_mutex_t	complete_queue_mutex;
	pthread_cond_t	io_ack_cond;

	pthread_t 	io_receiver_thread;
	pthread_t 	io_ack_sender_thread;

	/* All cmds after execution will go here for ack */
	STAILQ_HEAD(, zvol_io_cmd_s)	complete_queue;

	uint8_t		io_ack_waiting;
	uint8_t		error_count;

	/* Will be used to singal ack-sender to exit */
	uint8_t		conn_closed;

	/* Perfromance counter */

	/* Debug counters */
	int 		read_req_received_cnt;
	int 		write_req_received_cnt;
	int 		read_req_ack_cnt;
	int 		write_req_ack_cnt;
} zvol_info_t;

typedef enum zvol_op_code_e {
	ZVOL_OPCODE_HANDSHAKE = 1,
	ZVOL_OPCODE_READ,
	ZVOL_OPCODE_WRITE,
	ZVOL_OPCODE_UNMAP,
	ZVOL_OPCODE_SYNC,
	ZVOL_OPCODE_SNAP_CREATE,
	ZVOL_OPCODE_SNAP_ROLLBACK,
} zvol_op_code_t;

typedef enum zvol_op_status_e {
	ZVOL_OP_STATUS_OK = 1,
	ZVOL_OP_STATUS_FAILED,
} zvol_op_status_t;

typedef struct zvol_io_hdr_s {
	zvol_op_code_t		opcode;
	uint64_t		io_seq;
	uint64_t		offset;
	uint64_t		len;
	void			*q_ptr;
	zvol_op_status_t 	status;
} zvol_io_hdr_t;

typedef struct zvol_io_cmd_s {
	STAILQ_ENTRY(zvol_io_cmd_s) cmd_link;
	zvol_io_hdr_t 	hdr;
	void		*zv;
	void		*buf;
	int		conn;
} zvol_io_cmd_t;

typedef struct mgmt_ack_s {
	char		volname[MAXNAMELEN];
	char		ip[MAX_IP_LEN];
	int		port;
} mgmt_ack_t;

extern int uzfs_zinfo_init(void *zv, const char *ds_name);
extern zvol_info_t *uzfs_zinfo_lookup(const char *name);
extern void uzfs_zinfo_drop_refcnt(zvol_info_t *zinfo, int locked);
extern void uzfs_zinfo_take_refcnt(zvol_info_t *zinfo, int locked);
extern void uzfs_zinfo_replay_zil_all(void);
extern int uzfs_zinfo_destroy(const char *ds_name);

#define	ZREPL_LOG(fmt, ...)  syslog(LOG_NOTICE,				\
		"%-18.18s:%4d: %-20.20s: " fmt, __func__, __LINE__,	\
    tinfo, ##__VA_ARGS__)

#define	ZREPL_NOTICELOG(fmt, ...) syslog(LOG_NOTICE,			\
		"%-18.18s:%4d: %-20.20s: " fmt, __func__, __LINE__,	\
    tinfo, ##__VA_ARGS__)

#define	ZREPL_ERRLOG(fmt, ...) syslog(LOG_ERR,				\
		"%-18.18s:%4d: %-20.20s: " fmt, __func__, __LINE__,	\
    tinfo, ##__VA_ARGS__)

#define	ZREPL_WARNLOG(fmt, ...) syslog(LOG_ERR,				\
		"%-18.18s:%4d: %-20.20s: " fmt, __func__, __LINE__,	\
    tinfo, ##__VA_ARGS__)

#define	ZREPL_TRACELOG(FLAG, fmt, ...)					\
	do {								\
		syslog(LOG_NOTICE, "%-18.18s:%4d: %-20.20s: "		\
		    fmt, __func__, __LINE__, tinfo, ##__VA_ARGS__);	\
	} while (0)

#endif /* ZREPL_MGMT_H */
