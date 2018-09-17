/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright (c) 2018 Cloudbyte. All rights reserved.
 */

#ifndef	ZREPL_PROT_H
#define	ZREPL_PROT_H

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Over the wire spec for replica protocol.
 *
 * We don't expect replica protocol to be used between nodes with different
 * architecture nevertheless we try to be precise in defining size of members
 * and all number values are supposed to be little endian.
 *
 * Version can be negotiated on mgmt conn. Target sends handshake message with
 * version number. If replica does not support the version, then it replies
 * with "version mismatch" error, puts supported version in version field
 * and closes the connection.
 *
 * If you modify the struct definitions in this file make sure they are
 * properly aligned (and packed).
 */

#define	REPLICA_VERSION	1
#define	MAX_NAME_LEN	256
#define	MAX_IP_LEN	64
#define	TARGET_PORT	6060

#define	ZVOL_OP_FLAG_REBUILD		0x01
#define	ZVOL_OP_FLAG_READ_METADATA	0x02

enum zvol_op_code {
	// Used to obtain info about a zvol on mgmt connection
	ZVOL_OPCODE_HANDSHAKE = 0,
	// Following 4 requests are used on data connection
	ZVOL_OPCODE_OPEN,
	ZVOL_OPCODE_READ,
	ZVOL_OPCODE_WRITE,
	ZVOL_OPCODE_SYNC,
	// Following commands apply to mgmt connection
	ZVOL_OPCODE_UNMAP,
	ZVOL_OPCODE_REPLICA_STATUS,
	ZVOL_OPCODE_PREPARE_FOR_REBUILD,
	ZVOL_OPCODE_START_REBUILD,
	ZVOL_OPCODE_REBUILD_STEP,
	ZVOL_OPCODE_REBUILD_STEP_DONE,
	ZVOL_OPCODE_REBUILD_SNAP_DONE,
	ZVOL_OPCODE_REBUILD_ALL_SNAP_DONE,
	ZVOL_OPCODE_REBUILD_COMPLETE,
	ZVOL_OPCODE_SNAP_CREATE,
	ZVOL_OPCODE_SNAP_DESTROY,
	ZVOL_OPCODE_RESIZE,
	ZVOL_OPCODE_STATS,
} __attribute__((packed));

typedef enum zvol_op_code zvol_op_code_t;

enum zvol_op_status {
	ZVOL_OP_STATUS_OK = 0,
	ZVOL_OP_STATUS_FAILED,
	ZVOL_OP_STATUS_VERSION_MISMATCH,
} __attribute__((packed));

typedef enum zvol_op_status zvol_op_status_t;

/*
 * Future protocol versions need to respect that the first field must be
 * 2-byte version number. The rest of struct is version dependent.
 */
struct zvol_io_hdr {
	uint16_t	version;
	zvol_op_code_t	opcode;
	zvol_op_status_t status;
	uint8_t 	flags;
	uint8_t 	padding[3];
	uint64_t	io_seq;
	/* only used for read/write */
	uint64_t	offset;
	/*
	 * Length of data in payload, with following exceptions:
	 *  1) for read request: size of data to read (payload has zero length)
	 *  2) for write reply: size of data written (payload has zero length)
	 * Note that for write request it includes size of io headers with
	 * meta data.
	 */
	uint64_t	len;
	uint64_t	checkpointed_io_seq;
	uint64_t	checkpointed_degraded_io_seq;
} __attribute__((packed));

typedef struct zvol_io_hdr zvol_io_hdr_t;

struct zvol_op_open_data {
	uint32_t	tgt_block_size;	// used block size for rw in bytes
	uint32_t	timeout;	// replica timeout in seconds
	char		volname[MAX_NAME_LEN];
} __attribute__((packed));

typedef struct zvol_op_open_data zvol_op_open_data_t;

/*
 * Payload data send in response to handshake on control connection. It tells
 * IP, port where replica listens for data connection to zvol.
 */
struct mgmt_ack {
	uint64_t pool_guid;
	uint64_t zvol_guid;
	uint16_t port;
	char	ip[MAX_IP_LEN];
	char	volname[MAX_NAME_LEN]; // zvol helping rebuild
	char	dw_volname[MAX_NAME_LEN]; // zvol being rebuilt
} __attribute__((packed));

typedef struct mgmt_ack mgmt_ack_t;

/*
 * zvol rebuild related state
 */
enum zvol_rebuild_status {
	ZVOL_REBUILDING_INIT,		/* rebuilding can be initiated */
	ZVOL_REBUILDING_SNAP,		/* zvol is rebuilding snapshots */
	ZVOL_REBUILDING_AFS,		/* zvol is rebuilding active dataset */
	ZVOL_REBUILDING_DONE,		/* Rebuilding completed with success */

	/* errored during rebuilding, but not completed */
	ZVOL_REBUILDING_ERRORED,

	ZVOL_REBUILDING_FAILED		/* Rebuilding completed with error */
} __attribute__((packed));

typedef enum zvol_rebuild_status zvol_rebuild_status_t;
/*
 * zvol status
 */
enum zvol_status {
	ZVOL_STATUS_DEGRADED,		/* zvol is missing some data */
	ZVOL_STATUS_HEALTHY		/* zvol has latest data */
} __attribute__((packed));

typedef enum zvol_status zvol_status_t;

struct zrepl_status_ack {
	zvol_status_t state;
	zvol_rebuild_status_t rebuild_status;
} __attribute__((packed));

typedef struct zrepl_status_ack zrepl_status_ack_t;

struct zvol_op_resize_data {
	char	volname[MAX_NAME_LEN];	/* zvol to resize */
	uint64_t size;			/* new size of zvol */
} __attribute__((packed));

typedef struct zvol_op_resize_data zvol_op_resize_data_t;

struct zvol_op_stat {
	char		label[24];	/* name of the stat */
	uint64_t	value;		/* value of the stat */
} __attribute__((packed));

typedef struct zvol_op_stat zvol_op_stat_t;

/*
 * Describes chunk of data following this header.
 *
 * The length in zvol_io_hdr designates the length of the whole payload
 * including other headers in the payload itself. The length in this
 * header designates the lenght of data chunk following this header.
 *
 * ---------------------------------------------------------------------
 * | zvol_io_hdr | zvol_io_rw_hdr | .. data .. | zvol_io_rw_hdr | .. data ..
 * ---------------------------------------------------------------------
 */
struct zvol_io_rw_hdr {
	uint64_t	io_num;
	uint64_t	len;
} __attribute__((packed));

#define	SLIST_FOREACH_SAFE(var, head, field, tvar)			\
	for ((var) = SLIST_FIRST((head));				\
	    (var) && ((tvar) = SLIST_NEXT((var), field), 1);		\
	    (var) = (tvar))

#ifdef	__cplusplus
}
#endif

#endif
