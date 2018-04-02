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
 */

#define	REPLICA_VERSION	1
#define	MAX_NAME_LEN	256
#define	MAX_IP_LEN	64
#define	TARGET_PORT	6060

enum zvol_op_code {
	ZVOL_OPCODE_HANDSHAKE = 0,
	ZVOL_OPCODE_READ,
	ZVOL_OPCODE_WRITE,
	ZVOL_OPCODE_UNMAP,
	ZVOL_OPCODE_SYNC,
	ZVOL_OPCODE_SNAP_CREATE,
	ZVOL_OPCODE_SNAP_ROLLBACK,
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
	uint64_t	io_seq;
	/* only used for read/write */
	uint64_t	offset;
	/*
	 * Length of data in payload.
	 * (for read/write that includes size of io headers with meta data).
	 */
	uint64_t	len;
	uint64_t	checkpointed_io_seq;
	uint8_t 	flags;
	zvol_op_status_t status;
} __attribute__((packed));

typedef struct zvol_io_hdr zvol_io_hdr_t;

/*
 * Payload data send in response to handshake on control connection. It tells
 * IP, port where replica listens for data connection to zvol.
 */
struct mgmt_ack {
	uint64_t pool_guid;
	uint64_t zvol_guid;
	uint16_t port;
	char	ip[MAX_IP_LEN];
	char	volname[MAX_NAME_LEN];
} __attribute__((packed));

typedef struct mgmt_ack mgmt_ack_t;

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

#ifdef	__cplusplus
}
#endif

#endif
