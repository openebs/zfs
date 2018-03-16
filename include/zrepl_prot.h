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
 * TODO: All structures should be defined with "packed" attribute to avoid
 * ambiguous padding added by compiler.
 */

#define	MAX_NAME_LEN	256
#define	MAX_IP_LEN	56
#define	TARGET_PORT	6060

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
	zvol_op_code_t	opcode;
	uint64_t	io_seq;
	uint64_t	offset;
	uint64_t	len;
	// XXX (void *) must be removed from over-the-wire data
	void		*q_ptr;
	zvol_op_status_t status;
} zvol_io_hdr_t;

typedef struct mgmt_ack_s {
	char	volname[MAX_NAME_LEN];
	char	ip[MAX_IP_LEN];
	// XXX this should be uint16_t type
	int	port;
} mgmt_ack_t;

#ifdef	__cplusplus
}
#endif

#endif
