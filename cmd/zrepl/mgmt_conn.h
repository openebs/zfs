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

#ifndef _MGMT_CONN_H
#define	_MGMT_CONN_H

#include <zrepl_mgmt.h>

extern char *target_addr;

void zinfo_create_cb(zvol_info_t *zinfo, nvlist_t *create_props);
void zinfo_destroy_cb(zvol_info_t *zinfo);
void uzfs_zvol_mgmt_thread(void *arg);

#endif	/* _MGMT_CONN_H */
