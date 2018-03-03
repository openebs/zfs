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

#ifndef	_UZFS_MGMT_H

#define	_UZFS_MGMT_H

extern int uzfs_init(void);
extern int uzfs_create_pool(char *name, char *path, void **spa);
extern int uzfs_open_pool(char *name, void **spa);
extern int uzfs_vdev_add(void *spa, char *path, int ashift, int log);
extern int uzfs_create_dataset(void *spa, char *ds, uint64_t vol_size,
    uint64_t block_size, void **zv);
extern int uzfs_open_dataset(void *spa, char *ds, void **zv);
extern uint64_t uzfs_synced_txg(void *zv);
extern void uzfs_close_dataset(void *zv);
extern void uzfs_close_pool(void *spa);
extern void uzfs_fini(void);
extern uint64_t uzfs_random(uint64_t);

#endif
