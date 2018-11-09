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
#ifdef __cplusplus
extern "C" {
#endif
#include <sys/spa.h>
#include <sys/uzfs_zvol.h>

extern int uzfs_init(void);
extern int uzfs_create_pool(char *name, char *path, spa_t **spa);
extern int uzfs_open_pool(char *name, spa_t **spa);
extern int uzfs_vdev_add(spa_t *spa, char *path, int ashift, int log);
extern int uzfs_create_dataset(spa_t *spa, char *ds, uint64_t vol_size,
    uint64_t block_size, zvol_state_t **zv);
extern int uzfs_zvol_create_meta(objset_t *os, uint64_t block_size,
    uint64_t meta_block_size, dmu_tx_t *tx);
extern int uzfs_open_dataset(spa_t *spa, const char *ds, zvol_state_t **zv);
extern int uzfs_zvol_create_cb(const char *ds_name, void *n);
extern void uzfs_zvol_create_minors(spa_t *spa, const char *name);
extern int uzfs_zvol_destroy_cb(const char *ds_name, void *n);
extern uint64_t uzfs_synced_txg(zvol_state_t *zv);
extern void uzfs_close_dataset(zvol_state_t *zv);
extern void uzfs_close_pool(spa_t *spa);
extern void uzfs_fini(void);
extern uint64_t uzfs_random(uint64_t);
extern int uzfs_hold_dataset(zvol_state_t *zv);
extern void uzfs_rele_dataset(zvol_state_t *zv);

int uzfs_pool_create(const char *name, char *path, spa_t **spa);
int
get_snapshot_zv(zvol_state_t *zv, char *snap_name, zvol_state_t **snap_zv,
    boolean_t fail_exists, boolean_t fail_notexists);

#ifdef __cplusplus
}
#endif
#endif
