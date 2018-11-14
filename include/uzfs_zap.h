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

#ifndef	_UZFS_ZAP_H
#define	_UZFS_ZAP_H

#include <sys/spa.h>

typedef struct {
	char *key;	/* zap key to update */
	uint64_t value;	/* value to update against zap key */
	size_t size;	/* size of value */
} uzfs_zap_kv_t;

#define	LAST_ITER_TXG	"last_iter_txg"

/*
 * Here, allocation/freeing of kv_array needs to be handled by
 * caller function. uzfs_*_zap_entry will handle only microzap
 * entries or value with uint64_t entries.
 */
int uzfs_update_zap_entries(void *zv, const uzfs_zap_kv_t **kv_array,
    uint64_t n);
int uzfs_read_zap_entry(void *zv, uzfs_zap_kv_t *entry);
int uzfs_read_last_iter_txg(void *spa, uint64_t *val);
void uzfs_update_txg_zap_thread(void *s);
void uzfs_update_txg_interval(spa_t *spa, uint32_t timeout);

#endif
