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

#ifndef	_UZFS_MTREE_H
#define	_UZFS_MTREE_H

extern int uzfs_get_txg_diff_tree(void *zv, uint64_t start_txg,
    uint64_t end_txg, void **tree);
extern void dump_txg_diff_tree(void *tree);
extern void uzfs_create_txg_diff_tree(void **tree);
extern void uzfs_destroy_txg_diff_tree(void *tree);
extern int add_to_txg_diff_tree(void *tree, uint64_t offset, uint64_t size);
#endif
