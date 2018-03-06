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

/*
 * API to get modified blocks between start_txg and end_txg
 * Note: API will alocate condensed tree and populate it witch
 *	modified block details (offset:lenth entries).
 */
extern int uzfs_txg_block_diff(void *zv, uint64_t start_txg,
    uint64_t end_txg, void **tree);

extern int uzfs_txg_data_diff(void *zv, uint64_t start_txg,
    uint64_t end_txg, void *r_data);


/*
 * dump_mblktree will print all entries (offset:length) to stdout
 */
extern void dump_mblktree(void *tree);

/*
 * dump_io_mblktree will print all entries from incoming io tree
 */
extern void dump_io_mblktree(void *zv);

/*
 * uzfs_create_mblktree will create avl tree to store incoming io's
 * during rebuilding
 */
extern void uzfs_create_mblktree(void **tree);
extern void uzfs_destroy_mblktree(void *tree);

extern int add_to_mblktree(void *tree, uint64_t offset, uint64_t size);

/*
 * to add incoming io's details in io_tree
 */
extern void uzfs_add_to_rebuilding_tree(void *zv, uint64_t offset,
    uint64_t len);

/*
 * API to search non-overlapping segment for rebuilding io
 * It will create linked list with non-overlapping segment
 * entries (i.e offset and length)
 */
extern int uzfs_search_rebuilding_tree(void *zv, uint64_t offset,
    uint64_t len, void **list);
#endif
