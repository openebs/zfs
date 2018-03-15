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
 * API to get modified block details between start_txg and end_txg
 * Note: Caller needs to pass a callback function which will be called
 *	for each modified block with (offset, length and blockId)
 */
extern int uzfs_get_txg_diff(void *zv, uint64_t start_txg,
    uint64_t end_txg, void *func, void *arg);

/*
 * dump_txg_diff_tree will print all entries (offset:length) to stdout
 */
extern void dump_txg_diff_tree(void *tree);

/*
 * dump_io_incoming_tree will print all entries from incoming io tree
 */
extern void dump_io_incoming_tree(void *zv);

/*
 * uzfs_create_txg_diff_tree will create avl tree to store incoming io's
 * during rebuilding
 */
extern void uzfs_create_txg_diff_tree(void **tree);
extern void uzfs_destroy_txg_diff_tree(void *tree);

extern int add_to_txg_diff_tree(void *tree, uint64_t offset, uint64_t size);

/*
 * to add incoming io's details in io_tree
 */
extern void uzfs_add_to_incoming_io_tree(void *zv, uint64_t offset,
    uint64_t len);

/*
 * API to search non-overlapping segment for rebuilding io
 * It will create linked list with non-overlapping segment
 * entries (i.e offset and length)
 */
extern int uzfs_search_incoming_io_tree(void *zv, uint64_t offset,
    uint64_t len, void **list);

extern int uzfs_txg_diff_tree_compare(const void *arg1, const void *arg2);
#endif
