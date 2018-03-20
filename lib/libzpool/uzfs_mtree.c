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

#include <sys/dmu_objset.h>
#include <sys/uzfs_zvol.h>
#include <sys/dmu_traverse.h>
#include <sys/dsl_pool.h>
#include <sys/dsl_dataset.h>
#include <sys/dsl_destroy.h>
#include <sys/dmu_tx.h>

#define	TXG_DIFF_SNAPNAME	"tsnap"

/*
 * TXG_SNAPLEN = snapname length + dataset name len +
 *     max hrtime_t print size
 */
#define	TXG_SNAPLEN	sizeof (TXG_DIFF_SNAPNAME) + 	\
    ZFS_MAX_DATASET_NAME_LEN + 21

#define	ADD_TO_IO_CHUNK_LIST(list, e_offset, e_len, node, count)	\
	do {	\
		node = umem_alloc(sizeof (*node), UMEM_NOFAIL);		\
		node->offset = e_offset;				\
		node->len = e_len;					\
		list_insert_tail(list, node);				\
		count++;						\
	} while (0)

typedef struct uzfs_txg_diff_cb_args {
	uzfs_txg_diff_traverse_cb_t *func;
	uint64_t start_txg;
	uint64_t end_txg;
	void *arg_data;
} uzfs_txg_diff_cb_args_t;

/*
 * Add entry with (offset, len) to tree.
 * Merge new entry with an existing entry if new entry overlaps with
 * existing entry.
 */
void
add_to_txg_diff_tree(avl_tree_t *tree, uint64_t boffset, uint64_t blen)
{
	uint64_t new_offset, new_len, b_end, a_end;
	uzfs_zvol_blk_phy_t *entry, *new_node, *b_entry, *a_entry;
	uzfs_zvol_blk_phy_t tofind;
	avl_index_t where;

	new_offset = boffset;
	new_len = blen;

find:
	tofind.offset = new_offset;
	tofind.len = new_len;
	entry = avl_find(tree, &tofind, &where);

	/*
	 * new_offset is available in tree.
	 * If entry->len is greater than or equal to new_len then skip adding
	 * a new_entry else remove entry and search again for new entry.
	 */
	if (entry != NULL) {
		if (entry->len >= new_len) {
			return;
		} else {
			avl_remove(tree, entry);
			umem_free(entry, sizeof (*entry));
			goto find;
		}
	}

	// search for nearest entry whose offset is lesser than new_offset
	b_entry = avl_nearest(tree, where, AVL_BEFORE);
	if (b_entry) {
		b_end = (b_entry->offset + b_entry->len);

		/*
		 * If new entry doesn't overlap with new_entry then search
		 * for after and entry whose offset is greater than
		 * new_entry's offset
		 */
		if (b_end < new_offset)
			goto after;

		/*
		 * If new_entry's offset and b_entry's end are same, then
		 * remove b_entry and add new entry whose offset =
		 * (b_entry's offset) and length  = (b_entry's len +
		 * new entry's len).
		 */
		if (b_end == new_offset) {
			new_len += (b_entry->len);
			new_offset = b_entry->offset;
			avl_remove(tree, b_entry);
			umem_free(b_entry, sizeof (*b_entry));
			goto find;
		}

		/*
		 * If new_entry overlaps with b_entry, then remove b_entry and
		 * add new entry whose offset = (b_entry's offset) and len =
		 * ("b_entry's len" + "new_entry's len" - "overlap len").
		 */
		if (b_end < (new_offset + new_len)) {
			new_len += (new_offset - b_entry->offset);
			new_offset = b_entry->offset;
			avl_remove(tree, b_entry);
			umem_free(b_entry, sizeof (*b_entry));
			goto find;
		}

		// new_entry overlaps with b_entry completely
		if (b_end >= (new_offset + new_len))
			return;
	}

after:
	/*
	 * search for nearest entry whose offset is greater than new_offset
	 * Here, If we can not find any entry which overlaps with new_entry then
	 * we will add new_entry to tree else merge new_entry with nearest
	 * entry.
	 */
	a_entry = avl_nearest(tree, where, AVL_AFTER);

	if (a_entry) {
		a_end = (a_entry->offset + a_entry->len);

		// new_entry doesn't overlap with a_entry
		if ((new_offset + new_len) < a_entry->offset)
			goto doadd;

		// new_entry's end and a_entry's offset are same
		if ((new_offset + new_len) == a_entry->offset) {
			new_len += a_entry->len;
			avl_remove(tree, a_entry);
			umem_free(a_entry, sizeof (*a_entry));
			goto find;
		}

		/*
		 * new_entry overlaps with a_entry and new_entry's end is
		 * lesser or equal to a_entry's end
		 */
		if ((new_offset + new_len) <= (a_end)) {
			new_len = (a_entry->len) +
			    (a_entry->offset - new_offset);
			avl_remove(tree, a_entry);
			umem_free(a_entry, sizeof (*a_entry));
			goto find;
		}

		/*
		 * new_entry overlaps with a_entry and new_entry's end is
		 * greater than a_entry's end
		 */
		if ((new_offset + new_len) > (a_end)) {
			avl_remove(tree, a_entry);
			umem_free(a_entry, sizeof (*a_entry));
			goto find;
		}
	}

doadd:
	new_node = umem_alloc(sizeof (uzfs_zvol_blk_phy_t), UMEM_NOFAIL);
	new_node->offset = new_offset;
	new_node->len = new_len;
	avl_insert(tree, new_node, where);
}

void
dump_txg_diff_tree(avl_tree_t *tree)
{
	uzfs_zvol_blk_phy_t *blk;

	for (blk = avl_first(tree); blk; blk = AVL_NEXT(tree, blk)) {
		printf("offset:%lu, length:%lu\n", blk->offset, blk->len);
	}
}

void
dump_incoming_io_tree(zvol_state_t *zv)
{
	mutex_enter(&zv->rebuild_data.io_tree_mtx);
	dump_txg_diff_tree(zv->rebuild_data.incoming_io_tree);
	mutex_exit(&zv->rebuild_data.io_tree_mtx);
}

int
uzfs_txg_diff_cb(spa_t *spa, zilog_t *zillog, const blkptr_t *bp,
    const zbookmark_phys_t *zb, const dnode_phys_t *dnp, void *arg)
{
	uint64_t blksz;
	uzfs_txg_diff_cb_args_t *diff_blk_info = (uzfs_txg_diff_cb_args_t *)arg;

	if ((bp == NULL) || (BP_IS_HOLE(bp)) || (zb->zb_object != ZVOL_OBJ) ||
	    (zb->zb_level != 0))
		return (0);

	if (bp->blk_birth > diff_blk_info->end_txg ||
	    bp->blk_birth < diff_blk_info->start_txg)
		return (0);

	blksz = BP_GET_LSIZE(bp);

	return diff_blk_info->func(zb->zb_blkid * blksz, blksz, zb->zb_blkid,
	    diff_blk_info->arg_data);
}

int
uzfs_txg_diff_tree_compare(const void *arg1, const void *arg2)
{
	uzfs_zvol_blk_phy_t *node1 = (uzfs_zvol_blk_phy_t *)arg1;
	uzfs_zvol_blk_phy_t *node2 = (uzfs_zvol_blk_phy_t *)arg2;

	return (AVL_CMP(node1->offset, node2->offset));
}

int
uzfs_get_txg_diff(zvol_state_t *zv, uint64_t start_txg, uint64_t end_txg,
    uzfs_txg_diff_traverse_cb_t *func, void *arg)
{
	int error;
	char snapname[TXG_SNAPLEN];
	uzfs_txg_diff_cb_args_t diff_blk;
	hrtime_t now;
	dsl_pool_t *dp;
	dsl_dataset_t *ds_snap;

	now = gethrtime();
	snprintf(snapname, sizeof (snapname), "%s%llu", TXG_DIFF_SNAPNAME, now);

	error = dmu_objset_snapshot_one(zv->zv_name, snapname);
	if (error) {
		printf("failed to create snapshot for %s\n", zv->zv_name);
		return (error);
	}

	memset(snapname, 0, sizeof (snapname));
	snprintf(snapname, sizeof (snapname), "%s@%s%llu", zv->zv_name,
	    TXG_DIFF_SNAPNAME, now);

	error = dsl_pool_hold(snapname, FTAG, &dp);
	if (error != 0)
		return (error);

	error = dsl_dataset_hold(dp, snapname, FTAG, &ds_snap);
	if (error != 0) {
		dsl_pool_rele(dp, FTAG);
		return (error);
	}

	dsl_dataset_long_hold(ds_snap, FTAG);

	memset(&diff_blk, 0, sizeof (diff_blk));

	diff_blk.func = func;
	diff_blk.start_txg = start_txg;
	diff_blk.end_txg = end_txg;
	diff_blk.arg_data = arg;

	error = traverse_dataset(ds_snap, start_txg,
	    TRAVERSE_PRE, uzfs_txg_diff_cb, &diff_blk);

	dsl_dataset_long_rele(ds_snap, FTAG);
	dsl_dataset_rele(ds_snap, FTAG);
	dsl_pool_rele(dp, FTAG);

	/*
	 * TODO: if we failed to destroy snapshot here then
	 * this should be handled separately from application.
	 */
	(void) dsl_destroy_snapshot(snapname, B_FALSE);
	return (error);
}

void
uzfs_create_txg_diff_tree(void **tree)
{
	avl_tree_t *temp_tree;

	temp_tree = umem_alloc(sizeof (avl_tree_t), UMEM_NOFAIL);
	avl_create(temp_tree, uzfs_txg_diff_tree_compare,
	    sizeof (uzfs_zvol_blk_phy_t),
	    offsetof(uzfs_zvol_blk_phy_t, uzb_link));
	*tree = temp_tree;
}

void
uzfs_destroy_txg_diff_tree(void *tree)
{
	avl_tree_t *temp_tree = tree;
	uzfs_zvol_blk_phy_t *node;
	void *cookie = NULL;

	while ((node = avl_destroy_nodes(temp_tree, &cookie)) != NULL) {
		umem_free(node, sizeof (*node));
	}

	avl_destroy(temp_tree);
	umem_free(temp_tree, sizeof (*temp_tree));
}

void
uzfs_add_to_incoming_io_tree(zvol_state_t *zv, uint64_t offset, uint64_t len)
{
	/*
	 * Here: Handling of incoming_io_tree creation is for error case only.
	 *	 It should be handled by replica or caller of uzfs_write_data
	 */
	mutex_enter(&zv->rebuild_data.io_tree_mtx);

	if (!zv->rebuild_data.incoming_io_tree)
		uzfs_create_txg_diff_tree((void **)
		    &zv->rebuild_data.incoming_io_tree);

	add_to_txg_diff_tree(zv->rebuild_data.incoming_io_tree, offset, len);
	mutex_exit(&zv->rebuild_data.io_tree_mtx);
}

/*
 * API to search non-overlapping segment for rebuilding io
 * It will create linked list with non-overlapping segment
 * entries (i.e offset and length)
 */
uint32_t
uzfs_search_incoming_io_tree(zvol_state_t *zv, uint64_t offset, uint64_t len,
    list_t **list)
{
	avl_tree_t *tree = zv->rebuild_data.incoming_io_tree;
	uint32_t count = 0;
	uzfs_zvol_blk_phy_t *b_entry, *a_entry, *entry;
	avl_index_t where;
	uzfs_zvol_blk_phy_t tofind;
	uint64_t a_end, b_end;
	list_t *chunk_list;
	uzfs_io_chunk_list_t  *node;

	if (!tree)
		return (0);

	chunk_list = umem_alloc(sizeof (*chunk_list), UMEM_NOFAIL);
	list_create(chunk_list, sizeof (uzfs_io_chunk_list_t),
	    offsetof(uzfs_io_chunk_list_t, link));

	mutex_enter(&zv->rebuild_data.io_tree_mtx);

again:
	tofind.offset = offset;
	tofind.len = len;

	// Check for exact match
	entry = avl_find(tree, &tofind, &where);
	if (entry) {
		/*
		 * Here, added entry length is greater or equals to rebuild
		 * io len
		 */
		if (entry->len >= len)
			goto done;

		/*
		 * Here added entry length is smaller than rebuild io len
		 * so make offset to added offset + length and length to
		 * len - rebuild io len
		 */
		if (entry->len < len) {
			offset = entry->offset + entry->len;
			len = len - entry->len;
			goto again;
		}
	}

	/*
	 * Check for entry whose offset is lesser than to_find.offset
	 * (or search_entry's offset)
	 */
	b_entry = avl_nearest(tree, where, AVL_BEFORE);
	if (b_entry) {
		b_end = b_entry->offset + b_entry->len;
		a_end = offset + len;

		// If b_entry is not overlapping with search_entry
		// like (b_entry->offset, b_end, offset, a_end)
		if (b_end <= offset)
			goto after;

		// If b_entry ends after search_entry
		// like (b_entry->offset, offset, a_end, b_end)
		if (a_end <= b_end) {
			goto done;
		}

		/*
		 * If search_entry ends before b_entry then change
		 * search_entry's offset to before_entry's end and
		 * length to length - (overlapping length)
		 * like.. (b_entry->offset, offset, b_end, a_end)
		 */
		len = len - (b_end - offset);
		offset = b_end;
		goto again;
	}

after:
	a_entry = avl_nearest(tree, where, AVL_AFTER);
	if (a_entry) {
		a_end = a_entry->offset + a_entry->len;
		b_end = offset + len;

		/*
		 * if search_entry ends <= a_entry's offset then add
		 * search_entry to io_chunk_list
		 * like (offset, b_end, a_entry->offset, a_end)
		 */
		if (b_end <= a_entry->offset) {
			ADD_TO_IO_CHUNK_LIST(chunk_list, offset, len, node,
			    count);
			goto done;
		}

		/*
		 * If search_entry end <= a_entry end, then change
		 * search_entry's length to ( len -  overlapping length) and
		 * add it to io_chunk_list
		 * like (offset, a_entry->offset, b_end, a_end)
		 */
		if (b_end <= a_end) {
			ADD_TO_IO_CHUNK_LIST(chunk_list, offset,
			    len - (b_end - a_entry->offset), node, count);
			goto done;
		}

		/*
		 * if search_entry end > a_entry end, then divide search entry
		 * in three parts. like, (offset, a_entry->offset, a_end, b_end)
		 * for example,
		 * 	search_entry = offset : 400, len : 100 and
		 *	a_entry = offset : 450, len : 20
		 * then, divide search entry to , A (off:400, len:50),
		 * B (off:450, len:20) and C (offset:470, len:30).
		 *	A entry : add this entry to chunk list
		 *	B entry : ignore this entry, as it overlaps with
		 *	    search_entry
		 *	C entry : search aggain for overlapping whith this entry
		 */
		ADD_TO_IO_CHUNK_LIST(chunk_list, offset,
		    a_entry->offset - offset, node, count);
		len = b_end - a_end;
		offset = a_end;
		goto again;
	}

	ADD_TO_IO_CHUNK_LIST(chunk_list, offset, len, node, count);
done:
	mutex_exit(&zv->rebuild_data.io_tree_mtx);
	*list = chunk_list;
	return (count);
}
