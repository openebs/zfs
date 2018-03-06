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

struct diff_txg_blk {
	void *data;
	uint64_t start_txg;
	uint64_t end_txg;
};

void
add_to_mblktree(avl_tree_t *tree, uint64_t boffset, uint64_t blen)
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

	if (entry != NULL) {
		if (entry->len >= new_len) {
			return;
		} else {
			avl_remove(tree, entry);
			umem_free(entry, sizeof (*entry));
			goto find;
		}
	}

	b_entry = avl_nearest(tree, where, AVL_BEFORE);
	if (b_entry) {
		b_end = (b_entry->offset + b_entry->len);
		if (b_end < new_offset)
			goto after;

		if (b_end == new_offset) {
			new_len += (b_entry->len);
			new_offset = b_entry->offset;
			avl_remove(tree, b_entry);
			umem_free(b_entry, sizeof (*b_entry));
			goto find;
		}

		if (b_end < (new_offset + new_len)) {
			new_len += (new_offset - b_entry->offset);
			new_offset = b_entry->offset;
			avl_remove(tree, b_entry);
			umem_free(b_entry, sizeof (*b_entry));
			goto find;
		}

		if (b_end >= (new_offset + new_len))
			return;
	}

after:
	a_entry = avl_nearest(tree, where, AVL_AFTER);

	if (a_entry) {
		a_end = (a_entry->offset + a_entry->len);
		if ((new_offset + new_len) < a_entry->offset)
			goto doadd;

		if ((new_offset + new_len) == a_entry->offset) {
			new_len += a_entry->len;
			avl_remove(tree, a_entry);
			umem_free(a_entry, sizeof (*a_entry));
			goto find;
		}

		if ((new_offset + new_len) <= (a_end)) {
			new_len = (a_entry->len) +
			    (a_entry->offset - new_offset);
			avl_remove(tree, a_entry);
			umem_free(a_entry, sizeof (*a_entry));
			goto find;
		}

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
dump_mblktree(avl_tree_t *tree)
{
	uzfs_zvol_blk_phy_t *blk;

	for (blk = avl_first(tree); blk; blk = AVL_NEXT(tree, blk)) {
		printf("offset:%lu, length:%lu\n", blk->offset, blk->len);
	}
}

#define	ADD_TO_IO_CHUNK_LIST(list, e_offset, e_len, node, count)	\
	do {	\
		node = umem_alloc(sizeof (*node), UMEM_NOFAIL);		\
		node->offset = e_offset;				\
		node->len = e_len;					\
		list_insert_tail(list, node);				\
		count++;						\
	} while (0)

void
dump_io_mblktree(zvol_state_t *zv)
{
	if (zv->incoming_io_tree)
		dump_mblktree(zv->incoming_io_tree);
}

int
uzfs_changed_block_cb(spa_t *spa, zilog_t *zillog, const blkptr_t *bp,
    const zbookmark_phys_t *zb, const dnode_phys_t *dnp, void *arg)
{
	uint64_t blksz;
	struct diff_txg_blk *diff_blk_info = (struct diff_txg_blk *)arg;

	if ((bp == NULL) || (BP_IS_HOLE(bp)) || (zb->zb_object != ZVOL_OBJ) ||
	    (zb->zb_level != 0))
		return (0);

	if (bp->blk_birth > diff_blk_info->end_txg ||
	    bp->blk_birth < diff_blk_info->start_txg)
		return (0);

	blksz = BP_GET_LSIZE(bp);
	add_to_mblktree((avl_tree_t *)diff_blk_info->data,
	    zb->zb_blkid * blksz, blksz);
	return (0);
}

int
uzfs_changed_block_data_cb(spa_t *spa, zilog_t *zillog, const blkptr_t *bp,
    const zbookmark_phys_t *zb, const dnode_phys_t *dnp, void *arg)
{
	uint64_t blksz;
	struct diff_txg_blk *diff_blk_info = (struct diff_txg_blk *)arg;
	uzfs_rebuild_data_t *r_data;
	int err = 0;
	arc_flags_t aflags = ARC_FLAG_WAIT;
	enum zio_flag zioflags = ZIO_FLAG_CANFAIL;
	struct uzfs_io_chunk_list *io;
	arc_buf_t *abuf = NULL;
	r_data = (uzfs_rebuild_data_t *)diff_blk_info->data;

	if ((bp == NULL) || (BP_IS_HOLE(bp)) || (zb->zb_object != ZVOL_OBJ) ||
	    (zb->zb_level != 0)) {
		return (0);
	}

	if (bp->blk_birth > diff_blk_info->end_txg ||
	    bp->blk_birth < diff_blk_info->start_txg)
		return (0);

	blksz = BP_GET_LSIZE(bp);

	if ((err = arc_read(NULL, spa, bp, arc_getbuf_func, &abuf,
	    ZIO_PRIORITY_ASYNC_READ, zioflags, &aflags, zb)) != 0) {
		printf("Error %d in arc_read..\n", err);
		return (SET_ERROR(EIO));
	}

	io = umem_alloc(sizeof (*io), UMEM_NOFAIL);
	io->offset = zb->zb_blkid * blksz;
	io->len = blksz;
	io->buf = umem_alloc(blksz, UMEM_NOFAIL);
	memcpy(io->buf, (char *)(abuf->b_data), blksz);

	mutex_enter(&r_data->mtx);
	list_insert_tail(r_data->io_list, io);
	mutex_exit(&r_data->mtx);

	arc_buf_destroy(abuf, &abuf);
	return (0);
}

static int
zvol_blk_off_cmpr(const void *arg1, const void *arg2)
{
	uzfs_zvol_blk_phy_t *node1 = (uzfs_zvol_blk_phy_t *)arg1;
	uzfs_zvol_blk_phy_t *node2 = (uzfs_zvol_blk_phy_t *)arg2;

	return (AVL_CMP(node1->offset, node2->offset));
}


int
uzfs_txg_block_diff(zvol_state_t *zv, uint64_t start_txg, uint64_t end_txg,
    avl_tree_t **tree)
{
	int error;
	char snapname[ZFS_MAX_DATASET_NAME_LEN];
	struct diff_txg_blk diff_blk;
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

	memset(&diff_blk, 0, sizeof (diff_blk));

	diff_blk.data = umem_alloc(sizeof (avl_tree_t), UMEM_NOFAIL);
	avl_create(diff_blk.data, zvol_blk_off_cmpr,
	    sizeof (uzfs_zvol_blk_phy_t),
	    offsetof(uzfs_zvol_blk_phy_t, uzb_link));

	diff_blk.start_txg = start_txg;
	diff_blk.end_txg = end_txg;

	error = traverse_dataset(ds_snap, start_txg,
	    TRAVERSE_PRE, uzfs_changed_block_cb, &diff_blk);

	*tree = diff_blk.data;

	dsl_dataset_rele(ds_snap, FTAG);
	dsl_pool_rele(dp, FTAG);

	/*
	 * TODO: if we failed to destroy snapshot here then
	 * this should be handled separately from application.
	 */
	(void) dsl_destroy_snapshot(snapname, B_FALSE);
	return (error);
}

int
uzfs_txg_data_diff(zvol_state_t *zv, uint64_t start_txg, uint64_t end_txg,
    uzfs_rebuild_data_t *r_data)
{
	int error;
	char snapname[ZFS_MAX_DATASET_NAME_LEN];
	struct diff_txg_blk diff_blk;
	hrtime_t now;
	dsl_pool_t *dp;
	dsl_dataset_t *ds_snap;

	now = gethrtime();
	snprintf(snapname, sizeof (snapname), "%s%llu", TXG_DIFF_SNAPNAME, now);

	error = dmu_objset_snapshot_one(zv->zv_name, snapname);
	if (error) {
		printf("failed to create snapshot for %s\n", zv->zv_name);
		goto done;
	}

	memset(snapname, 0, sizeof (snapname));
	snprintf(snapname, sizeof (snapname), "%s@%s%llu", zv->zv_name,
	    TXG_DIFF_SNAPNAME, now);

	error = dsl_pool_hold(snapname, FTAG, &dp);
	if (error != 0)
		goto done;

	error = dsl_dataset_hold(dp, snapname, FTAG, &ds_snap);
	if (error != 0) {
		dsl_pool_rele(dp, FTAG);
		goto done;
	}


	diff_blk.start_txg = start_txg;
	diff_blk.end_txg = end_txg;
	diff_blk.data = r_data;

	error = traverse_dataset(ds_snap, start_txg,
	    TRAVERSE_PRE, uzfs_changed_block_data_cb, &diff_blk);

	dsl_dataset_rele(ds_snap, FTAG);
	dsl_pool_rele(dp, FTAG);

	/*
	 * TODO: if we failed to destroy snapshot here then
	 * this should be handled separately from application.
	 */
	(void) dsl_destroy_snapshot(snapname, B_FALSE);

done:
	mutex_enter(&r_data->mtx);
	r_data->done = B_TRUE;
	cv_signal(&r_data->cv);
	mutex_exit(&r_data->mtx);
	return (error);
}


void
uzfs_create_mblktree(void **tree)
{
	avl_tree_t *temp_tree;

	temp_tree = umem_alloc(sizeof (avl_tree_t), UMEM_NOFAIL);
	avl_create(temp_tree, zvol_blk_off_cmpr, sizeof (uzfs_zvol_blk_phy_t),
	    offsetof(uzfs_zvol_blk_phy_t, uzb_link));
	*tree = temp_tree;
}

void
uzfs_destroy_mblktree(void *tree)
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
uzfs_add_to_rebuilding_tree(zvol_state_t *zv, uint64_t offset, uint64_t len)
{
	/*
	 * Here: Handling of incoming_io_tree creation is for error case only.
	 *	 It should be handled by replica or caller of uzfs_write_data
	 */
	if (!zv->incoming_io_tree)
		uzfs_create_mblktree((void **)&zv->incoming_io_tree);

	mutex_enter(&zv->io_tree_mtx);
	add_to_mblktree(zv->incoming_io_tree, offset, len);
	mutex_exit(&zv->io_tree_mtx);
}

uint32_t
uzfs_search_rebuilding_tree(zvol_state_t *zv, uint64_t offset, uint64_t len,
    list_t **list)
{
	avl_tree_t *tree = zv->incoming_io_tree;
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

	mutex_enter(&zv->io_tree_mtx);

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

	b_entry = avl_nearest(tree, where, AVL_BEFORE);
	if (b_entry) {
		b_end = b_entry->offset + b_entry->len;
		a_end = offset + len;
		if (b_end <= offset)
			goto after;

		if (a_end <= b_end) {
			goto done;
		}

		if (a_end > b_end) {
			len = len - (b_end - offset);
			offset = b_end;
			goto again;
		}
	}

after:
	a_entry = avl_nearest(tree, where, AVL_AFTER);
	if (a_entry) {
		a_end = a_entry->offset + a_entry->len;
		b_end = offset + len;
		if (b_end < a_entry->offset) {
			ADD_TO_IO_CHUNK_LIST(chunk_list, offset, len, node,
			    count);
			goto done;
		}

		if (b_end == a_entry->offset) {
			ADD_TO_IO_CHUNK_LIST(chunk_list, offset, len, node,
			    count);
			goto done;
		}

		if (b_end == a_end) {
			ADD_TO_IO_CHUNK_LIST(chunk_list, offset,
			    len - (b_end - a_entry->offset), node, count);
			goto done;
		}

		if (b_end < a_end) {
			ADD_TO_IO_CHUNK_LIST(chunk_list, offset,
			    len - (b_end - a_entry->offset), node, count);
			goto done;
		}

		if (b_end > a_end) {
			ADD_TO_IO_CHUNK_LIST(chunk_list, offset,
			    a_entry->offset - offset, node, count);
			len = b_end - a_end;
			offset = a_end;
			goto again;
		}
	}

	ADD_TO_IO_CHUNK_LIST(chunk_list, offset, len, node, count);
done:
	mutex_exit(&zv->io_tree_mtx);
	*list = chunk_list;
	return (count);
}
