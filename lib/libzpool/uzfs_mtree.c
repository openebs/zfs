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
	avl_tree_t *tree;
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
	add_to_mblktree(diff_blk_info->tree, zb->zb_blkid * blksz, blksz);
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

	diff_blk.tree = umem_alloc(sizeof (avl_tree_t), UMEM_NOFAIL);
	avl_create(diff_blk.tree, zvol_blk_off_cmpr,
	    sizeof (uzfs_zvol_blk_phy_t),
	    offsetof(uzfs_zvol_blk_phy_t, uzb_link));

	diff_blk.start_txg = start_txg;
	diff_blk.end_txg = end_txg;

	error = traverse_dataset(ds_snap, start_txg,
	    TRAVERSE_PRE, uzfs_changed_block_cb, &diff_blk);

	*tree = diff_blk.tree;

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
