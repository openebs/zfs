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
#include <uzfs_io.h>
#include <uzfs_mgmt.h>
#include <uzfs_rebuilding.h>
#include <zrepl_mgmt.h>

#define	ADD_TO_IO_CHUNK_LIST(list, e_offset, e_len, count)		\
	do {    							\
		uzfs_io_chunk_list_t  *node;				\
		node = umem_alloc(sizeof (*node), UMEM_NOFAIL);         \
		node->offset = e_offset;                                \
		node->len = e_len;                                      \
		list_insert_tail(list, node);                           \
		count++;                                                \
	} while (0)

int
compare_blk_metadata(blk_metadata_t *first, blk_metadata_t *second)
{
	if (first->io_num < second->io_num)
		return (-1);
	if (first->io_num == second->io_num)
		return (0);
	return (1);
}

boolean_t
iszero(blk_metadata_t *md)
{
	if (md->io_num == 0)
		return (B_TRUE);
	return (B_FALSE);
}

#define	EXECUTE_DIFF_CALLBACK(last_lun_offset, diff_count, buf, 	\
    last_index, arg, last_md, zv, func, ret)				\
		do {							\
			ret = func(last_lun_offset, diff_count * 	\
			    zv->zv_metavolblocksize, (blk_metadata_t *) \
			    (buf + last_index), zv, arg);		\
			diff_count = 0;					\
			last_index = 0;					\
			last_md = NULL;					\
		} while (0)

int
uzfs_get_io_diff(zvol_state_t *zv, blk_metadata_t *low, zvol_state_t *snap,
    uzfs_get_io_diff_cb_t *func, off_t lun_offset, size_t lun_len, void *arg)
{
	uint64_t blocksize = zv->zv_volmetablocksize;
	uint64_t metadata_read_chunk_size = 10 * blocksize;
	uint64_t metaobjectsize = (zv->zv_volsize / zv->zv_metavolblocksize) *
	    zv->zv_volmetadatasize;
	uint64_t metadatasize = zv->zv_volmetadatasize;
	char *buf;
	uint64_t i, read;
	uint64_t offset, len, end;
	int ret = 0;
	int diff_count = 0, last_index = 0;
	uint64_t last_lun_offset = 0;
	blk_metadata_t *last_md;
	zvol_state_t *snap_zv;
	metaobj_blk_offset_t snap_metablk;

	if (!func || snap == NULL)
		return (EINVAL);

	// dont fail if rebuilding from lower size volume
	// can we avoid rebuilding at all from smaller volume?
	if (lun_offset >= zv->zv_volsize)
		return (0);
	if ((lun_offset + lun_len) > zv->zv_volsize) {
		lun_len = zv->zv_volsize - lun_offset;
	}

	get_zv_metaobj_block_details(&snap_metablk, zv, lun_offset, lun_len);
	offset = snap_metablk.m_offset;
	end = snap_metablk.m_offset + snap_metablk.m_len;

	if (end > metaobjectsize)
		end = metaobjectsize;
	snap_zv = snap;

	metadata_read_chunk_size = (metadata_read_chunk_size / metadatasize) *
	    metadatasize;
	buf = umem_alloc(metadata_read_chunk_size, KM_SLEEP);
	len = metadata_read_chunk_size;

	for (; offset < end && !ret; offset += len) {
		read = 0;
		len = metadata_read_chunk_size;

		if ((offset + len) > end)
			len = (end - offset);

		ret = uzfs_read_metadata(snap_zv, buf, offset, len, &read);

		if (read != len || ret)
			break;

		lun_offset = (offset / metadatasize) * zv->zv_metavolblocksize;
		for (i = 0; i < len && !ret; i += sizeof (blk_metadata_t)) {
			if (!iszero((blk_metadata_t *)(buf+i)) &&
			    (compare_blk_metadata((blk_metadata_t *)(buf + i),
			    low) > 0)) {
				/*
				 * We will keep track of last lun_offset having
				 * metadata lesser than incoming_metadata and
				 * join adjacent chunk with the same on_disk
				 * io_number.
				 */
				if (diff_count == 0) {
					last_lun_offset = lun_offset;
					last_md = (blk_metadata_t *)(buf+i);
					last_index = i;
				}

				if (diff_count &&
				    compare_blk_metadata((blk_metadata_t *)
				    (buf + i), last_md) != 0) {
					/*
					 * Execute callback function with last
					 * metadata and diff_count if
					 * last compared metadata is changed
					 */
					EXECUTE_DIFF_CALLBACK(last_lun_offset,
					    diff_count, buf, last_index, arg,
					    last_md, snap_zv, func, ret);
					if (ret != 0)
						break;
					last_lun_offset = lun_offset;
					last_md = (blk_metadata_t *)(buf+i);
					last_index = i;
					diff_count++;
				} else {
					/*
					 * increament diff_count with 1 if
					 * metadata is same
					 */
					diff_count++;
				}
			} else if (diff_count) {
				EXECUTE_DIFF_CALLBACK(last_lun_offset,
				    diff_count, buf, last_index, arg, last_md,
				    snap_zv, func, ret);
				if (ret != 0)
					break;
			}

			lun_offset += zv->zv_metavolblocksize;
		}
		if (!ret && diff_count) {
			EXECUTE_DIFF_CALLBACK(last_lun_offset, diff_count, buf,
			    last_index, arg, last_md, snap_zv, func, ret);
			if (ret != 0)
				break;
		}
	}
	umem_free(buf, metadata_read_chunk_size);
	return (ret);
}

int
uzfs_get_nonoverlapping_ondisk_blks(zvol_state_t *zv, uint64_t offset,
    uint64_t len, blk_metadata_t *incoming_md, void **list)
{
	char *ondisk_metadata_buf;
	uint64_t rd_rlen;
	metaobj_blk_offset_t ondisk_metablk;
	blk_metadata_t *ondisk_md;
	int diff_count = 0;
	int count = 0;
	int ret = 0;
	int i = 0;
	uint64_t lun_offset = 0, last_lun_offset = 0;
	list_t *chunk_list = NULL;
	uint64_t metavolblocksize = zv->zv_metavolblocksize;
	uint64_t metadatasize = zv->zv_volmetadatasize;

	get_zv_metaobj_block_details(&ondisk_metablk, zv, offset, len);
	ondisk_metadata_buf = umem_alloc(ondisk_metablk.m_len, UMEM_NOFAIL);

	ret = uzfs_read_metadata(zv, ondisk_metadata_buf,
	    ondisk_metablk.m_offset, ondisk_metablk.m_len, &rd_rlen);
	if (ret || rd_rlen != ondisk_metablk.m_len) {
		LOG_ERR("Failed to read metadata");
		goto exit;
	}

	chunk_list = umem_alloc(sizeof (*chunk_list), UMEM_NOFAIL);
	list_create(chunk_list, sizeof (uzfs_io_chunk_list_t),
	    offsetof(uzfs_io_chunk_list_t, link));

	for (i = 0; i < ondisk_metablk.m_len; i += sizeof (blk_metadata_t)) {
		ondisk_md = (blk_metadata_t *)(ondisk_metadata_buf + i);
		lun_offset = ((ondisk_metablk.m_offset + i) *
		    metavolblocksize) / metadatasize;
		ret = compare_blk_metadata(ondisk_md, incoming_md);
		if (ret == -1) {
			// on_disk io number < incoming io number
			if (diff_count == 0)
				last_lun_offset = lun_offset;

			diff_count++;
		} else {
			// on_disk io number >= incoming io number
			if (diff_count != 0) {
				ADD_TO_IO_CHUNK_LIST(chunk_list,
				    last_lun_offset, diff_count *
				    metavolblocksize, count);
				diff_count = 0;
			}
		}
	}

	if (diff_count != 0)
		ADD_TO_IO_CHUNK_LIST(chunk_list, last_lun_offset,
		    diff_count * metavolblocksize, count);

exit:
	umem_free(ondisk_metadata_buf, ondisk_metablk.m_len);
	*list = chunk_list;
	return (count);
}

/*
 * This API is used to release internal clone dataset
 */
int
uzfs_zvol_release_internal_clone(zvol_state_t *zv, zvol_state_t *snap_zv,
    zvol_state_t *clone_zv)
{
	if (snap_zv == NULL) {
		ASSERT(clone_zv == NULL);
		return (0);
	}

	LOG_INFO("Closing %s and %s dataset on:%s", snap_zv->zv_name,
	    clone_zv->zv_name, zv->zv_name);

	/* Close clone dataset */
	uzfs_close_dataset(clone_zv);

	/* Close snapshot dataset */
	uzfs_close_dataset(snap_zv);

	return (0);
}

boolean_t
is_stale_clone(zvol_state_t *zv)
{
	uint64_t val;
	int rc;
	boolean_t ret = B_FALSE;

	rc = uzfs_zvol_get_kv_pair(zv, STALE, &val);
	if (rc == 0)
		ret = B_TRUE;

	return (ret);
}

/*
 * This API is used to create internal clone for rebuild.
 * It will load the clone dataset if clone already exist.
 * Cloned volume created through this API can not be exposed
 * to client.
 */
int
uzfs_zvol_get_or_create_internal_clone(zvol_state_t *zv,
    zvol_state_t **snap_zv, zvol_state_t **clone_zv, int *error)
{
	int ret = 0;
	char *snapname = NULL;
	char *clonename = NULL;
	char *clone_subname = NULL;
	zvol_state_t *l_snap_zv = NULL, *l_clone_zv = NULL;

again:
	ret = get_snapshot_zv(zv, REBUILD_SNAPSHOT_SNAPNAME, &l_snap_zv,
	    B_FALSE, B_FALSE);
	if (ret != 0) {
		LOG_ERR("Failed to get info about %s@%s",
		    zv->zv_name, REBUILD_SNAPSHOT_SNAPNAME);
		*snap_zv = *clone_zv = NULL;
		return (ret);
	}

	snapname = kmem_asprintf("%s@%s", zv->zv_name,
	    REBUILD_SNAPSHOT_SNAPNAME);

	clonename = kmem_asprintf("%s/%s_%s", spa_name(zv->zv_spa),
	    strchr(zv->zv_name, '/') + 1,
	    REBUILD_SNAPSHOT_CLONENAME);

	clone_subname = kmem_asprintf("%s_%s", strchr(zv->zv_name, '/') + 1,
	    REBUILD_SNAPSHOT_CLONENAME);

	ret = dmu_objset_clone(clonename, snapname);
	if (ret == EEXIST)
		LOG_INFO("Volume:%s already has clone for snap rebuild",
		    zv->zv_name);
	if (error)
		*error = ret;

	if ((ret == EEXIST) || (ret == 0)) {
		ret = uzfs_open_dataset(zv->zv_spa, clone_subname, &l_clone_zv);
		if (ret == 0) {
			ret = uzfs_hold_dataset(l_clone_zv);
			if (ret != 0) {
				LOG_ERR("Failed to hold clone: %d", ret);
				uzfs_close_dataset(l_clone_zv);
				l_clone_zv = NULL;
				/*
				 * commenting out destroy clone for sake
				 * of NOT to lose data
				 */
#if 0
				/* Destroy clone */
				ret = dsl_destroy_head(clonename);
				if (ret != 0)
					LOG_ERRNO("Rebuild_clone destroy "
					    "failed on:%s with err:%d",
					    zv->zv_name, ret);
#endif
				uzfs_close_dataset(l_snap_zv);
#if 0
				destroy_snapshot_zv(zv,
				    REBUILD_SNAPSHOT_SNAPNAME);
#endif
				l_snap_zv = NULL;
			} else {
				if (is_stale_clone(l_clone_zv) == B_TRUE) {
					LOG_INFO("Destroying clone %s being "
					    "stale", clonename);
					ret = uzfs_zvol_destroy_snapshot_clone(
					    zv, l_snap_zv, l_clone_zv);
					l_snap_zv = l_clone_zv = NULL;
					if (ret == 0) {
						strfree(clone_subname);
						strfree(clonename);
						strfree(snapname);
						goto again;
					}
					LOG_ERR("Destroying stale clone %s "
					    "failed", clonename);
				}
			}
		} else {
			uzfs_close_dataset(l_snap_zv);
/*
 *			destroy_snapshot_zv(zv, REBUILD_SNAPSHOT_SNAPNAME);
 */
			l_snap_zv = NULL;
			l_clone_zv = NULL;
			LOG_INFO("Clone:%s not able to open", clone_subname);
		}
	} else if (ret != 0) {
		uzfs_close_dataset(l_snap_zv);
/*
 *		destroy_snapshot_zv(zv, REBUILD_SNAPSHOT_SNAPNAME);
 */
		l_snap_zv = NULL;
		l_clone_zv = NULL;
		LOG_INFO("Clone:%s from snap %s fails", clonename, snapname);
	}

	*snap_zv = l_snap_zv;
	*clone_zv = l_clone_zv;

	strfree(clone_subname);
	strfree(clonename);
	strfree(snapname);
	return (ret);
}

typedef boolean_t (*uzfs_snapname_matching_func)(char *snapname);

/*
 * Return true for snaps that are internal created
 */
boolean_t
uzfs_match_internal_snapshots(char *snapname)
{
	if ((strcmp(snapname, REBUILD_SNAPSHOT_SNAPNAME) == 0) ||
	    (strncmp(snapname, IO_DIFF_SNAPNAME,
	    sizeof (IO_DIFF_SNAPNAME) - 1) == 0))
		return (B_TRUE);
	return (B_FALSE);
}

/*
 * Return true for snaps that starts with .io_snap
 */
boolean_t
uzfs_match_iosnap_snapshots(char *snapname)
{
	if (strncmp(snapname, IO_DIFF_SNAPNAME,
	    sizeof (IO_DIFF_SNAPNAME) - 1) == 0)
		return (B_TRUE);
	return (B_FALSE);
}

static int
uzfs_destroy_matching_snapshots(zvol_state_t *zv,
    uzfs_snapname_matching_func matching_fn)
{
	int ret;
	char snapname[MAXNAMELEN];
	objset_t *os;
	uint64_t obj = 0, cookie = 0;

	if (!zv || !zv->zv_objset)
		return (-1);

	os = zv->zv_objset;

	while (1) {
		dsl_pool_config_enter(spa_get_dsl(zv->zv_spa), FTAG);
		ret = dmu_snapshot_list_next(os, sizeof (snapname) - 1,
		    snapname, &obj, &cookie, NULL);
		dsl_pool_config_exit(spa_get_dsl(zv->zv_spa), FTAG);

		if (ret) {
			if (ret == ENOENT)
				ret = 0;
			break;
		}

		/* skip destroying non-matching snaps */
		if ((*matching_fn)(snapname) == B_FALSE)
			continue;

		ret = destroy_snapshot_zv(zv, snapname);
		if (ret != 0) {
			LOG_ERR("Failed to destroy internal snap(%s) on:%s "
			    "with err:%d", snapname, zv->zv_name, ret);
			break;
		}
	}

	return (ret);
}

/*
 * To destroy all internal created snapshot
 * on a dataset
 */
int
uzfs_destroy_all_internal_snapshots(zvol_state_t *zv)
{
	int ret;
	ret = uzfs_destroy_matching_snapshots(zv,
	    uzfs_match_internal_snapshots);
	return (ret);
}

int
uzfs_destroy_all_iosnap_snapshots(zvol_state_t *zv)
{
	int ret;
	ret = uzfs_destroy_matching_snapshots(zv,
	    uzfs_match_iosnap_snapshots);
	return (ret);
}
