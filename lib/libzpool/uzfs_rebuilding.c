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
	if (DECODE_IF_UNMAP_IOSEQ(first->io_num) <
	    DECODE_IF_UNMAP_IOSEQ(second->io_num))
		return (-1);
	if (DECODE_IF_UNMAP_IOSEQ(first->io_num) ==
	    DECODE_IF_UNMAP_IOSEQ(second->io_num))
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
	char *buf, *snap_name = NULL;
	uint64_t i, read;
	uint64_t offset, len, end;
	int ret = 0;
	int diff_count = 0, last_index = 0;
	uint64_t last_lun_offset = 0;
	blk_metadata_t *last_md;
	zvol_state_t *snap_zv;
	metaobj_blk_offset_t snap_metablk;

	if (!func || (lun_offset + lun_len) > zv->zv_volsize)
		return (EINVAL);

	get_zv_metaobj_block_details(&snap_metablk, zv, lun_offset, lun_len);
	offset = snap_metablk.m_offset;
	end = snap_metablk.m_offset + snap_metablk.m_len;

	if (end > metaobjectsize)
		end = metaobjectsize;
	if (snap == NULL) {
		snap_name = kmem_asprintf("%s%llu", IO_DIFF_SNAPNAME,
		    low->io_num);
		ret = get_snapshot_zv(zv, snap_name, &snap_zv);
		if (ret != 0) {
			LOG_ERR("Failed to get info about %s@%s io_num %lu",
			    zv->zv_name, snap_name, low->io_num);
			strfree(snap_name);
			return (ret);
		}
	} else {
		snap_zv = snap;
	}

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

	if (snap == NULL) {
		uzfs_close_dataset(snap_zv);

		/*
		 * TODO: if we failed to destroy snapshot here then
		 * this should be handled separately from application.
		 */
		if (end == metaobjectsize)
			destroy_snapshot_zv(zv, snap_name);

		strfree(snap_name);
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
uzfs_zvol_release_internal_clone(zvol_state_t *zv,
    zvol_state_t **snap_zv, zvol_state_t **clone_zv)
{
	int ret = 0;
	char *clonename;

	if (*snap_zv == NULL) {
		ASSERT(*clone_zv == NULL);
		return (ret);
	}

	clonename = kmem_asprintf("%s/%s_%s", spa_name(zv->zv_spa),
	    strchr(zv->zv_name, '/') + 1,
	    REBUILD_SNAPSHOT_CLONENAME);

	LOG_INFO("Closing rebuild_snap and rebuild_clone dataset on:%s",
	    zv->zv_name);
	/* Close clone dataset */
	uzfs_close_dataset(*clone_zv);
	*clone_zv = NULL;

	/* Close snapshot dataset */
	uzfs_close_dataset(*snap_zv);
	*snap_zv = NULL;

	strfree(clonename);

	return (ret);
}

/*
 * This API is used to delete internal
 * cloned volume and backing snapshot.
 */
int
uzfs_zvol_destroy_internal_clone(zvol_state_t *zv,
    zvol_state_t **snap_zv, zvol_state_t **clone_zv)
{
	int ret = 0;
	char *clonename;

	if (*snap_zv == NULL) {
		ASSERT(*clone_zv == NULL);
		return (ret);
	}

	clonename = kmem_asprintf("%s/%s_%s", spa_name(zv->zv_spa),
	    strchr(zv->zv_name, '/') + 1,
	    REBUILD_SNAPSHOT_CLONENAME);

	/* Close clone dataset */
	uzfs_close_dataset(*clone_zv);
	*clone_zv = NULL;
	LOG_INFO("Destroying rebuild_snap and rebuild_clone on:%s",
	    zv->zv_name);

	/* Destroy clone */
	ret = dsl_destroy_head(clonename);
	if (ret != 0)
		LOG_ERRNO("Rebuild_clone destroy failed on:%s"
		    " with err:%d", zv->zv_name, ret);

	/* Close snapshot dataset */
	uzfs_close_dataset(*snap_zv);
	*snap_zv = NULL;

	/* Destroy snapshot */
	destroy_snapshot_zv(zv, REBUILD_SNAPSHOT_SNAPNAME);
	strfree(clonename);

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

	ret = get_snapshot_zv(zv, REBUILD_SNAPSHOT_SNAPNAME, snap_zv);
	if (ret != 0) {
		LOG_ERR("Failed to get info about %s@%s",
		    zv->zv_name, REBUILD_SNAPSHOT_SNAPNAME);
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
		ret = uzfs_open_dataset(zv->zv_spa, clone_subname, clone_zv);
		if (ret == 0) {
			ret = uzfs_hold_dataset(*clone_zv);
			if (ret != 0) {
				LOG_ERR("Failed to hold clone: %d", ret);
				uzfs_close_dataset(*clone_zv);
				*clone_zv = NULL;
				/* Destroy clone */
				ret = dsl_destroy_head(clonename);
				if (ret != 0)
					LOG_ERRNO("Rebuild_clone destroy "
					    "failed on:%s with err:%d",
					    zv->zv_name, ret);
				uzfs_close_dataset(*snap_zv);
				destroy_snapshot_zv(zv,
				    REBUILD_SNAPSHOT_SNAPNAME);
				*snap_zv = NULL;
			}
		} else {
			uzfs_close_dataset(*snap_zv);
			destroy_snapshot_zv(zv, REBUILD_SNAPSHOT_SNAPNAME);
			*snap_zv = NULL;
			LOG_INFO("Clone:%s not able to open", clone_subname);
		}
	} else if (ret != 0) {
		uzfs_close_dataset(*snap_zv);
		destroy_snapshot_zv(zv, REBUILD_SNAPSHOT_SNAPNAME);
		*snap_zv = NULL;
	}

	strfree(clone_subname);
	strfree(clonename);
	strfree(snapname);
	return (ret);
}
