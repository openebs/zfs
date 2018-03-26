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

#define	IO_DIFF_SNAPNAME	".io_snap"

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
    last_index, arg, last_md, zv, func)					\
		do {							\
			func(last_lun_offset, diff_count * 		\
			    zv->zv_metavolblocksize, (blk_metadata_t *) \
			    (buf + last_index), arg);			\
			diff_count = 0;					\
			last_index = 0;					\
			last_md = NULL;					\
			diff_count = 0;					\
		} while (0)

int
uzfs_get_io_diff(zvol_state_t *zv, blk_metadata_t *low,
    uzfs_get_io_diff_cb_t *func, void *arg)
{
	uint64_t blocksize = zv->zv_volmetablocksize;
	uint64_t metadata_read_chunk_size = 10 * blocksize;
	uint64_t metaobjectsize = (zv->zv_volsize / zv->zv_metavolblocksize) *
	    zv->zv_volmetadatasize;
	uint64_t metadatasize = zv->zv_volmetadatasize;
	char *buf;
	uint64_t lun_offset, len, i, read, offset;
	int ret = 0;
	char *snap_name, *dataset;
	hrtime_t now;
	dsl_pool_t *dp;
	dsl_dataset_t *ds_snap;
	int diff_count = 0, last_index = 0;
	uint64_t last_lun_offset = 0;
	blk_metadata_t *last_md;

	if (!func)
		return (EINVAL);

	now = gethrtime();

	snap_name = kmem_asprintf("%s%llu", IO_DIFF_SNAPNAME, now);

	ret = dmu_objset_snapshot_one(zv->zv_name, snap_name);
	if (ret) {
		printf("failed to create snapshot for %s\n", zv->zv_name);
		strfree(snap_name);
		return (ret);
	}

	strfree(snap_name);

	dataset = kmem_asprintf("%s@%s%llu", zv->zv_name,
	    IO_DIFF_SNAPNAME, now);

	ret = dsl_pool_hold(dataset, FTAG, &dp);
	if (ret) {
		(void) dsl_destroy_snapshot(dataset, B_FALSE);
		strfree(dataset);
		return (ret);
	}

	ret = dsl_dataset_hold(dp, dataset, FTAG, &ds_snap);
	if (ret) {
		(void) dsl_destroy_snapshot(dataset, B_FALSE);
		dsl_pool_rele(dp, FTAG);
		strfree(dataset);
		return (ret);
	}

	dsl_dataset_long_hold(ds_snap, FTAG);

	metadata_read_chunk_size = (metadata_read_chunk_size / metadatasize) *
	    metadatasize;
	buf = umem_alloc(metadata_read_chunk_size, KM_SLEEP);
	len = metadata_read_chunk_size;

	for (offset = 0; offset < metaobjectsize; offset += len) {
		read = 0;
		len = metadata_read_chunk_size;

		if ((offset + len) > metaobjectsize)
			len = (metaobjectsize - offset);

		ret = uzfs_read_metadata(zv, buf, offset, len, &read);

		if (read != len || ret)
			break;

		lun_offset = (offset / metadatasize) * zv->zv_metavolblocksize;
		for (i = 0; i < len; i += sizeof (blk_metadata_t)) {
			if (!iszero((blk_metadata_t *)(buf+i)) &&
			    (compare_blk_metadata((blk_metadata_t *)(buf + i),
			    low) > 0)) {
				if (diff_count == 0) {
					last_lun_offset = lun_offset;
					last_md = (blk_metadata_t *)(buf+i);
					last_index = i;
				}
				diff_count++;
				if (last_md != NULL &&
				    compare_blk_metadata((blk_metadata_t *)
				    (buf + i), last_md) != 0) {
					EXECUTE_DIFF_CALLBACK(last_lun_offset,
					    diff_count, buf, last_index, arg,
					    last_md, zv, func);
				}
			} else if (diff_count) {
				EXECUTE_DIFF_CALLBACK(last_lun_offset,
				    diff_count, buf, last_index, arg, last_md,
				    zv, func);
			}

			lun_offset += zv->zv_metavolblocksize;
		}

		if (diff_count) {
			EXECUTE_DIFF_CALLBACK(last_lun_offset, diff_count, buf,
			    last_index, arg, last_md, zv, func);
		}
	}

	dsl_dataset_long_rele(ds_snap, FTAG);
	dsl_dataset_rele(ds_snap, FTAG);
	dsl_pool_rele(dp, FTAG);

	/*
	 * TODO: if we failed to destroy snapshot here then
	 * this should be handled separately from application.
	 */
	(void) dsl_destroy_snapshot(dataset, B_FALSE);
	umem_free(buf, metadata_read_chunk_size);
	strfree(dataset);
	return (ret);
}

int
uzfs_search_nonoverlapping_io(zvol_state_t *zv, uint64_t offset, uint64_t len,
    blk_metadata_t *metadata, void **list)
{
	char *rd_metadata_buf;
	uint64_t rd_rlen;
	metaobj_blk_offset_t rd_metablk;
	blk_metadata_t *rd_metadata;
	int diff_count = 0;
	int count = 0;
	int ret = 0;
	int i = 0;
	uint64_t lun_offset = 0, last_lun_offset = 0;
	list_t *chunk_list = NULL;
	uint64_t metavolblocksize = zv->zv_metavolblocksize;
	uint64_t metadatasize = zv->zv_volmetadatasize;

	get_zv_metaobj_block_details(&rd_metablk, zv, offset, len);
	rd_metadata_buf = umem_alloc(rd_metablk.m_len, UMEM_NOFAIL);

	ret = uzfs_read_metadata(zv, rd_metadata_buf, rd_metablk.m_offset,
	    rd_metablk.m_len, &rd_rlen);
	if (ret || rd_rlen != rd_metablk.m_len) {
		printf("failed to read metadata\n");
		goto exit;
	}

	chunk_list = umem_alloc(sizeof (*chunk_list), UMEM_NOFAIL);
	list_create(chunk_list, sizeof (uzfs_io_chunk_list_t),
	    offsetof(uzfs_io_chunk_list_t, link));

	for (i = 0; i < rd_metablk.m_len; i += sizeof (blk_metadata_t)) {
		rd_metadata = (blk_metadata_t *)(rd_metadata_buf + i);
		lun_offset = ((rd_metablk.m_offset + i) * metavolblocksize) /
		    metadatasize;
		ret = compare_blk_metadata(rd_metadata, metadata);
		if (ret == -1) {
			// old io number < new io number
			if (diff_count == 0) {
				last_lun_offset = lun_offset;
			}
			diff_count++;
		} else if (!ret) {
			// old io number == new io number
			if (diff_count == 0) {
				last_lun_offset = lun_offset;
			}
			diff_count++;
		} else {
			// old io number > new io number
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
	umem_free(rd_metadata_buf, rd_metablk.m_len);
	*list = chunk_list;
	return (count);
}
