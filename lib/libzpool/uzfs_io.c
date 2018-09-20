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
#include <sys/zap.h>
#include <sys/uzfs_zvol.h>
#include <uzfs_rebuilding.h>
#include <sys/dsl_dataset.h>
#include <sys/dbuf.h>
#include <uzfs_io.h>
#include <zrepl_mgmt.h>

#if DEBUG
inject_error_t	inject_error;
#endif

#define	GET_NEXT_CHUNK(chunk_io, offset, len, end)		\
	do {							\
		uzfs_io_chunk_list_t *node;			\
		node = list_remove_head(chunk_io);		\
		offset = node->offset;				\
		len = node->len;				\
		end = offset + len;				\
		umem_free(node, sizeof (*node));		\
	} while (0)

#define	CHECK_FIRST_ALIGNED_BLOCK(len_in_first_aligned_block,	\
    offset, len, blocksize)	\
	do {							\
		uint64_t r_offset;				\
		r_offset = P2ALIGN_TYPED(offset, blocksize,	\
		    uint64_t);					\
		len_in_first_aligned_block = (blocksize -	\
		    (offset - r_offset));			\
		if (len_in_first_aligned_block > len)		\
			len_in_first_aligned_block = len;	\
	} while (0)

#define	WRITE_METADATA(zv, metablk, mdata, tx)			\
	do {							\
		dmu_write(zv->zv_objset, ZVOL_META_OBJ,		\
		    metablk.m_offset, metablk.m_len,		\
		    mdata, tx);					\
	} while (0)

/* Writes data 'buf' to dataset 'zv' at 'offset' for 'len' */
int
uzfs_write_data(zvol_state_t *zv, char *buf, uint64_t offset, uint64_t len,
    blk_metadata_t *metadata, boolean_t is_rebuild)
{
	uint64_t bytes = 0, sync;
	uint64_t volsize = zv->zv_volsize;
	uint64_t blocksize = zv->zv_volblocksize;
	uint64_t end = len + offset;
	uint64_t wrote = 0;
	objset_t *os = zv->zv_objset;
	rl_t *rl;
	uint64_t mlen = 0;
	int ret = 0, error;
	metaobj_blk_offset_t metablk;
	uint64_t metadatasize = zv->zv_volmetadatasize;
	uint64_t len_in_first_aligned_block = 0;
	uint32_t count = 0;
	list_t *chunk_io = NULL;
	uint64_t orig_offset = offset;
	char *mdata = NULL, *tmdata = NULL, *tmdataend = NULL;

	/*
	 * If trying IO on fresh zvol before metadata granularity is set return
	 * error.
	 */

	if (zv->zv_metavolblocksize == 0)
		return (EINVAL);
	ASSERT3P(zv->zv_metavolblocksize, !=, 0);
	if (!IS_P2ALIGNED(offset, zv->zv_metavolblocksize) ||
	    !IS_P2ALIGNED(len, zv->zv_metavolblocksize) ||
	    len == 0)
		return (EINVAL);

	if (offset + len > zv->zv_volsize || offset > zv->zv_volsize)
		return (EINVAL);

	sync = (dmu_objset_syncprop(os) == ZFS_SYNC_ALWAYS) ? 1 : 0;
	ASSERT3P(zv->zv_volmetablocksize, !=, 0);

#if DEBUG
	if (inject_error.delay.pre_uzfs_write_data == 1) {
		LOG_DEBUG("delaying write");
		sleep(10);
	}
#endif
	if (metadata != NULL) {
		mlen = get_metadata_len(zv, offset, len);
		VERIFY((mlen % metadatasize) == 0);
		tmdata = mdata = kmem_alloc(mlen, KM_SLEEP);
		tmdataend = mdata + mlen;
		while (tmdata < tmdataend) {
			memcpy(tmdata, metadata, metadatasize);
			tmdata += metadatasize;
		}
	}

	CHECK_FIRST_ALIGNED_BLOCK(len_in_first_aligned_block, offset, len,
	    blocksize);

	rl = zfs_range_lock(&zv->zv_range_lock, offset, len, RL_WRITER);

	if (is_rebuild) {
		VERIFY(ZVOL_IS_DEGRADED(zv) && (ZVOL_IS_REBUILDING(zv) ||
		    ZVOL_IS_REBUILDING_ERRORED(zv)));
		count = uzfs_get_nonoverlapping_ondisk_blks(zv, offset,
		    len, metadata, (void **)&chunk_io);
		if (!count)
			goto exit_with_error;
chunk_io:
			GET_NEXT_CHUNK(chunk_io, offset, len, end);
			wrote = offset - orig_offset;
			CHECK_FIRST_ALIGNED_BLOCK(
			    len_in_first_aligned_block, offset, len,
			    blocksize);

			zv->rebuild_info.rebuild_bytes += len;
			count--;
	}

	while (offset < end && offset < volsize) {
		if (len_in_first_aligned_block != 0) {
			bytes = len_in_first_aligned_block;
			len_in_first_aligned_block = 0;
		} else
			bytes = (len < blocksize) ? len : blocksize;

		if (bytes > (volsize - offset))
			bytes = volsize - offset;

		dmu_tx_t *tx = dmu_tx_create(os);
		dmu_tx_hold_write(tx, ZVOL_OBJ, offset, bytes);

		if (metadata != NULL) {
			/* This assumes metavolblocksize same as volblocksize */
			get_zv_metaobj_block_details(&metablk, zv, offset,
			    bytes);

			dmu_tx_hold_write(tx, ZVOL_META_OBJ, metablk.m_offset,
			    metablk.m_len);
		}

		error = dmu_tx_assign(tx, TXG_WAIT);
		if (error) {
			dmu_tx_abort(tx);
			ret = UZFS_IO_TX_ASSIGN_FAIL;
			goto exit_with_error;
		}
		dmu_write(os, ZVOL_OBJ, offset, bytes, buf + wrote, tx);

		if (metadata)
			WRITE_METADATA(zv, metablk, mdata, tx);

		zvol_log_write(zv, tx, offset, bytes, sync, metadata);

		dmu_tx_commit(tx);

		offset += bytes;
		wrote += bytes;
		len -= bytes;
	}

exit_with_error:
	if (is_rebuild && count && !ret &&
	    ZVOL_IS_DEGRADED(zv) && ZVOL_IS_REBUILDING(zv))
		goto chunk_io;

	if (chunk_io) {
		list_destroy(chunk_io);
		umem_free(chunk_io, sizeof (*chunk_io));
	}

	zfs_range_unlock(rl);

	if (sync)
		zil_commit(zv->zv_zilog, ZVOL_OBJ);

	if (mdata)
		kmem_free(mdata, mlen);

	return (ret);
}

/*
 * Append to the tail of metadata list and return updated tail. If the list
 * is empty initially, the head pointer is updated here.
 */
static metadata_desc_t *
uzfs_metadata_append(zvol_state_t *zv, blk_metadata_t *metadata, int n,
    metadata_desc_t **head, metadata_desc_t *tail)
{
	metadata_desc_t *new_md;

	for (int i = 0; i < n; i++) {
		new_md = NULL;
		if (tail != NULL) {
			/*
			 * Join adjacent metadata with the same
			 * io number into one descriptor.
			 * Otherwise create a new one.
			 */
			if (tail->metadata.io_num == metadata[i].io_num) {
				tail->len += zv->zv_metavolblocksize;
			} else {
				new_md = kmem_alloc(sizeof (metadata_desc_t),
				    KM_SLEEP);
				tail->next = new_md;
			}
		} else {
			ASSERT3P(*head, ==, NULL);
			new_md = kmem_alloc(sizeof (metadata_desc_t), KM_SLEEP);
			*head = new_md;
		}
		if (new_md != NULL) {
			new_md->next = NULL;
			new_md->len = zv->zv_metavolblocksize;
			new_md->metadata = metadata[i];
			tail = new_md;
		}
	}

	return (tail);
}

/*
 * Reads data from volume 'zv', and fills up memory at buf
 * If caller has asked for data_error or metadata error then this
 * function will try to read for all the blocks requested by caller
 * else this function will return as soon as any error happens while
 * reading any requested block.
 */
int
uzfs_read_data(zvol_state_t *zv, char *buf, uint64_t offset, uint64_t len,
    metadata_desc_t **md_head, int *data_err, int *md_err)
{
	int error = EINVAL;	// in case we aren't able to read a single block
	uint64_t blocksize = zv->zv_volblocksize;
	uint64_t bytes = 0;
	uint64_t volsize = zv->zv_volsize;
	uint64_t end = len + offset;
	uint64_t read = 0;
	objset_t *os = zv->zv_objset;
	rl_t *rl;
	uint64_t r_offset;
	metaobj_blk_offset_t metablk;
	uint64_t len_in_first_aligned_block = 0;
	metadata_desc_t *md_ent = NULL;
	blk_metadata_t *metadata;
	int nmetas;

	/*
	 * If trying IO on fresh zvol before metadata granularity is set return
	 * error.
	 */
	if (zv->zv_metavolblocksize == 0)
		return (EINVAL);
	if (!IS_P2ALIGNED(offset, zv->zv_metavolblocksize) ||
	    !IS_P2ALIGNED(len, zv->zv_metavolblocksize) ||
	    len == 0)
		return (EINVAL);

	if (offset + len > zv->zv_volsize || offset > zv->zv_volsize)
		return (EINVAL);

	ASSERT3P(zv->zv_volmetadatasize, ==, sizeof (blk_metadata_t));

	/* init metadata in case caller wants to receive that info */
	if (md_head != NULL) {
		*md_head = NULL;
		ASSERT3P(zv->zv_volmetablocksize, !=, 0);
	}

	r_offset = P2ALIGN_TYPED(offset, blocksize, uint64_t);

	len_in_first_aligned_block = (blocksize - (offset - r_offset));

	if (len_in_first_aligned_block > len)
		len_in_first_aligned_block = len;

	rl = zfs_range_lock(&zv->zv_range_lock, offset, len, RL_READER);

	while ((offset < end) && (offset < volsize)) {
		if (len_in_first_aligned_block != 0) {
			bytes = len_in_first_aligned_block;
			len_in_first_aligned_block = 0;
		}
		else
			bytes = (len < blocksize) ? len : blocksize;

		if (bytes > (volsize - offset))
			bytes = volsize - offset;

		error = dmu_read(os, ZVOL_OBJ, offset, bytes,
		    buf + read, DMU_READ_CHECK_HOLE);
		if (error != 0) {
			if (data_err) {
				*data_err = error;
				error = 0;
			} else
				goto exit;
		}

		if (md_head != NULL) {
			get_zv_metaobj_block_details(&metablk, zv, offset,
			    bytes);

			metadata = kmem_alloc(metablk.m_len, KM_SLEEP);
			error = dmu_read(os, ZVOL_META_OBJ,
			    metablk.m_offset, metablk.m_len, metadata,
			    DMU_READ_CHECK_HOLE);
			if (error != 0) {
				if (md_err) {
					*md_err = error;
					error = 0;
				} else {
					kmem_free(metadata, metablk.m_len);
					goto exit;
				}
			}

			nmetas = metablk.m_len / sizeof (*metadata);
			ASSERT3P(zv->zv_metavolblocksize * nmetas, >=, bytes);
			ASSERT3P(zv->zv_metavolblocksize * nmetas, <,
			    bytes + blocksize);

			md_ent = uzfs_metadata_append(zv, metadata, nmetas,
			    md_head, md_ent);
			kmem_free(metadata, metablk.m_len);
		}
		offset += bytes;
		read += bytes;
		len -= bytes;
	}

exit:
	zfs_range_unlock(rl);

	if (md_head != NULL && error != 0) {
		FREE_METADATA_LIST(*md_head);
		*md_head = NULL;
	}
	return (error);
}

void
uzfs_flush_data(zvol_state_t *zv)
{
	zil_commit(zv->zv_zilog, ZVOL_OBJ);
}

static const char *
zvol_status_to_str(zvol_status_t status)
{
	switch (status) {
	case ZVOL_STATUS_HEALTHY:
		return ("HEALTHY");
	case ZVOL_STATUS_DEGRADED:
		return ("DEGRADED");
	default:
		break;
	}
	return ("UNKNOWN");
}

static const char *
rebuild_status_to_str(zvol_rebuild_status_t status)
{
	switch (status) {
	case ZVOL_REBUILDING_INIT:
		return ("INIT");
	case ZVOL_REBUILDING_SNAP:
		return ("SNAP REBUILD INPROGRESS");
	case ZVOL_REBUILDING_AFS:
		return ("ACTIVE DATASET REBUILD INPROGRESS");
	case ZVOL_REBUILDING_DONE:
		return ("DONE");
	case ZVOL_REBUILDING_ERRORED:
		return ("ERRORED");
	case ZVOL_REBUILDING_FAILED:
		return ("FAILED");
	default:
		break;
	}
	return ("UNKNOWN");
}

/*
 * Caller is responsible for locking to ensure
 * synchronization across below four functions
 */
void
uzfs_zvol_set_status(zvol_state_t *zv, zvol_status_t status)
{
	LOG_INFO("zvol %s status change: %s -> %s", zv->zv_name,
	    zvol_status_to_str(zv->zv_status), zvol_status_to_str(status));
	zv->zv_status = status;
}

zvol_status_t
uzfs_zvol_get_status(zvol_state_t *zv)
{
	return (zv->zv_status);
}
void
uzfs_zvol_set_rebuild_status(zvol_state_t *zv, zvol_rebuild_status_t status)
{
	LOG_INFO("zvol %s rebuild status change: %s -> %s", zv->zv_name,
	    rebuild_status_to_str(zv->rebuild_info.zv_rebuild_status),
	    rebuild_status_to_str(status));
	zv->rebuild_info.zv_rebuild_status = status;
}

zvol_rebuild_status_t
uzfs_zvol_get_rebuild_status(zvol_state_t *zv)
{
	return (zv->rebuild_info.zv_rebuild_status);
}

/*
 * uzfs_read_metadata will read metadata for given offset and length
 * Note: Caller must acquire zv_range_lock with related lun offset and length
 */
int
uzfs_read_metadata(zvol_state_t *zv, char *buf, uint64_t offset, uint64_t len,
    uint64_t *r)
{
	uint64_t blocksize = zv->zv_volmetablocksize;
	uint64_t len_in_first_aligned_block, bytes, read = 0;
	uint64_t end = offset + len;
	uint64_t metaobjectsize;
	uint64_t r_offset = P2ALIGN(offset, blocksize);
	int ret = 0;

	/*
	 * If trying IO on fresh zvol before metadata granularity is set return
	 * error.
	 */
	if (zv->zv_metavolblocksize == 0)
		return (EINVAL);
	ASSERT3P(zv->zv_metavolblocksize, !=, 0);
	metaobjectsize = (zv->zv_volsize / zv->zv_metavolblocksize) *
	    zv->zv_volmetadatasize;
	len_in_first_aligned_block = (blocksize - (offset - r_offset));
	if (len_in_first_aligned_block > len)
		len_in_first_aligned_block = len;

	while ((offset < end) && (offset < metaobjectsize)) {
		if (len_in_first_aligned_block != 0) {
			bytes = len_in_first_aligned_block;
			len_in_first_aligned_block = 0;
		} else {
			bytes = (len < blocksize) ? len : blocksize;
		}

		if (bytes > (metaobjectsize - offset))
			bytes = metaobjectsize - offset;

		ret = dmu_read(zv->zv_objset, ZVOL_META_OBJ, offset, bytes,
		    buf + read, 0);
		if (ret) {
			ret = UZFS_IO_READ_FAIL;
			break;
		}

		offset += bytes;
		read += bytes;
		len -= bytes;
	}

	if (r)
		*r = read;

	return (ret);
}

/*
 * Update metadata granularity. This is done when zvol is opened the first time
 * (based on value sent from iSCSI target) and afterwards the granularity must
 * not change.
 */
int
uzfs_update_metadata_granularity(zvol_state_t *zv, uint64_t tgt_block_size)
{
	int error;
	dmu_tx_t *tx;

	if (tgt_block_size == zv->zv_metavolblocksize)
		return (0);	/* nothing to update */

	if ((zv->zv_metavolblocksize != 0) &&
	    (tgt_block_size != zv->zv_metavolblocksize)) {
		LOG_ERR("Update metadata granularity from old %lu to new %lu "
		    "failed", zv->zv_metavolblocksize, tgt_block_size);
		return (-1);
	}

	tx = dmu_tx_create(zv->zv_objset);
	dmu_tx_hold_zap(tx, ZVOL_ZAP_OBJ, TRUE, NULL);
	error = dmu_tx_assign(tx, TXG_WAIT);
	if (error != 0) {
		dmu_tx_abort(tx);
		return (-1);
	}
	VERIFY0(zap_update(zv->zv_objset, ZVOL_ZAP_OBJ, "metavolblocksize",
	    8, 1, &tgt_block_size, tx));
	dmu_tx_commit(tx);
	zv->zv_metavolblocksize = tgt_block_size;
	return (0);
}

int
uzfs_unmap_data(zvol_state_t *zv, uint64_t offset, uint64_t len,
    blk_metadata_t *metadata, boolean_t is_rebuild)
{
	int error, ret = 0, i;
	dmu_tx_t *tx;
	itx_t *itx;
	lr_truncate_t *lr;
	metaobj_blk_offset_t metablk;
	uint8_t *buf;
	uint64_t moff, mend, mchunk, mwlen;
	rl_t *rl;
	uint32_t count = 0;
	list_t *chunk_io = NULL;
	uint64_t orig_offset = offset;
	uint64_t end = len + offset;
	uint64_t wrote = 0;
	uint64_t blocksize = zv->zv_volblocksize;
	uint64_t len_in_first_aligned_block = 0;

	/*
	 * If trying IO on fresh zvol before metadata granularity is set return
	 * error.
	 */

	if (zv->zv_metavolblocksize == 0)
		return (EINVAL);

	ASSERT(metadata);
	ASSERT3P(zv->zv_metavolblocksize, !=, 0);
	if (!IS_P2ALIGNED(offset, zv->zv_metavolblocksize) ||
	    !IS_P2ALIGNED(len, zv->zv_metavolblocksize) ||
	    len == 0)
		return (EINVAL);

	if (offset + len > zv->zv_volsize || offset > zv->zv_volsize)
		return (EINVAL);

	rl = zfs_range_lock(&zv->zv_range_lock, offset, len, RL_WRITER);

	if (is_rebuild) {
		VERIFY(ZVOL_IS_DEGRADED(zv) && (ZVOL_IS_REBUILDING(zv) ||
		    ZVOL_IS_REBUILDING_ERRORED(zv)));
		count = uzfs_get_nonoverlapping_ondisk_blks(zv, offset,
		    len, metadata, (void **)&chunk_io);
		if (!count)
			goto out;
chunk_io:
			GET_NEXT_CHUNK(chunk_io, offset, len, end);
			wrote = offset - orig_offset;
			CHECK_FIRST_ALIGNED_BLOCK(
			    len_in_first_aligned_block, offset, len,
			    blocksize);

			zv->rebuild_info.rebuild_bytes += len;
			count--;
	}

	error = dmu_free_long_range(zv->zv_objset, ZVOL_OBJ, offset, len);
	if (error) {
		/*
		 * Ingore error as we are also writing free op in zil
		 */
		LOG_ERR("Failed to free range %lu+%lu err:%d\n",
		    offset, len, error);
	}

	tx = dmu_tx_create(zv->zv_objset);
	get_zv_metaobj_block_details(&metablk, zv, offset, len);
	dmu_tx_hold_write(tx, ZVOL_META_OBJ, metablk.m_offset, metablk.m_len);

	error = dmu_tx_assign(tx, TXG_WAIT);
	if (error) {
		dmu_tx_abort(tx);
		ret = UZFS_IO_TX_ASSIGN_FAIL;
		goto out;
	}

	if (!zil_replaying(zv->zv_zilog, tx)) {
		itx = zil_itx_create(TX_TRUNCATE, sizeof (*lr));
		lr = (lr_truncate_t *)&itx->itx_lr;
		lr->lr_foid = ZVOL_OBJ;
		lr->lr_offset = offset;
		lr->lr_length = len;
		itx->itx_sync = FALSE;

		zil_itx_assign(zv->zv_zilog, itx, tx);
	}

	moff = metablk.m_offset;
	mend = moff + metablk.m_len;
	mchunk = zv->zv_volmetablocksize;
	buf = kmem_alloc(mchunk, KM_SLEEP);
	for (i = 0; i < mchunk; i += zv->zv_volmetadatasize) {
		memcpy(buf + i, metadata, sizeof (blk_metadata_t));
	}

	while (moff < mend) {
		mwlen = ((moff + mchunk) < mend) ? mchunk : (mend - moff);
		dmu_write(zv->zv_objset, ZVOL_META_OBJ, moff, mwlen, buf, tx);
		moff += mwlen;
	}
	kmem_free(buf, mchunk);
	dmu_tx_commit(tx);

out:
	if (is_rebuild && count && !ret &&
	    ZVOL_IS_DEGRADED(zv) && ZVOL_IS_REBUILDING(zv))
		goto chunk_io;

	if (chunk_io) {
		list_destroy(chunk_io);
		umem_free(chunk_io, sizeof (*chunk_io));
	}

	zfs_range_unlock(rl);
	return (ret);
}
