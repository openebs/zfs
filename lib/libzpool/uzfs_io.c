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
#include <uzfs_mtree.h>

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
    offset, blocksize)	\
	do {							\
		uint64_t r_offset;				\
		r_offset = P2ALIGN_TYPED(offset, blocksize,	\
		    uint64_t);					\
		len_in_first_aligned_block = (blocksize -	\
		    (offset - r_offset));			\
		if (len_in_first_aligned_block > len)		\
			len_in_first_aligned_block = len;	\
	} while (0)

#define	WRITE_METADATA(zv, metablk, metadata, tx)		\
	do {							\
		rl_t *mrl;					\
		mrl = zfs_range_lock(&zv->zv_mrange_lock,	\
		    metablk.m_offset, zv->zv_volmetadatasize, 	\
		    RL_WRITER);					\
		dmu_write(zv->zv_objset, ZVOL_META_OBJ,		\
		    metablk.m_offset, zv->zv_volmetadatasize,	\
		    metadata, tx);				\
		zfs_range_unlock(mrl);				\
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
	int ret = 0, error;
	metaobj_blk_offset_t metablk;
	uint64_t metadatasize = zv->zv_volmetadatasize;
	uint64_t len_in_first_aligned_block = 0;
	uint32_t count = 0;
	list_t *chunk_io = NULL;
	uint64_t orig_offset = offset;

	sync = (dmu_objset_syncprop(os) == ZFS_SYNC_ALWAYS) ? 1 : 0;
	if (zv->zv_volmetablocksize == 0)
		metadata = NULL;

	CHECK_FIRST_ALIGNED_BLOCK(len_in_first_aligned_block, offset,
	    blocksize);

	rl = zfs_range_lock(&zv->zv_range_lock, offset, len, RL_WRITER);

	if (!is_rebuild && (zv->zv_status & ZVOL_STATUS_DEGRADED))
		uzfs_add_to_incoming_io_tree(zv, offset, len);

	if (zv->zv_rebuild_status & ZVOL_REBUILDING_IN_PROGRESS) {
		if (is_rebuild) {
			count = uzfs_search_incoming_io_tree(zv, offset,
			    len, (void **)&chunk_io);
			if (!count)
				goto exit_with_error;
chunk_io:
			GET_NEXT_CHUNK(chunk_io, offset, len, end);
			wrote = offset - orig_offset;
			CHECK_FIRST_ALIGNED_BLOCK(
			    len_in_first_aligned_block, offset,
			    blocksize);

			zv->rebuild_data.rebuild_bytes += len;
			count--;
		}
	} else {
		VERIFY(is_rebuild == 0);
	}

	while (offset < end && offset < volsize) {
		if (len_in_first_aligned_block != 0) {
			bytes = len_in_first_aligned_block;
			len_in_first_aligned_block = 0;
		}
		else
			bytes = (len < blocksize) ? len : blocksize;

		if (bytes > (volsize - offset))
			bytes = volsize - offset;

		dmu_tx_t *tx = dmu_tx_create(os);
		dmu_tx_hold_write(tx, ZVOL_OBJ, offset, bytes);

		if (metadata != NULL) {
			/* This assumes metavolblocksize same as volblocksize */
			get_metaobj_block_details(&metablk, zv, offset);

			dmu_tx_hold_write(tx, ZVOL_META_OBJ, metablk.m_offset,
			    metadatasize);
		}

		error = dmu_tx_assign(tx, TXG_WAIT);
		if (error) {
			dmu_tx_abort(tx);
			ret = UZFS_IO_TX_ASSIGN_FAIL;
			goto exit_with_error;
		}
		dmu_write(os, ZVOL_OBJ, offset, bytes, buf + wrote, tx);

		if (metadata)
			WRITE_METADATA(zv, metablk, metadata, tx);

		zvol_log_write(zv, tx, offset, bytes, sync, metadata);

		dmu_tx_commit(tx);

		offset += bytes;
		wrote += bytes;
		len -= bytes;
	}

exit_with_error:
	if ((zv->zv_rebuild_status & ZVOL_REBUILDING_IN_PROGRESS) &&
	    is_rebuild && count && !ret)
		goto chunk_io;

	if (chunk_io) {
		list_destroy(chunk_io);
		umem_free(chunk_io, sizeof (*chunk_io));
	}

	zfs_range_unlock(rl);

	if (sync)
		zil_commit(zv->zv_zilog, ZVOL_OBJ);

	return (ret);
}

/* Reads data from volume 'zv', and fills up memory at buf */
int
uzfs_read_data(zvol_state_t *zv, char *buf, uint64_t offset, uint64_t len,
    void **md, uint64_t *mdlen)
{
	int error = 0;
	uint64_t blocksize = zv->zv_volblocksize;
	uint64_t bytes = 0;
	uint64_t volsize = zv->zv_volsize;
	uint64_t end = len + offset;
	uint64_t read = 0;
	objset_t *os = zv->zv_objset;
	rl_t *rl, *mrl;
	int ret = 0;
	uint64_t r_offset;
	uint64_t metadatasize = zv->zv_volmetadatasize;
	void *mdata = NULL;
	uint64_t mread = 0;
	uint64_t mlen = 0;
	metaobj_blk_offset_t metablk;
	uint64_t len_in_first_aligned_block = 0;

	if (zv->zv_volmetablocksize == 0)
		mdlen = NULL;

	if (md != NULL && mdlen != NULL) {
		mlen = get_metadata_len(zv, offset, len);
		mdata = kmem_alloc(mlen, KM_SLEEP);
		mread = 0;
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

		error = dmu_read(os, ZVOL_OBJ, offset, bytes, buf + read, 0);
		if (error) {
			ret = UZFS_IO_READ_FAIL;
			goto exit_with_error;
		}

		if ((md != NULL) && (mdlen != NULL)) {
			/* This assumes metavolblocksize same as volblocksize */
			get_metaobj_block_details(&metablk, zv, offset);

			mrl = zfs_range_lock(&zv->zv_mrange_lock,
			    metablk.m_offset, metadatasize, RL_READER);
			error = dmu_read(os, ZVOL_META_OBJ, metablk.m_offset,
			    metadatasize, mdata + mread, 0);
			if (error) {
				zfs_range_unlock(mrl);
				ret = UZFS_IO_MREAD_FAIL;
				goto exit_with_error;
			}
			zfs_range_unlock(mrl);
			mread += metadatasize;
		}
		offset += bytes;
		read += bytes;
		len -= bytes;
	}

exit_with_error:
	zfs_range_unlock(rl);

	if (error == 0) {
		VERIFY3P(mread, ==, mlen);
	}

	if ((md != NULL) && (mdlen != NULL)) {
		*mdlen = mlen;
		*md = mdata;
	}
	return (error);
}

void
uzfs_flush_data(zvol_state_t *zv)
{
	zil_commit(zv->zv_zilog, ZVOL_OBJ);
}

/*
 * Caller is responsible for locking to ensure
 * synchronization across below four functions
 */
void
uzfs_zvol_set_status(zvol_state_t *zv, zvol_status_t status)
{
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
	zv->zv_rebuild_status = status;
}

zvol_rebuild_status_t
uzfs_zvol_get_rebuild_status(zvol_state_t *zv)
{
	return (zv->zv_rebuild_status);
}
