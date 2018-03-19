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

/* Writes data 'buf' to dataset 'zv' at 'offset' for 'len' */
int
uzfs_write_data(zvol_state_t *zv, char *buf, uint64_t offset, uint64_t len,
    blk_metadata_t *metadata)
{
	uint64_t bytes = 0, sync;
	uint64_t volsize = zv->zv_volsize;
	uint64_t blocksize = zv->zv_volblocksize;
	uint64_t end = len + offset;
	uint64_t wrote = 0;
	objset_t *os = zv->zv_objset;
	rl_t *rl, *mrl;
	int ret = 0, error;
	uint64_t r_offset;
	metaobj_blk_offset_t metablk;
	uint64_t metadatasize = zv->zv_volmetadatasize;
	uint64_t len_in_first_aligned_block = 0;

	sync = (dmu_objset_syncprop(os) == ZFS_SYNC_ALWAYS) ? 1 : 0;
	if (zv->zv_volmetablocksize == 0)
		metadata = NULL;

	r_offset = P2ALIGN_TYPED(offset, blocksize, uint64_t);
	len_in_first_aligned_block = (blocksize - (offset - r_offset));

	if (len_in_first_aligned_block > len)
		len_in_first_aligned_block = len;

	rl = zfs_range_lock(&zv->zv_range_lock, offset, len, RL_WRITER);

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

		if (metadata != NULL) {
			mrl = zfs_range_lock(&zv->zv_mrange_lock,
			    metablk.m_offset, metadatasize, RL_WRITER);
			dmu_write(os, ZVOL_META_OBJ, metablk.m_offset,
			    metadatasize, metadata, tx);
			zfs_range_unlock(mrl);
		}

		zvol_log_write(zv, tx, offset, bytes, sync, metadata);

		dmu_tx_commit(tx);

		offset += bytes;
		wrote += bytes;
		len -= bytes;
	}
exit_with_error:
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
