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

#ifndef	_UZFS_IO_H
#define	_UZFS_IO_H

#include <sys/zil.h>
#include <sys/uzfs_zvol.h>

#ifdef __cplusplus
extern "C" {
#endif

struct metadata_desc;

/*
 * This describes a chunk of data associated with given meta data info.
 */
typedef struct metadata_desc {
	struct metadata_desc *next; /* next entry in list ordered by offset */
	size_t	len;	/* length of the chunk of data */
	blk_metadata_t	metadata;
} metadata_desc_t;

#define	FREE_METADATA_LIST(head)	\
	while ((head) != NULL) {	\
		metadata_desc_t *tmp = (head)->next;	\
		kmem_free((head), sizeof (metadata_desc_t));	\
		(head) = tmp;	\
	}

/*
 * writes metadata 'md' to zil records
 * is_rebuild: if IO is from target then it should be set to FALSE
 *		else it should be set to TRUE (in case of rebuild IO)
 */
int uzfs_write_data(zvol_state_t *zv, char *buf, uint64_t offset, uint64_t len,
    blk_metadata_t *metadata, boolean_t is_rebuild);

/*
 * reads data and metadata. Meta data is a list which must be freed by caller.
 */
int uzfs_read_data(zvol_state_t *zv, char *buf, uint64_t offset, uint64_t len,
    metadata_desc_t **md);

/*
 * UNMAP data at offset.
 */
int
uzfs_unmap_data(zvol_state_t *zv, uint64_t offset, uint64_t len,
    blk_metadata_t *metadata, boolean_t is_rebuild);

extern void uzfs_flush_data(zvol_state_t *zv);

int uzfs_update_metadata_granularity(zvol_state_t *zv, uint64_t block_size);

/*
 * API to set/get rebuilding status
 *
 * If, rebuilding mode is set, then every normal write IO will be added to
 * condensed avl tree (incoming io tree). For IO with is_rebuild
 * flag set in uzfs_write_data, it will be checked with incoming_io_tree and
 * only non-overlapping part from IO will be written.
 */
extern void uzfs_zvol_set_rebuild_status(zvol_state_t *zv,
    zvol_rebuild_status_t status);
extern zvol_rebuild_status_t uzfs_zvol_get_rebuild_status(zvol_state_t *zv);

/*
 * API to set/get zvol status
 */
extern void uzfs_zvol_set_status(zvol_state_t *zv, zvol_status_t status);
extern zvol_status_t uzfs_zvol_get_status(zvol_state_t *zv);

/*
 * API to read metadata
 */
extern int uzfs_read_metadata(zvol_state_t *zv, char *buf, uint64_t offset,
    uint64_t len, uint64_t *r);
/*
 * API to write metadata
 */
extern int uzfs_write_metadata(zvol_state_t *zv, uint64_t offset, uint64_t len,
    blk_metadata_t *metadata, dmu_tx_t *tx);

#define	WRITE_UNMAP_METADATA(_zv, _os, _off, _len, _md, _is_sync, _err)	\
do {									\
	if ((_zv == NULL) || (_len == 0) || (_md == NULL)) {		\
		_err = 0;						\
		break;							\
	}								\
	metaobj_blk_offset_t _metablk;					\
	dmu_tx_t *_tx = dmu_tx_create(_os);				\
	get_zv_metaobj_block_details(&_metablk, _zv,			\
	    _off, _len);						\
	dmu_tx_hold_write(_tx, ZVOL_META_OBJ, _metablk.m_offset,	\
	    _metablk.m_len);						\
	_err = dmu_tx_assign(_tx, TXG_WAIT);				\
	if (_err) {							\
		dmu_tx_abort(_tx);					\
		break;							\
	}								\
	_err = uzfs_write_metadata(_zv, _off, _len, _md, _tx);		\
	zvol_log_truncate(_zv, _tx, _off, _len, _is_sync, _md);		\
	dmu_tx_commit(_tx);						\
} while (0)

#ifdef __cplusplus
}
#endif
#endif
