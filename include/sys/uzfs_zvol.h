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

#ifndef	_SYS_UZFS_ZVOL_H
#define	_SYS_UZFS_ZVOL_H

#include <sys/zvol.h>
#include <sys/zfs_rlock.h>
#include <sys/zil.h>
#include <zrepl_prot.h>

#if !defined(_KERNEL)

typedef struct zvol_properties {
	uint64_t vol_size;
	uint64_t block_size;
	uint64_t meta_block_size;	/* explained in zvol_state_t def */
} zvol_properties_t;

/*
 * (r_offset, r_len) gives the range for range lock on metaobject
 * m_offset is the offset of metadata in metaobject
 */
typedef struct metaobj_blk_offset {
	uint64_t r_offset;
	uint64_t r_len;
	uint64_t m_offset;
	uint64_t m_len;
} metaobj_blk_offset_t;

/*
 * rebuild related information for zvol
 */
typedef struct zvol_rebuild_info {
	zvol_rebuild_status_t zv_rebuild_status; /* zvol rebuilding status */
	uint64_t rebuild_bytes;
	uint16_t rebuild_cnt;

	/* peer replica cnt whose rebuild is done either success or failure */
	uint16_t rebuild_done_cnt;

	/* peer replica cnt whose rebuild is done and failure */
	uint16_t rebuild_failed_cnt;
} zvol_rebuild_info_t;

/*
 * The in-core state of each volume.
 */
struct zvol_state {
	char zv_name[MAXNAMELEN];		/* name */
	uint64_t zv_volsize;			/* advertised space */
	uint64_t zv_volblocksize;		/* volume block size */
	objset_t *zv_objset;			/* objset handle */
	zilog_t *zv_zilog;			/* ZIL handle */
	dnode_t *zv_dn;				/* dnode hold */
	zfs_rlock_t zv_range_lock;		/* range lock */
	spa_t *zv_spa;				/* spa */
	char zv_target_host[MAXNAMELEN];	/* target address */
	uint64_t zv_volmetablocksize;		/* meta block size */
	uint64_t zv_volmetadatasize;		/* volume meta data size */

	/*
	 * block size at which metadata is calculated.
	 * This should not be greater than volblocksize
	 */
	uint64_t zv_metavolblocksize;

	/* Don't use status directly. Use getter/setter of zvol_info */
	zvol_status_t zv_status;		/* zvol status */
	kmutex_t rebuild_mtx;
	zvol_rebuild_info_t rebuild_info;
};

#define	ZVOL_VOLUME_SIZE(zv)	(zv->zv_volsize)
typedef struct zvol_state zvol_state_t;

#define	UZFS_IO_TX_ASSIGN_FAIL	1
#define	UZFS_IO_READ_FAIL	2
#define	UZFS_IO_MREAD_FAIL	3
#define	UZFS_IO_UNMAP_FAIL	4

#define	ZINFO_IS_HEALTHY(zinfo)		(ZVOL_IS_HEALTHY(zinfo->main_zv))
#define	ZINFO_IS_DEGRADED(zinfo)	(!(ZINFO_IS_HEALTHY(zinfo)))
#define	ZVOL_IS_DEGRADED(zv)		(zv->zv_status == ZVOL_STATUS_DEGRADED)
#define	ZVOL_IS_HEALTHY(zv)		(zv->zv_status == ZVOL_STATUS_HEALTHY)

#define	ZVOL_IS_REBUILDING(zv)		\
	((zv->rebuild_info.zv_rebuild_status == ZVOL_REBUILDING_SNAP) || \
	(zv->rebuild_info.zv_rebuild_status == ZVOL_REBUILDING_AFS))
#define	ZVOL_IS_REBUILDING_AFS(zv)		\
	(zv->rebuild_info.zv_rebuild_status == ZVOL_REBUILDING_AFS)
#define	ZVOL_IS_REBUILDED(zv)		\
	(zv->rebuild_info.zv_rebuild_status == ZVOL_REBUILDING_DONE)
#define	ZVOL_IS_REBUILDING_ERRORED(zv)	\
	(zv->rebuild_info.zv_rebuild_status == ZVOL_REBUILDING_ERRORED)
#define	ZVOL_IS_REBUILDING_FAILED(zv)	\
	(zv->rebuild_info.zv_rebuild_status == ZVOL_REBUILDING_FAILED)

extern int zvol_get_data(void *arg, lr_write_t *lr, char *buf, zio_t *zio);

/*
 * writes data and metadata
 */
extern void zvol_log_write(zvol_state_t *zv, dmu_tx_t *tx, uint64_t offset,
    uint64_t size, int sync, blk_metadata_t *md);

/*
 * unmap data and update metadata
 */
extern int dmu_free_long_range_impl(objset_t *os, dnode_t *dn, uint64_t offset,
    uint64_t length, blk_metadata_t *metadata, zvol_state_t *zv);
extern void zvol_log_truncate(zvol_state_t *zv, dmu_tx_t *tx, uint64_t off,
    uint64_t len, boolean_t sync, blk_metadata_t *metadata);

/*
 * returns through 'm' (offset, len) of the block containing metadata of data
 * at 'offset' of lun and length of meta vol block size
 */
void get_zv_metaobj_block_details(metaobj_blk_offset_t *m, zvol_state_t *zv,
    uint64_t offset, uint64_t len);

void get_metaobj_block_details(metaobj_blk_offset_t *m, uint64_t blocksize,
    uint64_t metablocksize, uint64_t metadatasize, uint64_t offset, uint64_t l);

/*
 * returns len of metadata for data at 'offset' of lun and length 'len'
 */
uint64_t get_metadata_len(zvol_state_t *zv, uint64_t offset, uint64_t len);

/*
 * Callback vectors for replaying records.
 * Only TX_WRITE and TX_TRUNCATE are needed for zvol.
 */
extern zil_replay_func_t zvol_replay_vector[TX_MAX_TYPE];

typedef struct uzfs_zvol_blk_phy {
	uint64_t offset;
	uint64_t len;
	avl_node_t uzb_link;
} uzfs_zvol_blk_phy_t;

/*
 * structure to hold information of non-overlapping
 * rebuild IO
 */
typedef struct uzfs_io_chunk_list {
	uint64_t offset;
	uint64_t len;
	uint64_t io_number;
	char *buf;
	list_node_t link;
} uzfs_io_chunk_list_t;

typedef int (uzfs_get_io_diff_cb_t)(off_t offset, size_t len,
    blk_metadata_t *metadata, zvol_state_t *zv, void *arg);
#endif
#endif
