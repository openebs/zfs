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

#if !defined(_KERNEL)

typedef struct zvol_properties {
	uint64_t vol_size;
	uint64_t block_size;

/* explained in zvol_state_t definition */
	uint64_t meta_block_size;
	uint64_t meta_vol_block_size;
} zvol_properties_t;

/*
 * (r_offset, r_len) gives the range for range lock on metaobject
 * m_offset is the offset of metadata in metaobject
 */
typedef struct metaobj_blk_offset {
	uint64_t r_offset;
	uint64_t r_len;
	uint64_t m_offset;
} metaobj_blk_offset_t;

/*
 * rebuild related information for zvol
 */
typedef struct zvol_rebuild_data {
	/* mutex to synchronize io tree operation */
	kmutex_t io_tree_mtx;
	uint64_t rebuild_bytes;
	avl_tree_t *incoming_io_tree;   /* incoming io tree */
} zvol_rebuild_data_t;

/*
 * zvol rebuild related state
 */
typedef enum zvol_rebuild_status {
	ZVOL_REBUILDING_INIT,		/* rebuilding initiated on zvol */
	ZVOL_REBUILDING_IN_PROGRESS,	/* zvol is rebuilding */
	ZVOL_REBUILDING_DONE		/* done with rebuilding */
} zvol_rebuild_status_t;

/*
 * zvol status
 */
typedef enum zvol_status {
	ZVOL_STATUS_HEALTHY,		/* zvol has latest data */
	ZVOL_STATUS_DEGRADED		/* zvol is missing some data */
} zvol_status_t;

/*
 * The in-core state of each volume.
 */
struct zvol_state {
	char zv_name[MAXNAMELEN];	/* name */
	uint64_t zv_volsize;		/* advertised space */
	uint64_t zv_volblocksize;	/* volume block size */
	objset_t *zv_objset;		/* objset handle */
	zilog_t *zv_zilog;		/* ZIL handle */
	dnode_t *zv_dn;			/* dnode hold */
	zfs_rlock_t zv_range_lock;	/* range lock */
	zfs_rlock_t zv_mrange_lock;	/* range lock */
	spa_t *zv_spa;			/* spa */
	uint64_t zv_volmetablocksize;	/* meta block size */
	uint64_t zv_volmetadatasize;	/* volume meta data size */

	/*
	 * block size at which metadata is calculated.
	 * This should not be greater than volblocksize
	 */
	uint64_t zv_metavolblocksize;
	zvol_rebuild_status_t zv_rebuild_status; /* zvol rebuilding status */
	zvol_status_t zv_status;	/* zvol status */
	zvol_rebuild_data_t rebuild_data;
};

typedef struct zvol_state zvol_state_t;

#define	UZFS_IO_TX_ASSIGN_FAIL	1
#define	UZFS_IO_READ_FAIL	2
#define	UZFS_IO_MREAD_FAIL	3

extern int zvol_get_data(void *arg, lr_write_t *lr, char *buf, zio_t *zio);

/*
 * writes data and metadata
 */
extern void zvol_log_write(zvol_state_t *zv, dmu_tx_t *tx, uint64_t offset,
    uint64_t size, int sync, blk_metadata_t *md);

/*
 * returns through 'm' (offset, len) of the block containing metadata of data
 * at 'offset' of lun and length of meta vol block size
 */
void get_metaobj_block_details(metaobj_blk_offset_t *m, zvol_state_t *zv,
    uint64_t offset);

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
	char *buf;
	list_node_t link;
} uzfs_io_chunk_list_t;

typedef int (uzfs_txg_diff_traverse_cb_t)(off_t offset, size_t len,
    uint64_t blkid, void *arg);
#endif
#endif
