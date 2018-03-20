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
#include <sys/stat.h>
#include <uzfs.h>
#include <uzfs_mtree.h>
#include <zrepl_mgmt.h>
#include <uzfs_mgmt.h>
#include <uzfs_io.h>

static int uzfs_fd_rand = -1;

/*
 * Pool tasks that need to be done during pool open and close
 */
uzfs_pool_task_funcs_t uzfs_pool_tasks[UZFS_POOL_MAX_TASKS] = {
	{ post_open_pool, post_close_pool },
	{ create_txg_update_thread, close_txg_update_thread },
	{ dummy_pool_task, pre_close_pool }
};

static nvlist_t *
make_root(char *path, int ashift, int log)
{
	nvlist_t *root = NULL, *child;
	struct stat64 statbuf;
	const char *vdev_type;

	if (stat64(path, &statbuf) != 0)
		goto ret;

	if (S_ISBLK(statbuf.st_mode)) {
		vdev_type = VDEV_TYPE_DISK;
	} else {
		vdev_type = VDEV_TYPE_FILE;
	}

	if (nvlist_alloc(&child, NV_UNIQUE_NAME, 0) != 0)
		goto ret;
	if (nvlist_add_string(child, ZPOOL_CONFIG_TYPE,
	    vdev_type) != 0)
		goto free_ret;
	if (nvlist_add_string(child, ZPOOL_CONFIG_PATH, path) != 0)
		goto free_ret;
	if (nvlist_add_uint64(child, ZPOOL_CONFIG_ASHIFT, ashift) != 0)
		goto free_ret;
	if (nvlist_add_uint64(child, ZPOOL_CONFIG_IS_LOG, log) != 0)
		goto free_ret;

	if (nvlist_alloc(&root, NV_UNIQUE_NAME, 0) != 0) {
		root = NULL;
		goto free_ret;
	}
	if (nvlist_add_string(root, ZPOOL_CONFIG_TYPE, VDEV_TYPE_ROOT) != 0)
		goto free_root_ret;
	if (nvlist_add_nvlist_array(root, ZPOOL_CONFIG_CHILDREN, &child, 1)
	    != 0) {
free_root_ret:
		nvlist_free(root);
		root = NULL;
		goto free_ret;
	}
free_ret:
	nvlist_free(child);
ret:
	return (root);
}

/* Generates random number in the [0-range] */
uint64_t
uzfs_random(uint64_t range)
{

	uint64_t r;

	ASSERT3S(uzfs_fd_rand, >=, 0);

	if (range == 0)
		return (0);

	while (read(uzfs_fd_rand, &r, sizeof (r)) != sizeof (r))
		;

	return (r % range);
}

int
uzfs_init(void)
{
	int err = 0;
	kernel_init(FREAD | FWRITE);
	uzfs_fd_rand = open("/dev/urandom", O_RDONLY);
	if (uzfs_fd_rand == -1)
		err = errno;
	return (err);
}

/*
 * closes uzfs pool
 */
void
uzfs_close_pool(spa_t *spa)
{
	int i;
	for (i = (UZFS_POOL_MAX_TASKS - 1); i >= 0; i--) {
		if (uzfs_spa(spa)->tasks_initialized[i] == B_TRUE) {
			uzfs_spa(spa)->tasks_initialized[i] = B_FALSE;
			uzfs_pool_tasks[i].close_func(spa);
		}
	}
	spa_close(spa, "UZFS_SPA_TAG");
}

/*
 * Opens the pool if any with 'name'
 */
int
uzfs_open_pool(char *name, spa_t **s)
{
	spa_t *spa = NULL;
	int i;
	int err = spa_open(name, &spa, "UZFS_SPA_TAG");
	if (err != 0) {
		spa = NULL;
		goto ret;
	}

	if (spa->spa_us != NULL) {
		spa_close(spa, "UZFS_SPA_TAG");
		spa = NULL;
		err = EEXIST;
		goto ret;
	}
	for (i = 0; i < UZFS_POOL_MAX_TASKS; i++) {
		err = uzfs_pool_tasks[i].open_func(spa);
		if (err != 0) {
			uzfs_close_pool(spa);
			spa = NULL;
			goto ret;
		}
		uzfs_spa(spa)->tasks_initialized[i] = B_TRUE;
	}
ret:
	*s = spa;
	return (err);
}

/* creates the pool 'name' with a disk at 'path' */
int
uzfs_create_pool(char *name, char *path, spa_t **s)
{
	nvlist_t *nvroot;
	spa_t *spa = NULL;
	int err = -1;
	/*
	 * Create the storage pool.
	 */

	(void) spa_destroy(name);

	nvroot = make_root(path, 12, 0);
	if (nvroot == NULL)
		goto ret;

	err = spa_create(name, nvroot, NULL, NULL);
	nvlist_free(nvroot);

	if (err != 0)
		goto ret;

	err = uzfs_open_pool(name, &spa);
	if (err != 0) {
		(void) spa_destroy(name);
		spa = NULL;
		goto ret;
	}
ret:
	*s = spa;
	return (err);
}

/* Adds vdev at 'path' to pool 'spa' as either log or data device */
int
uzfs_vdev_add(spa_t *spa, char *path, int ashift, int log)
{
	nvlist_t *nvroot;
	int error = -1;

	nvroot = make_root(path, ashift, log);
	if (nvroot == NULL)
		goto ret;

	error = spa_vdev_add(spa, nvroot);

	nvlist_free(nvroot);
ret:
	return (error);
}

/*
 * callback when a zvol objset is created
 * Any error here will bring down the process
 */
void
uzfs_objset_create_cb(objset_t *new_os, void *arg, cred_t *cr, dmu_tx_t *tx)
{
	/*
	 * Create the objects common to all uzfs datasets.
	 */
	uint64_t error, metablocksize, metadatasize, metavolblocksize;

	zvol_properties_t *properties = (zvol_properties_t *)arg;

	error = dmu_object_claim(new_os, ZVOL_OBJ, DMU_OT_ZVOL,
	    properties->block_size, DMU_OT_NONE, 0, tx);
	VERIFY(error == 0);

	error = zap_create_claim(new_os, ZVOL_ZAP_OBJ, DMU_OT_ZVOL_PROP,
	    DMU_OT_NONE, 0, tx);
	VERIFY(error == 0);

	metablocksize = (properties->meta_block_size < properties->block_size) ?
	    (properties->meta_block_size) : (properties->block_size);
	error = dmu_object_claim(new_os, ZVOL_META_OBJ, DMU_OT_ZVOL,
	    metablocksize, DMU_OT_NONE, 0, tx);
	VERIFY(error == 0);

	error = zap_update(new_os, ZVOL_ZAP_OBJ, "size", 8, 1,
	    &properties->vol_size, tx);
	VERIFY(error == 0);

	metadatasize = sizeof (blk_metadata_t);
	error = zap_update(new_os, ZVOL_ZAP_OBJ, "metadatasize", 8, 1,
	    &metadatasize, tx);
	VERIFY(error == 0);

	metavolblocksize = (properties->meta_vol_block_size <
	    properties->block_size) ? (properties->meta_vol_block_size) :
	    (properties->block_size);
	error = zap_update(new_os, ZVOL_ZAP_OBJ, "metavolblocksize", 8, 1,
	    &metavolblocksize, tx);
	VERIFY(error == 0);
}


/* owns objset with name 'ds_name' in pool 'spa'. Sets 'sync' property */
int
uzfs_open_dataset_init(const char *ds_name, zvol_state_t **z)
{
	zvol_state_t *zv = NULL;
	int error = -1;
	objset_t *os;
	dmu_object_info_t doi;
	uint64_t block_size, vol_size;
	uint64_t meta_vol_block_size;
	uint64_t meta_data_size;
	spa_t *spa = NULL;

	zv = kmem_zalloc(sizeof (zvol_state_t), KM_SLEEP);
	if (zv == NULL)
		goto ret;

	error = spa_open(ds_name, &spa, zv);
	if (error != 0) {
		kmem_free(zv, sizeof (zvol_state_t));
		goto ret;
	}

	zv->zv_spa = spa;
	zfs_rlock_init(&zv->zv_range_lock);
	zfs_rlock_init(&zv->zv_mrange_lock);
	mutex_init(&zv->rebuild_data.io_tree_mtx, NULL, MUTEX_DEFAULT, NULL);
	uzfs_create_txg_diff_tree((void **)&zv->rebuild_data.incoming_io_tree);

	strlcpy(zv->zv_name, ds_name, MAXNAMELEN);

	error = dmu_objset_own(ds_name, DMU_OST_ZVOL, 1, zv, &os);
	if (error)
		goto free_ret;
	zv->zv_objset = os;

	error = dmu_object_info(os, ZVOL_OBJ, &doi);
	if (error)
		goto disown_free;
	block_size = doi.doi_data_block_size;

	error = zap_lookup(os, ZVOL_ZAP_OBJ, "size", 8, 1, &vol_size);
	if (error)
		goto disown_free;

	error = dmu_object_info(os, ZVOL_META_OBJ, &doi);

	error |= zap_lookup(os, ZVOL_ZAP_OBJ, "metavolblocksize", 8, 1,
	    &meta_vol_block_size);

	error |= zap_lookup(os, ZVOL_ZAP_OBJ, "metadatasize", 8, 1,
	    &meta_data_size);

	if (error) {
		zv->zv_volmetablocksize = 0;
		zv->zv_volmetadatasize = 0;
		zv->zv_metavolblocksize = 0;
	} else {
		zv->zv_volmetablocksize = doi.doi_data_block_size;
		zv->zv_volmetadatasize = meta_data_size;
		zv->zv_metavolblocksize = meta_vol_block_size;
	}

	error = dnode_hold(os, ZVOL_OBJ, zv, &zv->zv_dn);
	if (error) {
disown_free:
		dmu_objset_disown(zv->zv_objset, zv);
free_ret:
		spa_close(spa, zv);
		zfs_rlock_destroy(&zv->zv_range_lock);
		zfs_rlock_destroy(&zv->zv_mrange_lock);
		kmem_free(zv, sizeof (zvol_state_t));
		zv = NULL;
		goto ret;
	}

	zv->zv_zilog = zil_open(os, zvol_get_data);
	zv->zv_volblocksize = block_size;
	zv->zv_volsize = vol_size;

	/* On boot, mark zvol status health */
	uzfs_zvol_set_status(zv, ZVOL_STATUS_DEGRADED);

	if (spa_writeable(dmu_objset_spa(os))) {
//		if (zil_replay_disable)
//			zil_destroy(dmu_objset_zil(os), B_FALSE);
//		else
			zil_replay(os, zv, zvol_replay_vector);
	}

ret:
	*z = zv;
	return (error);
}

/* owns objset with name 'ds_name' in pool 'spa'. Sets 'sync' property */
int
uzfs_open_dataset(spa_t *spa, const char *ds_name, zvol_state_t **z)
{
	char name[ZFS_MAX_DATASET_NAME_LEN];
	int error = -1;

	if (spa == NULL)
		return (error);
	(void) snprintf(name, sizeof (name), "%s/%s", spa_name(spa), ds_name);

	error = uzfs_open_dataset_init(name, z);
	return (error);
}

/*
 * Creates dataset 'ds_name' in pool 'spa' with volume size 'vol_size',
 * block size as 'block_size'
 */
int
uzfs_create_dataset(spa_t *spa, char *ds_name, uint64_t vol_size,
    uint64_t block_size, zvol_state_t **z)
{
	char name[ZFS_MAX_DATASET_NAME_LEN];
	zvol_state_t *zv = NULL;
	zvol_properties_t properties;
	int error = -1;

	if (spa == NULL)
		goto ret;
	(void) snprintf(name, sizeof (name), "%s/%s", spa_name(spa), ds_name);

	properties.vol_size = vol_size;
	properties.block_size = block_size;
	properties.meta_block_size = block_size;
	properties.meta_vol_block_size = block_size;

	error = dmu_objset_create(name, DMU_OST_ZVOL, 0,
	    uzfs_objset_create_cb, &properties);

	if (error)
		goto ret;

	error = uzfs_open_dataset(spa, ds_name, &zv);
	if (error != 0) {
		zv = NULL;
		goto ret;
	}
ret:
	*z = zv;
	return (error);
}

/* uZFS Zvol create call back function */
int
uzfs_zvol_create_cb(const char *ds_name, void *arg)
{

	zvol_state_t	*zv = NULL;
	int 		error = -1;

	printf("ds_name %s\n", ds_name);

	error = uzfs_open_dataset_init(ds_name, &zv);
	if (error) {
		printf("Failed to open dataset: %s\n", ds_name);
		return (error);
	}

	if (uzfs_zinfo_init(zv, ds_name) != 0) {
		printf("Failed in uzfs_zinfo_init\n");
		return (error);
	}

	return (0);
}

/* uZFS Zvol destroy call back function */
int
uzfs_zvol_destroy_cb(const char *ds_name, void *arg)
{

	printf("deleting ds_name %s\n", ds_name);

	uzfs_zinfo_destroy(ds_name);
	return (0);
}

/* disowns, closes dataset */
void
uzfs_close_dataset(zvol_state_t *zv)
{
	zil_close(zv->zv_zilog);
	dnode_rele(zv->zv_dn, zv);
	dmu_objset_disown(zv->zv_objset, zv);
	mutex_destroy(&zv->rebuild_data.io_tree_mtx);
	uzfs_destroy_txg_diff_tree(zv->rebuild_data.incoming_io_tree);
	zfs_rlock_destroy(&zv->zv_range_lock);
	zfs_rlock_destroy(&zv->zv_mrange_lock);
	spa_close(zv->zv_spa, zv);
	kmem_free(zv, sizeof (zvol_state_t));
}

void
uzfs_fini(void)
{
	kernel_fini();
	if (uzfs_fd_rand != -1)
		close(uzfs_fd_rand);
}
