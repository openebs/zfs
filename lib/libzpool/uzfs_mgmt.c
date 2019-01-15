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
#include <sys/dsl_destroy.h>
#include <sys/zap.h>
#include <sys/dsl_prop.h>
#include <sys/uzfs_zvol.h>
#include <sys/stat.h>
#include <sys/spa_impl.h>
#include <zrepl_mgmt.h>
#include <uzfs_mgmt.h>
#include <uzfs_io.h>
#include <uzfs_zap.h>
#include <uzfs_rebuilding.h>

static int uzfs_fd_rand = -1;
kmutex_t zvol_list_mutex;
char *uzfs_spa_tag = "UZFS_SPA_TAG";

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
	SLIST_INIT(&zvol_list);
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
	spa_close(spa, uzfs_spa_tag);
}

/*
 * Opens the pool if any with 'name'
 */
int
uzfs_open_pool(char *name, spa_t **s)
{
	spa_t *spa = NULL;
	int err = spa_open(name, &spa, uzfs_spa_tag);
	if (err != 0) {
		spa = NULL;
		goto ret;
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
 * Create zvol meta object and related entries in zvol zap object.
 */
int
uzfs_zvol_create_meta(objset_t *os, uint64_t block_size,
    uint64_t meta_block_size, dmu_tx_t *tx)
{
	uint64_t metadatasize;
	uint64_t io_seqnum = 0;
	int error;

	if (meta_block_size > block_size)
		meta_block_size = block_size;
	error = dmu_object_claim(os, ZVOL_META_OBJ, DMU_OT_ZVOL,
	    meta_block_size, DMU_OT_NONE, 0, tx);
	if (error != 0)
		return (error);

	metadatasize = sizeof (blk_metadata_t);
	error = zap_update(os, ZVOL_ZAP_OBJ, "metadatasize", 8, 1,
	    &metadatasize, tx);
	if (error != 0)
		return (error);

	error = zap_update(os, ZVOL_ZAP_OBJ, HEALTHY_IO_SEQNUM, 8, 1,
	    &io_seqnum, tx);
	ASSERT(error == 0);

	error = zap_update(os, ZVOL_ZAP_OBJ, DEGRADED_IO_SEQNUM, 8, 1,
	    &io_seqnum, tx);
	ASSERT(error == 0);

	return (0);
}

/*
 * callback when a zvol objset is created.
 * Create the objects common to all uzfs datasets.
 * Any error here will bring down the process
 *
 * XXX this function duplicates the code from zvol_create_cb()
 */
void
uzfs_objset_create_cb(objset_t *new_os, void *arg, cred_t *cr, dmu_tx_t *tx)
{
	zvol_properties_t *props = (zvol_properties_t *)arg;
	int error;

	error = dmu_object_claim(new_os, ZVOL_OBJ, DMU_OT_ZVOL,
	    props->block_size, DMU_OT_NONE, 0, tx);
	VERIFY(error == 0);

	error = zap_create_claim(new_os, ZVOL_ZAP_OBJ, DMU_OT_ZVOL_PROP,
	    DMU_OT_NONE, 0, tx);
	VERIFY(error == 0);

	error = zap_update(new_os, ZVOL_ZAP_OBJ, "size", 8, 1,
	    &props->vol_size, tx);
	VERIFY(error == 0);

	error = uzfs_zvol_create_meta(new_os, props->block_size,
	    props->meta_block_size, tx);
	VERIFY(error == 0);
}

/*
 * own the dataset, hold node, open zilog
 */
int
uzfs_hold_dataset(zvol_state_t *zv)
{
	int error = -1;
	objset_t *os;
	error = dmu_objset_own(zv->zv_name, DMU_OST_ZVOL, 1, zv, &os);
	if (error)
		goto free_ret;

	zv->zv_objset = os;

	error = dnode_hold(os, ZVOL_OBJ, zv, &zv->zv_dn);
	if (error) {
		dmu_objset_disown(zv->zv_objset, zv);
free_ret:
		zv->zv_objset = NULL;
		zv->zv_dn = NULL;
		goto ret;
	}

	zv->zv_zilog = zil_open(os, zvol_get_data);
ret:
	return (error);
}

/*
 * Try to obtain controller address from zfs property.
 */
static int
get_controller_ip(objset_t *os, char *buf, int len)
{
	nvlist_t *props, *propval;
	char *ip;
	int error;
	dsl_pool_t *dp = spa_get_dsl(os->os_spa);

	dsl_pool_config_enter(dp, FTAG);
	error = dsl_prop_get_all(os, &props);
	dsl_pool_config_exit(dp, FTAG);
	if (error != 0)
		return (error);
	if (nvlist_lookup_nvlist(props, ZFS_PROP_TARGET_IP, &propval) != 0) {
		nvlist_free(props);
		return (ENOENT);
	}
	if (nvlist_lookup_string(propval, ZPROP_VALUE, &ip) != 0) {
		nvlist_free(props);
		return (EINVAL);
	}
	strncpy(buf, ip, len);
	nvlist_free(props);
	return (0);
}

/* owns objset with name 'ds_name' in pool 'spa' */
static int
uzfs_dataset_zv_create(const char *ds_name, zvol_state_t **z)
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
	if (zv == NULL) {
		error = ENOMEM;
		goto ret;
	}

	error = spa_open(ds_name, &spa, zv);
	if (error != 0) {
		kmem_free(zv, sizeof (zvol_state_t));
		zv = NULL;
		goto ret;
	}

	zv->zv_spa = spa;
	zfs_rlock_init(&zv->zv_range_lock);
	mutex_init(&zv->rebuild_mtx, NULL, MUTEX_DEFAULT, NULL);

	strlcpy(zv->zv_name, ds_name, MAXNAMELEN);

	error = dmu_objset_own(ds_name, DMU_OST_ZVOL, 1, zv, &os);
	if (error != 0)
		goto free_ret;

	zv->zv_objset = os;

	error = dmu_object_info(os, ZVOL_OBJ, &doi);
	if (error) {
disown_free:
		dmu_objset_disown(zv->zv_objset, zv);
free_ret:
		mutex_destroy(&zv->rebuild_mtx);
		zfs_rlock_destroy(&zv->zv_range_lock);
		spa_close(spa, zv);
		kmem_free(zv, sizeof (zvol_state_t));
		zv = NULL;
		goto ret;
	}

	block_size = doi.doi_data_block_size;

	error = zap_lookup(os, ZVOL_ZAP_OBJ, "size", 8, 1, &vol_size);
	if (error)
		goto disown_free;

	/* Meta-object may not exist if dataset wasn't created by uzfs */
	error = dmu_object_info(os, ZVOL_META_OBJ, &doi);
	if (error)
		goto disown_free;

	error = zap_lookup(os, ZVOL_ZAP_OBJ, "metavolblocksize", 8, 1,
	    &meta_vol_block_size);
	/* ok if doesn't exist, it is initialized after zvol creation */
	if (error) {
		if (error == ENOENT)
			meta_vol_block_size = 0;
		else
			goto disown_free;
	}

	error = zap_lookup(os, ZVOL_ZAP_OBJ, "metadatasize", 8, 1,
	    &meta_data_size);
	if (error)
		goto disown_free;

	zv->zv_volmetablocksize = doi.doi_data_block_size;
	zv->zv_volmetadatasize = meta_data_size;
	zv->zv_metavolblocksize = meta_vol_block_size;

	error = get_controller_ip(os, zv->zv_target_host,
	    sizeof (zv->zv_target_host));
	if (error != 0 && error != ENOENT)
		goto disown_free;

	error = 0;
	zv->zv_volblocksize = block_size;
	zv->zv_volsize = vol_size;

	/* On boot, mark zvol status health */
	uzfs_zvol_set_status(zv, ZVOL_STATUS_DEGRADED);
	uzfs_zvol_set_rebuild_status(zv, ZVOL_REBUILDING_INIT);

	if (spa_writeable(dmu_objset_spa(os))) {
//		if (zil_replay_disable)
//			zil_destroy(dmu_objset_zil(os), B_FALSE);
//		else
			zil_replay(os, zv, zvol_replay_vector);
	}

	dmu_objset_disown(zv->zv_objset, zv);

	zv->zv_objset = NULL;
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

	error = uzfs_dataset_zv_create(name, z);
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

/*
 * This function is checked if volume is internally
 * created cloned volume for rebuild purpose.
 * Input: Volume name [pool/volume_name].
 * Output: 0 if volume is internally created cloned volume.
 * Otherwise non-zero value.
 */
int
is_internally_created_clone_volume(const char *ds_name)
{
	size_t ds_len  = strlen(ds_name);
	size_t pattern_len = strlen(REBUILD_SNAPSHOT_CLONENAME);

	if (ds_len < pattern_len)
		return (-1);

	return (strcmp(ds_name + (ds_len - pattern_len),
	    REBUILD_SNAPSHOT_CLONENAME));
}

/* uZFS Zvol create call back function */
int
uzfs_zvol_create_cb(const char *ds_name, void *arg)
{
	zvol_state_t	*zv = NULL;
	int 		error = -1;
	nvlist_t	*nvprops = arg;
	char		*ip;

	if (strrchr(ds_name, '@') != NULL) {
		return (0);
	}

	/*
	 * Internally created cloned volume do not have target IP stored
	 * infact they do not need to have zinfo and connection to target
	 * as these are not meant for client/application.
	 */
	if (is_internally_created_clone_volume(ds_name) == 0)
		return (0);

	error = uzfs_dataset_zv_create(ds_name, &zv);
	if (error) {
		/* happens normally for all non-zvol-type datasets */
		return (error);
	}

	/* if zvol is being created, read target address from nvlist */
	if (nvprops != NULL) {
		error = nvlist_lookup_string(nvprops, ZFS_PROP_TARGET_IP, &ip);
		if (error == 0)
			strncpy(zv->zv_target_host, ip,
			    sizeof (zv->zv_target_host));
		else {
			LOG_ERR("target IP address is not set for %s", ds_name);
			uzfs_close_dataset(zv);
			return (error);
		}
	} else {
		if (zv->zv_target_host[0] == '\0') {
			LOG_ERR("target IP address is empty for %s", ds_name);
			uzfs_close_dataset(zv);
			return (EINVAL);
		}
	}
	if (uzfs_zinfo_init(zv, ds_name, nvprops) != 0) {
		LOG_ERR("Failed in uzfs_zinfo_init");
		return (error);
	}

	return (0);
}

/*
 * similar to zvol_create_minors which does
 * - own dataset, zil replay, disown dataset
 * for all children
 */
void
uzfs_zvol_create_minors(spa_t *spa, const char *name)
{
	char *pool_name;

	if (strrchr(name, '@') != NULL)
		return;

	pool_name = kmem_zalloc(MAXNAMELEN, KM_SLEEP);
	strncpy(pool_name, name, MAXNAMELEN);
	dmu_objset_find(pool_name, uzfs_zvol_create_cb, NULL, DS_FIND_CHILDREN);
	kmem_free(pool_name, MAXNAMELEN);
}

/*
 * For given zv, a snapshot with snap_name will be created if doesn't exists.
 * Opens/holds the snapshot and fills the snap_zv.
 * fail_exists being true returns EEXIST if snapshot already exists.
 * fail_notexists being true returns ENOENT if snapshot doesn't exists.
 */
int
get_snapshot_zv(zvol_state_t *zv, const char *snap_name, zvol_state_t **snap_zv,
    boolean_t fail_exists, boolean_t fail_notexists)
{
	char *dataset;
	int ret = 0;

	dataset = kmem_asprintf("%s@%s", strchr(zv->zv_name, '/') + 1,
	    snap_name);

	ret = uzfs_open_dataset(zv->zv_spa, dataset, snap_zv);
	if (ret == ENOENT) {
		if (fail_notexists) {
			LOG_ERR("fail on unavailable snapshot %s",
			    dataset);
			strfree(dataset);
			ret = SET_ERROR(ENOENT);
			return (ret);
		}
		ret = dmu_objset_snapshot_one(zv->zv_name, snap_name);
		if (ret) {
			LOG_ERR("Failed to create snapshot %s: %d",
			    dataset, ret);
			strfree(dataset);
			return (ret);
		}

		ret = uzfs_open_dataset(zv->zv_spa, dataset, snap_zv);
		if (ret == 0) {
			ret = uzfs_hold_dataset(*snap_zv);
			if (ret != 0) {
				LOG_ERR("Failed to hold snapshot %s: %d",
				    dataset, ret);
				uzfs_close_dataset(*snap_zv);
				*snap_zv = NULL;
			}
		}
		else
			LOG_ERR("Failed to open snapshot: %d", ret);
	} else if (ret == 0) {
		if (fail_exists) {
			LOG_ERR("fail on already available snapshot %s",
			    dataset);
			uzfs_close_dataset(*snap_zv);
			*snap_zv = NULL;
			ret = SET_ERROR(EEXIST);
		} else {
			LOG_INFO("holding already available snapshot %s",
			    dataset);
			ret = uzfs_hold_dataset(*snap_zv);
			if (ret != 0) {
				LOG_ERR("Failed to hold already existing "
				    "snapshot %s: %d", dataset, ret);
				uzfs_close_dataset(*snap_zv);
				*snap_zv = NULL;
			}
		}
	} else
		LOG_ERR("Failed to open snapshot: %d", ret);

	strfree(dataset);
	return (ret);
}

int
destroy_snapshot_zv(zvol_state_t *zv, char *snap_name)
{
	char *dataset;
	int ret;

	dataset = kmem_asprintf("%s@%s", zv->zv_name, snap_name);
	ret = dsl_destroy_snapshot(dataset, B_FALSE);
	strfree(dataset);
	return (ret);
}

/* uZFS Zvol destroy call back function */
int
uzfs_zvol_destroy_cb(const char *ds_name, void *arg)
{
	return (uzfs_zinfo_destroy(ds_name, arg));
}

void
uzfs_rele_dataset(zvol_state_t *zv)
{
	if (zv->zv_zilog != NULL)
		zil_close(zv->zv_zilog);
	if (zv->zv_dn != NULL)
		dnode_rele(zv->zv_dn, zv);
	if (zv->zv_objset != NULL)
		dmu_objset_disown(zv->zv_objset, zv);
	zv->zv_zilog = NULL;
	zv->zv_dn = NULL;
	zv->zv_objset = NULL;
}

/* disowns, closes dataset */
void
uzfs_close_dataset(zvol_state_t *zv)
{
	uzfs_rele_dataset(zv);
	mutex_destroy(&zv->rebuild_mtx);
	zfs_rlock_destroy(&zv->zv_range_lock);
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

int
uzfs_pool_create(const char *name, char *path, spa_t **s)
{
	nvlist_t *nvroot;

	if ((nvroot = make_root(path, 12, 0)) == NULL)
		return (1);
	return (spa_create(name, nvroot, NULL, NULL));
}
