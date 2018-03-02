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

#include <sys/zfs_context.h>
#include <sys/dsl_synctask.h>
#include <sys/dsl_pool.h>
#include <sys/dmu_objset.h>
#include <sys/zap_impl.h>
#include <sys/dmu_tx.h>
#include <sys/zap.h>
#include <sys/uzfs_zvol.h>
#include <uzfs.h>
#include <uzfs_zap.h>

/*
 * this is in seconds. Default is 600 seconds.
 * It depends on the IO timeout at iscsi controller.
 * At this interval, txg value taken in last iteration is stored into zap
 */
long long txg_update_interval_time = (600 * hz);

/*
 * update/add key-value entry in zvol zap object
 */
int
uzfs_update_zap_entries(void *zvol, const uzfs_zap_kv_t **array,
    uint64_t count)
{
	zvol_state_t *zv = (zvol_state_t *)zvol;
	objset_t *os = zv->zv_objset;
	dmu_tx_t *tx;
	const uzfs_zap_kv_t *kv;
	int err;
	int i = 0;

	/*
	 * check if key length is greater than MZAP_NAME_LEN.
	 * key with MZAP_NAME_LEN+ length will convert microzap
	 * to fatzap.
	 */
	for (i = 0; i < count; i++) {
		kv = array[i];
		if (strlen(kv->key) >= MZAP_NAME_LEN)
			return (EINVAL);
	}

	tx = dmu_tx_create(os);
	dmu_tx_hold_zap(tx, ZVOL_ZAP_OBJ, TRUE, NULL);

	err = dmu_tx_assign(tx, TXG_WAIT);
	if (err) {
		dmu_tx_abort(tx);
		return (SET_ERROR(err));
	}

	for (i = 0; i < count; i++) {
		kv = array[i];
		VERIFY0(zap_update(os, ZVOL_ZAP_OBJ, kv->key, kv->size, 1,
		    &kv->value, tx));
	}

	dmu_tx_commit(tx);

	return (0);
}

/*
 * fetch value stored in zap object of zvol by key
 */
int
uzfs_read_zap_entry(void *zvol, uzfs_zap_kv_t *entry)
{
	zvol_state_t *zv = (zvol_state_t *)zvol;
	objset_t *os = zv->zv_objset;
	int err;

	err = zap_lookup(os, ZVOL_ZAP_OBJ, entry->key, entry->size, 1,
	    &entry->value);
	if (err)
		return (SET_ERROR(err));

	return (0);
}

int
uzfs_read_last_iter_txg(void *spa, uint64_t *val)
{
	uint64_t zapobj = DMU_POOL_DIRECTORY_OBJECT;
	int err;
	err = zap_lookup(spa_meta_objset(spa), zapobj, LAST_ITER_TXG, 1, 8,
	    val);
	if (err)
		return (SET_ERROR(err));

	return (0);
}

void
update_txg_sync_impl(void *txg, dmu_tx_t *tx)
{
	objset_t *mos = dmu_tx_pool(tx)->dp_meta_objset;
	uint64_t zapobj = DMU_POOL_DIRECTORY_OBJECT;
	VERIFY0(zap_update(mos, zapobj, LAST_ITER_TXG, 1, 8, txg, tx));
}

void
uzfs_update_txg_zap_thread(void *s)
{
	spa_t *spa = (spa_t *)s;
	uint64_t txg = spa_last_synced_txg(spa);

	mutex_enter(&(uzfs_spa(spa)->mtx));
	cv_timedwait(&(uzfs_spa(spa)->cv), &(uzfs_spa(spa)->mtx),
	    ddi_get_lbolt() + txg_update_interval_time);

	while (uzfs_spa(spa)->close_pool == 0) {
		mutex_exit(&(uzfs_spa(spa)->mtx));
		dsl_sync_task(spa_name(spa), NULL, update_txg_sync_impl, &txg,
		    0, ZFS_SPACE_CHECK_NONE);

		txg = spa_last_synced_txg(spa);

		mutex_enter(&(uzfs_spa(spa)->mtx));
		cv_timedwait(&(uzfs_spa(spa)->cv), &(uzfs_spa(spa)->mtx),
		    ddi_get_lbolt() + txg_update_interval_time);
	}
	mutex_exit(&(uzfs_spa(spa)->mtx));
	uzfs_spa(spa)->update_txg_tid = NULL;
	zk_thread_exit();
}
