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
#include <uzfs_zap.h>

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
	 * micro zap will upgrade to fat-zap in following cases:
	 * 	1. key length is greater or equal to MZAP_NAME_LEN
	 *	2. value size is greater than 8
	 * To avoid this, update zap-entries only if key length < MZAP_NAME_LEN
	 * and value_size == 1.
	 */
	for (i = 0; i < count; i++) {
		kv = array[i];
		/*
		 * checks to avoid fat zap upgrade and value size
		 */
		if (strlen(kv->key) >= MZAP_NAME_LEN)
			return (EINVAL);
		if (kv->size != 8)
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
 * Remove ZAP key from ZVOL_ZAP_OBJ
 */
int
uzfs_remove_zap_entries(void *zvol, const char *key)
{
	zvol_state_t *zv = (zvol_state_t *)zvol;
	objset_t *os = zv->zv_objset;
	dmu_tx_t *tx;
	int err;

	tx = dmu_tx_create(os);
	dmu_tx_hold_zap(tx, ZVOL_ZAP_OBJ, TRUE, NULL);

	err = dmu_tx_assign(tx, TXG_WAIT);
	if (err) {
		dmu_tx_abort(tx);
		return (SET_ERROR(err));
	}

	VERIFY0(zap_remove(os, ZVOL_ZAP_OBJ, key, tx));

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

/*
 * Rename ZAP key
 */
int
uzfs_update_zap_key_name(void *zvol, const char *old_key, const char *new_key)
{
	zvol_state_t *zv = (zvol_state_t *)zvol;
	objset_t *os = zv->zv_objset;
	int err;
	uint64_t integer_size = 0, num_integers = 0;
	uzfs_zap_kv_t entry = { 0 }, *kv_array[0];

	err = zap_length(os, ZVOL_ZAP_OBJ, new_key, &integer_size,
	    &num_integers);
	if (err == ENOENT) {
		err = zap_length(os, ZVOL_ZAP_OBJ, old_key, &integer_size,
		    &num_integers);
		if (err) {
			if (err == ENOENT)
				err = 0;
			goto out;
		}

		if (integer_size != 8 || num_integers != 1) {
			err = EINVAL;
			goto out;
		}

		err = zap_lookup(os, ZVOL_ZAP_OBJ, old_key,
		    integer_size, num_integers, &entry.value);
		if (err)
			goto out;

		entry.key = (char *)new_key;
		entry.size = sizeof (uint64_t);
		kv_array[0] = &entry;
		err = uzfs_update_zap_entries(zvol,
		    (const uzfs_zap_kv_t **) kv_array, 1);
		if (err)
			goto out;

		err = uzfs_remove_zap_entries(zvol, old_key);
	}

out:
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
