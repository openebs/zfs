#include <sys/types.h>
#include <sys/spa.h>
#include <sys/zap_impl.h>
#include <uzfs_mgmt.h>
#include <uzfs_zap.h>
#include <zrepl_mgmt.h>
#include <uzfs_test.h>

/*
 * populate_string will fill buf with [A-Z] characters
 */
void
populate_string(char *buf, uint64_t size)
{
	int i = 0;
	int idx;

	for (i = 0; i < size; i++) {
		idx = uzfs_random('Z' - 'A');
		idx += 'A';
		buf[i] = (char)idx;
	}
	buf[size - 1] = '\0';
}

static void
destroy_zap_entries(uzfs_zap_kv_t **kv_array, uint64_t zap_count)
{
	int i = 0;
	uzfs_zap_kv_t *kv;

	for (i = 0; i < zap_count; i++) {
		kv = kv_array[i];
		umem_free(kv->key,  strlen(kv->key) + 1);
		umem_free(kv, sizeof (*kv));
		kv = NULL;
	}
}

static void
fill_up_zap_entries(uzfs_zap_kv_t **array, uint64_t n)
{
	int i = 0;
	uzfs_zap_kv_t *zap;
	uint64_t key_len, value;

	for (i = 0; i < n; i++, zap = NULL) {
		zap = umem_alloc(sizeof (uzfs_zap_kv_t), UMEM_NOFAIL);
		key_len = uzfs_random(32);

		key_len = (key_len < 8) ? 8 : key_len;

		zap->key = umem_alloc(key_len, UMEM_NOFAIL);
		zap->value = uzfs_random(ULONG_MAX);
		zap->size = sizeof (value);

		populate_string(zap->key, key_len);
		array[i] = zap;
	}
}

static void
update_zap_entries(uzfs_zap_kv_t **array, uint64_t n)
{
	int i = 0;
	uzfs_zap_kv_t *zap;

	for (i = 0; i < n; i++) {
		zap = array[i];
		zap->value = uzfs_random(ULONG_MAX);
	}

}

void
verify_zap_entries(void *zvol, uzfs_zap_kv_t **key_array, uint64_t count)
{
	uzfs_zap_kv_t *kv;
	uint64_t value;
	int i = 0, err;
	uzfs_zap_kv_t *dummy_key;

	for (i = 0; i < count; i++) {
		kv = key_array[i];
		value = kv->value;
		kv->value = 0;
		uzfs_read_zap_entry(zvol, kv);
		VERIFY(kv->value == value);
	}

	dummy_key = umem_alloc(sizeof (*dummy_key), UMEM_NOFAIL);
	dummy_key->size = sizeof (dummy_key->value);

	dummy_key->key = "DUMMY";
	err = uzfs_read_zap_entry(zvol, dummy_key);
	if (err == 0) {
		printf("read zap should fail..\n");
		exit(1);
	}

	dummy_key->size = 16;
	err = uzfs_update_zap_entries(zvol,
	    (const uzfs_zap_kv_t **) &dummy_key, 1);
	if (err != EINVAL) {
		printf("error in zap update\n");
		exit(1);
	}

	umem_free(dummy_key, sizeof (*dummy_key));
}

void
uzfs_zvol_zap_operation(void *arg)
{
	uzfs_test_info_t *test_info = (uzfs_test_info_t *)arg;
	int i = 0;
	hrtime_t end, now;
	spa_t *spa;
	zvol_state_t *zvol;
	uzfs_zap_kv_t **kv_array;
	int zap_count;

	open_pool(&spa);
	open_ds(spa, ds, &zvol);
	if (!zvol) {
		printf("couldn't find zvol\n");
		uzfs_close_pool(spa);
		uzfs_fini();
		exit(1);
	}

	while (i++ < test_iterations) {
		zap_count = uzfs_random(16) + 1;

		kv_array = umem_alloc(zap_count * sizeof (*kv_array),
		    UMEM_NOFAIL);
		fill_up_zap_entries(kv_array, zap_count);

		/* update key/value pair in ZAP entries */
		VERIFY0(uzfs_update_zap_entries(zvol,
		    (const uzfs_zap_kv_t **) kv_array, zap_count));

		verify_zap_entries(zvol, kv_array, zap_count);

		/* update value against existing ZAP key entries */
		update_zap_entries(kv_array, zap_count);

		VERIFY0(uzfs_update_zap_entries(zvol,
		    (const uzfs_zap_kv_t **) kv_array, zap_count));

		verify_zap_entries(zvol, kv_array, zap_count);

		uzfs_zap_kv_t *temp_kv;
		temp_kv = kv_array[0];
		umem_free(temp_kv->key, strlen(temp_kv->key) + 1);
		temp_kv->key = umem_alloc(MZAP_NAME_LEN + 4, UMEM_NOFAIL);
		populate_string(temp_kv->key, MZAP_NAME_LEN + 4);
		temp_kv->value = 2;
		temp_kv->size = sizeof (temp_kv->value);
		VERIFY(uzfs_update_zap_entries(zvol,
		    (const uzfs_zap_kv_t **) kv_array, zap_count) == EINVAL);

		destroy_zap_entries(kv_array, zap_count);
		umem_free(kv_array, zap_count * sizeof (*kv_array));
		kv_array = NULL;

		printf("%s pass:%d\n", test_info->name, i);
	}

	now = gethrtime();
	end = now + (hrtime_t)(total_time_in_sec * (hrtime_t)(NANOSEC));

	uzfs_close_dataset(zvol);
	uzfs_close_pool(spa);
}
