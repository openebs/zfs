#!/bin/bash

run_sync_test()
{
	#sync:standard log:false
	echo "running sync test with sync:standard, bs:4K and no log device"
	log_must setup_uzfs_test nolog 4096 $UZFS_TEST_VOLSIZE standard uzfs_sync_pool1 \
		uzfs_sync_vol1 uzfs_test_sync_vdev1
	log_must export_pool uzfs_sync_pool1
	for i in {1..10}
	do
		sudo $UZFS_TEST -S -w -T 1 -p uzfs_sync_pool1 -d uzfs_sync_vol1 | grep uzfs_sync_data > $TMPDIR/uzfs_sync_data
		if [ $? != 0 ]; then
			return 1
		fi

		sudo $UZFS_TEST -T 1 -p uzfs_sync_pool1 -d uzfs_sync_vol1 \
		    -V `awk '{print $2}' $TMPDIR/uzfs_sync_data` -m `awk '{print $3}' $TMPDIR/uzfs_sync_data`
		if [ $? != 0 ]; then
			return 1
		fi
	done
	cleanup_uzfs_test uzfs_sync_pool1 uzfs_test_sync_vdev1

	#sync:standard log:yes
	echo "running sync test with sync:standard, bs:4k and log device"
	log_must setup_uzfs_test log 4096 $UZFS_TEST_VOLSIZE standard uzfs_sync_pool2 \
		    uzfs_sync_vol2 uzfs_test_sync_vdev2 uzfs_test_sync_log2
	log_must export_pool uzfs_sync_pool2
	for i in {1..10}
	do
		sudo $UZFS_TEST -S -l -p uzfs_sync_pool2 -d uzfs_sync_vol2 -T 1 -w | grep uzfs_sync_data > $TMPDIR/uzfs_sync_data
		if [ $? != 0 ]; then
			return 1;
		fi

		sudo $UZFS_TEST -T 1 -p uzfs_sync_pool2 -d uzfs_sync_vol2 \
		    -V `awk '{print $2}' $TMPDIR/uzfs_sync_data` -m `awk '{print $3}' $TMPDIR/uzfs_sync_data`
		if [ $? != 0 ]; then
			return 1;
		fi
	done
	cleanup_uzfs_test uzfs_sync_pool2 uzfs_test_sync_vdev2 uzfs_test_sync_log2

	#sync:standard log:false
	echo "running sync test with sync:standard, bs:64k and no log device"
	log_must setup_uzfs_test nolog 65536 $UZFS_TEST_VOLSIZE standard uzfs_sync_pool3 \
	    uzfs_sync_vol3 uzfs_test_sync_vdev3
	log_must export_pool uzfs_sync_pool3
	for i in {1..10}
	do
		sudo $UZFS_TEST -S -i 8192 -p uzfs_sync_pool3 -d uzfs_sync_vol3 -b 65536 -T 1 -w | grep uzfs_sync_data > $TMPDIR/uzfs_sync_data
		if [ $? != 0 ]; then
			return 1;
		fi

		sudo $UZFS_TEST -i 8192 -b 65536 -T 1 -p uzfs_sync_pool3 -d uzfs_sync_vol3 \
		    -V `awk '{print $2}' $TMPDIR/uzfs_sync_data` -m `awk '{print $3}' $TMPDIR/uzfs_sync_data`
		if [ $? != 0 ]; then
			return 1;
		fi
	done
	cleanup_uzfs_test uzfs_sync_pool3 uzfs_test_sync_vdev3

	#sync:standard log:true
	echo "running sync test with sync:standard, bs=64k and log device"
	log_must setup_uzfs_test log 65536 $UZFS_TEST_VOLSIZE standard uzfs_sync_pool4 \
	    uzfs_sync_vol4 uzfs_test_sync_vdev4 uzfs_test_sync_log4
	log_must export_pool uzfs_sync_pool4
	for i in {1..10}
	do
		sudo $UZFS_TEST -S -i 8192 -b 65536 -p uzfs_sync_pool4 -d uzfs_sync_vol4 -l -T 1 -w | grep uzfs_sync_data > $TMPDIR/uzfs_sync_data
		if [ $? != 0 ]; then
			return 1;
		fi

		sudo $UZFS_TEST -i 8192 -b 65536 -T 1 -p uzfs_sync_pool4 -d uzfs_sync_vol4 \
		    -V `awk '{print $2}' $TMPDIR/uzfs_sync_data` -m `awk '{print $3}' $TMPDIR/uzfs_sync_data`
		if [ $? != 0 ]; then
			return 1;
		fi

		sudo $UZFS_TEST -S -i 8192 -b 65536 -p uzfs_sync_pool4 -d uzfs_sync_vol4 -l -T 1 -u | grep uzfs_sync_data > $TMPDIR/uzfs_sync_data
		if [ $? != 0 ]; then
			return 1;
		fi

		sudo $UZFS_TEST -i 8192 -b 65536 -T 1 -p uzfs_sync_pool4 -d uzfs_sync_vol4 \
		    -V `awk '{print $2}' $TMPDIR/uzfs_sync_data` -m `awk '{print $3}' $TMPDIR/uzfs_sync_data`
		if [ $? != 0 ]; then
			return 1;
		fi
	done
	cleanup_uzfs_test uzfs_sync_pool4 uzfs_test_sync_vdev4 uzfs_test_sync_log4

	rm $TMPDIR/uzfs_sync_data
	return 0
: '
	for i in {1..10}
	do
	#	log_must setup_uzfs_test nolog 4096 always
		sudo $UZFS_TEST -c -S -s -T 1 -w | grep uzfs_sync_data > $TMPDIR/uzfs_sync_data
		if [ $? != 0 ]; then
			exit 1;
		fi

		sudo $UZFS_TEST -T 1 -V `awk '{print $2}' $TMPDIR/uzfs_sync_data` -m `awk '{print $3}' $TMPDIR/uzfs_sync_data`
		if [ $? != 0 ]; then
			exit 1;
		fi
	done
	for i in {1..10}
	do
	#	log_must setup_uzfs_test log 4096 always
		sudo $UZFS_TEST -c -S -l -s -T 1 -w | grep uzfs_sync_data > $TMPDIR/uzfs_sync_data
		if [ $? != 0 ]; then
			exit 1;
		fi

		sudo $UZFS_TEST -T 1 -V `awk '{print $2}' $TMPDIR/uzfs_sync_data` -m `awk '{print $3}' $TMPDIR/uzfs_sync_data`
		if [ $? != 0 ]; then
			exit 1;
		fi
	done

	for i in {1..10}
	do
	#	log_must setup_uzfs_test nolog 65536 always
		sudo $UZFS_TEST -c -S -s -i 8192 -b 65536 -T 1 -w | grep uzfs_sync_data > $TMPDIR/uzfs_sync_data
		if [ $? != 0 ]; then
			exit 1;
		fi

		sudo $UZFS_TEST -i 8192 -b 65536 -T 1 -V `awk '{print $2}' $TMPDIR/uzfs_sync_data` -m `awk '{print $3}' $TMPDIR/uzfs_sync_data`
		if [ $? != 0 ]; then
			exit 1;
		fi
	done
	for i in {1..10}
	do
	#	log_must setup_uzfs_test log 65536 always
		sudo $UZFS_TEST -c -S -i 8192 -b 65536 -l -s -T 1 -w | grep uzfs_sync_data > $TMPDIR/uzfs_sync_data
		if [ $? != 0 ]; then
			exit 1;
		fi

		sudo $UZFS_TEST -i 8192 -b 65536 -T 1 -V `awk '{print $2}' $TMPDIR/uzfs_sync_data` -m `awk '{print $3}' $TMPDIR/uzfs_sync_data`
		if [ $? != 0 ]; then
			exit 1;
		fi
	done
'
}
