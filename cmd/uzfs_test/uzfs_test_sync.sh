#!/bin/bash
for i in {1..10}
do
	log_must setup_uzfs_test nolog 4096 nosync
	sudo $UZFS_TEST -S -w -T 1 > $PWD/$1/uzfs_sync_data
	if [ $? != 0 ]; then
		exit 1;
	fi

	sudo $UZFS_TEST -T 1 -V `awk '{print $1}' $PWD/$1/uzfs_sync_data` -m `awk '{print $2}' $PWD/$1/uzfs_sync_data`
	if [ $? != 0 ]; then
		exit 1;
	fi
done
for i in {1..10}
do
	log_must setup_uzfs_test log 4096 nosync
	sudo $UZFS_TEST -S -l -T 1 -w > $PWD/$1/uzfs_sync_data
	if [ $? != 0 ]; then
		exit 1;
	fi

	sudo $UZFS_TEST -T 1 -V `awk '{print $1}' $PWD/$1/uzfs_sync_data` -m `awk '{print $2}' $PWD/$1/uzfs_sync_data`
	if [ $? != 0 ]; then
		exit 1;
	fi
done
for i in {1..10}
do
	log_must setup_uzfs_test nolog 4096 sync
	sudo $UZFS_TEST -S -s -T 1 -w > $PWD/$1/uzfs_sync_data
	if [ $? != 0 ]; then
		exit 1;
	fi

	sudo $UZFS_TEST -T 1 -V `awk '{print $1}' $PWD/$1/uzfs_sync_data` -m `awk '{print $2}' $PWD/$1/uzfs_sync_data`
	if [ $? != 0 ]; then
		exit 1;
	fi
done
for i in {1..10}
do
	log_must setup_uzfs_test log 4096 sync
	sudo $UZFS_TEST -S -l -s -T 1 -w > $PWD/$1/uzfs_sync_data
	if [ $? != 0 ]; then
		exit 1;
	fi

	sudo $UZFS_TEST -T 1 -V `awk '{print $1}' $PWD/$1/uzfs_sync_data` -m `awk '{print $2}' $PWD/$1/uzfs_sync_data`
	if [ $? != 0 ]; then
		exit 1;
	fi
done

for i in {1..10}
do
	log_must setup_uzfs_test nolog 65536 nosync
	sudo $UZFS_TEST -S -i 8192 -b 65536 -T 1 -w > $PWD/$1/uzfs_sync_data
	if [ $? != 0 ]; then
		exit 1;
	fi

	sudo $UZFS_TEST -i 8192 -b 65536 -T 1 -V `awk '{print $1}' $PWD/$1/uzfs_sync_data` -m `awk '{print $2}' $PWD/$1/uzfs_sync_data`
	if [ $? != 0 ]; then
		exit 1;
	fi
done
for i in {1..10}
do
	log_must setup_uzfs_test log 65536 nosync
	sudo $UZFS_TEST -S -i 8192 -b 65536 -l -T 1 -w > $PWD/$1/uzfs_sync_data
	if [ $? != 0 ]; then
		exit 1;
	fi

	sudo $UZFS_TEST -i 8192 -b 65536 -T 1 -V `awk '{print $1}' $PWD/$1/uzfs_sync_data` -m `awk '{print $2}' $PWD/$1/uzfs_sync_data`
	if [ $? != 0 ]; then
		exit 1;
	fi
done
for i in {1..10}
do
	log_must setup_uzfs_test nolog 65536 sync
	sudo $UZFS_TEST -S -s -i 8192 -b 65536 -T 1 -w > $PWD/$1/uzfs_sync_data
	if [ $? != 0 ]; then
		exit 1;
	fi

	sudo $UZFS_TEST -i 8192 -b 65536 -T 1 -V `awk '{print $1}' $PWD/$1/uzfs_sync_data` -m `awk '{print $2}' $PWD/$1/uzfs_sync_data`
	if [ $? != 0 ]; then
		exit 1;
	fi
done
for i in {1..10}
do
	log_must setup_uzfs_test log 65536 sync
	sudo $UZFS_TEST -S -i 8192 -b 65536 -l -s -T 1 -w > $PWD/$1/uzfs_sync_data
	if [ $? != 0 ]; then
		exit 1;
	fi

	sudo $UZFS_TEST -i 8192 -b 65536 -T 1 -V `awk '{print $1}' $PWD/$1/uzfs_sync_data` -m `awk '{print $2}' $PWD/$1/uzfs_sync_data`
	if [ $? != 0 ]; then
		exit 1;
	fi
done
exit 0
