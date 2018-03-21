#!/bin/bash
for i in {1..10}
do
#	log_must setup_uzfs_test nolog 4096 standard
	sudo $UZFS_TEST -c -S -w -T 1 | grep uzfs_sync_data > $PWD/$1/uzfs_sync_data
	if [ $? != 0 ]; then
		exit 1;
	fi

	sudo $UZFS_TEST -T 1 -V `awk '{print $2}' $PWD/$1/uzfs_sync_data` -m `awk '{print $3}' $PWD/$1/uzfs_sync_data`
	if [ $? != 0 ]; then
		exit 1;
	fi
done
for i in {1..10}
do
#	log_must setup_uzfs_test log 4096 standard
	sudo $UZFS_TEST -c -S -l -T 1 -w | grep uzfs_sync_data > $PWD/$1/uzfs_sync_data
	if [ $? != 0 ]; then
		exit 1;
	fi

	sudo $UZFS_TEST -T 1 -V `awk '{print $2}' $PWD/$1/uzfs_sync_data` -m `awk '{print $3}' $PWD/$1/uzfs_sync_data`
	if [ $? != 0 ]; then
		exit 1;
	fi
done
: '
for i in {1..10}
do
#	log_must setup_uzfs_test nolog 4096 always
	sudo $UZFS_TEST -c -S -s -T 1 -w | grep uzfs_sync_data > $PWD/$1/uzfs_sync_data
	if [ $? != 0 ]; then
		exit 1;
	fi

	sudo $UZFS_TEST -T 1 -V `awk '{print $2}' $PWD/$1/uzfs_sync_data` -m `awk '{print $3}' $PWD/$1/uzfs_sync_data`
	if [ $? != 0 ]; then
		exit 1;
	fi
done
for i in {1..10}
do
#	log_must setup_uzfs_test log 4096 always
	sudo $UZFS_TEST -c -S -l -s -T 1 -w | grep uzfs_sync_data > $PWD/$1/uzfs_sync_data
	if [ $? != 0 ]; then
		exit 1;
	fi

	sudo $UZFS_TEST -T 1 -V `awk '{print $2}' $PWD/$1/uzfs_sync_data` -m `awk '{print $3}' $PWD/$1/uzfs_sync_data`
	if [ $? != 0 ]; then
		exit 1;
	fi
done
'

for i in {1..10}
do
#	log_must setup_uzfs_test nolog 65536 standard
	sudo $UZFS_TEST -c -S -i 8192 -b 65536 -T 1 -w | grep uzfs_sync_data > $PWD/$1/uzfs_sync_data
	if [ $? != 0 ]; then
		exit 1;
	fi

	sudo $UZFS_TEST -i 8192 -b 65536 -T 1 -V `awk '{print $2}' $PWD/$1/uzfs_sync_data` -m `awk '{print $3}' $PWD/$1/uzfs_sync_data`
	if [ $? != 0 ]; then
		exit 1;
	fi
done
for i in {1..10}
do
#	log_must setup_uzfs_test log 65536 standard
	sudo $UZFS_TEST -c -S -i 8192 -b 65536 -l -T 1 -w | grep uzfs_sync_data > $PWD/$1/uzfs_sync_data
	if [ $? != 0 ]; then
		exit 1;
	fi

	sudo $UZFS_TEST -i 8192 -b 65536 -T 1 -V `awk '{print $2}' $PWD/$1/uzfs_sync_data` -m `awk '{print $3}' $PWD/$1/uzfs_sync_data`
	if [ $? != 0 ]; then
		exit 1;
	fi
done
: '
for i in {1..10}
do
#	log_must setup_uzfs_test nolog 65536 always
	sudo $UZFS_TEST -c -S -s -i 8192 -b 65536 -T 1 -w | grep uzfs_sync_data > $PWD/$1/uzfs_sync_data
	if [ $? != 0 ]; then
		exit 1;
	fi

	sudo $UZFS_TEST -i 8192 -b 65536 -T 1 -V `awk '{print $2}' $PWD/$1/uzfs_sync_data` -m `awk '{print $3}' $PWD/$1/uzfs_sync_data`
	if [ $? != 0 ]; then
		exit 1;
	fi
done
for i in {1..10}
do
#	log_must setup_uzfs_test log 65536 always
	sudo $UZFS_TEST -c -S -i 8192 -b 65536 -l -s -T 1 -w | grep uzfs_sync_data > $PWD/$1/uzfs_sync_data
	if [ $? != 0 ]; then
		exit 1;
	fi

	sudo $UZFS_TEST -i 8192 -b 65536 -T 1 -V `awk '{print $2}' $PWD/$1/uzfs_sync_data` -m `awk '{print $3}' $PWD/$1/uzfs_sync_data`
	if [ $? != 0 ]; then
		exit 1;
	fi
done
'
