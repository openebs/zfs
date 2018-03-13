#!/bin/bash
#
#  (C) Copyright 2017 CloudByte, Inc.
#  All Rights Reserved.
#
#  This program is an unpublished copyrighted work which is proprietary
#  to CloudByte, Inc. and contains confidential information that is not
#  to be reproduced or disclosed to any other person or entity without
#  prior written consent from CloudByte, Inc. in each and every instance.
#
#  WARNING:  Unauthorized reproduction of this program as well as
#  unauthorized preparation of derivative works based upon the
#  program or distribution of copies by sale, rental, lease or
#  lending are violations of federal copyright laws and state trade
#  secret laws, punishable by civil and criminal penalties.
#

if [ -z $SRC_PATH ]
then
	SRC_PATH=`pwd`
fi

ZPOOL="$SRC_PATH/cmd/zpool/zpool"
ZFS="$SRC_PATH/cmd/zfs/zfs"
ZDB="$SRC_PATH/cmd/zdb/zdb"
TGT="$SRC_PATH/cmd/zrepl/zrepl"
GTEST="$SRC_PATH/tests/cbtest/gtest/test_uzfs"
ZTEST="$SRC_PATH/cmd/ztest/ztest"
UZFS_TEST="$SRC_PATH/cmd/uzfs_test/uzfs_test"
UZFS_TEST_SYNC_SH="$SRC_PATH/cmd/uzfs_test/uzfs_test_sync.sh"
DMU_IO_TEST="cmd/dmu_io_test/dmu_io_test"
TMPDIR="/tmp"
VOLSIZE="1G"
UZFS_TEST_POOL="testp"
UZFS_TEST_VOL="ds0"
UZFS_TEST_VOLSIZE="1G"
SRCPOOL="src_pool"
SRCVOL="src_vol"
DSTPOOL="dst_pool"
DSTVOL="dst_vol"
TGT_PID="-1"
TGT_PID2="-1"

log_fail()
{
	echo "failed => [$@]"
	close_test
	exit 1
}

log_note()
{
	echo "executing => $@"
}

# Execute a positive test and exit if test fails
#
# $@ - command to execute
log_must()
{
	log_note $@
	$@
	test $? != 0 && log_fail $@
}

log_must_not()
{
	log_note $@
	$@
	test $? -eq 0 && log_fail $@
}

init_test()
{
	log_must truncate -s 2G "$TMPDIR/test_disk1.img"
	log_must truncate -s 2G "$TMPDIR/test_disk2.img"
	log_must truncate -s 2G "$TMPDIR/test_disk3.img"
	log_must truncate -s 2G "$TMPDIR/test_disk4.img"
	log_must truncate -s 2G "$TMPDIR/test_disk5.img"
	log_must truncate -s 2G "$TMPDIR/test_disk6.img"
	log_must truncate -s 2G "$TMPDIR/test_disk7.img"
	log_must truncate -s 2G "$TMPDIR/test_disk8.img"
	log_must truncate -s 2G "$TMPDIR/test_spare1.img"
	log_must truncate -s 2G "$TMPDIR/test_spare2.img"
	log_must truncate -s 2G "$TMPDIR/test_spare3.img"
	log_must truncate -s 2G "$TMPDIR/test_spare4.img"
	log_must truncate -s 2G "$TMPDIR/test_spare5.img"
	log_must truncate -s 2G "$TMPDIR/test_spare6.img"
	log_must truncate -s 2G "$TMPDIR/test_spare7.img"
	log_must truncate -s 2G "$TMPDIR/test_spare8.img"
	log_must truncate -s 2G "$TMPDIR/test_log.img"

	$TGT -v $SRCPOOL/$SRCVOL &
	TGT_PID=$!
	sleep 1
}

close_test()
{
	log_must kill -SIGKILL $TGT_PID
	log_must rm "$TMPDIR/test_disk1.img"
	log_must rm "$TMPDIR/test_disk2.img"
	log_must rm "$TMPDIR/test_disk3.img"
	log_must rm "$TMPDIR/test_disk4.img"
	log_must rm "$TMPDIR/test_disk5.img"
	log_must rm "$TMPDIR/test_disk6.img"
	log_must rm "$TMPDIR/test_disk7.img"
	log_must rm "$TMPDIR/test_disk8.img"
	log_must rm "$TMPDIR/test_spare1.img"
	log_must rm "$TMPDIR/test_spare2.img"
	log_must rm "$TMPDIR/test_spare3.img"
	log_must rm "$TMPDIR/test_spare4.img"
	log_must rm "$TMPDIR/test_spare5.img"
	log_must rm "$TMPDIR/test_spare6.img"
	log_must rm "$TMPDIR/test_spare7.img"
	log_must rm "$TMPDIR/test_spare8.img"
	log_must rm "$TMPDIR/test_log.img"
}

dump_data()
{
	kill -SIGHUP $TGT_PID
	ret=$?
	# wait for some data to be dumped
	sleep 3
	return $ret
}

run_zvol_tests()
{
	if poolnotexists $SRCPOOL ; then
		return 1
	fi

	if poolnotexists $DSTPOOL ; then
		return 1
	fi

	# test volume creation
	log_must $ZFS create -V $VOLSIZE $SRCPOOL/$SRCVOL
	log_must datasetexists $SRCPOOL/$SRCVOL
	log_must check_prop $SRCPOOL/$SRCVOL type volume

	# test volume properties
	log_must $ZFS get all $SRCPOOL/$SRCVOL > /dev/null
	log_must $ZFS list $SRCPOOL/$SRCVOL > /dev/null
	log_must $ZFS set dedup=on $SRCPOOL/$SRCVOL
	log_must check_prop "$SRCPOOL/$SRCVOL" dedup on
	log_must $ZFS set compression=on $SRCPOOL/$SRCVOL
	log_must check_prop "$SRCPOOL/$SRCVOL" compression on

	log_must $ZFS set sync=standard $SRCPOOL/$SRCVOL
	log_must check_prop "$SRCPOOL/$SRCVOL" sync standard

	log_must $ZFS set sync=disabled $SRCPOOL/$SRCVOL
	log_must check_prop "$SRCPOOL/$SRCVOL" sync disabled

	log_must $ZFS set sync=always $SRCPOOL/$SRCVOL
	log_must check_prop "$SRCPOOL/$SRCVOL" sync always

	# dump some data
	#log_must dump_data

	# test snapshot creation
	log_must create_snapshot "$SRCPOOL/$SRCVOL" "snap"
	log_must snapexists "$SRCPOOL/$SRCVOL@snap"
	log_must check_prop "$SRCPOOL/$SRCVOL@snap" type snapshot

	# test zfs send/recv
	log_note "zfs send/recv"
	$ZFS send -vv "$SRCPOOL/$SRCVOL@snap" | $ZFS recv "$DSTPOOL/$DSTVOL"

	# after zfs recv, dataset and snap should exist
	log_must datasetexists $DSTPOOL/$DSTVOL
	log_must check_prop $DSTPOOL/$DSTVOL type volume
	log_must snapexists "$DSTPOOL/$DSTVOL@snap"
	log_must check_prop "$DSTPOOL/$DSTVOL@snap" type snapshot

	# should fail as it has children and -r is not passed
	log_must_not $ZFS destroy $DSTPOOL/$DSTVOL 2> /dev/null
	log_must_not $ZFS destroy $SRCPOOL/$SRCVOL 2> /dev/null

	# test volume destroy
	log_must $ZFS list -t all $DSTPOOL/$DSTVOL > /dev/null
	log_must $ZFS destroy -r $DSTPOOL/$DSTVOL
	log_must $ZFS list -t all $SRCPOOL/$SRCVOL > /dev/null
	log_must $ZFS destroy -r $SRCPOOL/$SRCVOL

	# test snap destroy
	log_must $ZFS create -s -V $VOLSIZE $SRCPOOL/$SRCVOL
	log_must datasetexists $SRCPOOL/$SRCVOL

	log_must create_snapshot "$SRCPOOL/$SRCVOL" "snap"
	log_must snapexists "$SRCPOOL/$SRCVOL@snap"
	log_must check_prop "$SRCPOOL/$SRCVOL@snap" type snapshot
	log_must destroy_snapshot "$SRCPOOL/$SRCVOL@snap"
	log_must_not snapexists "$SRCPOOL/$SRCVOL@snap"

	return 0
}

run_pool_tests()
{
	if poolnotexists $SRCPOOL ; then
		return 1
	fi

	if poolnotexists $DSTPOOL ; then
		return 1
	fi

	log_must cp $TMPDIR/zpool_$SRCPOOL.cache $TMPDIR/$SRCPOOL.cache
	log_must cp $TMPDIR/zpool_$DSTPOOL.cache $TMPDIR/$DSTPOOL.cache

	# test log addition/removal
	log_must $ZPOOL add -f $SRCPOOL log "$TMPDIR/test_log.img"
	log_must $ZPOOL remove $SRCPOOL "$TMPDIR/test_log.img"
	log_must $ZPOOL add -f $DSTPOOL log "$TMPDIR/test_log.img"
	log_must $ZPOOL remove $DSTPOOL "$TMPDIR/test_log.img"

	# test pool export
	log_must export_pool $SRCPOOL
	log_must export_pool $DSTPOOL

	# should fail
	#log_must check_state $SRCPOOL "$TMPDIR/test_disk1.img" "online"

	# test pool import
	log_must $ZPOOL import -c "$TMPDIR/$SRCPOOL.cache" $SRCPOOL
	log_must $ZPOOL import -c "$TMPDIR/$DSTPOOL.cache" $DSTPOOL

	log_must rm "$TMPDIR/$SRCPOOL.cache"
	log_must rm "$TMPDIR/$DSTPOOL.cache"

	log_must $ZPOOL set cachefile="$TMPDIR/zpool_$SRCPOOL.cache" $SRCPOOL
	log_must $ZPOOL set cachefile="$TMPDIR/zpool_$DSTPOOL.cache" $DSTPOOL
	cache=$($ZPOOL get -H -o value cachefile $SRCPOOL)
	if [ $cache != "$TMPDIR/zpool_$SRCPOOL.cache" ]; then
		log_fail "cachefile not set for $SRCPOOL [$cache => $TMPDIR/zpool_$SRCPOOL.cache]"
		return 1
	fi
	cache=$($ZPOOL get -H -o value cachefile $DSTPOOL)
	if [ $cache != "$TMPDIR/zpool_$DSTPOOL.cache" ]; then
		log_fail "cachefile not set for $DSTPOOL [$cache => $TMPDIR/zpool_$DSTPOOL.cache]"
		return 1
	fi

	# check pool status
	log_must check_state $SRCPOOL "online"
	log_must check_state $DSTPOOL "online"

	# check history
	log_must check_history $SRCPOOL "import -c $TMPDIR/$SRCPOOL.cache $SRCPOOL"
	log_must check_history $SRCPOOL "export $SRCPOOL"
	log_must check_history $SRCPOOL "set cachefile=$TMPDIR/$SRCPOOL.cache $SRCPOOL"
	log_must check_history $DSTPOOL "import -c $TMPDIR/$DSTPOOL.cache $DSTPOOL"
	log_must check_history $DSTPOOL "export $DSTPOOL"
	log_must check_history $DSTPOOL "set cachefile=$TMPDIR/$DSTPOOL.cache $DSTPOOL"

	log_must $ZPOOL iostat -v $SRCPOOL 1 5 > /dev/null
	log_must $ZPOOL iostat -v $DSTPOOL 1 5 > /dev/null

	return 0
}

#
# $1 Existing filesystem or volume name.
# $2 snapshot name. Default, $TESTSNAP
#
create_snapshot()
{
	fs_vol=$1
	snap=$2
	test -z $fs_vol && log_fail "Filesystem or volume's name is undefined."
	test -z $snap && log_fail "Snapshot's name is undefined."

	if snapexists $fs_vol@$snap; then
		return 1
	fi
	datasetexists $fs_vol || \
		return 1

	$ZFS snapshot $fs_vol@$snap
	return $?
}

# delete the file system's snapshot
destroy_snapshot()
{
	snap=$1

	if ! snapexists $snap; then
		return 1
	fi

	$ZFS destroy $snap
	return $?
}

# $1 - snapshot name
snapexists()
{
	$ZFS list -H -t snapshot "$1" > /dev/null 2>&1
	return $?
}

# $1 - pool name
poolexists()
{
	pool=$1

	if [ -z $pool ]; then
		echo "No pool name given."
		return 1
	fi

	$ZPOOL get name "$pool" > /dev/null 2>&1
	return $?
}

# $1 - pool name
poolnotexists()
{
	pool=$1

	if [ -z $pool ]; then
		echo "No pool name given."
		return 1
	fi

	if poolexists "$pool" ; then
		return 1
	else
		return 0
	fi
}

# $1  dataset name
datasetexists()
{
	if [ $# -eq 0 ]; then
		echo "No dataset name given."
		return 1
	fi

	$ZFS get name $1 > /dev/null 2>&1 || return $?

	return 0
}

# Destroy pool with the given parameters.
destroy_pool()
{
	pool=$1

	if [ -z $pool ]; then
		echo "No pool name given."
		return 1
	fi

	if poolexists "$pool" ; then
		$ZPOOL destroy -f $pool
	else
		echo "Pool does not exist. ($pool)"
		return 1
	fi

	return $?
}

# $1 - pool name
export_pool()
{
	pool=$1

	if [ -z $pool ]; then
		echo "No pool name given."
		return 1
	fi

	if poolexists "$pool" ; then
		$ZPOOL export $pool
	else
		echo "Pool does not exist. ($pool)"
		return 1
	fi

	return $?
}

#
# Return 0 is pool matches expected state, 1 otherwise
check_state() # pool state{online,offline,degraded}
{
	pool=$1
	disk=$2
	state=$3

	test -z $pool \
	    && log_fail "Arguments invalid or missing"

	$ZPOOL get -H -o value health $pool \
	    | grep -i "$state" > /dev/null 2>&1

	return $?
}

#
# Return 0 is history matches expected string
check_history()
{
	pool=$1
	match=$2

	test -z $pool \
	    && log_fail "Arguments invalid or missing"

	$ZPOOL history -li $pool \
	    | grep -i "$match" > /dev/null 2>&1

	return $?
}

check_prop()
{
	type=$($ZFS get -pH -o value "$2" "$1")
	test $type = "$3" && return 0
	return 1
}

test_stripe_pool()
{
	# test pool creation
	log_must $ZPOOL create -f $SRCPOOL -o cachefile="$TMPDIR/zpool_$SRCPOOL.cache" \
	    "$TMPDIR/test_disk1.img"
	log_must $ZPOOL create -f $DSTPOOL -o cachefile="$TMPDIR/zpool_$DSTPOOL.cache" \
	    "$TMPDIR/test_disk2.img"

	# test pool expansion
	log_must $ZPOOL add -f $SRCPOOL "$TMPDIR/test_spare1.img"
	log_must $ZPOOL add -f $DSTPOOL "$TMPDIR/test_spare2.img"

	# test vdev remove
	log_must_not $ZPOOL remove $SRCPOOL "$TMPDIR/test_spare1.img"
	log_must_not $ZPOOL remove $DSTPOOL "$TMPDIR/test_spare2.img"

	# read cachefile
	log_must $ZDB -C -U "$TMPDIR/zpool_$SRCPOOL.cache" $SRCPOOL > /dev/null
	log_must $ZDB -C -U "$TMPDIR/zpool_$DSTPOOL.cache" $DSTPOOL > /dev/null

	# read disk labels
	log_must $ZDB -l "$TMPDIR/test_disk1.img" > /dev/null
	log_must $ZDB -l "$TMPDIR/test_disk2.img" > /dev/null

	# run test cases
	log_must run_zvol_tests
	log_must run_pool_tests

	# test pool destroy
	log_must destroy_pool $SRCPOOL
	log_must destroy_pool $DSTPOOL

	return 0
}

test_mirror_pool()
{
	# test pool creation
	log_must $ZPOOL create -f $SRCPOOL mirror \
	    -o cachefile="$TMPDIR/zpool_$SRCPOOL.cache" \
	    "$TMPDIR/test_disk1.img" "$TMPDIR/test_disk2.img"

	log_must $ZPOOL create -f $DSTPOOL mirror \
	    -o cachefile="$TMPDIR/zpool_$DSTPOOL.cache" \
	    "$TMPDIR/test_disk3.img" "$TMPDIR/test_disk4.img"

	# test pool expansion
	log_must $ZPOOL add -f $SRCPOOL "$TMPDIR/test_spare1.img" \
	    "$TMPDIR/test_spare2.img"
	log_must $ZPOOL add -f $DSTPOOL "$TMPDIR/test_spare3.img" \
	    "$TMPDIR/test_spare4.img"

	# test vdev remove
	log_must_not $ZPOOL remove $SRCPOOL "$TMPDIR/test_spare1.img"
	log_must_not $ZPOOL remove $DSTPOOL "$TMPDIR/test_spare3.img"

	# read cachefile
	log_must $ZDB -C -U "$TMPDIR/zpool_$SRCPOOL.cache" $SRCPOOL > /dev/null
	log_must $ZDB -C -U "$TMPDIR/zpool_$DSTPOOL.cache" $DSTPOOL > /dev/null

	# read disk labels
	log_must $ZDB -l "$TMPDIR/test_disk1.img" > /dev/null
	log_must $ZDB -l "$TMPDIR/test_disk2.img" > /dev/null
	log_must $ZDB -l "$TMPDIR/test_disk3.img" > /dev/null
	log_must $ZDB -l "$TMPDIR/test_disk4.img" > /dev/null

	# run test cases
	log_must run_zvol_tests
	log_must run_pool_tests

	# test pool destroy
	log_must destroy_pool $SRCPOOL
	log_must destroy_pool $DSTPOOL

	return 0
}

test_raidz_pool()
{
	# test pool creation
	log_must $ZPOOL create -f $SRCPOOL raidz1 \
	    -o cachefile="$TMPDIR/zpool_$SRCPOOL.cache" \
	    "$TMPDIR/test_disk1.img" "$TMPDIR/test_disk2.img" \
	    "$TMPDIR/test_disk3.img" "$TMPDIR/test_disk4.img"

	log_must $ZPOOL create -f $DSTPOOL raidz1 \
	    -o cachefile="$TMPDIR/zpool_$DSTPOOL.cache" \
	    "$TMPDIR/test_disk5.img" "$TMPDIR/test_disk6.img" \
	    "$TMPDIR/test_disk7.img" "$TMPDIR/test_disk8.img"

	# test pool expansion
	log_must $ZPOOL add -f $SRCPOOL \
	    "$TMPDIR/test_spare1.img" "$TMPDIR/test_spare2.img" \
	    "$TMPDIR/test_spare3.img" "$TMPDIR/test_spare4.img"
	log_must $ZPOOL add -f $DSTPOOL \
	    "$TMPDIR/test_spare5.img" "$TMPDIR/test_spare6.img"
	    "$TMPDIR/test_spare7.img" "$TMPDIR/test_spare8.img"

	# test vdev remove
	log_must_not $ZPOOL remove $SRCPOOL "$TMPDIR/test_spare1.img"
	log_must_not $ZPOOL remove $DSTPOOL "$TMPDIR/test_spare5.img"

	# read cachefile
	log_must $ZDB -C -U "$TMPDIR/zpool_$SRCPOOL.cache" $SRCPOOL > /dev/null
	log_must $ZDB -C -U "$TMPDIR/zpool_$DSTPOOL.cache" $DSTPOOL > /dev/null

	# read disk labels
	log_must $ZDB -l "$TMPDIR/test_disk1.img" > /dev/null
	log_must $ZDB -l "$TMPDIR/test_disk2.img" > /dev/null
	log_must $ZDB -l "$TMPDIR/test_disk3.img" > /dev/null
	log_must $ZDB -l "$TMPDIR/test_disk4.img" > /dev/null
	log_must $ZDB -l "$TMPDIR/test_disk5.img" > /dev/null
	log_must $ZDB -l "$TMPDIR/test_disk6.img" > /dev/null
	log_must $ZDB -l "$TMPDIR/test_disk7.img" > /dev/null
	log_must $ZDB -l "$TMPDIR/test_disk8.img" > /dev/null

	# run test cases
	log_must run_zvol_tests
	log_must run_pool_tests

	# test pool destroy
	log_must destroy_pool $SRCPOOL
	log_must destroy_pool $DSTPOOL

	return 0
}

setup_uzfs_test()
{
	$TGT &
	sleep 10
	TGT_PID2=$!

	export_pool $UZFS_TEST_POOL

	if [ "$1" == "log" ]; then
		log_must $ZPOOL create -f $UZFS_TEST_POOL "$TMPDIR/uztest.1a" \
		    log "$TMPDIR/uztest.log"
	else
		log_must $ZPOOL create -f $UZFS_TEST_POOL "$TMPDIR/uztest.1a"
	fi

	log_must $ZFS create -V $UZFS_TEST_VOLSIZE \
	    $UZFS_TEST_POOL/$UZFS_TEST_VOL -b $2

	if [ "$3" == "sync" ]; then
		log_must $ZFS set sync=always $UZFS_TEST_POOL/$UZFS_TEST_VOL
	else
		log_must $ZFS set sync=standard $UZFS_TEST_POOL/$UZFS_TEST_VOL
	fi
	log_must kill -SIGKILL $TGT_PID2
	return 0
}

run_uzfs_test()
{
	log_must_not $UZFS_TEST

	log_must truncate -s 2G "$TMPDIR/uztest.1a"
	log_must truncate -s 2G "$TMPDIR/uztest.log"

	log_must setup_uzfs_test nolog 4096 nosync
	log_must $UZFS_TEST -T 2

	log_must setup_uzfs_test nolog 4096 sync
	log_must $UZFS_TEST -s -T 2

	log_must setup_uzfs_test log 4096 nosync
	log_must $UZFS_TEST -l -T 2

	log_must setup_uzfs_test log 4096 sync
	log_must $UZFS_TEST -s -l -T 2

	log_must setup_uzfs_test nolog 65536 nosync
	log_must $UZFS_TEST -i 8192 -b 65536 -T 2

	log_must setup_uzfs_test nolog 65536 sync
	log_must $UZFS_TEST -s -i 8192 -b 65536 -T 2

	log_must setup_uzfs_test log 65536 nosync
	log_must $UZFS_TEST -l -i 8192 -b 65536 -T 2

	log_must setup_uzfs_test log 65536 sync
	log_must $UZFS_TEST -s -l -i 8192 -b 65536 -T 2

	log_must $UZFS_TEST -t 10 -T 0
	log_must $UZFS_TEST -t 10 -T 0 -n 10

#	log_must . $UZFS_TEST_SYNC_SH

	log_must rm "$TMPDIR/uztest.1a"
	log_must rm "$TMPDIR/uztest.log"

	return 0
}

run_dmu_test()
{
	log_must truncate -s 100MB /tmp/disk;
	log_must $DMU_IO_TEST tpool/vol /tmp/disk;
	log_must sudo mknod /dev/fake-dev b 7 200;
	log_must sudo chmod 666 /dev/fake-dev;
	log_must sudo losetup /dev/fake-dev /tmp/disk;
	log_must $DMU_IO_TEST tpool/vol /dev/fake-dev;
	log_must sudo losetup -d /dev/fake-dev;
	log_must sudo rm /dev/fake-dev;
	log_must rm /tmp/disk;

	return 0
}

usage()
{
cat << EOF
usage:
$0 [h] [-T test_type]

test_type :
	- pool_test (verify pool create/destroy functionality)
	- zvol_test (zvol sync test, read/write and replay tests)
	- rebuild_test (zvol rebuild related tests)
EOF
}

while getopts 'hT:' OPTION; do
	case $OPTION in
	h)
		usage
		exit 1
		;;
	T)
		test_type="$OPTARG"
		;;
	?)
		usage
		exit
		;;
	esac
done

shift $((OPTIND-1))

if [ -z $test_type ]; then
	usage
	exit
fi

run_pool_test()
{
	init_test
	sleep 10

	log_must test_stripe_pool
	log_must test_mirror_pool
	log_must test_raidz_pool

	close_test
}

run_zvol_test()
{
	log_must run_uzfs_test
	log_must run_dmu_test
	log_must $GTEST
	log_must $ZTEST
}

run_rebuild_test()
{
	K=1024
	M=$(( 1024 * 1024 ))
	G=$(( 1024 * 1024 * 1024 ))

	log_must $UZFS_TEST -t 10 -a  $(( 50 * 1024 * 1024 )) -T 3 -n 10000
	log_must $UZFS_TEST -t 10 -a  $(( 100 * 1024 * 1024 )) -T 3 -n 10000
	log_must $UZFS_TEST -t 10 -a  $(( 1000 * 1024 * 1024 )) -T 3 -n 10000
	log_must $UZFS_TEST -t 10 -T 4
	log_must $UZFS_TEST -t 10 -T 5 -t 60 -n 3
	log_must $UZFS_TEST -t 10 -T 5 -t 120 -n 3
	log_must $UZFS_TEST -t 10 -T 5 -t 500 -n 3
}


test_func="run_${test_type}"
type -t $test_func
if [ $? -eq 0 ]; then
	START=$(date +%s.%N)
	$test_func
	END=$(date +%s.%N)
	DIFF=$(echo "scale=0;$END - $START" | bc)
	echo "####################################"
	echo "All cases passed for $test_type in ${DIFF%.*} seconds"
	echo "####################################"
else
	usage
	exit 1
fi
