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
ZREPL="$SRC_PATH/cmd/zrepl/zrepl"
GTEST_UZFS="$SRC_PATH/tests/cbtest/gtest/test_uzfs"
GTEST_ZFS="$SRC_PATH/tests/cbtest/gtest/test_zfs"
GTEST_ZREPL_PROT="$SRC_PATH/tests/cbtest/gtest/test_zrepl_prot"
ZTEST="$SRC_PATH/cmd/ztest/ztest"
UZFS_TEST="$SRC_PATH/cmd/uzfs_test/uzfs_test"
UZFS_TEST_SYNC_SH="$SRC_PATH/cmd/uzfs_test/uzfs_test_sync.sh"
TMPDIR="/tmp"
VOLSIZE="1G"
UZFS_TEST_POOL="testp"
UZFS_TEST_VOL="ds0"
UZFS_REBUILD_VOL="ds1"
UZFS_REBUILD_VOL1="ds2"
UZFS_REBUILD_VOL2="ds3"
UZFS_TEST_VOLSIZE="128M"
UZFS_TEST_VOLSIZE_IN_NUM=134217728
ZREPL_PID="-1"

source $UZFS_TEST_SYNC_SH

log_fail()
{
	echo "failed => [$@]"
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
	local logfile status

	logfile=`mktemp`

	log_note $@ >> $logfile 2>&1
	$@ >> $logfile 2>&1
	status=$?

	if [ $status -ne 0 ]; then
		cat $logfile > /dev/tty 2>&1
		rm $logfile
		log_fail $@
	fi
	rm $logfile
}

log_must_not()
{
	local logfile status

	logfile=`mktemp`

	log_note $@ >> $logfile 2>&1
	$@ >> $logfile 2>&1
	status=$?

	if [ $status -eq 0 ]; then
		cat $logfile >  /dev/tty 2>&1
		rm $logfile
		log_fail $@
	fi
	rm $logfile
}

start_zrepl()
{
	if [ $ZREPL_PID -eq -1 ]; then
		# XXX Remove redirection to /dev/null when debug messages are removed
		# from zrepl
		$ZREPL >/dev/null &
		ZREPL_PID=$!
		sleep 5
	else
		echo "warning.. zrepl is already started"
	fi
}

stop_zrepl()
{
	if [ $ZREPL_PID -ne -1 ]; then
		kill -SIGKILL $ZREPL_PID
		ZREPL_PID=-1
	fi
}

wait_for_pids()
{
	for p in "$@"; do
		wait $p
		status=$?
		if [ $status -ne 0 ] && [ $status -ne 127 ]; then
			exit 1
		fi
	done
}

create_disk()
{
	for disk in "$@"; do
		disk_name=$disk
		log_must truncate -s 2G $disk_name
	done
}

destroy_disk()
{
	for disk in "$@"; do
		disk_name=$disk
		stat $disk_name >/dev/null && rm $disk_name
	done
}

dump_data()
{
	if [ $ZREPL_PID -ne -1 ]; then
		kill -SIGHUP $ZREPL_PID
		ret=$?
	else
		echo "warning.. zrepl was not started"
	fi
	# wait for some data to be dumped
	sleep 3
	return $ret
}

run_zvol_tests()
{
	local src_pool
	local src_vol
	local dst_pool
	local dst_vol

	[[ $# -ne 2 ]] && return 1

	src_pool=`echo $1| awk -F '/' '{print $1}'`
	dst_pool=`echo $2| awk -F '/' '{print $1}'`

	src_vol=`echo $1| awk -F '/' '{print $2}'`
	dst_vol=`echo $2| awk -F '/' '{print $2}'`

	[[ -z $src_pool || -z $dst_pool || -z $src_vol || -z $dst_vol ]] && return 1

	if poolnotexists $src_pool || poolnotexists $dst_pool ; then
		echo "pool does not exists"
		return 1
	fi

	# test volume creation
	log_must $ZFS create -V $VOLSIZE $src_pool/$src_vol
	log_must datasetexists $src_pool/$src_vol
	log_must check_prop $src_pool/$src_vol type volume

	log_must $ZFS create -V $VOLSIZE -o io.openebs:targetip=127.0.0.1:6060 $src_pool/$src_vol"_1"

	# test volume properties
	log_must $ZFS get all $src_pool/$src_vol > /dev/null
	log_must $ZFS list $src_pool/$src_vol > /dev/null
	log_must $ZFS set dedup=on $src_pool/$src_vol
	log_must check_prop "$src_pool/$src_vol" dedup on
	log_must $ZFS set compression=on $src_pool/$src_vol
	log_must check_prop "$src_pool/$src_vol" compression on

	log_must $ZFS set sync=standard $src_pool/$src_vol
	log_must check_prop "$src_pool/$src_vol" sync standard

	log_must $ZFS set sync=disabled $src_pool/$src_vol
	log_must check_prop "$src_pool/$src_vol" sync disabled

	log_must $ZFS set sync=always $src_pool/$src_vol
	log_must check_prop "$src_pool/$src_vol" sync always

	log_must check_prop "$src_pool/$src_vol""_1" io.openebs:targetip 127.0.0.1:6060

	# dump some data
	#log_must dump_data

	# test snapshot creation
	log_must create_snapshot "$src_pool/$src_vol" "snap"
	log_must snapexists "$src_pool/$src_vol@snap"
	log_must check_prop "$src_pool/$src_vol@snap" type snapshot

	# test zfs send/recv
	log_note "zfs send/recv"
	$ZFS send -vv "$src_pool/$src_vol@snap" | $ZFS recv "$dst_pool/$dst_vol"

	# after zfs recv, dataset and snap should exist
	log_must datasetexists $dst_pool/$dst_vol
	log_must check_prop $dst_pool/$dst_vol type volume
	log_must snapexists "$dst_pool/$dst_vol@snap"
	log_must check_prop "$dst_pool/$dst_vol@snap" type snapshot

	# should fail as it has children and -r is not passed
	log_must_not $ZFS destroy $dst_pool/$dst_vol 2> /dev/null
	log_must_not $ZFS destroy $src_pool/$src_vol 2> /dev/null

	# test volume destroy
	log_must $ZFS list -t all $dst_pool/$dst_vol > /dev/null
	log_must $ZFS destroy -r $dst_pool/$dst_vol
	log_must $ZFS list -t all $src_pool/$src_vol > /dev/null
	log_must $ZFS destroy -r $src_pool/$src_vol
	log_must $ZFS destroy -r $src_pool/$src_vol"_1"

	# test snap destroy
	log_must $ZFS create -s -V $VOLSIZE $src_pool/$src_vol
	log_must datasetexists $src_pool/$src_vol

	log_must create_snapshot "$src_pool/$src_vol" "snap"
	log_must snapexists "$src_pool/$src_vol@snap"
	log_must check_prop "$src_pool/$src_vol@snap" type snapshot
	log_must destroy_snapshot "$src_pool/$src_vol@snap"
	log_must_not snapexists "$src_pool/$src_vol@snap"

	return 0
}

run_pool_tests()
{
	local src_pool
	local src_vol
	local dst_pool
	local dst_vol
	local log_disk

	[[ $# -ne 2 ]] && return 1

	src_pool=`echo $1| awk -F '/' '{print $1}'`
	dst_pool=`echo $2| awk -F '/' '{print $1}'`

	src_vol=`echo $1| awk -F '/' '{print $2}'`
	dst_vol=`echo $2| awk -F '/' '{print $2}'`

	[[ -z $src_pool || -z $dst_pool || -z $src_vol || -z $dst_vol ]] && return 1

	if poolnotexists $src_pool || poolnotexists $dst_pool ; then
		echo "pool does not exists"
		return 1
	fi

	log_must cp $TMPDIR/zpool_$src_pool.cache $TMPDIR/$src_pool.cache
	log_must cp $TMPDIR/zpool_$dst_pool.cache $TMPDIR/$dst_pool.cache

	# test log addition/removal
	log_disk="$TMPDIR/${src_pool}_disk.img"
	create_disk $log_disk
	log_must $ZPOOL add -f $src_pool log $log_disk
	log_must $ZPOOL remove $src_pool $log_disk
	log_must $ZPOOL add -f $dst_pool log $log_disk
	log_must $ZPOOL remove $dst_pool $log_disk
	destroy_disk $log_disk

	# test pool export
	log_must export_pool $src_pool
	log_must export_pool $dst_pool

	# should fail
	#log_must check_state $src_pool "$TMPDIR/test_disk1.img" "online"

	# test pool import
	log_must $ZPOOL import -c "$TMPDIR/$src_pool.cache" $src_pool
	log_must $ZPOOL import -c "$TMPDIR/$dst_pool.cache" $dst_pool

	log_must rm "$TMPDIR/$src_pool.cache"
	log_must rm "$TMPDIR/$dst_pool.cache"

	log_must $ZPOOL set cachefile="$TMPDIR/zpool_$src_pool.cache" $src_pool
	log_must $ZPOOL set cachefile="$TMPDIR/zpool_$dst_pool.cache" $dst_pool
	cache=$($ZPOOL get -H -o value cachefile $src_pool)
	if [ $cache != "$TMPDIR/zpool_$src_pool.cache" ]; then
		log_fail "cachefile not set for $src_pool [$cache => $TMPDIR/zpool_$src_pool.cache]"
		return 1
	fi
	cache=$($ZPOOL get -H -o value cachefile $dst_pool)
	if [ $cache != "$TMPDIR/zpool_$dst_pool.cache" ]; then
		log_fail "cachefile not set for $dst_pool [$cache => $TMPDIR/zpool_$dst_pool.cache]"
		return 1
	fi

	# check pool status
	log_must check_state $src_pool "online"
	log_must check_state $dst_pool "online"

	# check history
	log_must check_history $src_pool "import -c $TMPDIR/$src_pool.cache $src_pool"
	log_must check_history $src_pool "export $src_pool"
	log_must check_history $src_pool "set cachefile=$TMPDIR/$src_pool.cache $src_pool"
	log_must check_history $dst_pool "import -c $TMPDIR/$dst_pool.cache $dst_pool"
	log_must check_history $dst_pool "export $dst_pool"
	log_must check_history $dst_pool "set cachefile=$TMPDIR/$dst_pool.cache $dst_pool"

	log_must $ZPOOL iostat -v $src_pool 1 5 > /dev/null
	log_must $ZPOOL iostat -v $dst_pool 1 5 > /dev/null

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
import_pool()
{
	pool=$1

	if [ -z $pool ]; then
		echo "No pool name given."
		return 1
	fi

	if poolexists "$pool" ; then
		echo "Pool already imported. ($pool)"
		return 1
	else
		log_must $ZPOOL import $pool -d $TMPDIR
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
	local src_pool dst_pool src_vol dst_vol
	local src_pool_disk dst_pool_disk
	local src_pool_spare_disk dst_pool_spare_disk

	if [ $# -ne 2 ]; then
		echo "missing src and dst pool"
		exit 1
	fi

	src_pool=`echo $1| awk -F '/' '{print $1}'`
	dst_pool=`echo $2| awk -F '/' '{print $1}'`

	src_vol=`echo $1| awk -F '/' '{print $2}'`
	dst_vol=`echo $2| awk -F '/' '{print $2}'`

	src_pool_disk="$TMPDIR/test_stripe_s.img"
	dst_pool_disk="$TMPDIR/test_stripe_d.img"
	src_pool_spare_disk="$TMPDIR/test_stripe_spare_s.img"
	dst_pool_spare_disk="$TMPDIR/test_stripe_spare_d.img"

	# test pool creation
	create_disk $src_pool_disk
	create_disk $dst_pool_disk

	log_must $ZPOOL create -f $src_pool -o cachefile="$TMPDIR/zpool_$src_pool.cache" \
	    $src_pool_disk
	log_must $ZPOOL create -f $dst_pool -o cachefile="$TMPDIR/zpool_$dst_pool.cache" \
	    $dst_pool_disk

	# test pool expansion
	create_disk $src_pool_spare_disk
	create_disk $dst_pool_spare_disk

	log_must $ZPOOL add -f $src_pool $src_pool_spare_disk
	log_must $ZPOOL add -f $dst_pool $dst_pool_spare_disk

	# test vdev remove
	log_must_not $ZPOOL remove $src_pool $src_pool_spare_disk
	log_must_not $ZPOOL remove $dst_pool $dst_pool_spare_disk

	# read cachefile
	log_must $ZDB -C -U "$TMPDIR/zpool_$src_pool.cache" $src_pool > /dev/null
	log_must $ZDB -C -U "$TMPDIR/zpool_$dst_pool.cache" $dst_pool > /dev/null

	# read disk labels
	log_must $ZDB -l $src_pool_disk > /dev/null
	log_must $ZDB -l $dst_pool_disk > /dev/null

	# run test cases
	log_must run_zvol_tests $src_pool/$src_vol $dst_pool/$dst_vol
	log_must run_pool_tests $src_pool/$src_vol $dst_pool/$dst_vol

	# test pool destroy
	log_must destroy_pool $src_pool
	log_must destroy_pool $dst_pool

	destroy_disk $src_pool_disk
	destroy_disk $dst_pool_disk
	destroy_disk $src_pool_spare_disk
	destroy_disk $dst_pool_spare_disk

	return 0
}

test_mirror_pool()
{
	local src_pool dst_pool src_vol dst_vol
	local src_pool_disk_a src_pool_disk_b
	local dst_pool_disk_a dst_pool_disk_b
	local src_pool_spare_disk_a src_pool_spare_disk_b
	local dst_pool_spare_disk_a dst_pool_spare_disk_b

	if [ $# -ne 2 ]; then
		echo "missing src and dst pool"
		exit 1
	fi

	src_pool=`echo $1| awk -F '/' '{print $1}'`
	dst_pool=`echo $2| awk -F '/' '{print $1}'`

	src_vol=`echo $1| awk -F '/' '{print $2}'`
	dst_vol=`echo $2| awk -F '/' '{print $2}'`

	src_pool_disk_a="$TMPDIR/test_mirror_s_a.img"
	src_pool_disk_b="$TMPDIR/test_mirror_s_b.img"
	dst_pool_disk_a="$TMPDIR/test_mirror_d_a.img"
	dst_pool_disk_b="$TMPDIR/test_mirror_d_b.img"
	src_pool_spare_disk_a="$TMPDIR/test_mirror_spare_s_a.img"
	src_pool_spare_disk_b="$TMPDIR/test_mirror_spare_s_b.img"
	dst_pool_spare_disk_a="$TMPDIR/test_mirror_spare_d_a.img"
	dst_pool_spare_disk_b="$TMPDIR/test_mirror_spare_d_b.img"

	# test pool creation
	create_disk $src_pool_disk_a $src_pool_disk_b
	create_disk $dst_pool_disk_a $dst_pool_disk_b
	# test pool creation
	log_must $ZPOOL create -f $src_pool mirror \
	    -o cachefile="$TMPDIR/zpool_$src_pool.cache" \
	    $src_pool_disk_a $src_pool_disk_b

	log_must $ZPOOL create -f $dst_pool mirror \
	    -o cachefile="$TMPDIR/zpool_$dst_pool.cache" \
	    $dst_pool_disk_a $dst_pool_disk_b

	# test pool expansion
	create_disk $src_pool_spare_disk_a $src_pool_spare_disk_b
	create_disk $dst_pool_spare_disk_a $dst_pool_spare_disk_b

	log_must $ZPOOL add -f $src_pool $src_pool_spare_disk_a $src_pool_spare_disk_b
	log_must $ZPOOL add -f $dst_pool $dst_pool_spare_disk_a $dst_pool_spare_disk_b

	# test vdev remove
	log_must_not $ZPOOL remove $src_pool $src_pool_spare_disk_a
	log_must_not $ZPOOL remove $dst_pool $dst_pool_spare_disk_b

	# read cachefile
	log_must $ZDB -C -U "$TMPDIR/zpool_$src_pool.cache" $src_pool > /dev/null
	log_must $ZDB -C -U "$TMPDIR/zpool_$dst_pool.cache" $dst_pool > /dev/null

	# read disk labels
	log_must $ZDB -l $src_pool_disk_a > /dev/null
	log_must $ZDB -l $src_pool_disk_b > /dev/null
	log_must $ZDB -l $dst_pool_disk_a > /dev/null
	log_must $ZDB -l $dst_pool_disk_b > /dev/null

	# run test cases
	log_must run_zvol_tests $src_pool/$src_vol $dst_pool/$dst_vol
	log_must run_pool_tests $src_pool/$src_vol $dst_pool/$dst_vol

	# test pool destroy
	log_must destroy_pool $src_pool
	log_must destroy_pool $dst_pool

	destroy_disk $src_pool_disk_a $src_pool_disk_b
	destroy_disk $dst_pool_disk_a $dst_pool_disk_b
	destroy_disk $src_pool_spare_disk_a $src_pool_spare_disk_b
	destroy_disk $dst_pool_spare_disk_a $dst_pool_spare_disk_b

	return 0
}

test_raidz_pool()
{
        local src_pool dst_pool src_vol dst_vol
        local src_pool_disk dst_pool_disk
        local src_pool_spare_disk dst_pool_spare_disk

        if [ $# -ne 2 ]; then
                echo "missing src and dst pool"
                exit 1
        fi

        src_pool=`echo $1| awk -F '/' '{print $1}'`
        dst_pool=`echo $2| awk -F '/' '{print $1}'`

        src_vol=`echo $1| awk -F '/' '{print $2}'`
        dst_vol=`echo $2| awk -F '/' '{print $2}'`

	for (( i = 1; i <= 4; i++ )) do
		src_pool_disk[$i]="$TMPDIR/test_raidz_s_$i.img"
		dst_pool_disk[$i]="$TMPDIR/test_raidz_d_$i.img"
		src_pool_spare_disk[$i]="$TMPDIR/test_raidz_spare_s_$i.img"
		dst_pool_spare_disk[$i]="$TMPDIR/test_raidz_spare_d_$i.img"
		create_disk ${src_pool_disk[$i]} ${dst_pool_disk[$i]} \
			${src_pool_spare_disk[$i]} ${dst_pool_spare_disk[$i]}
	done

	# test pool creation
	log_must $ZPOOL create -f $src_pool raidz1 \
	    -o cachefile="$TMPDIR/zpool_$src_pool.cache" \
	    ${src_pool_disk[1]} ${src_pool_disk[2]} ${src_pool_disk[3]} ${src_pool_disk[4]}

	log_must $ZPOOL create -f $dst_pool raidz1 \
	    -o cachefile="$TMPDIR/zpool_$dst_pool.cache" \
	    ${dst_pool_disk[1]} ${dst_pool_disk[2]} ${dst_pool_disk[3]} ${dst_pool_disk[4]}

	# test pool expansion
	log_must $ZPOOL add -f $src_pool \
	    ${src_pool_spare_disk[1]} ${src_pool_spare_disk[2]} \
	    ${src_pool_spare_disk[3]} ${src_pool_spare_disk[4]}
	log_must $ZPOOL add -f $dst_pool \
	    ${dst_pool_spare_disk[1]} ${dst_pool_spare_disk[2]} \
	    ${dst_pool_spare_disk[3]} ${dst_pool_spare_disk[4]}

	# test vdev remove
	log_must_not $ZPOOL remove $src_pool ${src_pool_spare_disk[2]}
	log_must_not $ZPOOL remove $dst_pool ${dst_pool_spare_disk[3]}

	# read cachefile
	log_must $ZDB -C -U "$TMPDIR/zpool_$src_pool.cache" $src_pool > /dev/null
	log_must $ZDB -C -U "$TMPDIR/zpool_$dst_pool.cache" $dst_pool > /dev/null

	# read disk labels
	for (( i = 1; i <= 4; i++ )) do
		log_must $ZDB -l ${src_pool_disk[$i]} > /dev/null
		log_must $ZDB -l ${dst_pool_disk[$i]} > /dev/null
	done

	# run test cases
	log_must run_zvol_tests $src_pool/$src_vol $dst_pool/$dst_vol
	log_must run_pool_tests $src_pool/$src_vol $dst_pool/$dst_vol

	# test pool destroy
	log_must destroy_pool $src_pool
	log_must destroy_pool $dst_pool

	for (( i = 1; i <= 4; i++ )) do
		destroy_disk ${src_pool_disk[$i]} ${dst_pool_disk[$i]} \
			${src_pool_spare_disk[$i]} ${dst_pool_spare_disk[$i]}
	done

	return 0
}

run_fio_test()
{
	local fio_pool="fio_pool"

	stop_zrepl
	while [ 1 ]; do
		netstat -apnt |grep 6060
		if [ $? -ne 0 ]; then
			break
		else
			sleep 5
		fi
	done
	start_zrepl

	[ -z "$FIO_SRCDIR" ] && log_fail "FIO_SRCDIR must be defined"

	create_disk "$TMPDIR/fio_disk1.img"

	log_must $ZPOOL create -f $fio_pool \
	    -o cachefile="$TMPDIR/zpool_$fio_pool.cache" \
	    "$TMPDIR/fio_disk1.img"
	log_must $ZFS create -sV $VOLSIZE -o volblocksize=4k -o io.openebs:targetip=127.0.0.1:6060 $fio_pool/vol1
	log_must $ZFS create -sV $VOLSIZE -o volblocksize=4k -o io.openebs:targetip=127.0.0.1:6060 $fio_pool/vol2
	cat >$TMPDIR/test.fio <<EOF
[global]
ioengine=replica.so
thread=1
group_reporting=1
direct=1
verify=md5
ramp_time=0
iodepth=128
rw=randrw
bs=4k
filesize=100m
fallocate=none
time_based=1
runtime=15
numjobs=1
[vol1]
filename=$fio_pool/vol1
[vol2]
filename=$fio_pool/vol2
EOF

	# run the fio
	echo "Running $FIO_SRCDIR/fio with lib path $SRC_PATH/lib/fio/.libs"
	echo " and following configuration:"
	cat $TMPDIR/test.fio
	echo
	LD_LIBRARY_PATH=$SRC_PATH/lib/fio/.libs $FIO_SRCDIR/fio $TMPDIR/test.fio
	[ $? -eq 0 ] || log_fail "Fio test run failed"

	# test pool destroy
	# XXX Bug: we must destroy volumes before pool. If not then EBUSY
	log_must $ZFS destroy -r $fio_pool/vol1
	log_must $ZFS destroy -r $fio_pool/vol2
	log_must destroy_pool $fio_pool
	log_must rm $TMPDIR/test.fio
	destroy_disk "$TMPDIR/fio_disk1.img"

	return 0
}

#setup_uzfs_test log/nolog block_size vol_size sync pool_name \
#		volume_name vdev_file log_file
setup_uzfs_test()
{
	local block_size=$2
	local vol_size=$3
	local sync_prop=$4
	local pool_name=$5
	local volume_name=$6
	local vdev_file=$7
	local log_file

	if [ $ZREPL_PID -eq -1 ]; then
		echo "zrepl is not started..."
		$ZREPL &
		sleep 10
		ZREPL_PID=$!
	fi

	export_pool $pool_name

	if [ "$1" == "log" ]; then
		if [ $# -ne 8 ]; then
			echo "log file missing"
			return 1
		fi

		log_file=$8
		create_disk $TMPDIR/$vdev_file
		create_disk $TMPDIR/$log_file
		log_must $ZPOOL create -f $pool_name "$TMPDIR/$vdev_file" \
		    log "$TMPDIR/$log_file"
	else
		create_disk $TMPDIR/$vdev_file
		log_must $ZPOOL create -f $pool_name "$TMPDIR/$vdev_file"
	fi

	log_must $ZFS create -V $vol_size $pool_name/$volume_name -b $block_size
	log_must $ZFS set sync=$sync_prop $pool_name/$volume_name

	return 0
}

#cleanup_uzfs_test pool_name vdev_file log_file
cleanup_uzfs_test()
{
	local pool_name vdev_file log_file

	if [ $# -lt 2 ]; then
		echo "missing pool name and disk name"
		exit 1
	fi

	pool_name=$1
	vdev_file=$2

	if poolnotexists $pool_name ; then
		log_must $ZPOOL import $pool_name -d $TMPDIR
	fi

	log_must $ZPOOL destroy $pool_name 2> /dev/null
	log_must $ZPOOL labelclear -f $TMPDIR/$vdev_file 2> /dev/null
	log_must dd if=/dev/zero of=$TMPDIR/$vdev_file bs=1M count=100

	destroy_disk $TMPDIR/$vdev_file
	if [ $# -eq 3 ]; then
		log_file=$3
		log_must $ZPOOL labelclear -f $TMPDIR/$log_file 2> /dev/null
		log_must dd if=/dev/zero of=$TMPDIR/$log_file bs=1M count=100
		destroy_disk $TMPDIR/$log_file
	fi
}

run_zrepl_uzfs_test()
{
	export_pool $UZFS_TEST_POOL

	if [ "$1" == "log" ]; then
		log_must setup_uzfs_test log $2 $UZFS_TEST_VOLSIZE $3 $UZFS_TEST_POOL \
		    $UZFS_TEST_VOL uzfs_zrepl_vdev1 uzfs_zrepl_log1
	else
		log_must setup_uzfs_test nolog $2 $UZFS_TEST_VOLSIZE $3 $UZFS_TEST_POOL $UZFS_TEST_VOL uzfs_zrepl_vdev1
	fi

	log_must $ZFS set io.openebs:targetip=127.0.0.1:6060 $UZFS_TEST_POOL/$UZFS_TEST_VOL
	log_must export_pool $UZFS_TEST_POOL
	log_must import_pool $UZFS_TEST_POOL

	log_must $UZFS_TEST -T 4
	sleep 5

	if [ "$1" == "log" ]; then
		cleanup_uzfs_test $UZFS_TEST_POOL uzfs_zrepl_vdev1 uzfs_zrepl_log1
	else
		cleanup_uzfs_test $UZFS_TEST_POOL uzfs_zrepl_vdev1
	fi

	return 0
}

run_zrepl_rebuild_uzfs_test()
{
	export_pool $UZFS_TEST_POOL

	if [ "$1" == "log" ]; then
		log_must setup_uzfs_test log $2 $UZFS_TEST_VOLSIZE $3 $UZFS_TEST_POOL \
		    $UZFS_TEST_VOL uzfs_zrepl_rebuild_vdev1 uzfs_zrepl_rebuild_log1
	else
		log_must setup_uzfs_test nolog $2 $UZFS_TEST_VOLSIZE $3 $UZFS_TEST_POOL \
		    $UZFS_TEST_VOL uzfs_zrepl_rebuild_vdev1
	fi

	log_must $ZFS set io.openebs:targetip=127.0.0.1:6060 $UZFS_TEST_POOL/$UZFS_TEST_VOL

	log_must $ZFS create -V $UZFS_TEST_VOLSIZE \
	    -o io.openebs:targetip=127.0.0.1:99159 $UZFS_TEST_POOL/$UZFS_REBUILD_VOL -b $2
	log_must $ZFS set sync=$3 $UZFS_TEST_POOL/$UZFS_REBUILD_VOL
	
	log_must $ZFS create -V $UZFS_TEST_VOLSIZE \
	    -o io.openebs:targetip=127.0.0.1:99160 $UZFS_TEST_POOL/$UZFS_REBUILD_VOL1 -b $2
	log_must $ZFS set sync=$3 $UZFS_TEST_POOL/$UZFS_REBUILD_VOL1

	log_must $ZFS create -V $UZFS_TEST_VOLSIZE \
	    -o io.openebs:targetip=127.0.0.1:99161 $UZFS_TEST_POOL/$UZFS_REBUILD_VOL2 -b $2
	log_must $ZFS set sync=$3 $UZFS_TEST_POOL/$UZFS_REBUILD_VOL2

	log_must export_pool $UZFS_TEST_POOL
	log_must import_pool $UZFS_TEST_POOL

	log_must $UZFS_TEST -T 7
	sleep 20

	if [ "$1" == "log" ]; then
		cleanup_uzfs_test $UZFS_TEST_POOL uzfs_zrepl_rebuild_vdev1 uzfs_zrepl_rebuild_log1
	else
		cleanup_uzfs_test $UZFS_TEST_POOL uzfs_zrepl_rebuild_vdev1
	fi

	return 0
}

greater()
{
	if [ $1 -le $2 ]; then
		return 0
	fi
	return 1
}

run_uzfs_test()
{
	log_must_not $UZFS_TEST
	local pid1 pid2 pid3 pid4 pid5
	local sync_pid

	log_must run_sync_test &
	sync_pid=$!

	log_must setup_uzfs_test nolog 4096 $UZFS_TEST_VOLSIZE disabled uzfs_pool1 uzfs_vol1 uzfs_test_vdev1
	log_must export_pool uzfs_pool1
	log_must $UZFS_TEST -t 30 -v $UZFS_TEST_VOLSIZE_IN_NUM -a $UZFS_TEST_VOLSIZE_IN_NUM -p uzfs_pool1 -d uzfs_vol1 -T 6 &
	pid1=$!

	log_must setup_uzfs_test nolog 4096 $UZFS_TEST_VOLSIZE disabled uzfs_pool2 uzfs_vol2 uzfs_test_vdev2
	log_must export_pool uzfs_pool2
	log_must $UZFS_TEST -t 30 -v $UZFS_TEST_VOLSIZE_IN_NUM -a $UZFS_TEST_VOLSIZE_IN_NUM -l -p uzfs_pool2 -d uzfs_vol2  -T 6 &
	pid2=$!

	log_must setup_uzfs_test nolog 4096 $UZFS_TEST_VOLSIZE disabled uzfs_pool3 uzfs_vol3 uzfs_test_vdev3
	log_must export_pool uzfs_pool3
	log_must $UZFS_TEST -t 30 -v $UZFS_TEST_VOLSIZE_IN_NUM -a $UZFS_TEST_VOLSIZE_IN_NUM \
	    -i 8192 -b 65536 -p uzfs_pool3 -d uzfs_vol3 -T 6 &
	pid3=$!
	log_must setup_uzfs_test nolog 4096 $UZFS_TEST_VOLSIZE disabled uzfs_pool4 uzfs_vol4 uzfs_test_vdev4
	log_must export_pool uzfs_pool4
	log_must $UZFS_TEST -t 30 -v $UZFS_TEST_VOLSIZE_IN_NUM -a $UZFS_TEST_VOLSIZE_IN_NUM \
	    -p uzfs_pool4 -d uzfs_vol4 -l -i 8192 -b 65536 -T 6 &
	pid4=$!

	wait_for_pids $pid1 $pid2 $pid3 $pid4
	cleanup_uzfs_test uzfs_pool1 uzfs_test_vdev1
	cleanup_uzfs_test uzfs_pool2 uzfs_test_vdev2
	cleanup_uzfs_test uzfs_pool3 uzfs_test_vdev3
	cleanup_uzfs_test uzfs_pool4 uzfs_test_vdev4

	log_must setup_uzfs_test nolog 4096 $UZFS_TEST_VOLSIZE disabled uzfs_pool5 uzfs_vol5 uzfs_test_vdev5
	log_must export_pool uzfs_pool5
	$UZFS_TEST -v $UZFS_TEST_VOLSIZE_IN_NUM -p uzfs_pool5 -d uzfs_vol5\
	    -a $UZFS_TEST_VOLSIZE_IN_NUM -T 2 > $TMPDIR/uzfs_test1.out &
	pid1=$!

	log_must setup_uzfs_test nolog 4096 $UZFS_TEST_VOLSIZE always uzfs_pool6 uzfs_vol6 uzfs_test_vdev6
	log_must export_pool uzfs_pool6
	$UZFS_TEST -v $UZFS_TEST_VOLSIZE_IN_NUM -p uzfs_pool6 -d uzfs_vol6 \
	    -a $UZFS_TEST_VOLSIZE_IN_NUM -s -T 2 > $TMPDIR/uzfs_test2.out &
	pid2=$!

	log_must setup_uzfs_test nolog 4096 $UZFS_TEST_VOLSIZE standard uzfs_pool06 uzfs_vol06 uzfs_test_vdev06
	log_must export_pool uzfs_pool06
	log_must $UZFS_TEST -t 30 -v $UZFS_TEST_VOLSIZE_IN_NUM -a $UZFS_TEST_VOLSIZE_IN_NUM \
	     -p uzfs_pool06 -d uzfs_vol06 -T 2 &
	pid3=$!

	wait_for_pids $pid1 $pid2 $pid3
        [[ $? -ne 0 ]] && { echo "test failed.."; cat $TMPDIR/uzfs_test*.out; return 1; }

	ios1=$(cat /tmp/uzfs_test1.out  | grep "Total write IOs" | awk '{print $4}')
	ios2=$(cat /tmp/uzfs_test2.out  | grep "Total write IOs" | awk '{print $4}')
	log_must_not greater $ios1 $ios2

	cleanup_uzfs_test uzfs_pool5 uzfs_test_vdev5
	cleanup_uzfs_test uzfs_pool6 uzfs_test_vdev6
	cleanup_uzfs_test uzfs_pool06 uzfs_test_vdev06

	log_must setup_uzfs_test log 4096 $UZFS_TEST_VOLSIZE disabled uzfs_pool7 uzfs_vol7 uzfs_test_vdev7 uzfs_test_log7
	log_must export_pool uzfs_pool7
	$UZFS_TEST -v $UZFS_TEST_VOLSIZE_IN_NUM -a $UZFS_TEST_VOLSIZE_IN_NUM \
	    -p uzfs_pool7 -d uzfs_vol7 -l -T 2 > $TMPDIR/uzfs_test1.out &
	pid1=$!

	log_must setup_uzfs_test log 4096 $UZFS_TEST_VOLSIZE always uzfs_pool8 uzfs_vol8 uzfs_test_vdev8 uzfs_test_log8
	log_must export_pool uzfs_pool8
	$UZFS_TEST -v $UZFS_TEST_VOLSIZE_IN_NUM -a $UZFS_TEST_VOLSIZE_IN_NUM \
	    -p uzfs_pool8 -d uzfs_vol8 -s -l -T 2 > $TMPDIR/uzfs_test2.out &
	pid2=$!

	log_must setup_uzfs_test log 4096 $UZFS_TEST_VOLSIZE standard uzfs_pool9 uzfs_vol9 uzfs_test_vdev9 uzfs_test_log9
	log_must export_pool uzfs_pool9
	log_must $UZFS_TEST -t 30 -v $UZFS_TEST_VOLSIZE_IN_NUM -a $UZFS_TEST_VOLSIZE_IN_NUM \
	    -p uzfs_pool9 -d uzfs_vol9 -l -T 2 &
	pid3=$!

	wait_for_pids $pid1 $pid2 $pid3
        [[ $? -ne 0 ]] && { echo "test failed.."; cat $TMPDIR/uzfs_test*.out; return 1; }

	ios1=$(cat /tmp/uzfs_test1.out  | grep "Total write IOs" | awk '{print $4}')
	ios2=$(cat /tmp/uzfs_test2.out  | grep "Total write IOs" | awk '{print $4}')

	log_must_not greater $ios1 $ios2

	cleanup_uzfs_test uzfs_pool7 uzfs_test_vdev7 uzfs_test_log7
	cleanup_uzfs_test uzfs_pool8 uzfs_test_vdev8 uzfs_test_log8
	cleanup_uzfs_test uzfs_pool9 uzfs_test_vdev9 uzfs_test_log9

	log_must setup_uzfs_test nolog 65536 $UZFS_TEST_VOLSIZE disabled uzfs_pool10 uzfs_vol10 uzfs_test_vdev10
	log_must export_pool uzfs_pool10
	$UZFS_TEST -v $UZFS_TEST_VOLSIZE_IN_NUM -a $UZFS_TEST_VOLSIZE_IN_NUM \
	    -p uzfs_pool10 -d uzfs_vol10 -i 8192 -b 65536 -T 2 > $TMPDIR/uzfs_test1.out &
	pid1=$!

	log_must setup_uzfs_test nolog 65536 $UZFS_TEST_VOLSIZE always uzfs_pool11 uzfs_vol11 uzfs_test_vdev11
	log_must export_pool uzfs_pool11
	$UZFS_TEST -v $UZFS_TEST_VOLSIZE_IN_NUM -a $UZFS_TEST_VOLSIZE_IN_NUM \
	    -p uzfs_pool11 -d uzfs_vol11 -s -i 8192 -b 65536 -T 2 > $TMPDIR/uzfs_test2.out &
	pid2=$!

	log_must setup_uzfs_test nolog 65536 $UZFS_TEST_VOLSIZE standard uzfs_pool12 uzfs_vol12 uzfs_test_vdev12
	log_must export_pool uzfs_pool12
	log_must $UZFS_TEST -t 30 -v $UZFS_TEST_VOLSIZE_IN_NUM -a $UZFS_TEST_VOLSIZE_IN_NUM \
	    -p uzfs_pool12 -d uzfs_vol12 -i 8192 -b 65536 -T 2 &
	pid3=$!

	wait_for_pids $pid1 $pid2 $pid3
        [[ $? -ne 0 ]] && { echo "test failed.."; cat $TMPDIR/uzfs_test*.out; return 1; }

	ios1=$(cat /tmp/uzfs_test1.out  | grep "Total write IOs" | awk '{print $4}')
	ios2=$(cat /tmp/uzfs_test2.out  | grep "Total write IOs" | awk '{print $4}')

	log_must_not greater $ios1 $ios2
	cleanup_uzfs_test uzfs_pool10 uzfs_test_vdev10
	cleanup_uzfs_test uzfs_pool11 uzfs_test_vdev11
	cleanup_uzfs_test uzfs_pool12 uzfs_test_vdev12

	log_must setup_uzfs_test log 65536 $UZFS_TEST_VOLSIZE disabled uzfs_pool13 uzfs_vol13 uzfs_test_vdev13 uzfs_test_log13
	log_must export_pool uzfs_pool13
	$UZFS_TEST -v $UZFS_TEST_VOLSIZE_IN_NUM -a $UZFS_TEST_VOLSIZE_IN_NUM \
	    -p uzfs_pool13 -d uzfs_vol13 -l -i 8192 -b 65536 -T 2 > $TMPDIR/uzfs_test1.out &
	pid1=$!

	log_must setup_uzfs_test log 65536 $UZFS_TEST_VOLSIZE always uzfs_pool14 uzfs_vol14 uzfs_test_vdev14 uzfs_test_log14
	log_must export_pool uzfs_pool14
	$UZFS_TEST -v $UZFS_TEST_VOLSIZE_IN_NUM -a $UZFS_TEST_VOLSIZE_IN_NUM \
	    -p uzfs_pool14 -d uzfs_vol14 -s -l -i 8192 -b 65536 -T 2 > $TMPDIR/uzfs_test2.out &
	pid2=$!

	log_must setup_uzfs_test nolog 4096 $UZFS_TEST_VOLSIZE standard uzfs_pool16 uzfs_vol16 uzfs_test_vdev16
	log_must export_pool uzfs_pool16
	log_must $UZFS_TEST -t 10 -T 0 -n 10 -p uzfs_pool16 -d uzfs_vol16 &
	pid3=$!

	wait_for_pids $pid1 $pid2 $pid3
        [[ $? -ne 0 ]] && { echo "test failed.."; cat $TMPDIR/uzfs_test*.out; return 1; }

	ios1=$(cat /tmp/uzfs_test1.out  | grep "Total write IOs" | awk '{print $4}')
	ios2=$(cat /tmp/uzfs_test2.out  | grep "Total write IOs" | awk '{print $4}')
	log_must_not greater $ios1 $ios2

	cleanup_uzfs_test uzfs_pool13 uzfs_test_vdev13 uzfs_test_log13
	cleanup_uzfs_test uzfs_pool14 uzfs_test_vdev14 uzfs_test_log14
	cleanup_uzfs_test uzfs_pool16 uzfs_test_vdev16

	log_must setup_uzfs_test log 65536 $UZFS_TEST_VOLSIZE standard uzfs_pool15 uzfs_vol15 uzfs_test_vdev15 uzfs_test_log15
	log_must export_pool uzfs_pool15
	log_must $UZFS_TEST -t 30 -v $UZFS_TEST_VOLSIZE_IN_NUM -a $UZFS_TEST_VOLSIZE_IN_NUM \
	    -p uzfs_pool15 -d uzfs_vol15 -l -i 8192 -b 65536 -T 2 &
	pid1=$!

	wait_for_pids $pid1 $sync_pid
	cleanup_uzfs_test uzfs_pool15 uzfs_test_vdev15 uzfs_test_log15

	return 0
}

run_dmu_test()
{
	log_must truncate -s 100MB /tmp/disk;
	log_must sudo mknod /dev/fake-dev b 7 200;
	log_must sudo chmod 666 /dev/fake-dev;
	log_must sudo losetup /dev/fake-dev /tmp/disk;
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
	- fio_test
	- zrepl_test
	- zrepl_rebuild_test
	- all (run all test)
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
	local stripe_pid mirror_pid raidz_pid

	log_must test_stripe_pool pool_test_ss_pool/ss_vol pool_test_ds_pool/ds_vol &
	stripe_pid=$!

	log_must test_mirror_pool pool_test_sm_pool/sm_vol pool_test_dm_pool/dm_vol &
	mirror_pid=$!

	log_must test_raidz_pool pool_test_sr_pool/sr_vol pool_test_dr_pool/dr_vol &
	raidz_pid=$!

	wait_for_pids $stripe_pid $mirror_pid $raidz_pid
}

run_zrepl_test()
{
	log_must run_zrepl_uzfs_test log 4096 disabled
	#log_must run_zrepl_uzfs_test log 4096 always
	#log_must run_zrepl_uzfs_test log 4096 standard
}

run_zvol_test()
{
	log_must nice -n -20 $ZTEST -VVVVV

	run_uzfs_test
	run_dmu_test

	stop_zrepl
	log_must $GTEST_UZFS
	log_must $GTEST_ZFS
	log_must $GTEST_ZREPL_PROT
	start_zrepl
}

run_rebuild_test()
{
	local pid1 pid2

	log_must setup_uzfs_test nolog 4096 $VOLSIZE standard uzfs_rebuild_pool2 uzfs_vol1 uzfs_rebuild_vdev2
	log_must export_pool uzfs_rebuild_pool2
	log_must $UZFS_TEST -T 0 -t 10 -n 10 -p uzfs_rebuild_pool2 -d uzfs_vol1 -a 419430400 &
	pid1=$!

	log_must setup_uzfs_test nolog 4096 $VOLSIZE standard uzfs_rebuild_pool3 uzfs_vol1 uzfs_rebuild_vdev3
	log_must setup_uzfs_test nolog 4096 $VOLSIZE standard uzfs_rebuild_pool4 uzfs_vol1 uzfs_rebuild_vdev4
	log_must export_pool uzfs_rebuild_pool3
	log_must export_pool uzfs_rebuild_pool4

	log_must $UZFS_TEST -T 3 -t 60 -n 2 -p uzfs_rebuild_pool3,uzfs_rebuild_pool4 -d uzfs_vol1 -a 629145600 &
	pid2=$!

	wait_for_pids $pid1 $pid2

	cleanup_uzfs_test uzfs_rebuild_pool2 uzfs_rebuild_vdev2
	cleanup_uzfs_test uzfs_rebuild_pool3 uzfs_rebuild_vdev3
	cleanup_uzfs_test uzfs_rebuild_pool4 uzfs_rebuild_vdev4
}

execute_test() {
	local START END DIFF

	test_func="run_$1"
	type -t $test_func > /dev/null
	if [ $? -eq 0 ]; then
		START=$(date +%s.%N)
		$test_func
		END=$(date +%s.%N)
		DIFF=$(echo "scale=0;$END - $START" | bc | awk '{printf "%.1f\n", $0}')
		echo -e "\n####################################"
		echo "All cases passed for $1 in ${DIFF%.*} seconds.. (start:`date -u -d @${START%.*} +%H:%M:%S` end:`date -u -d @${END%.*} +%H:%M:%S`)"
		echo "####################################"
	else
		usage
		exit 1
	fi
}

run_zrepl_rebuild_test()
{
	log_must run_zrepl_rebuild_uzfs_test log 4096 disabled
}

echo "ulimit -c unlimited" >> ~/.bash_rc
sysctl -p

start_zrepl
if [ $test_type == "all" ]; then
	START=$(date +%s.%N)
	execute_test "pool_test"
	execute_test "zvol_test"
	execute_test "rebuild_test"
	execute_test "zrepl_test"
	execute_test "zrepl_rebuild_test"
	execute_test "fio_test"
	END=$(date +%s.%N)
	DIFF=$(echo "scale=0;$END - $START" | bc | awk '{printf "%.1f\n", $0}')
	echo -e "\n####################################"
	echo "All cases passed in ${DIFF%.*} seconds.. (start:`date -u -d @${START%.*} +%H:%M:%S` end:`date -u -d @${END%.*} +%H:%M:%S`)"
	echo "####################################"
else
	execute_test $test_type
fi
stop_zrepl

ls -ltr

