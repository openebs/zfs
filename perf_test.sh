#!/bin/bash

check_zrepl()
{
	for (( cnt = 0; cnt < 5; cnt++ )) do
		./cmd/zfs/zfs list
		if [ $? -eq 0 ]; then
			break
		fi
		sleep 2
	done
	if [ $cnt -eq 5 ]; then
		echo "zrepl is not up yet"
		exit
	fi
}

create_pool()
{
	rm /tmp/test1.img
	truncate -s 50G /tmp/test1.img

	./cmd/zrepl/zrepl &
	zrepl_pid=$!

	check_zrepl
	./cmd/zpool/zpool create -f tpool /tmp/test1.img
	./cmd/zfs/zfs set recordsize=4k tpool

	./cmd/zfs/zfs create -s -V 15G -o volblocksize=4k tpool/zvol1

	pkill -9 -P $zrepl_pid
	kill -9 $zrepl_pid
}

compile_zfs()
{
	bash autogen.sh
	#./configure --with-config=user --enable-uzfs=yes --with-jemalloc --disable-writes
	./configure --with-config=user --enable-uzfs=yes --with-jemalloc $*
	make clean
	make
}

compile_fio()
{
	zfs_dir_for_fio=`pwd`
	cd fio
	./configure --with-zfs=$zfs_dir_for_fio
	make
	cd ..
}

if [ $# != 2 ]; then
	echo "Usage: perf_test.sh zfs_dir outfile_ext"
	echo "zfs_dir can be absolute / relative path"
	echo "logs will be saved to current directory"
	exit
fi

zfs_dir=$1
outfile_ext=$2

logs_dir=`pwd`
pushd .

cd $zfs_dir
compile_zfs
create_pool
compile_fio

cd fio
script -a -c "bash run_test.sh $logs_dir $outfile_ext" $logs_dir/script.$outfile_ext
cd ..

popd

