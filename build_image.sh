#!/bin/bash
set -e

pwd

# Build libcstor
cd ../libcstor
make clean
sh autogen.sh
./configure --with-zfs-headers=$PWD/../cstor/include --with-spl-headers=$PWD/../cstor/lib/libspl/include
make -j4
sudo make install
sudo ldconfig

# Build cstor
cd ../cstor
make clean
sh autogen.sh
./configure --enable-uzfs=yes --with-config=user --with-jemalloc --with-libcstor=$PWD/../libcstor/include
make clean
make

BUILD_DATE=$(date +'%Y%m%d%H%M%S')
REPO_NAME="openebs/cstor-base"

mkdir -p ./docker/zfs/bin
mkdir -p ./docker/zfs/lib

cp cmd/zrepl/.libs/zrepl ./docker/zfs/bin
cp cmd/zpool/.libs/zpool ./docker/zfs/bin
cp cmd/zfs/.libs/zfs ./docker/zfs/bin
cp cmd/zstreamdump/.libs/zstreamdump ./docker/zfs/bin

cp lib/libzpool/.libs/*.so* ./docker/zfs/lib
cp lib/libuutil/.libs/*.so* ./docker/zfs/lib
cp lib/libnvpair/.libs/*.so* ./docker/zfs/lib
cp lib/libzfs/.libs/*.so* ./docker/zfs/lib
cp lib/libzfs_core/.libs/*.so* ./docker/zfs/lib
cp ../libcstor/src/.libs/*.so* ./docker/zfs/lib

sudo docker version
sudo docker build --help

echo "Build image ${REPO_NAME}:ci with BUILD_DATE=${BUILD_DATE}"
cd docker && \
 sudo docker build -f Dockerfile.base -t ${REPO_NAME}:ci --build-arg BUILD_DATE=${BUILD_DATE} . && \
 IMAGE_REPO=${REPO_NAME} ./push && \
 cd ..

REPO_NAME="openebs/cstor-pool"
echo "Build image ${REPO_NAME}:ci with BUILD_DATE=${BUILD_DATE}"
cd docker && \
 sudo docker build -f Dockerfile -t ${REPO_NAME}:ci --build-arg BUILD_DATE=${BUILD_DATE} . && \
 IMAGE_REPO=${REPO_NAME} ./push && \
 cd ..

rm -rf ./docker/zfs
