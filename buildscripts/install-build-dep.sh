#!/bin/bash

# Mandatory variables
# $REPO_ORG organisation from which to clone the dependent repositories
# $BRANCH to be used for building
#
# Optional variables
# $UZFS_BUILD variable need to be set. If not kernel mode zfs will be built

if [ -z "${REPO_ORG}" ]; then
  echo "REPO_ORG variable not set. Required for fetching dependent build repositories"
  exit 1
else
  echo "Using repository organization: ${REPO_ORG}"
fi

if [ -z "${BRANCH}" ]; then
  echo "BRANCH variable not set. Required for checking out libcstor repository"
  exit 1
else
  echo "Using branch: ${BRANCH} for libcstor"
fi

if [ "$UZFS_BUILD" = 1 ]; then
  echo "Installing dependencies for uZFS features"
else
  echo "Installing dependencies for kernel mode ZFS"
fi

# zrepl will make use of /var/tmp/sock directory to create a sock file.
mkdir -p /var/tmp/sock
pushd .
cd /usr/src/gtest || exit 1
sudo cmake CMakeLists.txt
sudo make -j4
sudo cp *.a /usr/lib
popd || exit 1

# save the current location of cstor code to get back after installing dependencies
pushd .
# move to parent directory and clone dependent repositories
cd ..

# we need fio repo to build zfs replica fio engine
git clone https://github.com/axboe/fio
cd fio || exit 1
git checkout fio-3.9
./configure
make -j4

cd ..

# clone and build SPL
git clone https://github.com/${REPO_ORG}/spl
cd spl || exit 1
git checkout spl-0.7.9
sh autogen.sh
./configure

if [ "$UZFS_BUILD" = 1 ]; then
  make -j4
else
  make --no-print-directory -s pkg-utils pkg-kmod
  sudo dpkg -i *.deb
fi

cd ..

# Build libcstor for uzfs feature
git clone https://github.com/${REPO_ORG}/libcstor.git
cd libcstor || exit 1
if [ "${BRANCH}" == "develop" ]; then
  git checkout master
else
  git checkout ${BRANCH} || git checkout master
fi

sh autogen.sh;
./configure --enable-debug --with-zfs-headers=$PWD/../cstor/include --with-spl-headers=$PWD/../cstor/lib/libspl/include
make -j4;
sudo make install;
sudo ldconfig

# return to cstor code
popd || exit 1

sh autogen.sh
if [ "$UZFS_BUILD" = 1 ]; then
  ./configure --with-config=user --enable-debug --enable-uzfs=yes --with-jemalloc --with-fio=$PWD/../fio --with-libcstor=$PWD/../libcstor/include || exit 1
  make -j4
else
  ./configure  --enable-debug || exit 1
  make --no-print-directory -s pkg-utils pkg-kmod || exit 1
  sudo dpkg -i *.deb || exit 1
fi

# If build is to build uZFS feature then go to zrepl in libcstor and build zrepl binary
if [ "$UZFS_BUILD" = 1 ]; then
  pushd .
  cd ../libcstor/cmd/zrepl && make || exit 1
  popd || exit 1
fi
