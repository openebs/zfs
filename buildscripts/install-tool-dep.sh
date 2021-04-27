#!/bin/bash

# get the machine architecture
ARCH=$(uname -p)

sudo add-apt-repository -y ppa:ubuntu-toolchain-r/test
sudo apt-get update -qq
sudo apt-get install --yes -qq gcc-6 g++-6
sudo apt-get install --yes -qq build-essential autoconf libtool gawk alien fakeroot libaio-dev jq
sudo apt-get install --yes -qq linux-headers-$(uname -r);
sudo apt-get install --yes -qq zlib1g-dev uuid-dev libattr1-dev libblkid-dev libselinux-dev libudev-dev libssl-dev libjson-c-dev
sudo apt-get install --yes -qq lcov libjemalloc-dev
sudo apt-get install --yes -qq bc

# The below packages are to be installed only if the processor is x86_64
if [ "$ARCH" == "x86_64" ]; then
  sudo apt-get install --yes -qq parted lsscsi ksh attr acl nfs-kernel-server fio;
fi

sudo apt-get install --yes -qq libgtest-dev cmake

# packages for debugging
sudo apt-get install gdb

# use gcc-6 by default
sudo unlink /usr/bin/gcc && sudo ln -s /usr/bin/gcc-6 /usr/bin/gcc
sudo unlink /usr/bin/g++ && sudo ln -s /usr/bin/g++-6 /usr/bin/g++

