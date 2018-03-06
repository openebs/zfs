![img](http://zfsonlinux.org/images/zfs-linux.png)

ZFS on Linux is an advanced file system and volume manager which was originally
developed for Solaris and is now maintained by the OpenZFS community.

[![codecov](https://codecov.io/gh/cloudbytestorage/ZoL/branch/zfs-0.7-release/graph/badge.svg?token=i6wwszvnyt)](https://codecov.io/gh/cloudbytestorage/ZoL)

# Official Resources
  * [Site](http://zfsonlinux.org)
  * [Wiki](https://github.com/zfsonlinux/zfs/wiki)
  * [Mailing lists](https://github.com/zfsonlinux/zfs/wiki/Mailing-Lists)
  * [OpenZFS site](http://open-zfs.org/)

# Installation
Full documentation for installing ZoL on your favorite Linux distribution can
be found at [our site](http://zfsonlinux.org/).

# Contribute & Develop
We have a separate document with [contribution guidelines](./.github/CONTRIBUTING.md).

# Building
In addition to standard dependencies of ZFS on Linux project following
packages need to be installed:

```bash
sudo apt-get install libaio-dev libgtest-dev cmake libjemalloc-dev
```

Google test framework library does not have a binary package so it needs to be compiled manually:
```bash
cd /usr/src/gtest
sudo cmake -DBUILD_SHARED_LIBS=ON CMakeLists.txt
sudo make

# copy or symlink libgtest.a and libgtest_main.a to your /usr/lib folder
sudo cp *.so /usr/lib
```

Special configure option `--enable-debug` should be used in order to create
zfs and zpool commands which don't call into the kernel using ioctls, but
instead call into uZFS process for serving "ioctls" using tcp connection.
Other than that the build steps are the same as for ZoL:
```bash
./autogen.sh
CFLAGS="-g -O0" ./configure --enable-debug --enable-uzfs=yes
make
```

# Running uzfs

This assumes that you have configured zfs with `--enable-uzfs=yes` option.
To try zpool and zfs commands, start `cmd/tgt/tgt` binary with `sudo` and
leave it running. Now zpool and zfs commands from cmd/ directory can be
used in usual way.

# Contributing
Make sure to run cstyle on your changes before you submit a pull request:

```bash
make cstyle
```

And assure that the tests are passing. For possible tests to run see .travis.yml
file in root directory. Here is an example of running a couple of available
tests:

```bash
cmd/ztest/ztest -V
tests/cbtest/gtest/test_uzfs
sudo tests/cbtest/script/test_uzfs.sh
```
