![img](http://zfsonlinux.org/images/zfs-linux.png)
[![FOSSA Status](https://app.fossa.io/api/projects/git%2Bgithub.com%2Fopenebs%2Fcstor.svg?type=shield)](https://app.fossa.io/projects/git%2Bgithub.com%2Fopenebs%2Fcstor?ref=badge_shield)

ZFS on Linux is an advanced file system and volume manager which was originally
developed for Solaris and is now maintained by the OpenZFS community, on which
cStor data engine is built.

[![codecov](https://codecov.io/gh/zfsonlinux/zfs/branch/master/graph/badge.svg)](https://codecov.io/gh/zfsonlinux/zfs)

# Official Resources for Zol
  * [Site](http://zfsonlinux.org)
  * [Wiki](https://github.com/zfsonlinux/zfs/wiki)
  * [Mailing lists](https://github.com/zfsonlinux/zfs/wiki/Mailing-Lists)
  * [OpenZFS site](http://open-zfs.org/)

# Contribute & Develop
We have a separate document with [contribution guidelines](./.github/CONTRIBUTING.md).

# Building
In addition to standard dependencies of ZFS on Linux project following
packages need to be installed on a ubuntu machine:

```bash
sudo add-apt-repository -y ppa:ubuntu-toolchain-r/test
sudo apt-get update -qq
sudo apt-get install --yes -qq gcc-6 g++-6
sudo apt-get install --yes -qq build-essential autoconf libtool gawk alien fakeroot linux-headers-$(uname -r) libaio-dev
sudo apt-get install --yes -qq zlib1g-dev uuid-dev libattr1-dev libblkid-dev libselinux-dev libudev-dev libssl-dev libjson-c-dev
sudo apt-get install --yes -qq lcov libjemalloc-dev
sudo apt-get install --yes -qq parted lsscsi ksh attr acl nfs-kernel-server fio
sudo apt-get install --yes -qq libgtest-dev cmake
sudo unlink /usr/bin/gcc && sudo ln -s /usr/bin/gcc-6 /usr/bin/gcc
sudo unlink /usr/bin/g++ && sudo ln -s /usr/bin/g++-6 /usr/bin/g++
```

Google test framework library does not have a binary package so it needs to be compiled manually:
```bash
cd /usr/src/gtest
sudo cmake -DBUILD_SHARED_LIBS=ON CMakeLists.txt
sudo make

# copy or symlink libgtest.a and libgtest_main.a to your /usr/lib folder
sudo cp *.so /usr/lib
```
Clone the shim layer which adds the core interfaces..

```bash
git clone https://github.com/openebs/spl
cd spl
git checkout spl-0.7.9
sh autogen.sh
./configure
make -j4
```

Special configure option `--enable-uzfs` should be used in order to create
zfs and zpool commands which don't call into the kernel using ioctls, but
instead call into uZFS process for serving "ioctls" using unix domain socket.
Other than that the build steps are the same as for ZoL:

```bash
git clone https://github.com/openebs/zfs.git
cd zfs
./autogen.sh
CFLAGS="-g -O0" ./configure --enable-debug --enable-uzfs=yes
make
```

Additional configure option `--with-fio=<path-to-fio-repo>` can be supplied
in case that fio engine for `zrepl` is wanted.

# Running it

This assumes that you have configured zfs with `--enable-uzfs=yes` option.
To try zpool and zfs commands, start `cmd/zrepl/zrepl` binary with `sudo` and
leave it running. Now zpool and zfs commands from cmd/ directory can be
run in usual way and they will act on running instance of `zrepl`.

# Testing performance

Standard IO benchmarking tool `fio` can be used with special engine for
`zrepl`. Make sure that uzfs was configured and built with fio engine.
If that is the case, then the fio can be started as follows (replace
`$UZFS_PATH` by path to built uzfs repository):

```bash
LD_LIBRARY_PATH=fio
LD_LIBRARY_PATH=$UZFS_PATH/lib/fio/.libs fio config.fio
```

Example of fio config file can be found in `lib/fio` directory.

# Docker image

A docker image with zrepl *for testing purpose* can be built as follows.
The privileged parameter when starting container is to enable process
tracing inside the container. The last command gets you a shell inside
the container which can be used for debugging, running zfs & zpool commands,
etc. Explanation of the two mounted volumes follows:

 * /dev: All devices from host are visible inside the container so we can create pools on arbitrary block device.
 * /tmp: This is a directory where core is dumped in case of a fatal failure. We make it persistent in order to preserve core dumps for later debugging.

```bash
sudo docker build -t my-cstor .
sudo mkdir /tmp/cstor
sudo docker run --privileged -it -v /dev:/dev -v /run/udev:/run/udev --mount source=cstortmp,target=/tmp my-cstor
sudo docker exec -it <container-id> /bin/bash
```

You could also run local image repo and upload the test image there:

```bash
sudo docker run -d -p 5000:5000 --restart=always --name registry registry:2
sudo docker build -t localhost:5000/my-cstor .
sudo docker push localhost:5000/my-cstor
```

# Troubleshooting

In order to print debug messages start zrepl with `-l debug` argument. If
running zrepl in container with standard entrypoint.sh script, set env
variable LOGLEVEL=debug. To do the same when running zrepl on k8s cluster
use patch command to insert the same env variable to pod definition.
Details differ based on how zrepl container was deployed on k8s cluster:

```bash
kubectl patch deployment cstor-deployment-name --patch "$(cat patch.yaml)"
```

where patch.yaml content is:
```
spec:
  template:
    spec:
      containers:
      - name: cstor-container-name
        env:
        - name: LOGLEVEL
          value: "debug"
```

# Caveats

Disk write cache must be disabled for any device not managed by linux
sd driver. Cache flush is not supported for other drivers than sd.

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
tests/cbtest/gtest/test_zrepl_prot
sudo tests/cbtest/script/test_uzfs.sh
```


## License
[![FOSSA Status](https://app.fossa.io/api/projects/git%2Bgithub.com%2Fopenebs%2Fcstor.svg?type=large)](https://app.fossa.io/projects/git%2Bgithub.com%2Fopenebs%2Fcstor?ref=badge_large)